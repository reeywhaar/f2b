package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"f2b/internal/f2bsock"
)

// Supervisor runs fail2ban as a child, starts it again when it stops, and answers for it.
type Supervisor struct {
	// Dir is the composed configuration fail2ban is started with.
	Dir string
	// Prepare composes Dir before each start, so a start always reads what is on disk now.
	Prepare func() error
	Client  *f2bsock.Client
	Lines   *Lines
	Log     *slog.Logger
	// Program is fail2ban-client, which with -f runs the server in the foreground.
	Program string

	mu      sync.Mutex
	state   DaemonState
	stop    context.CancelFunc
	kick    chan struct{}
	asked   bool
	version string
}

// stopGrace is how long fail2ban has to take its rules down before it is killed. Inside
// Docker's own default of ten seconds, so a stopping container gets to finish it.
const stopGrace = 8 * time.Second

func (s *Supervisor) State() DaemonState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state
	st.Version = s.version
	return st
}

func (s *Supervisor) set(state string, pid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.State, s.state.Pid, s.state.Since = state, pid, time.Now().Unix()
}

// Restart stops the running fail2ban, which Run then starts again at once.
func (s *Supervisor) Restart() {
	s.mu.Lock()
	stop := s.stop
	s.asked = true
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run keeps fail2ban running until ctx ends, and then stops it.
func (s *Supervisor) Run(ctx context.Context) {
	s.mu.Lock()
	s.kick = make(chan struct{}, 1)
	s.state = DaemonState{State: Stopped, Since: time.Now().Unix()}
	s.mu.Unlock()

	backoff := time.Second
	for ctx.Err() == nil {
		began := time.Now()
		err := s.once(ctx)
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		asked := s.asked
		s.asked = false
		if !asked {
			s.state.Restarts++
		}
		s.state.LastExit = describe(err)
		s.mu.Unlock()
		s.set(Stopped, 0)

		if asked {
			backoff = time.Second
			select {
			case <-s.kick:
			default:
			}
			continue
		}
		// A fail2ban that ran a while and then fell over is started again quickly; one that
		// cannot start at all, slower and slower, rather than filling the log.
		if time.Since(began) > time.Minute {
			backoff = time.Second
		}
		s.Lines.Note("ERROR", fmt.Sprintf("fail2ban stopped (%s); starting it again in %s", describe(err), backoff))
		s.Log.Warn("fail2ban stopped", "error", describe(err), "retry", backoff)
		select {
		case <-ctx.Done():
			return
		case <-s.kick:
			backoff = time.Second
		case <-time.After(backoff):
			backoff = min(backoff*2, time.Minute)
		}
	}
}

func describe(err error) string {
	if err == nil {
		return "it exited"
	}
	return err.Error()
}

// once runs fail2ban until it stops, or until it is asked to.
func (s *Supervisor) once(parent context.Context) error {
	if err := s.Prepare(); err != nil {
		return fmt.Errorf("its configuration could not be written: %w", err)
	}
	ctx, stop := context.WithCancel(parent)
	defer stop()
	s.mu.Lock()
	s.stop = stop
	s.mu.Unlock()

	cmd := exec.CommandContext(ctx, s.Program, "-c", s.Dir, "-x", "-f", "start")
	// SIGTERM rather than a kill: fail2ban takes its rules out of the firewall on the way down.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopGrace
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("it could not be started: %w", err)
	}
	s.set(Starting, cmd.Process.Pid)
	s.Log.Info("fail2ban starting", "pid", cmd.Process.Pid)

	fed := make(chan struct{})
	go func() {
		s.Lines.Feed(out)
		close(fed)
	}()
	go s.watch(ctx, cmd.Process.Pid)

	err = cmd.Wait()
	<-fed
	if err != nil && ctx.Err() != nil {
		return errors.New("it was stopped")
	}
	return err
}

// watch marks fail2ban running once it answers on its socket.
func (s *Supervisor) watch(ctx context.Context, pid int) {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if v, err := s.Client.Do(ctx, "ping"); err == nil && v == "pong" {
			if v, err := s.Client.Do(ctx, "version"); err == nil {
				s.mu.Lock()
				s.version, _ = v.(string)
				s.mu.Unlock()
			}
			s.set(Running, pid)
			s.Log.Info("fail2ban running", "pid", pid)
			return
		}
	}
}

// Jails asks for every running jail and its counts.
func (s *Supervisor) Jails(ctx context.Context) ([]Jail, error) {
	v, err := s.Client.Do(ctx, "status")
	if err != nil {
		return nil, err
	}
	var names []string
	if list, _ := f2bsock.Pairs(v)["Jail list"].(string); list != "" {
		for _, n := range strings.Split(list, ",") {
			names = append(names, strings.TrimSpace(n))
		}
	}
	sort.Strings(names)
	jails := make([]Jail, 0, len(names))
	for _, name := range names {
		j := Jail{Name: name, Logs: []string{}}
		v, err := s.Client.Do(ctx, "status", name)
		if err != nil {
			return nil, err
		}
		p := f2bsock.Pairs(v)
		filter, actions := f2bsock.Pairs(p["Filter"]), f2bsock.Pairs(p["Actions"])
		j.FailedNow = f2bsock.Int(filter["Currently failed"])
		j.FailedTotal = f2bsock.Int(filter["Total failed"])
		j.BannedNow = f2bsock.Int(actions["Currently banned"])
		j.BannedTotal = f2bsock.Int(actions["Total banned"])
		if logs, err := s.Client.Do(ctx, "get", name, "logpath"); err == nil {
			j.Logs = f2bsock.Strings(logs)
		}
		for key, into := range map[string]*int64{"findtime": &j.FindTime, "bantime": &j.BanTime, "maxretry": &j.MaxRetry} {
			if v, err := s.Client.Do(ctx, "get", name, key); err == nil {
				*into = f2bsock.Int(v)
			}
		}
		jails = append(jails, j)
	}
	return jails, nil
}

func (s *Supervisor) Banned(ctx context.Context) (map[string][]string, error) {
	v, err := s.Client.Do(ctx, "banned")
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	list, _ := v.([]any)
	for _, e := range list {
		m, _ := e.(map[string]any)
		for jail, ips := range m {
			out[jail] = f2bsock.Strings(ips)
		}
	}
	return out, nil
}

func (s *Supervisor) Ban(ctx context.Context, jail, ip string) error {
	_, err := s.Client.Do(ctx, "set", jail, "banip", ip)
	return err
}

func (s *Supervisor) Unban(ctx context.Context, jail, ip string) error {
	if jail == "" {
		_, err := s.Client.Do(ctx, "unban", ip)
		return err
	}
	_, err := s.Client.Do(ctx, "set", jail, "unbanip", ip)
	return err
}
