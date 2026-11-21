package demo

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"f2b/internal/engine"
	"f2b/internal/f2bsock"
)

// jailDef is a jail as the composed configuration defines it.
type jailDef struct {
	name     string
	filter   string
	logs     []string
	maxRetry int64
	findTime int64
	banTime  int64
}

// daemon stands in for fail2ban: the jails the configuration enables, bans held in memory and
// written to a database in fail2ban's own shape, and a log of what it did.
type daemon struct {
	live  string
	db    *sql.DB
	lines *engine.Lines
	now   func() time.Time

	mu          sync.Mutex
	state       engine.DaemonState
	defs        []jailDef
	banned      map[string]map[string]int64
	failedTotal map[string]int64
	bannedTotal map[string]int64
}

func (d *daemon) State() engine.DaemonState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}

func (d *daemon) Restart() {
	d.mu.Lock()
	d.state = engine.DaemonState{State: engine.Starting, Version: d.state.Version, Pid: d.state.Pid + 1, Since: d.now().Unix(), Restarts: d.state.Restarts}
	d.mu.Unlock()
	t := d.now()
	d.lines.Add(fail2banLine(t, "fail2ban.server", "INFO", "Shutdown in progress..."))
	d.lines.Add(fail2banLine(t, "fail2ban.server", "INFO", "Exiting Fail2ban"))
	go func() {
		time.Sleep(1500 * time.Millisecond)
		d.reload(d.live)
		d.mu.Lock()
		d.state.State, d.state.Since = engine.Running, d.now().Unix()
		d.mu.Unlock()
		d.lines.Add(fail2banLine(d.now(), "fail2ban.server", "INFO", "Starting Fail2ban v1.1.0"))
		d.lines.Add(fail2banLine(d.now(), "fail2ban.server", "INFO", "Server ready"))
	}()
}

func (d *daemon) running() error {
	if d.State().State != engine.Running {
		return fmt.Errorf("%w: the demo's fail2ban is restarting", f2bsock.ErrUnreachable)
	}
	return nil
}

func (d *daemon) Jails(ctx context.Context) ([]engine.Jail, error) {
	if err := d.running(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]engine.Jail, 0, len(d.defs))
	for _, def := range d.defs {
		now := int64(len(d.banned[def.name]))
		out = append(out, engine.Jail{
			Name:        def.name,
			FailedNow:   int64(len(def.name)) % 3,
			FailedTotal: d.failedTotal[def.name],
			BannedNow:   now,
			BannedTotal: d.bannedTotal[def.name],
			Logs:        def.logs,
			FindTime:    def.findTime,
			BanTime:     def.banTime,
			MaxRetry:    def.maxRetry,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (d *daemon) Banned(ctx context.Context) (map[string][]string, error) {
	if err := d.running(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string][]string{}
	for _, def := range d.defs {
		out[def.name] = []string{}
		for ip := range d.banned[def.name] {
			out[def.name] = append(out[def.name], ip)
		}
		sort.Strings(out[def.name])
	}
	return out, nil
}

func (d *daemon) def(name string) (jailDef, bool) {
	for _, def := range d.defs {
		if def.name == name {
			return def, true
		}
	}
	return jailDef{}, false
}

func (d *daemon) Ban(ctx context.Context, jail, ip string) error {
	if err := d.running(); err != nil {
		return err
	}
	d.mu.Lock()
	def, ok := d.def(jail)
	d.mu.Unlock()
	if !ok {
		return &f2bsock.Error{Kind: "UnknownJailException", Message: "there is no running jail " + jail}
	}
	return d.ban(def, ip, d.now(), nil)
}

// ban records a ban as fail2ban would: in force, in the history, and in the log.
func (d *daemon) ban(def jailDef, ip string, at time.Time, matches []string) error {
	d.mu.Lock()
	if d.banned[def.name] == nil {
		d.banned[def.name] = map[string]int64{}
	}
	if _, already := d.banned[def.name][ip]; already {
		d.mu.Unlock()
		d.lines.Add(fail2banLine(at, "fail2ban.actions", "NOTICE", jailNote(def.name, ip+" already banned")))
		return nil
	}
	until := int64(0)
	if def.banTime > 0 {
		until = at.Unix() + def.banTime
	}
	d.banned[def.name][ip] = until
	d.bannedTotal[def.name]++
	d.failedTotal[def.name] += int64(max(len(matches), 1))
	d.mu.Unlock()

	if matches == nil {
		matches = []string{}
	}
	data, _ := json.Marshal(map[string]any{"matches": matches, "failures": max(len(matches), 1)})
	var count int64
	d.db.QueryRow(`SELECT bancount FROM bips WHERE ip = ? AND jail = ?`, ip, def.name).Scan(&count)
	count++
	if _, err := d.db.Exec(`INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES (?, ?, ?, ?, ?, ?)`,
		def.name, ip, at.Unix(), def.banTime, count, string(data)); err != nil {
		return err
	}
	if _, err := d.db.Exec(`INSERT OR REPLACE INTO bips(ip, jail, timeofban, bantime, bancount, data) VALUES (?, ?, ?, ?, ?, ?)`,
		ip, def.name, at.Unix(), def.banTime, count, string(data)); err != nil {
		return err
	}
	d.lines.Add(fail2banLine(at, "fail2ban.actions", "NOTICE", jailNote(def.name, "Ban "+ip)))
	return nil
}

func (d *daemon) Unban(ctx context.Context, jail, ip string) error {
	if err := d.running(); err != nil {
		return err
	}
	d.mu.Lock()
	var from []string
	for name, ips := range d.banned {
		if jail != "" && name != jail {
			continue
		}
		if _, ok := ips[ip]; ok {
			delete(ips, ip)
			from = append(from, name)
		}
	}
	d.mu.Unlock()
	sort.Strings(from)
	for _, name := range from {
		d.lines.Add(fail2banLine(d.now(), "fail2ban.actions", "NOTICE", jailNote(name, "Unban "+ip)))
	}
	return nil
}

// expire lifts the bans whose time is up.
func (d *daemon) expire() {
	now := d.now()
	d.mu.Lock()
	var lifted [][2]string
	for name, ips := range d.banned {
		for ip, until := range ips {
			if until > 0 && until <= now.Unix() {
				delete(ips, ip)
				lifted = append(lifted, [2]string{name, ip})
			}
		}
	}
	d.mu.Unlock()
	for _, l := range lifted {
		d.lines.Add(fail2banLine(now, "fail2ban.actions", "NOTICE", jailNote(l[0], "Unban "+l[1])))
	}
}

// reload reads which jails the configuration in dir enables, keeping the bans of those still
// there.
func (d *daemon) reload(dir string) error {
	defs, err := readJails(dir)
	if err != nil {
		return err
	}
	d.mu.Lock()
	kept := map[string]bool{}
	for _, def := range defs {
		kept[def.name] = true
	}
	var stopped []string
	for _, old := range d.defs {
		if !kept[old.name] {
			stopped = append(stopped, old.name)
			delete(d.banned, old.name)
		}
	}
	var started []string
	for _, def := range defs {
		if _, ok := d.def(def.name); !ok {
			started = append(started, def.name)
		}
	}
	d.defs = defs
	d.mu.Unlock()
	t := d.now()
	for _, name := range stopped {
		d.lines.Add(fail2banLine(t, "fail2ban.jail", "INFO", fmt.Sprintf("Jail '%s' stopped", name)))
	}
	for _, name := range started {
		d.lines.Add(fail2banLine(t, "fail2ban.jail", "INFO", fmt.Sprintf("Jail '%s' started", name)))
	}
	d.lines.Add(fail2banLine(t, "fail2ban.server", "INFO", "Reload finished."))
	return nil
}

// readJails merges jail.conf, jail.d/*.conf, jail.local and jail.d/*.local as fail2ban does, and
// returns the jails that end up enabled.
func readJails(dir string) ([]jailDef, error) {
	var ordered []section
	read := func(p string) error {
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		secs, err := parseINI(p, string(b))
		if err != nil {
			return err
		}
		ordered = append(ordered, secs...)
		return nil
	}
	if err := read(filepath.Join(dir, "paths-debian.conf")); err != nil {
		return nil, err
	}
	if err := read(filepath.Join(dir, "jail.conf")); err != nil {
		return nil, err
	}
	for _, ext := range []string{".conf", ".local"} {
		if ext == ".local" {
			if err := read(filepath.Join(dir, "jail.local")); err != nil {
				return nil, err
			}
		}
		matches, _ := filepath.Glob(filepath.Join(dir, "jail.d", "*"+ext))
		sort.Strings(matches)
		for _, m := range matches {
			if err := read(m); err != nil {
				return nil, err
			}
		}
	}
	defaults := map[string]string{}
	jails := map[string]map[string]string{}
	var order []string
	for _, s := range ordered {
		if strings.EqualFold(s.name, "DEFAULT") {
			for k, v := range s.keys {
				defaults[k] = v
			}
			continue
		}
		if strings.EqualFold(s.name, "INCLUDES") {
			continue
		}
		if jails[s.name] == nil {
			jails[s.name] = map[string]string{}
			order = append(order, s.name)
		}
		for k, v := range s.keys {
			jails[s.name][k] = v
		}
	}
	var out []jailDef
	for _, name := range order {
		keys := map[string]string{"__name__": name, "mode": "normal"}
		for k, v := range defaults {
			keys[k] = v
		}
		for k, v := range jails[name] {
			keys[k] = v
		}
		if strings.ToLower(keys["enabled"]) != "true" {
			continue
		}
		filter := expand(keys["filter"], keys)
		if filter == "" {
			filter = name
		}
		out = append(out, jailDef{
			name:     name,
			filter:   filter,
			logs:     strings.Fields(expand(keys["logpath"], keys)),
			maxRetry: seconds(keys["maxretry"], 5),
			findTime: seconds(keys["findtime"], 600),
			banTime:  seconds(keys["bantime"], 600),
		})
	}
	return out, nil
}

// seconds reads fail2ban's durations: a number of seconds, or one with a unit.
func seconds(v string, fallback int64) int64 {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	units := map[byte]int64{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
	if u, ok := units[v[len(v)-1]]; ok {
		if n, err := strconv.ParseInt(v[:len(v)-1], 10, 64); err == nil {
			return n * u
		}
	}
	return fallback
}

// activity bans somebody now and then, so the demo has something happening while it is watched.
func (d *daemon) activity(ctx context.Context, js []jail, r *rand.Rand) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(15+r.IntN(30)) * time.Second):
		}
		d.expire()
		if d.State().State != engine.Running {
			continue
		}
		j := pick(js, r)
		d.mu.Lock()
		def, ok := d.def(j.name)
		d.mu.Unlock()
		if !ok {
			continue
		}
		ip := address(r)
		now := d.now()
		var matches []string
		step := time.Duration(5+r.IntN(40)) * time.Second
		for i := range int(def.maxRetry) {
			t := now.Add(-time.Duration(int(def.maxRetry)-i) * step)
			line := j.line(t, ip, r)
			matches = append(matches, line)
			appendLine(j.log, background(j, t, r))
			appendLine(j.log, line)
			d.lines.Add(fail2banLine(t, "fail2ban.filter", "INFO", jailNote(def.name, "Found "+ip+" - "+t.UTC().Format("2006-01-02 15:04:05"))))
		}
		d.ban(def, ip, now, matches)
	}
}

func pick(js []jail, r *rand.Rand) jail {
	var total float64
	for _, j := range js {
		total += j.perDay
	}
	x := r.Float64() * total
	for _, j := range js {
		if x < j.perDay {
			return j
		}
		x -= j.perDay
	}
	return js[0]
}

func appendLine(path, line string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, line)
}
