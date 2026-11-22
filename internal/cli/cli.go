// Package cli is the command line: the engine, the web, the demo's stand-in engine, and the
// questions a container asks of them.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"f2b/internal/app"
	"f2b/internal/config"
	"f2b/internal/demo"
	"f2b/internal/engine"
	"f2b/internal/f2bsock"
	"f2b/internal/history"
	"f2b/internal/webui"
)

const usage = `usage: f2b <command>

  engine              run fail2ban and its API; the engine image's default
  web                 serve the interface; the web image's default
  demo                a stand-in engine with invented jails and bans, for ./run_demo.sh
  healthcheck engine  ask the running engine whether it and fail2ban are well
  healthcheck web     ask the running web whether it is well
  version             print the version this binary was built from
`

// Execute runs the command line and returns a process exit code.
func Execute(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	var err error
	switch {
	case args[0] == "engine" && len(args) == 1:
		err = runEngine()
	case args[0] == "web" && len(args) == 1:
		err = runWeb()
	case args[0] == "demo" && len(args) == 1:
		err = runDemo()
	case args[0] == "healthcheck" && len(args) == 2 && (args[1] == "engine" || args[1] == "web"):
		err = healthcheck(args[1])
	case args[0] == "version" && len(args) == 1:
		fmt.Println(app.Version)
	case args[0] == "help" || args[0] == "-h" || args[0] == "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, app.Name+":", err)
		return 1
	}
	return 0
}

func logger(level slog.Level) *slog.Logger {
	// JSON, so a line is a record a collector reads field by field.
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level, ReplaceAttr: readable}))
}

// readable writes a duration as one reads it, "1.2s", rather than as a count of nanoseconds.
func readable(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindDuration {
		return slog.String(a.Key, a.Value.Duration().String())
	}
	return a
}

func runEngine() error {
	cfg, err := config.LoadCommon()
	if err != nil {
		return err
	}
	log := logger(cfg.LogLevel)
	l := cfg.Layout

	files := &engine.Files{Root: l.Config}
	if err := files.Ensure(); err != nil {
		return err
	}
	if err := os.MkdirAll(app.RunDir, 0o755); err != nil {
		return err
	}
	// fail2ban's own lines go to the container's output as they are, beside this log.
	lines, err := engine.OpenLines(l.Log, os.Stdout)
	if err != nil {
		return err
	}
	defer lines.Close()

	sock := filepath.Join(app.RunDir, "fail2ban.sock")
	composer := &engine.Composer{
		Stock:    app.StockDir,
		Files:    files,
		Socket:   sock,
		PidFile:  filepath.Join(app.RunDir, "fail2ban.pid"),
		Database: l.Database,
	}
	sup := &engine.Supervisor{
		Dir:     filepath.Join(app.RunDir, "etc"),
		Client:  f2bsock.New(sock),
		Lines:   lines,
		Log:     log,
		Program: "fail2ban-client",
	}
	db := history.Open(l.Database)
	defer db.Close()
	srv := &engine.Server{
		Files:    files,
		Composer: composer,
		Daemon:   sup,
		Tools:    engine.Programs{Client: "fail2ban-client", Tester: "fail2ban-regex"},
		History:  db,
		Lines:    lines,
		Log:      log,
		Live:     sup.Dir,
		Scratch:  filepath.Join(app.RunDir, "scratch"),
	}
	sup.Prepare = srv.PrepareLive

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var background sync.WaitGroup
	background.Go(func() { sup.Run(ctx) })
	log.Info("f2b engine started", "version", app.Version, "data", l.Data, "socket", l.Socket)
	err = serveSocket(ctx, l.Socket, srv.Handler(), log)
	stop()
	// fail2ban takes its rules down on the way out; waited for, so the container does not stop
	// with them half removed.
	background.Wait()
	return err
}

// serveSocket answers on a unix socket in the data directory until ctx ends.
func serveSocket(ctx context.Context, path string, h http.Handler, log *slog.Logger) error {
	// A socket left by a run that did not stop cleanly refuses the bind.
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", path, err)
	}
	os.Chmod(path, 0o660)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("f2b engine stopping")
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := srv.Shutdown(shutdown)
		os.Remove(path)
		return err
	}
}

func runWeb() error {
	cfg, err := config.LoadWeb()
	if err != nil {
		return err
	}
	log := logger(cfg.LogLevel)
	if !cfg.Secure {
		log.Warn("the public url is http, so the session cookie goes without Secure")
	}
	sessions, err := webui.NewSessions(cfg.Layout.SessionKey, cfg.Password, cfg.Secure)
	if err != nil {
		return err
	}
	tokens, err := webui.OpenTokens(cfg.Layout.Tokens)
	if err != nil {
		return err
	}
	spa, err := webui.NewSPA(bundle(log))
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              app.ListenAddr,
		Handler:           webui.New(cfg, log, sessions, tokens, spa),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		log.Info("f2b web started", "addr", app.ListenAddr, "version", app.Version, "engine", cfg.Layout.Socket)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		// Bounded, or one slow request costs the full kill timeout every deploy.
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		log.Info("f2b web stopping")
		return srv.Shutdown(shutdown)
	}
}

// bundle is the built frontend: the image's, or a checkout's own web/dist. Neither is the
// placeholder page, said once at startup.
func bundle(log *slog.Logger) fs.FS {
	for _, dir := range []string{app.WebDir, "web/dist"} {
		if _, err := os.Stat(dir); err == nil {
			return os.DirFS(dir)
		}
	}
	log.Warn("no web directory: browsers get the placeholder page instead of the interface", "dir", app.WebDir)
	return nil
}

func runDemo() error {
	cfg, err := config.LoadCommon()
	if err != nil {
		return err
	}
	log := logger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := demo.New(ctx, cfg.Layout, log)
	if err != nil {
		return err
	}
	log.Info("f2b demo engine started", "version", app.Version, "data", cfg.Layout.Data, "socket", cfg.Layout.Socket)
	return serveSocket(ctx, cfg.Layout.Socket, srv, log)
}

// healthcheck is what HEALTHCHECK runs: a second process asking the first, so the image needs
// no HTTP client and a wedged server fails it. The engine is well when fail2ban is running.
func healthcheck(which string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	url := "http://127.0.0.1" + app.ListenAddr + "/healthz"
	if which == "engine" {
		cfg, err := config.LoadCommon()
		if err != nil {
			return err
		}
		socket := cfg.Layout.Socket
		client.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}}
		url = "http://engine/healthz"
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz answered %s", resp.Status)
	}
	if which == "engine" {
		var body struct {
			Fail2ban string `json:"fail2ban"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		if body.Fail2ban != engine.Running {
			return fmt.Errorf("fail2ban is %s", body.Fail2ban)
		}
	}
	return nil
}
