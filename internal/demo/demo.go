// Package demo is a stand-in engine: the engine's own API over invented jails, bans and logs,
// for trying the interface, and for its screenshots, without fail2ban or a firewall.
//
// Everything but fail2ban is the real thing. The files are edited on disk and composed as the
// engine composes them, and the history is read from a database in fail2ban's own shape, by the
// same code. What stands in is fail2ban itself: its jails and bans are kept in memory, and its
// tools are answered in Go.
package demo

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"f2b/internal/app"
	"f2b/internal/engine"
	"f2b/internal/history"
)

// days of history the demo starts with.
const days = 90

// New writes the demo's files, logs and history afresh, and returns the engine API over them.
// The session key is the one thing in the data directory it leaves alone, so a browser signed in
// stays signed in.
func New(ctx context.Context, l app.Layout, log *slog.Logger) (http.Handler, error) {
	r := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 7))
	logs := filepath.Join(l.Data, "logs")
	stockDir := filepath.Join(l.Data, "demo-stock")
	run := filepath.Join(l.Data, "run")
	for _, p := range []string{l.Config, logs, stockDir, run, l.Database, l.Log, l.Log + ".1"} {
		if err := os.RemoveAll(p); err != nil {
			return nil, err
		}
	}
	files := &engine.Files{Root: l.Config}
	if err := files.Ensure(); err != nil {
		return nil, err
	}
	for path, content := range configFiles(logs) {
		kind, name, _ := strings.Cut(path, "/")
		if err := files.Write(engine.Kind(kind), name, content); err != nil {
			return nil, err
		}
	}
	for rel, content := range stock {
		p := filepath.Join(stockDir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(logs, 0o755); err != nil {
		return nil, err
	}

	lines, err := engine.OpenLines(l.Log, nil)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+l.Database+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(DELETE)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(history.Schema); err != nil {
		return nil, fmt.Errorf("making the demo's database: %w", err)
	}

	composer := &engine.Composer{
		Stock:    stockDir,
		Files:    files,
		Socket:   filepath.Join(run, "fail2ban.sock"),
		PidFile:  filepath.Join(run, "fail2ban.pid"),
		Database: l.Database,
	}
	live := filepath.Join(run, "etc")
	if err := composer.Compose(live, nil); err != nil {
		return nil, err
	}
	js := jails(logs)
	d := &daemon{
		live:        live,
		db:          db,
		lines:       lines,
		now:         time.Now,
		banned:      map[string]map[string]int64{},
		failedTotal: map[string]int64{},
		bannedTotal: map[string]int64{},
	}
	d.state = engine.DaemonState{State: engine.Running, Version: "1.1.0", Pid: 7, Since: time.Now().Add(-26 * time.Hour).Unix()}
	if err := d.reload(live); err != nil {
		return nil, err
	}
	if err := seed(d, js, r, l.Database); err != nil {
		return nil, fmt.Errorf("filling the demo's history: %w", err)
	}
	go d.activity(ctx, js, r)
	go func() {
		<-ctx.Done()
		db.Close()
		lines.Close()
	}()

	srv := &engine.Server{
		Files:    files,
		Composer: composer,
		Daemon:   d,
		Tools:    tools{d: d},
		History:  history.Open(l.Database),
		Lines:    lines,
		Log:      log,
		Live:     live,
		Scratch:  filepath.Join(run, "scratch"),
	}
	return srv.Handler(), nil
}

// seed fills ninety days of history, the bans still in force, each jail's log, and fail2ban's own.
func seed(d *daemon, js []jail, r *rand.Rand, database string) error {
	now := time.Now()
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, j := range js {
		if _, err := tx.Exec(`INSERT INTO jails(name, enabled) VALUES (?, 1)`, j.name); err != nil {
			return err
		}
	}
	counts := map[[2]string]int64{}
	type latest struct {
		at, banTime, count int64
		data               string
	}
	bips := map[[2]string]latest{}
	for day := days; day >= 0; day-- {
		// Busier lately, and busier on weekdays, so the chart has a shape.
		trend := 0.55 + 0.45*float64(days-day)/days
		date := now.AddDate(0, 0, -day)
		if wd := date.Weekday(); wd == time.Saturday || wd == time.Sunday {
			trend *= 0.7
		}
		for _, j := range js {
			n := poisson(j.perDay*trend, r)
			for range n {
				at := date.Add(-time.Duration(r.IntN(86400)) * time.Second)
				if at.After(now) {
					continue
				}
				ip := address(r)
				k := [2]string{j.name, ip}
				counts[k]++
				var matches []string
				for i := range 3 + r.IntN(3) {
					matches = append(matches, j.line(at.Add(-time.Duration(30*(5-i))*time.Second), ip, r))
				}
				data, _ := json.Marshal(map[string]any{"matches": matches, "failures": len(matches)})
				if _, err := tx.Exec(`INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES (?, ?, ?, ?, ?, ?)`,
					j.name, ip, at.Unix(), j.banTime, counts[k], string(data)); err != nil {
					return err
				}
				if prev, ok := bips[k]; !ok || prev.at < at.Unix() {
					bips[k] = latest{at.Unix(), j.banTime, counts[k], string(data)}
				}
				d.bannedTotal[j.name]++
				d.failedTotal[j.name] += int64(len(matches))
			}
		}
	}
	for k, b := range bips {
		if _, err := tx.Exec(`INSERT INTO bips(ip, jail, timeofban, bantime, bancount, data) VALUES (?, ?, ?, ?, ?, ?)`,
			k[1], k[0], b.at, b.banTime, b.count, b.data); err != nil {
			return err
		}
		if until := b.at + b.banTime; until > now.Unix() {
			if d.banned[k[0]] == nil {
				d.banned[k[0]] = map[string]int64{}
			}
			d.banned[k[0]][k[1]] = until
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	for _, j := range js {
		var b strings.Builder
		for i := 300; i > 0; i-- {
			t := now.Add(-time.Duration(i) * 3 * time.Minute)
			if r.IntN(5) == 0 {
				ip := address(r)
				for range 3 {
					fmt.Fprintln(&b, j.line(t, ip, r))
				}
				continue
			}
			fmt.Fprintln(&b, background(j, t, r))
		}
		if err := os.WriteFile(j.log, []byte(b.String()), 0o644); err != nil {
			return err
		}
	}

	start := now.Add(-26 * time.Hour)
	d.lines.Add(fail2banLine(start, "fail2ban.server", "INFO", "Starting Fail2ban v1.1.0"))
	d.lines.Add(fail2banLine(start, "fail2ban.observer", "INFO", "Observer start..."))
	d.lines.Add(fail2banLine(start, "fail2ban.database", "INFO", "Connected to fail2ban persistent database '"+database+"'"))
	for _, j := range js {
		d.lines.Add(fail2banLine(start, "fail2ban.jail", "INFO", fmt.Sprintf("Creating new jail '%s'", j.name)))
		d.lines.Add(fail2banLine(start, "fail2ban.filter", "INFO", jailNote(j.name, "Added logfile: '"+j.log+"' (pos = 0, hash = 0)")))
		d.lines.Add(fail2banLine(start, "fail2ban.jail", "INFO", fmt.Sprintf("Jail '%s' started", j.name)))
	}
	d.lines.Add(fail2banLine(start, "fail2ban.server", "INFO", "Server ready"))
	rows, err := d.db.Query(`SELECT jail, ip, timeofban FROM bans WHERE timeofban >= ? ORDER BY timeofban`, now.Add(-6*time.Hour).Unix())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var jail, ip string
		var at int64
		if err := rows.Scan(&jail, &ip, &at); err != nil {
			return err
		}
		t := time.Unix(at, 0)
		d.lines.Add(fail2banLine(t.Add(-40*time.Second), "fail2ban.filter", "INFO", jailNote(jail, "Found "+ip+" - "+t.UTC().Format("2006-01-02 15:04:05"))))
		d.lines.Add(fail2banLine(t, "fail2ban.actions", "NOTICE", jailNote(jail, "Ban "+ip)))
	}
	return rows.Err()
}

func poisson(mean float64, r *rand.Rand) int {
	limit, k, p := math.Exp(-mean), 0, 1.0
	for {
		p *= r.Float64()
		if p < limit {
			return k
		}
		k++
	}
}
