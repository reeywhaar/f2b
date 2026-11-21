// Package history reads fail2ban's own database: who was banned, where, when, for how long, and
// the log lines that did it.
//
// Read-only, and only ever read: fail2ban owns the file and writes it as it bans. The engine
// keeps nothing of its own about bans; the database keeps them for its purge age, which the
// engine sets to ninety days unless fail2ban.local says otherwise.
package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// DB is fail2ban's database, opened when first asked and only once it exists.
type DB struct {
	path string
	mu   sync.Mutex
	db   *sql.DB
}

func Open(path string) *DB { return &DB{path: path} }

func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.db == nil {
		return nil
	}
	return d.db.Close()
}

// errMissing is a database fail2ban has not made yet, which is an empty history, not a failure.
var errMissing = errors.New("fail2ban has no database yet")

func (d *DB) conn() (*sql.DB, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.db != nil {
		return d.db, nil
	}
	if _, err := os.Stat(d.path); errors.Is(err, fs.ErrNotExist) {
		return nil, errMissing
	}
	// Read-only, and waiting out fail2ban's writes rather than failing on them.
	dsn := (&url.URL{Scheme: "file", Path: d.path, RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening fail2ban's database: %w", err)
	}
	db.SetMaxOpenConns(2)
	d.db = db
	return db, nil
}

// Ban is one ban as fail2ban recorded it.
type Ban struct {
	ID   int64  `json:"id"`
	Jail string `json:"jail"`
	IP   string `json:"ip"`
	// At is when it began, in Unix seconds.
	At int64 `json:"at"`
	// Duration is in seconds; -1 is for good.
	Duration int64 `json:"duration"`
	// Count is which ban of this address in this jail it was, fail2ban's own count.
	Count    int64    `json:"count"`
	Failures int64    `json:"failures"`
	Matches  []string `json:"matches"`
}

// data is what fail2ban keeps beside a ban: the lines that matched, each a string or the pieces
// of one, and how many failures there were.
type data struct {
	Matches  []json.RawMessage `json:"matches"`
	Failures int64             `json:"failures"`
}

func readData(raw sql.NullString, b *Ban) {
	b.Matches = []string{}
	if !raw.Valid || raw.String == "" {
		return
	}
	var d data
	if json.Unmarshal([]byte(raw.String), &d) != nil {
		return
	}
	b.Failures = d.Failures
	for _, m := range d.Matches {
		var s string
		if json.Unmarshal(m, &s) == nil {
			b.Matches = append(b.Matches, s)
			continue
		}
		var parts []string
		if json.Unmarshal(m, &parts) == nil {
			b.Matches = append(b.Matches, strings.Join(parts, ""))
		}
	}
}

// Key names a ban by jail and address.
type Key struct{ Jail, IP string }

// Latest is the latest ban of each address in each jail: when the ban in force began and how
// long it is for.
func (d *DB) Latest(ctx context.Context) (map[Key]Ban, error) {
	out := map[Key]Ban{}
	db, err := d.conn()
	if errors.Is(err, errMissing) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT rowid, jail, ip, timeofban, bantime, bancount, data FROM bips`)
	if err != nil {
		return nil, fmt.Errorf("reading the bans in force: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var b Ban
		var raw sql.NullString
		if err := rows.Scan(&b.ID, &b.Jail, &b.IP, &b.At, &b.Duration, &b.Count, &raw); err != nil {
			return nil, err
		}
		readData(raw, &b)
		out[Key{b.Jail, b.IP}] = b
	}
	return out, rows.Err()
}

// Query narrows the history.
type Query struct {
	Jail   string
	IP     string
	Before int64
	Limit  int
}

// List is bans, newest first, and the id to ask before for the page after, or 0 at the end.
func (d *DB) List(ctx context.Context, q Query) ([]Ban, int64, error) {
	bans := []Ban{}
	db, err := d.conn()
	if errors.Is(err, errMissing) {
		return bans, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 50
	}
	where, args := []string{"1=1"}, []any{}
	if q.Jail != "" {
		where, args = append(where, "jail = ?"), append(args, q.Jail)
	}
	if q.IP != "" {
		where, args = append(where, "ip = ?"), append(args, q.IP)
	}
	if q.Before > 0 {
		where, args = append(where, "rowid < ?"), append(args, q.Before)
	}
	args = append(args, q.Limit+1)
	rows, err := db.QueryContext(ctx, `SELECT rowid, jail, ip, timeofban, bantime, bancount, data FROM bans
		WHERE `+strings.Join(where, " AND ")+` ORDER BY rowid DESC LIMIT ?`, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("reading the history: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var b Ban
		var raw sql.NullString
		if err := rows.Scan(&b.ID, &b.Jail, &b.IP, &b.At, &b.Duration, &b.Count, &raw); err != nil {
			return nil, 0, err
		}
		readData(raw, &b)
		bans = append(bans, b)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var next int64
	if len(bans) > q.Limit {
		bans = bans[:q.Limit]
		next = bans[len(bans)-1].ID
	}
	return bans, next, nil
}

// Stats is a window of days of bans, counted.
type Stats struct {
	Days int `json:"days"`
	// From is the start of the first day, in Unix seconds, UTC.
	From int64 `json:"from"`
	// Jails are every jail with a ban in the window, most bans first.
	Jails  []string `json:"jails"`
	PerDay []Day    `json:"perDay"`
	// Bans, IPs and Repeat count bans, the addresses banned, and those banned more than once.
	Bans    int64      `json:"bans"`
	IPs     int64      `json:"ips"`
	Repeat  int64      `json:"repeat"`
	LastDay int64      `json:"lastDay"`
	Top     []Offender `json:"top"`
}

// Day is one day's bans by jail.
type Day struct {
	Day    string           `json:"day"`
	Total  int64            `json:"total"`
	ByJail map[string]int64 `json:"byJail"`
}

// Offender is one address and how often it was banned.
type Offender struct {
	IP    string   `json:"ip"`
	Bans  int64    `json:"bans"`
	Last  int64    `json:"last"`
	Jails []string `json:"jails"`
}

const day = 24 * 60 * 60

// Stats counts the days up to and including today, UTC.
func (d *DB) Stats(ctx context.Context, days int, now time.Time) (Stats, error) {
	today := now.UTC().Truncate(24 * time.Hour).Unix()
	from := today - int64(days-1)*day
	s := Stats{Days: days, From: from, Jails: []string{}, PerDay: make([]Day, days), Top: []Offender{}}
	for i := range s.PerDay {
		s.PerDay[i] = Day{Day: time.Unix(from+int64(i)*day, 0).UTC().Format("2006-01-02"), ByJail: map[string]int64{}}
	}
	db, err := d.conn()
	if errors.Is(err, errMissing) {
		return s, nil
	}
	if err != nil {
		return s, err
	}

	rows, err := db.QueryContext(ctx, `SELECT jail, (timeofban - ?) / ?, COUNT(*) FROM bans
		WHERE timeofban >= ? GROUP BY 1, 2`, from, day, from)
	if err != nil {
		return s, fmt.Errorf("counting bans: %w", err)
	}
	perJail := map[string]int64{}
	for rows.Next() {
		var jail string
		var i, n int64
		if err := rows.Scan(&jail, &i, &n); err != nil {
			rows.Close()
			return s, err
		}
		if i < 0 || i >= int64(days) {
			continue
		}
		s.PerDay[i].ByJail[jail] += n
		s.PerDay[i].Total += n
		perJail[jail] += n
		s.Bans += n
	}
	rows.Close()
	for j := range perJail {
		s.Jails = append(s.Jails, j)
	}
	sort.Slice(s.Jails, func(a, b int) bool {
		if perJail[s.Jails[a]] != perJail[s.Jails[b]] {
			return perJail[s.Jails[a]] > perJail[s.Jails[b]]
		}
		return s.Jails[a] < s.Jails[b]
	})

	err = db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(n > 1), 0) FROM
		(SELECT ip, COUNT(*) AS n FROM bans WHERE timeofban >= ? GROUP BY ip)`, from).Scan(&s.IPs, &s.Repeat)
	if err != nil {
		return s, fmt.Errorf("counting addresses: %w", err)
	}
	err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bans WHERE timeofban >= ?`, now.Unix()-day).Scan(&s.LastDay)
	if err != nil {
		return s, fmt.Errorf("counting the last day: %w", err)
	}

	rows, err = db.QueryContext(ctx, `SELECT ip, COUNT(*) AS n, MAX(timeofban), GROUP_CONCAT(DISTINCT jail)
		FROM bans WHERE timeofban >= ? GROUP BY ip ORDER BY n DESC, MAX(timeofban) DESC LIMIT 20`, from)
	if err != nil {
		return s, fmt.Errorf("finding the most banned: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var o Offender
		var jails string
		if err := rows.Scan(&o.IP, &o.Bans, &o.Last, &jails); err != nil {
			return s, err
		}
		o.Jails = strings.Split(jails, ",")
		sort.Strings(o.Jails)
		s.Top = append(s.Top, o)
	}
	return s, rows.Err()
}

// Schema is fail2ban 1.1's own, as it creates it, for a test or the demo to make a database
// fail2ban would have made.
const Schema = `
CREATE TABLE fail2banDb(version INTEGER);
INSERT INTO fail2banDb VALUES (4);
CREATE TABLE jails(name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);
CREATE INDEX jails_name ON jails(name);
CREATE TABLE logs(jail TEXT NOT NULL, path TEXT, firstlinemd5 TEXT, lastfilepos INTEGER DEFAULT 0, FOREIGN KEY(jail) REFERENCES jails(name) ON DELETE CASCADE, UNIQUE(jail, path),UNIQUE(jail, path, firstlinemd5));
CREATE INDEX logs_path ON logs(path);
CREATE INDEX logs_jail_path ON logs(jail, path);
CREATE TABLE bans(jail TEXT NOT NULL, ip TEXT, timeofban INTEGER NOT NULL, bantime INTEGER NOT NULL, bancount INTEGER NOT NULL default 1, data JSON, FOREIGN KEY(jail) REFERENCES jails(name) );
CREATE INDEX bans_jail_timeofban_ip ON bans(jail, timeofban);
CREATE INDEX bans_jail_ip ON bans(jail, ip);
CREATE INDEX bans_ip ON bans(ip);
CREATE TABLE bips(ip TEXT NOT NULL, jail TEXT NOT NULL, timeofban INTEGER NOT NULL, bantime INTEGER NOT NULL, bancount INTEGER NOT NULL default 1, data JSON, PRIMARY KEY(ip, jail), FOREIGN KEY(jail) REFERENCES jails(name) );
CREATE INDEX bips_timeofban ON bips(timeofban);
CREATE INDEX bips_ip ON bips(ip);
`
