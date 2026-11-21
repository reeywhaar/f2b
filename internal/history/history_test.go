package history

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 21, 15, 0, 0, 0, time.UTC)

// fixture is a database as fail2ban makes it, with these bans in it.
func fixture(t *testing.T, rows [][]any) *DB {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fail2ban.sqlite3")
	db, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(Schema); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES (?, ?, ?, ?, ?, ?)`, r...); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT OR REPLACE INTO bips(jail, ip, timeofban, bantime, bancount, data) VALUES (?, ?, ?, ?, ?, ?)`, r...); err != nil {
			t.Fatal(err)
		}
	}
	d := Open(p)
	t.Cleanup(func() { d.Close() })
	return d
}

func at(daysAgo int, hour int) int64 {
	return now.Truncate(24*time.Hour).AddDate(0, 0, -daysAgo).Add(time.Duration(hour) * time.Hour).Unix()
}

func TestNoDatabaseIsAnEmptyHistory(t *testing.T) {
	d := Open(filepath.Join(t.TempDir(), "none.sqlite3"))
	s, err := d.Stats(context.Background(), 7, now)
	if err != nil || s.Bans != 0 || len(s.PerDay) != 7 {
		t.Fatalf("%v %+v", err, s)
	}
	bans, next, err := d.List(context.Background(), Query{})
	if err != nil || len(bans) != 0 || next != 0 {
		t.Fatalf("%v %v %v", err, bans, next)
	}
}

func TestMatchesAreReadInBothOfFail2bansShapes(t *testing.T) {
	// A match is a line, or the line in pieces around its date: fail2ban writes both.
	data := `{"matches": [["{\"time\":\"", "2026-11-21T07:43:20Z", "\",\"ip\":\"192.0.2.77\"}"], "plain line"], "failures": 3, "ip4": "192.0.2.77"}`
	d := fixture(t, [][]any{{"app", "192.0.2.77", at(0, 1), 3600, 1, data}})
	bans, _, err := d.List(context.Background(), Query{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`{"time":"2026-11-21T07:43:20Z","ip":"192.0.2.77"}`, "plain line"}
	if len(bans) != 1 || !slices.Equal(bans[0].Matches, want) || bans[0].Failures != 3 {
		t.Fatalf("got %+v", bans)
	}
}

func TestStatsCountByDayJailAndAddress(t *testing.T) {
	d := fixture(t, [][]any{
		{"sshd", "192.0.2.1", at(0, 2), 3600, 1, nil},
		{"sshd", "192.0.2.1", at(0, 3), 3600, 2, nil},
		{"app", "192.0.2.1", at(1, 3), 3600, 1, nil},
		{"app", "192.0.2.2", at(6, 3), 3600, 1, nil},
		// Outside a week.
		{"app", "192.0.2.3", at(7, 3), 3600, 1, nil},
	})
	s, err := d.Stats(context.Background(), 7, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Bans != 4 || s.IPs != 2 || s.Repeat != 1 {
		t.Fatalf("bans %d, addresses %d, repeat %d", s.Bans, s.IPs, s.Repeat)
	}
	if s.PerDay[6].Day != "2026-11-21" || s.PerDay[6].ByJail["sshd"] != 2 || s.PerDay[5].ByJail["app"] != 1 || s.PerDay[0].Total != 1 {
		t.Fatalf("per day %+v", s.PerDay)
	}
	if !slices.Equal(s.Jails, []string{"app", "sshd"}) && !slices.Equal(s.Jails, []string{"sshd", "app"}) {
		t.Fatalf("jails %v", s.Jails)
	}
	if s.Top[0].IP != "192.0.2.1" || s.Top[0].Bans != 3 || !slices.Equal(s.Top[0].Jails, []string{"app", "sshd"}) {
		t.Fatalf("top %+v", s.Top[0])
	}
	if s.LastDay != 2 {
		t.Fatalf("last day %d", s.LastDay)
	}
}

func TestListPagesNewestFirst(t *testing.T) {
	var rows [][]any
	for i := range 5 {
		rows = append(rows, []any{"sshd", "192.0.2.9", at(0, i), 60, i + 1, nil})
	}
	d := fixture(t, rows)
	first, next, err := d.List(context.Background(), Query{Limit: 3})
	if err != nil || len(first) != 3 || first[0].Count != 5 || next == 0 {
		t.Fatalf("%v %+v %d", err, first, next)
	}
	rest, next, err := d.List(context.Background(), Query{Limit: 3, Before: next})
	if err != nil || len(rest) != 2 || rest[1].Count != 1 || next != 0 {
		t.Fatalf("%v %+v %d", err, rest, next)
	}
	only, _, _ := d.List(context.Background(), Query{IP: "192.0.2.1"})
	if len(only) != 0 {
		t.Fatalf("filtered to %d", len(only))
	}
}
