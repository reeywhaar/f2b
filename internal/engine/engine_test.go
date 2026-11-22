package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"f2b/internal/history"
)

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func composer(t *testing.T) (*Composer, string) {
	t.Helper()
	root := t.TempDir()
	stock := filepath.Join(root, "stock")
	write(t, filepath.Join(stock, "jail.conf"), "[DEFAULT]\nbantime = 10m\n")
	write(t, filepath.Join(stock, "jail.d", "alpine-ssh.conf"), "[sshd]\nenabled = true\n")
	write(t, filepath.Join(stock, "filter.d", "sshd.conf"), "[Definition]\n")
	files := &Files{Root: filepath.Join(root, "user")}
	if err := files.Ensure(); err != nil {
		t.Fatal(err)
	}
	return &Composer{Stock: stock, Files: files, Socket: "/run/f2b/fail2ban.sock", PidFile: "/run/f2b/fail2ban.pid", Database: "/data/fail2ban.sqlite3"}, root
}

func TestComposeLeavesOutTheJailsThePackageEnables(t *testing.T) {
	c, root := composer(t)
	dst := filepath.Join(root, "etc")
	if err := c.Compose(dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "jail.d", "alpine-ssh.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the package's jail is there: %v", err)
	}
	if read(t, filepath.Join(dst, "filter.d", "sshd.conf")) != "[Definition]\n" {
		t.Fatal("the package's filter is missing")
	}
}

func TestComposeLaysEditedFilesAndAChangeOverThePackage(t *testing.T) {
	c, root := composer(t)
	write(t, filepath.Join(root, "user", "jail.d", "sshd.local"), "[sshd]\nenabled = true\n")
	write(t, filepath.Join(root, "user", "filter.d", "app.local"), "old")
	write(t, filepath.Join(root, "user", "fail2ban.local"), "[DEFAULT]\nloglevel = DEBUG\n")
	// Not a name fail2ban reads, so not handed to it either.
	write(t, filepath.Join(root, "user", "filter.d", "notes.txt"), "x")
	dst := filepath.Join(root, "etc")
	content := "new"
	if err := c.Compose(dst, Change{Kind: Filters, Name: "app.local", Content: &content}); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(dst, "jail.d", "sshd.local")) != "[sshd]\nenabled = true\n" {
		t.Fatal("the edited jail is missing")
	}
	if read(t, filepath.Join(dst, "filter.d", "app.local")) != "new" {
		t.Fatal("the change is not what was composed")
	}
	if read(t, filepath.Join(dst, "fail2ban.local")) != "[DEFAULT]\nloglevel = DEBUG\n" {
		t.Fatal("the settings are missing")
	}
	if _, err := os.Stat(filepath.Join(dst, "filter.d", "notes.txt")); err == nil {
		t.Fatal("a file fail2ban does not read was composed")
	}
	if read(t, filepath.Join(root, "user", "filter.d", "app.local")) != "old" {
		t.Fatal("composing a change wrote it to the edited files")
	}
}

func TestComposeWritesWhatTheEngineDependsOnLast(t *testing.T) {
	c, root := composer(t)
	dst := filepath.Join(root, "etc")
	if err := c.Compose(dst); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(dst, "fail2ban.d"))
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	// fail2ban reads fail2ban.d/*.conf before fail2ban.local and *.local after it.
	if !slices.Equal(names, []string{"00-f2b.conf", "zz-f2b.local"}) {
		t.Fatalf("fail2ban.d holds %v", names)
	}
	forced := read(t, filepath.Join(dst, "fail2ban.d", "zz-f2b.local"))
	for _, want := range []string{"[Definition]", "logtarget = STDOUT", "socket = /run/f2b/fail2ban.sock", "dbfile = /data/fail2ban.sqlite3"} {
		if !strings.Contains(forced, want) {
			t.Fatalf("forced settings lack %q:\n%s", want, forced)
		}
	}
	if !strings.Contains(read(t, filepath.Join(dst, "fail2ban.d", "00-f2b.conf")), "[DEFAULT]\ndbpurgeage = 90d") {
		t.Fatal("the defaults are not under DEFAULT, where fail2ban.local overrides them")
	}
}

func TestANameMustBeAFileFail2banReads(t *testing.T) {
	for _, name := range []string{"../x.local", "x.txt", ".hidden.local", "a/b.local", ""} {
		if CheckName(Filters, name) == nil {
			t.Errorf("%q was accepted", name)
		}
	}
	for _, name := range []string{"sshd.local", "caddy-scanners.local", "a_b.conf", "x@y.local"} {
		if err := CheckName(Jails, name); err != nil {
			t.Errorf("%q was refused: %v", name, err)
		}
	}
	if CheckName(Settings, "jail.conf") == nil || CheckName(Settings, "fail2ban.local") != nil {
		t.Error("settings are only the top-level .local files")
	}
}

func TestSectionsNameTheJailsInAFile(t *testing.T) {
	got := sections("[DEFAULT]\nx = 1\n[sshd]\n  [ mailio ]\n[INCLUDES]\n[sshd]\n")
	if !slices.Equal(got, []string{"sshd", "mailio"}) {
		t.Fatalf("got %v", got)
	}
}

// stubDaemon is a running fail2ban that remembers being restarted, with the actions it is given.
type stubDaemon struct {
	mu       sync.Mutex
	state    string
	restarts int
	actions  map[string][]string
}

func (d *stubDaemon) State() DaemonState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return DaemonState{State: d.state}
}
func (d *stubDaemon) Restart() { d.mu.Lock(); d.restarts++; d.mu.Unlock() }
func (d *stubDaemon) Jails(context.Context) ([]Jail, error) {
	return []Jail{{Name: "sshd"}, {Name: "app"}}, nil
}
func (d *stubDaemon) Banned(context.Context) (map[string][]string, error) { return nil, nil }
func (d *stubDaemon) Ban(context.Context, string, string) error           { return nil }
func (d *stubDaemon) Unban(context.Context, string, string) error         { return nil }
func (d *stubDaemon) Actions(context.Context) (map[string][]string, error) {
	return d.actions, nil
}

// stubTools refuses any configuration with "bad" in a filter, counts reloads, keeps the log the
// tester was last given, and configures the actions it is given.
type stubTools struct {
	mu      sync.Mutex
	reloads int
	sample  string
	actions map[string][]string
}

func (s *stubTools) Actions(context.Context, string) (map[string][]string, error) {
	return s.actions, nil
}

func (s *stubTools) Check(_ context.Context, dir string) Result {
	matches, _ := filepath.Glob(filepath.Join(dir, "filter.d", "*"))
	for _, m := range matches {
		if b, _ := os.ReadFile(m); strings.Contains(string(b), "bad") {
			return Result{Output: "ERROR in " + filepath.Base(m)}
		}
	}
	return Result{OK: true, Output: "OK"}
}
func (s *stubTools) Reload(context.Context, string) Result {
	s.mu.Lock()
	s.reloads++
	s.mu.Unlock()
	return Result{OK: true, Output: "OK"}
}
func (s *stubTools) Regex(_ context.Context, _, log, _ string) Result {
	b, _ := os.ReadFile(log)
	s.mu.Lock()
	s.sample = string(b)
	s.mu.Unlock()
	return Result{OK: true}
}

func server(t *testing.T) (*Server, *stubDaemon, *stubTools, string) {
	t.Helper()
	c, root := composer(t)
	lines, err := OpenLines("", nil)
	if err != nil {
		t.Fatal(err)
	}
	d, tools := &stubDaemon{state: Running}, &stubTools{}
	s := &Server{
		Files: c.Files, Composer: c, Daemon: d, Tools: tools,
		History: history.Open(filepath.Join(root, "none.sqlite3")),
		Lines:   lines, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Live: filepath.Join(root, "live"), Scratch: filepath.Join(root, "scratch"),
	}
	s.Handler()
	return s, d, tools, root
}

func do(t *testing.T, s *Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestARefusedSaveLeavesTheDiskAsItWas(t *testing.T) {
	s, _, tools, root := server(t)
	code, out := do(t, s, "PUT", "/api/files/filters/app.local", `{"content":"bad","version":""}`)
	if code != http.StatusUnprocessableEntity || out["code"] != "config_rejected" || out["output"] != "ERROR in app.local" {
		t.Fatalf("%d %v", code, out)
	}
	if _, err := os.Stat(filepath.Join(root, "user", "filter.d", "app.local")); err == nil {
		t.Fatal("a refused file was written")
	}
	if tools.reloads != 0 {
		t.Fatal("fail2ban was reloaded for a refused change")
	}
}

func TestASaveWritesComposesAndReloads(t *testing.T) {
	s, _, tools, root := server(t)
	code, out := do(t, s, "PUT", "/api/files/filters/app.local", `{"content":"good","version":""}`)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, out)
	}
	if read(t, filepath.Join(root, "user", "filter.d", "app.local")) != "good" {
		t.Fatal("the file was not written")
	}
	if read(t, filepath.Join(root, "live", "filter.d", "app.local")) != "good" {
		t.Fatal("the live configuration was not composed again")
	}
	if tools.reloads != 1 {
		t.Fatalf("reloaded %d times", tools.reloads)
	}
}

func TestAReloadThatLeavesAJailWithoutItsActionsRestartsFail2ban(t *testing.T) {
	s, d, tools, _ := server(t)
	tools.actions = map[string][]string{"app": {"iptables-allports"}, "sshd": {"iptables-allports"}}
	d.actions = map[string][]string{"app": {}, "sshd": {"iptables-allports"}}
	code, out := do(t, s, "PUT", "/api/files/jails/app.local", `{"content":"[app]","version":""}`)
	if code != http.StatusOK || tools.reloads != 1 || d.restarts != 1 {
		t.Fatalf("%d, %d reloads, %d restarts: %v", code, tools.reloads, d.restarts, out)
	}
	if reload, _ := out["reload"].(map[string]any); !strings.Contains(reload["output"].(string), "app without the actions configured") {
		t.Fatalf("the reply does not say why: %v", out)
	}
	d.actions = tools.actions
	do(t, s, "PUT", "/api/files/jails/app.local", `{"content":"[app]\n","version":"`+VersionOf("[app]")+`"}`)
	if d.restarts != 1 {
		t.Fatal("restarted although every jail has the actions configured")
	}
}

func TestOnlyASaveOfAJailOrASettingLooksAtTheActions(t *testing.T) {
	s, d, tools, _ := server(t)
	tools.actions = map[string][]string{"app": {"iptables-allports"}}
	d.actions = map[string][]string{"app": {}}
	do(t, s, "PUT", "/api/files/filters/app.local", `{"content":"good","version":""}`)
	if d.restarts != 0 {
		t.Fatal("a filter's save restarted fail2ban")
	}
}

func TestTheActionsAJailIsGivenAreReadFromFail2bansDump(t *testing.T) {
	dump := `['set', 'sshd', 'addaction', 'iptables-allports']
['multi-set', 'sshd', 'action', 'iptables-allports', [['actionstart', "for proto in $(echo 'all'); do"]]]
['set', 'web', 'addaction', 'iptables-multiport-Docker']
['set', 'web', 'addaction', 'sendmail-whois']
['start', 'web']
`
	got := actionsIn(dump)
	want := map[string][]string{"sshd": {"iptables-allports"}, "web": {"iptables-multiport-Docker", "sendmail-whois"}}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("got %v", got)
	}
}

func TestASaveAgainstAnOlderVersionIsAConflict(t *testing.T) {
	s, _, _, _ := server(t)
	do(t, s, "PUT", "/api/files/filters/app.local", `{"content":"one","version":""}`)
	code, out := do(t, s, "PUT", "/api/files/filters/app.local", `{"content":"two","version":"`+VersionOf("zero")+`"}`)
	if code != http.StatusConflict {
		t.Fatalf("%d %v", code, out)
	}
	code, _ = do(t, s, "PUT", "/api/files/filters/app.local", `{"content":"two","version":""}`)
	if code != http.StatusConflict {
		t.Fatalf("a new file over an existing one answered %d", code)
	}
	code, _ = do(t, s, "PUT", "/api/files/filters/app.local", `{"content":"two","version":"`+VersionOf("one")+`"}`)
	if code != http.StatusOK {
		t.Fatalf("a save against the current version answered %d", code)
	}
}

func TestASaveWhileFail2banIsStoppedStartsIt(t *testing.T) {
	s, d, tools, _ := server(t)
	d.state = Stopped
	code, _ := do(t, s, "PUT", "/api/files/jails/app.local", `{"content":"[app]","version":""}`)
	if code != http.StatusOK || d.restarts != 1 || tools.reloads != 0 {
		t.Fatalf("%d, %d restarts, %d reloads", code, d.restarts, tools.reloads)
	}
}

func TestDeletingAFileReloadsWithoutIt(t *testing.T) {
	s, _, tools, root := server(t)
	do(t, s, "PUT", "/api/files/filters/app.local", `{"content":"x","version":""}`)
	code, out := do(t, s, "DELETE", "/api/files/filters/app.local?version="+VersionOf("x"), "")
	if code != http.StatusOK || out["file"] != nil {
		t.Fatalf("%d %v", code, out)
	}
	if _, err := os.Stat(filepath.Join(root, "live", "filter.d", "app.local")); err == nil {
		t.Fatal("the deleted file is still in the live configuration")
	}
	if tools.reloads != 2 {
		t.Fatalf("reloaded %d times", tools.reloads)
	}
}

func TestJailsNameTheFileThatDefinesThem(t *testing.T) {
	s, _, _, _ := server(t)
	do(t, s, "PUT", "/api/files/jails/mine.local", `{"content":"[app]\nenabled = true\n","version":""}`)
	_, out := do(t, s, "GET", "/api/jails", "")
	jails := out["jails"].([]any)
	app := jails[1].(map[string]any)
	if app["name"] != "app" || app["file"].(map[string]any)["name"] != "mine.local" {
		t.Fatalf("got %v", app)
	}
	if jails[0].(map[string]any)["file"] != nil {
		t.Fatal("sshd has a file it is not in")
	}
}

func TestAnAddressToBanIsAnAddress(t *testing.T) {
	s, _, _, _ := server(t)
	for body, want := range map[string]int{
		`{"jail":"sshd","ip":"203.0.113.7"}`:   http.StatusNoContent,
		`{"jail":"sshd","ip":"2001:db8::/48"}`: http.StatusNoContent,
		`{"jail":"sshd","ip":"203.0.113"}`:     http.StatusBadRequest,
		`{"jail":"","ip":"203.0.113.7"}`:       http.StatusBadRequest,
	} {
		if code, out := do(t, s, "POST", "/api/bans", body); code != want {
			t.Errorf("%s answered %d %v", body, code, out)
		}
	}
}

func TestTheTesterReadsOnlyTheEndOfALog(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := range 5000 {
		b.WriteString(strings.Repeat("x", 10) + string(rune('a'+i%26)) + "\n")
	}
	write(t, filepath.Join(dir, "big.log"), b.String())
	if err := copyTail(filepath.Join(dir, "big.log"), filepath.Join(dir, "out.log"), 100); err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimRight(read(t, filepath.Join(dir, "out.log")), "\n"), "\n")
	if len(got) != 100 || got[99] != "xxxxxxxxxx"+string(rune('a'+4999%26)) {
		t.Fatalf("%d lines, last %q", len(got), got[len(got)-1])
	}
	if copyTail("relative.log", filepath.Join(dir, "x"), 10) == nil {
		t.Fatal("a relative path was read")
	}
}

func TestTheLogStartsOverForACursorFromAnotherRun(t *testing.T) {
	s, _, _, _ := server(t)
	for i := range 5 {
		s.Lines.Add("line " + string(rune('0'+i)))
	}
	_, out := do(t, s, "GET", "/api/log?after=2&epoch="+s.Lines.Epoch(), "")
	if n := len(out["lines"].([]any)); n != 2 {
		t.Fatalf("%d lines after 2", n)
	}
	_, out = do(t, s, "GET", "/api/log?after=2&epoch=elsewhere", "")
	if n := len(out["lines"].([]any)); n != 5 {
		t.Fatalf("%d lines for a cursor from another run", n)
	}
}

func TestLinesKeepTheLatestAndPersistThem(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.log")
	l, err := OpenLines(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range ringSize + 10 {
		l.Add("line " + strconv.Itoa(i))
	}
	lines, _, last := l.Since(-1, ringSize)
	if len(lines) != ringSize || lines[0].Seq != 10 || last != ringSize+9 {
		t.Fatalf("%d lines from %d, last %d", len(lines), lines[0].Seq, last)
	}
	l.Close()
	again, err := OpenLines(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if lines, _, _ := again.Since(-1, 5000); len(lines) != 1000 {
		t.Fatalf("a restart starts from %d lines", len(lines))
	}
}

func TestAJailsFilterIsTheOneItNamesOrItsOwnName(t *testing.T) {
	content := "[DEFAULT]\nfilter = base\n[scanners]\nfilter   = caddy-scanners\n[sshd]\nfilter = sshd[mode=aggressive]\n[plain]\nenabled = true\n"
	for jail, want := range map[string]string{"scanners": "caddy-scanners", "sshd": "sshd", "plain": "base"} {
		if got := FilterOf(content, jail); got != want {
			t.Errorf("%s: got %q", jail, got)
		}
	}
	if got := FilterOf("[x]\nfilter = %(__name__)s\n", "x"); got != "x" {
		t.Errorf("an interpolated filter is %q", got)
	}
}

func TestRewritingChangesOnlyWhereAJailNamesIt(t *testing.T) {
	content := `# filter = old-name stays, being a comment
[app]
filter    = old-name[mode=aggressive]
logpath   = /logs/old-name.log
[other]
filter = old-names
banaction = iptables-allports
action = %(action_)s
         old-name[port=22]
`
	if n := Mentions(content, refKeys[Filters], "old-name"); n != 1 {
		t.Fatalf("%d mentions as a filter", n)
	}
	got := Rewrite(content, refKeys[Filters], "old-name", "new-name")
	for _, want := range []string{
		"# filter = old-name stays",
		"filter    = new-name[mode=aggressive]",
		"logpath   = /logs/old-name.log",
		"filter = old-names",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	// An action carried on to the next line is still the action's value.
	got = Rewrite(content, refKeys[Actions], "old-name", "new-name")
	if !strings.Contains(got, "         new-name[port=22]") || !strings.Contains(got, "filter    = old-name[") {
		t.Errorf("as an action:\n%s", got)
	}
}

func TestARenameMovesTheFileAndTheJailsThatNameIt(t *testing.T) {
	s, _, tools, root := server(t)
	do(t, s, "PUT", "/api/files/filters/typo.local", `{"content":"[Definition]\n","version":""}`)
	do(t, s, "PUT", "/api/files/jails/app.local", `{"content":"[app]\nfilter = typo\n","version":""}`)
	_, out := do(t, s, "GET", "/api/files/filters/typo.local/references", "")
	if refs := out["files"].([]any); len(refs) != 1 || refs[0].(map[string]any)["name"] != "app.local" {
		t.Fatalf("references %v", out)
	}
	code, out := do(t, s, "POST", "/api/files/filters/typo.local/rename",
		`{"to":"right.local","version":"`+VersionOf("[Definition]\n")+`","references":true}`)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, out)
	}
	if _, err := os.Stat(filepath.Join(root, "user", "filter.d", "typo.local")); err == nil {
		t.Fatal("the old name is still there")
	}
	if read(t, filepath.Join(root, "user", "filter.d", "right.local")) != "[Definition]\n" {
		t.Fatal("the new name does not hold the content")
	}
	if read(t, filepath.Join(root, "user", "jail.d", "app.local")) != "[app]\nfilter = right\n" {
		t.Fatal("the jail still names the old filter")
	}
	if also := out["also"].([]any); len(also) != 1 {
		t.Fatalf("also %v", also)
	}
	// Two saves to set up, and the rename as one reload.
	if tools.reloads != 3 {
		t.Fatalf("reloaded %d times", tools.reloads)
	}
}

func TestARenameOntoAnExistingFileOrOfSettingsIsRefused(t *testing.T) {
	s, _, _, root := server(t)
	do(t, s, "PUT", "/api/files/filters/ok.local", `{"content":"[Definition]\n","version":""}`)
	write(t, filepath.Join(root, "user", "filter.d", "keep.local"), "fine")
	code, out := do(t, s, "POST", "/api/files/filters/ok.local/rename",
		`{"to":"keep.local","version":"`+VersionOf("[Definition]\n")+`"}`)
	if code != http.StatusConflict {
		t.Fatalf("renaming onto a file that exists answered %d %v", code, out)
	}
	if read(t, filepath.Join(root, "user", "filter.d", "ok.local")) != "[Definition]\n" {
		t.Fatal("the file moved")
	}
	code, _ = do(t, s, "POST", "/api/files/settings/jail.local/rename", `{"to":"fail2ban.local","version":""}`)
	if code != http.StatusBadRequest {
		t.Fatalf("renaming settings answered %d", code)
	}
}

func TestPastedLinesEndInANewlineSoTheLastOneCounts(t *testing.T) {
	s, _, tools, _ := server(t)
	for text, want := range map[string]string{
		`one line`:         "one line\n",
		"two\r\nlines\r\n": "two\nlines\n",
		"already\n":        "already\n",
	} {
		body, _ := json.Marshal(map[string]any{"filter": "sshd", "text": text})
		if code, out := do(t, s, "POST", "/api/regex", string(body)); code != http.StatusOK {
			t.Fatalf("%d %v", code, out)
		}
		if tools.sample != want {
			t.Errorf("%q was tried as %q", text, tools.sample)
		}
	}
}
