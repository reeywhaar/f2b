package engine

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const mountinfo = `22 1 0:21 / / rw,relatime - overlay overlay rw,lowerdir=/x
23 22 0:22 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
24 23 0:22 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
25 22 0:23 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
26 25 0:24 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw
27 22 254:1 /var/lib/docker/volumes/f2b_data/_data /data rw,relatime - ext4 /dev/vda1 rw
28 22 254:1 /var/log /var/log ro,relatime master:1 - ext4 /dev/vda1 rw
29 22 254:1 /srv/logs /remotelogs/docker ro,relatime - ext4 /dev/vda1 rw
30 22 254:1 /srv/my\040logs /my\040logs ro,relatime - ext4 /dev/vda1 rw
31 22 254:1 /etc/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/vda1 rw
32 22 0:40 / /run/secrets/admin ro,relatime - tmpfs tmpfs rw
33 22 0:41 / /var/log/ram ro,relatime - tmpfs tmpfs rw
`

func TestTheReadOnlyMountsAreTheLogs(t *testing.T) {
	got := readOnlyMounts(mountinfo)
	want := []string{"/var/log", "/remotelogs/docker", "/my logs", "/var/log/ram"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// logsServer is a server whose logs are a read-only mount, a jail's log directory, and a jail's
// log in the data directory.
func logsServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, d, _, _ := server(t)
	base := t.TempDir()
	for p, content := range map[string]string{
		"data/session.key":              "secret\n",
		"data/fail2ban.log":             "fail2ban's own\n",
		"data/logs/app.log":             "one\ntwo\n",
		"host/var/log/auth.log":         "sshd\n",
		"host/var/log/nginx/access.log": "GET /\n",
		"jails/web.log":                 "web\n",
	} {
		write(t, filepath.Join(base, p), content)
	}
	// A link out of a log directory, to the session key.
	if err := os.Symlink(filepath.Join(base, "data", "session.key"), filepath.Join(base, "host", "var", "log", "key")); err != nil {
		t.Fatal(err)
	}
	s.Logs = LogPlaces{Mounts: []string{filepath.Join(base, "host/var/log"), filepath.Join(base, "data")}, Data: filepath.Join(base, "data")}
	d.logs = map[string][]string{
		"sshd": {filepath.Join(base, "host/var/log/auth.log"), filepath.Join(base, "data/fail2ban.log")},
		"app":  {filepath.Join(base, "jails/web.log"), filepath.Join(base, "data/logs/app.log")},
	}
	return s, base
}

func TestTheLogsAreTheMountsAndTheJailsDirectoriesButNotTheData(t *testing.T) {
	s, base := logsServer(t)
	code, out := do(t, s, "GET", "/api/logs", "")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, out)
	}
	var got []string
	for _, r := range out["roots"].([]any) {
		e := r.(map[string]any)
		got = append(got, strings.TrimPrefix(e["path"].(string), base)+" "+e["source"].(string))
	}
	want := []string{"/data/fail2ban.log jail", "/data/logs jail", "/host/var/log mount", "/jails jail"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestADirectoryListsDirectoriesFirstAndSaysWhichJailsReadEach(t *testing.T) {
	s, base := logsServer(t)
	code, out := do(t, s, "GET", "/api/logs"+filepath.Join(base, "host/var/log"), "")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, out)
	}
	var got []string
	for _, e := range out["entries"].([]any) {
		e := e.(map[string]any)
		got = append(got, e["name"].(string)+" "+strings.Join(strings.Fields(strings.Trim(jsonOf(e["jails"]), "[]\"")), ","))
	}
	// The link to the session key leads out of the directory, and is not listed.
	if want := []string{"nginx ", "auth.log sshd"}; !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestTheTesterReadsOnlyAmongTheLogs(t *testing.T) {
	s, base := logsServer(t)
	for log, want := range map[string]int{
		filepath.Join(base, "host/var/log/nginx/access.log"):       http.StatusOK,
		filepath.Join(base, "jails/web.log"):                       http.StatusOK,
		filepath.Join(base, "data/logs/app.log"):                   http.StatusOK,
		filepath.Join(base, "data/fail2ban.log"):                   http.StatusOK,
		filepath.Join(base, "data/session.key"):                    http.StatusBadRequest,
		filepath.Join(base, "host/var/log/key"):                    http.StatusBadRequest,
		filepath.Join(base, "host/var/log/../../data/session.key"): http.StatusBadRequest,
		"/etc/hostname": http.StatusBadRequest,
		"relative.log":  http.StatusBadRequest,
		filepath.Join(base, "host/var/log/nginx"): http.StatusBadRequest,
	} {
		body, _ := json.Marshal(map[string]any{"filter": "sshd", "log": log})
		if code, out := do(t, s, "POST", "/api/regex", string(body)); code != want {
			t.Errorf("%s answered %d %v, want %d", log, code, out, want)
		}
	}
}

func TestAPathOutsideTheLogsIsNotListed(t *testing.T) {
	s, base := logsServer(t)
	for _, p := range []string{base, filepath.Join(base, "data"), "/etc", filepath.Join(base, "host/var/log/none")} {
		if code, out := do(t, s, "GET", "/api/logs"+p, ""); code != http.StatusNotFound {
			t.Errorf("%s answered %d %v", p, code, out)
		}
	}
}

func TestARotatedLogIsReadThrough(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log.2.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	for i := range 1000 {
		z.Write([]byte("line " + strings.Repeat("x", i%7) + "\n"))
	}
	z.Close()
	f.Close()
	f, err = os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := copyTail(f, filepath.Join(dir, "out.log"), 3); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dir, "out.log")); got != "line xxx\nline xxxx\nline xxxxx\n" {
		t.Fatalf("%q", got)
	}
}

func TestAReadTokenListsTheLogsInJSONAPI(t *testing.T) {
	s, base := logsServer(t)
	read := map[string]string{"F2B-Scope": "read"}
	code, _, out := v1(t, s, "GET", "/api/v1/log-files", "", read)
	if code != http.StatusOK || len(out["data"].([]any)) != 4 {
		t.Fatalf("%d %v", code, out)
	}
	dir := filepath.Join(base, "host/var/log")
	code, _, out = v1(t, s, "GET", "/api/v1/log-files?filter[dir]="+dir, "", read)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, out)
	}
	first := out["data"].([]any)[0].(map[string]any)
	if first["type"] != "log-files" || first["id"] != filepath.Join(dir, "nginx") || out["meta"].(map[string]any)["more"] != false {
		t.Fatalf("%v", out)
	}
	code, _, out = v1(t, s, "GET", "/api/v1/log-files"+filepath.Join(dir, "auth.log"), "", read)
	attrs := out["data"].(map[string]any)["attributes"].(map[string]any)
	if code != http.StatusOK || attrs["dir"] != false || attrs["size"] != float64(5) {
		t.Fatalf("%d %v", code, out)
	}
	if code, _, out := v1(t, s, "GET", "/api/v1/log-files"+filepath.Join(base, "data/session.key"), "", read); code != http.StatusNotFound {
		t.Fatalf("the session key answered %d %v", code, out)
	}
}

func TestEveryFileAmongTheLogsIsFoundByItsPath(t *testing.T) {
	s, base := logsServer(t)
	write(t, filepath.Join(base, "host/var/log/backup/restic.log"), "saved\n")
	code, out := do(t, s, "GET", "/api/logs?files=1", "")
	if code != http.StatusOK || out["more"] != false {
		t.Fatalf("%d %v", code, out)
	}
	var got []string
	for _, f := range out["files"].([]any) {
		got = append(got, strings.TrimPrefix(f.(map[string]any)["path"].(string), base))
	}
	// Not the link out to the session key, nor anything else in the data directory.
	want := []string{"/data/fail2ban.log", "/data/logs/app.log", "/host/var/log/auth.log",
		"/host/var/log/backup/restic.log", "/host/var/log/nginx/access.log", "/jails/web.log"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	code, _, doc := v1(t, s, "GET", "/api/v1/log-files?filter[path]=RES", "", readScope)
	data := doc["data"].([]any)
	if code != http.StatusOK || len(data) != 1 || data[0].(map[string]any)["id"] != filepath.Join(base, "host/var/log/backup/restic.log") {
		t.Fatalf("%d %v", code, doc)
	}
}
