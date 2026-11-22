package webui

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"f2b/internal/app"
	"f2b/internal/config"
)

const password = "correct horse"

func server(t *testing.T) (*Server, *bytes.Buffer, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "f2b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	proxies, _ := config.ParseProxies("private")
	cfg := &config.Web{
		Common:         config.Common{Layout: app.LayoutOf(dir)},
		Password:       password,
		Secure:         true,
		TrustedProxies: proxies,
		Label:          "hellogram",
	}
	sessions, err := NewSessions(cfg.Layout.SessionKey, password, true)
	if err != nil {
		t.Fatal(err)
	}
	spa, err := NewSPA(fstest.MapFS{
		"index.html": {Data: []byte("app")},
		"login.html": {Data: []byte("login")},
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := OpenTokens(cfg.Layout.Tokens)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	return New(cfg, slog.New(slog.NewJSONHandler(&logs, nil)), sessions, tokens, spa), &logs, dir
}

func send(s *Server, method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "172.18.0.5:4000"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func signIn(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	rec := send(s, "POST", "/api/auth/login", `{"password":"`+password+`"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("sign-in answered %d %s", rec.Code, rec.Body)
	}
	return rec.Result().Cookies()[0]
}

func TestAWrongPasswordIsLoggedWithTheCallersAddressForFail2ban(t *testing.T) {
	s, logs, _ := server(t)
	rec := send(s, "POST", "/api/auth/login", `{"password":"nope"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("answered %d", rec.Code)
	}
	line := logs.String()
	if !strings.Contains(line, `"msg":"password refused","ip":"203.0.113.50"`) {
		t.Fatalf("logged %s", line)
	}
	if strings.Contains(line, "nope") {
		t.Fatal("the password tried was logged")
	}
}

func TestASignedInBrowserIsLetThroughAndOthersAreNot(t *testing.T) {
	s, _, _ := server(t)
	if rec := send(s, "GET", "/api/auth/me", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("signed out answered %d", rec.Code)
	}
	if rec := send(s, "GET", "/", ""); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Fatalf("signed out navigation answered %d %s", rec.Code, rec.Header().Get("Location"))
	}
	cookie := signIn(t, s)
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie %+v", cookie)
	}
	if rec := send(s, "GET", "/api/auth/me", "", cookie); rec.Code != http.StatusOK {
		t.Fatalf("signed in answered %d", rec.Code)
	}
	if rec := send(s, "GET", "/login", "", cookie); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("the sign-in page answered a signed-in browser %d", rec.Code)
	}
}

func TestAForgedOrExpiredCookieIsRefused(t *testing.T) {
	s, _, _ := server(t)
	cookie := signIn(t, s)
	forged := *cookie
	forged.Value = cookie.Value[:len(cookie.Value)-2] + "AA"
	if rec := send(s, "GET", "/api/auth/me", "", &forged); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a forged cookie answered %d", rec.Code)
	}
	s.sessions.now = func() time.Time { return time.Now().Add(sessionLife + time.Minute) }
	if rec := send(s, "GET", "/api/auth/me", "", cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an expired cookie answered %d", rec.Code)
	}
}

func TestSigningOutEverywhereEndsEverySession(t *testing.T) {
	s, _, _ := server(t)
	one, two := signIn(t, s), signIn(t, s)
	if rec := send(s, "POST", "/api/auth/logout-everywhere", "", one); rec.Code != http.StatusNoContent {
		t.Fatalf("answered %d", rec.Code)
	}
	if rec := send(s, "GET", "/api/auth/me", "", two); rec.Code != http.StatusUnauthorized {
		t.Fatalf("another browser's session answered %d", rec.Code)
	}
}

func TestAChangedPasswordEndsEverySession(t *testing.T) {
	s, _, dir := server(t)
	cookie := signIn(t, s)
	other, err := NewSessions(filepath.Join(dir, "session.key"), "another password", true)
	if err != nil {
		t.Fatal(err)
	}
	s.sessions = other
	if rec := send(s, "GET", "/api/auth/me", "", cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("answered %d", rec.Code)
	}
}

func TestACrossSiteWriteIsRefused(t *testing.T) {
	s, _, _ := server(t)
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("answered %d", rec.Code)
	}
	req = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`password=x`))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("a form post answered %d", rec.Code)
	}
}

func TestTheCallerIsTheFirstUntrustedHop(t *testing.T) {
	s, _, _ := server(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "172.18.0.5:1"
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.50, 10.0.0.2")
	if got := s.clientIP(req); got != "203.0.113.50" {
		t.Fatalf("got %s", got)
	}
	req.RemoteAddr = "203.0.113.99:1"
	if got := s.clientIP(req); got != "203.0.113.99" {
		t.Fatalf("an untrusted peer's header was believed: %s", got)
	}
}

func TestSignedInRequestsReachTheEngineWithoutTheCookie(t *testing.T) {
	s, _, dir := server(t)
	ln, err := net.Listen("unix", filepath.Join(dir, "engine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan *http.Request, 1)
	engine := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r
		io.WriteString(w, `{"jails":[]}`)
	})}
	go engine.Serve(ln)
	defer engine.Close()

	if rec := send(s, "GET", "/api/jails", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("signed out reached the engine: %d", rec.Code)
	}
	cookie := signIn(t, s)
	rec := send(s, "GET", "/api/jails?x=1", "", cookie)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"jails":[]}` {
		t.Fatalf("answered %d %s", rec.Code, rec.Body)
	}
	r := <-seen
	if r.URL.Path != "/api/jails" || r.URL.RawQuery != "x=1" || r.Header.Get("Cookie") != "" {
		t.Fatalf("the engine got %s %q cookie %q", r.URL.Path, r.URL.RawQuery, r.Header.Get("Cookie"))
	}
}

func TestAnEngineThatIsNotThereSaysSo(t *testing.T) {
	s, _, _ := server(t)
	cookie := signIn(t, s)
	rec := send(s, "GET", "/api/jails", "", cookie)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "engine_unreachable") {
		t.Fatalf("answered %d %s", rec.Code, rec.Body)
	}
}

func TestAFileNameInARouteIsANavigationAndAMissingAssetIsNot(t *testing.T) {
	s, _, _ := server(t)
	cookie := signIn(t, s)
	for path, want := range map[string]int{
		"/config/filters/caddy-scanners.local": http.StatusOK,
		"/stock/filter.d/sshd.conf":            http.StatusOK,
		"/assets/missing.js":                   http.StatusNotFound,
	} {
		if rec := send(s, "GET", path, "", cookie); rec.Code != want {
			t.Errorf("%s answered %d", path, rec.Code)
		}
	}
}

func TestTheLabelIsToldOnlyToASignedInBrowser(t *testing.T) {
	s, _, _ := server(t)
	if rec := send(s, "GET", "/api/auth/me", ""); strings.Contains(rec.Body.String(), "hellogram") {
		t.Fatal("a stranger was told the label")
	}
	rec := send(s, "GET", "/api/auth/me", "", signIn(t, s))
	if !strings.Contains(rec.Body.String(), `"label":"hellogram"`) {
		t.Fatalf("answered %s", rec.Body)
	}
}
