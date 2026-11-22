package webui

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"f2b/internal/app"
)

// clock is a time a test moves by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time       { return c.t }
func (c *clock) pass(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock                { return &clock{t: time.Unix(1_800_000_000, 0)} }
func tokensAt(t *testing.T, c *clock) (*Tokens, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens.json")
	tk, err := OpenTokens(path)
	if err != nil {
		t.Fatal(err)
	}
	tk.now = c.now
	return tk, path
}

func TestATokenIsKeptAsADigestAndWorksUntilRevoked(t *testing.T) {
	c := newClock()
	tk, path := tokensAt(t, c)
	view, text, err := tk.Issue("agent", "read", "30d", "never")
	if err != nil || !strings.HasPrefix(text, "f2b_"+view.ID+"_") {
		t.Fatalf("%v %q", err, text)
	}
	b, _ := os.ReadFile(path)
	secret := strings.TrimPrefix(text, "f2b_"+view.ID+"_")
	if strings.Contains(string(b), secret) {
		t.Fatal("the secret is on disk")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("tokens.json is %v", info.Mode().Perm())
	}
	if tok, ok := tk.Verify(text); !ok || tok.Name != "agent" || tok.Scope != "read" {
		t.Fatalf("%v %v", tok, ok)
	}
	if _, ok := tk.Verify(text + "x"); ok {
		t.Fatal("a token with another secret works")
	}
	again, err := OpenTokens(path)
	if err != nil {
		t.Fatal(err)
	}
	again.now = c.now
	if _, ok := again.Verify(text); !ok {
		t.Fatal("a token does not work after the web starts again")
	}
	if _, found, err := again.Revoke(view.ID); !found || err != nil {
		t.Fatalf("%v %v", found, err)
	}
	if _, ok := again.Verify(text); ok {
		t.Fatal("a revoked token works")
	}
	if list := again.List(); len(list) != 0 {
		t.Fatalf("a revoked token is listed: %v", list)
	}
}

func TestATokenEndsWithItsLifetime(t *testing.T) {
	c := newClock()
	tk, _ := tokensAt(t, c)
	view, text, _ := tk.Issue("ci", "write", "1d", "never")
	if view.Ends != c.t.Add(24*time.Hour).Unix() || view.Expired {
		t.Fatalf("%+v", view)
	}
	c.pass(23 * time.Hour)
	if _, ok := tk.Verify(text); !ok {
		t.Fatal("refused within its day")
	}
	c.pass(2 * time.Hour)
	if _, ok := tk.Verify(text); ok {
		t.Fatal("works past its day")
	}
	if list := tk.List(); !list[0].Expired {
		t.Fatalf("not listed as expired: %+v", list[0])
	}
}

func TestATokenEndsUnused(t *testing.T) {
	c := newClock()
	tk, _ := tokensAt(t, c)
	_, text, _ := tk.Issue("agent", "read", "never", "1w")
	c.pass(6 * 24 * time.Hour)
	if _, ok := tk.Verify(text); !ok {
		t.Fatal("refused within a week of being issued")
	}
	// Used, it counts the week from then.
	c.pass(6 * 24 * time.Hour)
	if _, ok := tk.Verify(text); !ok {
		t.Fatal("refused within a week of its last use")
	}
	c.pass(8 * 24 * time.Hour)
	if _, ok := tk.Verify(text); ok {
		t.Fatal("works after a week unused")
	}
}

func TestAUseIsWrittenDownAtMostOnceAMinute(t *testing.T) {
	c := newClock()
	tk, path := tokensAt(t, c)
	_, text, _ := tk.Issue("agent", "read", "never", "never")
	onDisk := func() int64 {
		var list []Token
		b, _ := os.ReadFile(path)
		json.Unmarshal(b, &list)
		return list[0].LastUsed
	}
	start := c.t.Unix()
	tk.Verify(text)
	c.pass(10 * time.Second)
	tk.Verify(text)
	if onDisk() != start {
		t.Fatalf("on disk %d, want the first use %d", onDisk(), start)
	}
	if tk.List()[0].LastUsed != start+10 {
		t.Fatal("the list does not say the latest use")
	}
	c.pass(time.Minute)
	tk.Verify(text)
	if onDisk() != start+70 {
		t.Fatalf("on disk %d after a minute", onDisk())
	}
}

func TestATokensNameIsOneShortLineNoOtherHas(t *testing.T) {
	tk, _ := tokensAt(t, newClock())
	tk.Issue("agent", "read", "30d", "30d")
	for _, bad := range []struct{ name, scope, life, idle string }{
		{"", "read", "30d", "30d"},
		{strings.Repeat("x", 61), "read", "30d", "30d"},
		{"two\nlines", "read", "30d", "30d"},
		{"other", "admin", "30d", "30d"},
		{"other", "read", "2d", "30d"},
		{"other", "read", "30d", "forever"},
	} {
		if _, _, err := tk.Issue(bad.name, bad.scope, bad.life, bad.idle); err == nil {
			t.Errorf("issued %+v", bad)
		}
	}
	if _, _, err := tk.Issue("Agent", "write", "30d", "30d"); err == nil {
		t.Error("issued a second token named agent")
	}
}

// engineAt stands in for the engine on the socket, keeping each request it is sent.
func engineAt(t *testing.T, dir string) <-chan *http.Request {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(dir, "engine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan *http.Request, 16)
	engine := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r
		w.Header().Set("Content-Type", jsonAPI)
		io.WriteString(w, `{"jsonapi":{"version":"1.1"},"data":[]}`)
	})}
	go engine.Serve(ln)
	t.Cleanup(func() { engine.Close() })
	return seen
}

func sendWith(s *Server, method, path, body string, header map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "172.18.0.5:4000"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func issue(t *testing.T, s *Server, cookie *http.Cookie, body string) (string, string) {
	t.Helper()
	rec := send(s, "POST", "/api/auth/tokens", body, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issuing answered %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Token  TokenView `json:"token"`
		Secret string    `json:"secret"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Token.ID, out.Secret
}

func TestATokenReachesV1WithItsScopeAndNoFurther(t *testing.T) {
	s, logs, dir := server(t)
	seen := engineAt(t, dir)
	_, secret := issue(t, s, signIn(t, s), `{"name":"agent","scope":"read","expiresIn":"30d","idleFor":"never"}`)
	bearer := map[string]string{"Authorization": "Bearer " + secret, app.ScopeHeader: app.ScopeWrite}

	rec := sendWith(s, "GET", "/api/v1/jails", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d %s", rec.Code, rec.Body)
	}
	r := <-seen
	if r.Header.Get(app.ScopeHeader) != app.ScopeRead || r.Header.Get("Authorization") != "" {
		t.Fatalf("the engine got scope %q and authorization %q", r.Header.Get(app.ScopeHeader), r.Header.Get("Authorization"))
	}
	if rec := sendWith(s, "GET", "/api/jails", "", bearer); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a token reached the interface's API: %d", rec.Code)
	}
	if rec := sendWith(s, "POST", "/api/auth/tokens", `{"name":"x","scope":"write","expiresIn":"1d","idleFor":"1d"}`,
		map[string]string{"Authorization": "Bearer " + secret, "Content-Type": "application/json"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a token issued a token: %d", rec.Code)
	}

	write := sendWith(s, "POST", "/api/v1/regex-tests", `{"data":{}}`,
		map[string]string{"Authorization": "Bearer " + secret, "Content-Type": jsonAPI})
	if write.Code != http.StatusOK {
		t.Fatalf("a JSON:API body answered %d %s", write.Code, write.Body)
	}
	<-seen
	if !strings.Contains(logs.String(), `"token":"agent"`) {
		t.Fatalf("the request's line does not name the token:\n%s", logs)
	}
}

func TestASessionReachesV1AbleToDoEverything(t *testing.T) {
	s, _, dir := server(t)
	seen := engineAt(t, dir)
	if rec := send(s, "GET", "/api/v1/engine", "", signIn(t, s)); rec.Code != http.StatusOK {
		t.Fatalf("answered %d", rec.Code)
	}
	if r := <-seen; r.Header.Get(app.ScopeHeader) != app.ScopeWrite {
		t.Fatalf("scope %q", r.Header.Get(app.ScopeHeader))
	}
	if rec := send(s, "GET", "/api/v1/engine", ""); rec.Code != http.StatusUnauthorized || rec.Header().Get("Content-Type") != jsonAPI {
		t.Fatalf("signed out and tokenless: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestARefusedTokenIsALineForFail2banAndThenRateLimited(t *testing.T) {
	s, logs, dir := server(t)
	engineAt(t, dir)
	bad := map[string]string{"Authorization": "Bearer f2b_0000000000000000_nope"}
	rec := sendWith(s, "GET", "/api/v1/jails", "", bad)
	var out struct {
		Errors []struct{ Code string } `json:"errors"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("Content-Type") != jsonAPI || len(out.Errors) != 1 || out.Errors[0].Code != "unauthenticated" {
		t.Fatalf("answered %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(logs.String(), `"msg":"token refused","ip":"203.0.113.50"`) || strings.Contains(logs.String(), "nope") {
		t.Fatalf("the log line:\n%s", logs)
	}
	for range 5 {
		rec = sendWith(s, "GET", "/api/v1/jails", "", bad)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the sixth refused token answered %d", rec.Code)
	}
}

func TestARevokedTokenStopsAtOnce(t *testing.T) {
	s, _, dir := server(t)
	engineAt(t, dir)
	cookie := signIn(t, s)
	id, secret := issue(t, s, cookie, `{"name":"agent","scope":"read","expiresIn":"never","idleFor":"never"}`)
	list := send(s, "GET", "/api/auth/tokens", "", cookie)
	if !strings.Contains(list.Body.String(), `"name":"agent"`) || strings.Contains(list.Body.String(), "hash") || strings.Contains(list.Body.String(), secret) {
		t.Fatalf("the list: %s", list.Body)
	}
	if rec := send(s, "DELETE", "/api/auth/tokens/"+id, "", cookie); rec.Code != http.StatusNoContent {
		t.Fatalf("revoking answered %d", rec.Code)
	}
	if rec := sendWith(s, "GET", "/api/v1/jails", "", map[string]string{"Authorization": "Bearer " + secret}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked token answered %d", rec.Code)
	}
	if rec := send(s, "DELETE", "/api/auth/tokens/"+id, "", cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("revoking it again answered %d", rec.Code)
	}
}

func TestWhatV1IsNeedsNoSignIn(t *testing.T) {
	s, _, dir := server(t)
	seen := engineAt(t, dir)
	if rec := send(s, "GET", "/api/v1/openapi.json", ""); rec.Code != http.StatusOK {
		t.Fatalf("answered %d", rec.Code)
	}
	if r := <-seen; r.URL.Path != "/api/v1/openapi.json" {
		t.Fatalf("the engine got %s", r.URL.Path)
	}
}
