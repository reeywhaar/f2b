package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"f2b/internal/app"
)

func TestAnAgentsLinkShowsItsTokenForFiveMinutesAndTheTokenWorksForThirty(t *testing.T) {
	c := newClock()
	tk, path := tokensAt(t, c)
	code, view, ends, err := tk.AgentAccess("read")
	if err != nil || !view.Temporary || view.Scope != "read" || ends != c.t.Add(AccessLinkFor).Unix() || view.Expires != c.t.Add(AccessTokenFor).Unix() {
		t.Fatalf("%v %+v %d", err, view, ends)
	}
	text, shown, _, ok := tk.OpenAccess(code)
	if !ok || shown.ID != view.ID {
		t.Fatalf("the link shows nothing: %v %+v", ok, shown)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), code) || strings.Contains(string(b), strings.TrimPrefix(text, "f2b_"+view.ID+"_")) {
		t.Fatal("the link's code or the token is on disk")
	}
	if _, ok := tk.Verify(text); !ok {
		t.Fatal("the token does not work")
	}

	c.pass(AccessLinkFor)
	if _, _, _, ok := tk.OpenAccess(code); ok {
		t.Fatal("the link shows its token after five minutes")
	}
	if _, ok := tk.Verify(text); !ok {
		t.Fatal("the token stopped with its link")
	}
	if n, err := tk.Sweep(); err != nil || n != 0 {
		t.Fatalf("a working token was swept: %d %v", n, err)
	}

	c.pass(AccessTokenFor - AccessLinkFor)
	if _, ok := tk.Verify(text); ok {
		t.Fatal("the token works after thirty minutes")
	}
	if len(tk.List()) != 0 {
		t.Fatalf("a lapsed agent's token is listed: %+v", tk.List())
	}
	if n, err := tk.Sweep(); err != nil || n != 1 {
		t.Fatalf("swept %d, %v", n, err)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), view.ID) {
		t.Fatal("the lapsed token is still on disk")
	}
}

func TestAnAgentsTokenIsListedWhileItWorksAndRevokingItEndsItsLink(t *testing.T) {
	c := newClock()
	tk, _ := tokensAt(t, c)
	tk.Issue("ci", "write", "30d", "never")
	code, view, _, _ := tk.AgentAccess("write")
	list := tk.List()
	if len(list) != 2 || !list[0].Temporary && !list[1].Temporary {
		t.Fatalf("%+v", list)
	}
	if _, _, err := tk.Revoke(view.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := tk.OpenAccess(code); ok {
		t.Fatal("a revoked token's link still shows it")
	}
	if _, _, _, err := tk.AgentAccess("everything"); err == nil {
		t.Fatal("a scope that is neither was taken")
	}
}

func TestAnAgentAccessLinkIsABriefWithTheToken(t *testing.T) {
	s, logs, dir := server(t)
	seen := engineAt(t, dir)
	cookie := signIn(t, s)
	if rec := send(s, "POST", "/api/auth/agent-access", `{"scope":"read"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a link was made signed out: %d", rec.Code)
	}
	rec := send(s, "POST", "/api/auth/agent-access", `{"scope":"read"}`, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var made struct {
		URL      string    `json:"url"`
		Token    TokenView `json:"token"`
		LinkEnds int64     `json:"linkEnds"`
	}
	json.Unmarshal(rec.Body.Bytes(), &made)
	// No F2B_PUBLIC_URL: the address the request came to.
	path, ok := strings.CutPrefix(made.URL, "https://example.com/agent-access/")
	if !ok || made.LinkEnds == 0 || !made.Token.Temporary {
		t.Fatalf("%+v", made)
	}

	page := send(s, "GET", "/agent-access/"+path, "")
	body := page.Body.String()
	if page.Code != http.StatusOK || !strings.HasPrefix(page.Header().Get("Content-Type"), "text/plain") ||
		page.Header().Get("Cache-Control") != "no-store" || page.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("%d %v", page.Code, page.Header())
	}
	first := strings.Join(strings.SplitN(body, "\n", 4)[:3], "\n")
	if strings.Contains(first, "f2b_") {
		t.Fatalf("the token is in the lines a preview shows:\n%s", first)
	}
	for _, want := range []string{"the fail2ban on hellogram", "https://example.com/api/v1/openapi.json", "This token reads.", "export TOKEN=f2b_" + made.Token.ID + "_"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the brief does not say %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "A ban is real") {
		t.Fatalf("a read token's brief speaks of banning:\n%s", body)
	}

	// The token it shows reaches /api/v1 with its scope.
	var token string
	for line := range strings.SplitSeq(body, "\n") {
		if t, ok := strings.CutPrefix(line, "export TOKEN="); ok {
			token = t
		}
	}
	if rec := sendWith(s, "GET", "/api/v1/jails", "", map[string]string{"Authorization": "Bearer " + token}); rec.Code != http.StatusOK {
		t.Fatalf("the token answered %d", rec.Code)
	}
	if r := <-seen; r.Header.Get(app.ScopeHeader) != app.ScopeRead {
		t.Fatalf("scope %q", r.Header.Get(app.ScopeHeader))
	}
	if strings.Contains(logs.String(), path) {
		t.Fatalf("the link's code is in the log:\n%s", logs)
	}
	if !strings.Contains(logs.String(), `"msg":"agent access opened"`) {
		t.Fatalf("%s", logs)
	}
}

func TestALinkThatShowsNothingIsALineForFail2banAndThenRateLimited(t *testing.T) {
	s, logs, _ := server(t)
	for i := range 5 {
		if rec := send(s, "GET", "/agent-access/guessed", ""); rec.Code != http.StatusNotFound {
			t.Fatalf("guess %d answered %d", i, rec.Code)
		}
	}
	if rec := send(s, "GET", "/agent-access/guessed", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the sixth guess answered %d", rec.Code)
	}
	if !strings.Contains(logs.String(), `"msg":"link refused","ip":"203.0.113.50"`) {
		t.Fatalf("%s", logs)
	}
}

func TestAWritersBriefSaysABanIsReal(t *testing.T) {
	brief := accessBrief("https://f2b.example.com", "", "f2b_x_y", TokenView{Scope: "write", Name: "Agent access abc", Expires: time.Unix(1_800_001_800, 0).Unix()}, 1_800_000_300)
	for _, want := range []string{"the dashboard of a fail2ban,", "reads and writes", "A ban is real", "If-Match", "2027-01-15T08:30:00Z"} {
		if !strings.Contains(brief, want) {
			t.Fatalf("the brief does not say %q:\n%s", want, brief)
		}
	}
}
