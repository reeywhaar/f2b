package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"f2b/internal/app"
)

// v1 sends one request to /api/v1 as the web would pass it on.
func v1(t *testing.T, s *Server, method, path, body string, header map[string]string) (int, http.Header, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", MediaType)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, rec.Header(), out
}

func firstError(out map[string]any) map[string]any {
	errs, _ := out["errors"].([]any)
	if len(errs) == 0 {
		return nil
	}
	e, _ := errs[0].(map[string]any)
	return e
}

var readScope = map[string]string{app.ScopeHeader: app.ScopeRead}

func TestTheOpenAPIDocumentListsEveryRouteAndNoOther(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openAPI, &spec); err != nil {
		t.Fatal(err)
	}
	var documented []string
	for p, ops := range spec.Paths {
		for m := range ops {
			if m != "parameters" {
				documented = append(documented, strings.ToUpper(m)+" "+p)
			}
		}
	}
	s, _, _, _ := server(t)
	served := []string{"GET /api/v1/openapi.json"}
	rest := regexp.MustCompile(`\{(\w+)\.\.\.\}`)
	for _, rt := range s.v1Routes() {
		served = append(served, rt.Method+" "+rest.ReplaceAllString(rt.Path, "{$1}"))
	}
	sort.Strings(documented)
	sort.Strings(served)
	if !slices.Equal(documented, served) {
		t.Fatalf("openapi.json and the routes differ:\ndocumented %v\nserved     %v", documented, served)
	}
}

func TestEveryRouteSaysWhichScopeTakesIt(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]struct {
			Scope string `json:"x-f2b-scope"`
		} `json:"paths"`
	}
	json.Unmarshal(openAPI, &spec)
	s, _, _, _ := server(t)
	rest := regexp.MustCompile(`\{(\w+)\.\.\.\}`)
	for _, rt := range s.v1Routes() {
		want := app.ScopeRead
		if rt.Write {
			want = app.ScopeWrite
		}
		got := spec.Paths[rest.ReplaceAllString(rt.Path, "{$1}")][strings.ToLower(rt.Method)].Scope
		if got != want {
			t.Errorf("%s %s: documented as %q, served as %q", rt.Method, rt.Path, got, want)
		}
	}
}

func TestAV1AnswerIsAJSONAPIDocument(t *testing.T) {
	s, _, _, _ := server(t)
	do(t, s, "PUT", "/api/files/jails/mine.local", `{"content":"[app]\nfilter = app-auth\n","version":""}`)
	code, h, out := v1(t, s, "GET", "/api/v1/jails", "", readScope)
	if code != http.StatusOK || h.Get("Content-Type") != MediaType {
		t.Fatalf("%d %s", code, h.Get("Content-Type"))
	}
	if out["jsonapi"].(map[string]any)["version"] != "1.1" {
		t.Fatalf("no jsonapi member: %v", out)
	}
	jails := map[string]map[string]any{}
	for _, d := range out["data"].([]any) {
		j := d.(map[string]any)
		jails[j["id"].(string)] = j
	}
	app, sshd := jails["app"], jails["sshd"]
	attrs := app["attributes"].(map[string]any)
	if app["type"] != "jails" || attrs["filter"] != "app-auth" || attrs["logs"] == nil {
		t.Fatalf("%v", app)
	}
	file := app["relationships"].(map[string]any)["file"].(map[string]any)["data"].(map[string]any)
	if file["type"] != "files" || file["id"] != "jails/mine.local" {
		t.Fatalf("the jail's file: %v", file)
	}
	if sshd["relationships"].(map[string]any)["file"].(map[string]any)["data"] != nil {
		t.Fatal("a jail no edited file defines names one")
	}
}

func TestAReadTokenIsRefusedWhatChangesSomethingAndNothingElse(t *testing.T) {
	s, d, _, _ := server(t)
	ban := `{"data":{"type":"bans","attributes":{"ip":"203.0.113.7"},"relationships":{"jail":{"data":{"type":"jails","id":"sshd"}}}}}`
	code, _, out := v1(t, s, "POST", "/api/v1/bans", ban, readScope)
	if code != http.StatusForbidden || firstError(out)["code"] != "forbidden" || len(d.banned) != 0 {
		t.Fatalf("%d %v, banned %v", code, out, d.banned)
	}
	// Trying a filter changes nothing, so a read token may.
	code, _, out = v1(t, s, "POST", "/api/v1/regex-tests", `{"data":{"type":"regex-tests","attributes":{"filter":"sshd","text":"a line"}}}`, readScope)
	if code != http.StatusOK || out["data"].(map[string]any)["type"] != "regex-tests" {
		t.Fatalf("the tester: %d %v", code, out)
	}
	code, h, out := v1(t, s, "POST", "/api/v1/bans", ban, map[string]string{app.ScopeHeader: app.ScopeWrite})
	if code != http.StatusCreated || h.Get("Location") != "/api/v1/jails/sshd/bans/203.0.113.7" || !slices.Equal(d.banned, []string{"sshd 203.0.113.7"}) {
		t.Fatalf("a write token: %d %v %v", code, out, d.banned)
	}
	if out["data"].(map[string]any)["id"] != "sshd/203.0.113.7" {
		t.Fatalf("%v", out)
	}
}

func TestARangeKeepsItsSlashInsideItsSegment(t *testing.T) {
	s, d, _, _ := server(t)
	code, _, out := v1(t, s, "DELETE", "/api/v1/jails/sshd/bans/203.0.113.0%2F24", "", nil)
	if code != http.StatusNoContent || !slices.Equal(d.unbanned, []string{"sshd 203.0.113.0/24"}) {
		t.Fatalf("%d %v %v", code, out, d.unbanned)
	}
}

func TestAWriteToAFileNamesTheVersionItWasMadeAgainst(t *testing.T) {
	s, _, tools, _ := server(t)
	code, h, out := v1(t, s, "POST", "/api/v1/files", `{"data":{"type":"files","attributes":{"kind":"filters","name":"app.local","content":"one"}}}`, nil)
	if code != http.StatusCreated || h.Get("ETag") != `"`+VersionOf("one")+`"` || h.Get("Location") != "/api/v1/files/filters/app.local" {
		t.Fatalf("create: %d %v %v", code, h, out)
	}
	if out["meta"].(map[string]any)["reload"].(map[string]any)["ok"] != true || tools.reloads != 1 {
		t.Fatalf("create's meta: %v", out)
	}
	save := `{"data":{"type":"files","id":"filters/app.local","attributes":{"content":"two"}}}`
	if code, _, out := v1(t, s, "PATCH", "/api/v1/files/filters/app.local", save, nil); code != http.StatusPreconditionRequired || firstError(out)["code"] != "precondition_required" {
		t.Fatalf("without If-Match: %d %v", code, out)
	}
	if code, _, out := v1(t, s, "PATCH", "/api/v1/files/filters/app.local", save, map[string]string{"If-Match": `"` + VersionOf("zero") + `"`}); code != http.StatusPreconditionFailed {
		t.Fatalf("against an old version: %d %v", code, out)
	}
	code, h, out = v1(t, s, "PATCH", "/api/v1/files/filters/app.local", save, map[string]string{"If-Match": h.Get("ETag")})
	if code != http.StatusOK || h.Get("ETag") != `"`+VersionOf("two")+`"` || out["data"].(map[string]any)["attributes"].(map[string]any)["content"] != "two" {
		t.Fatalf("against the current version: %d %v", code, out)
	}
	wrong := `{"data":{"type":"files","id":"filters/other.local","attributes":{"content":"x"}}}`
	if code, _, _ := v1(t, s, "PATCH", "/api/v1/files/filters/app.local", wrong, map[string]string{"If-Match": h.Get("ETag")}); code != http.StatusConflict {
		t.Fatalf("an id that is not the address's: %d", code)
	}
	none := `{"data":{"type":"files","id":"filters/none.local","attributes":{"content":"x"}}}`
	if code, _, _ := v1(t, s, "PATCH", "/api/v1/files/filters/none.local", none, map[string]string{"If-Match": h.Get("ETag")}); code != http.StatusNotFound {
		t.Fatalf("a file that is not there: %d", code)
	}
	code, _, out = v1(t, s, "DELETE", "/api/v1/files/filters/app.local", "", map[string]string{"If-Match": h.Get("ETag")})
	if code != http.StatusOK || out["meta"] == nil {
		t.Fatalf("delete: %d %v", code, out)
	}
}

func TestARefusedSaveSaysWhatFail2banSaid(t *testing.T) {
	s, _, _, _ := server(t)
	code, _, out := v1(t, s, "POST", "/api/v1/files", `{"data":{"type":"files","attributes":{"kind":"filters","name":"app.local","content":"bad"}}}`, nil)
	e := firstError(out)
	if code != http.StatusUnprocessableEntity || e["code"] != "config_rejected" || e["meta"].(map[string]any)["output"] != "ERROR in app.local" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestJSONAPIsMediaTypeIsTheOneSpoken(t *testing.T) {
	s, _, _, _ := server(t)
	code, _, out := v1(t, s, "POST", "/api/v1/regex-tests", `{}`, map[string]string{"Content-Type": "application/json"})
	if code != http.StatusUnsupportedMediaType || firstError(out)["code"] != "unsupported_media_type" {
		t.Fatalf("plain JSON in: %d %v", code, out)
	}
	if code, _, _ := v1(t, s, "GET", "/api/v1/engine", "", map[string]string{"Accept": MediaType + `; charset=utf-8`}); code != http.StatusNotAcceptable {
		t.Fatalf("an Accept with a parameter it cannot honor: %d", code)
	}
	if code, _, _ := v1(t, s, "GET", "/api/v1/engine", "", map[string]string{"Accept": "text/html, " + MediaType}); code != http.StatusOK {
		t.Fatalf("an Accept naming it bare: %d", code)
	}
	if code, _, _ := v1(t, s, "GET", "/api/v1/engine", "", map[string]string{"Accept": "*/*"}); code != http.StatusOK {
		t.Fatalf("an Accept not naming it: %d", code)
	}
	if code, _, out := v1(t, s, "GET", "/api/v1/nothing", "", nil); code != http.StatusNotFound || firstError(out) == nil {
		t.Fatalf("an unknown route: %d %v", code, out)
	}
}

func TestATypeThatIsNotTheEndpointsIsAConflict(t *testing.T) {
	s, _, _, _ := server(t)
	code, _, out := v1(t, s, "POST", "/api/v1/regex-tests", `{"data":{"type":"bans","attributes":{"filter":"sshd"}}}`, nil)
	if code != http.StatusConflict {
		t.Fatalf("%d %v", code, out)
	}
	code, _, out = v1(t, s, "POST", "/api/v1/regex-tests", `{"data":{"type":"regex-tests","attributes":{"filter":"sshd","typo":1}}}`, nil)
	if code != http.StatusBadRequest || firstError(out)["code"] != "invalid" {
		t.Fatalf("an unknown attribute: %d %v", code, out)
	}
}

func TestTheOpenAPIDocumentIsServed(t *testing.T) {
	s, _, _, _ := server(t)
	req := httptest.NewRequest("GET", "/api/v1/openapi.json", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	var spec map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &spec) != nil || spec["openapi"] != "3.1.0" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
