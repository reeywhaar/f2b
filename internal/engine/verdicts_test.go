package engine

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// said is fail2ban-regex 1.1.0's own output, given --print-all-matched, -ignored and -missed.
const said = `Running tests
=============

Results
=======

Failregex: 3 total
|-  #) [# of hits] regular expression
|   1) [3] ^.*"msg":"password refused".*"ip":"<ADDR>"
` + "`-" + `

Lines: 5 lines, 1 ignored, 3 matched, 1 missed
[processed in 0.01 sec]

|- Matched line(s):
|  {"msg":"password refused","ip":"192.0.2.216"}
|  no date "msg":"password refused","ip":"192.0.2.1"
|  {"msg":"password refused","ip":"192.0.2.216"}
` + "`-" + `
|- Ignored line(s):
|  {"msg":"password refused","ip":"10.0.0.5"}
` + "`-" + `
|- Missed line(s):
|  {"msg":"message delivered"}
` + "`-"

var tried = []string{
	`{"msg":"password refused","ip":"192.0.2.216"}`,
	`{"msg":"message delivered"}`,
	`{"msg":"password refused","ip":"10.0.0.5"}`,
	`no date "msg":"password refused","ip":"192.0.2.1"`,
	`{"msg":"password refused","ip":"192.0.2.216"}`,
}

func TestEachLineIsWhatFail2banRegexMadeOfIt(t *testing.T) {
	lines, rest := verdicts(tried, said)
	var got []string
	for _, l := range lines {
		got = append(got, l.Verdict)
	}
	if want := []string{"matched", "missed", "ignored", "matched", "matched"}; !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if strings.Contains(rest, "line(s):") || strings.Contains(rest, "message delivered") {
		t.Fatalf("the lines are still in what is said:\n%s", rest)
	}
	if !strings.Contains(rest, "Lines: 5 lines, 1 ignored, 3 matched, 1 missed") || !strings.Contains(rest, "[3] ^.*") {
		t.Fatalf("the count went with the lines:\n%s", rest)
	}
}

func TestALineFail2banRegexDidNotGetToSaysNothing(t *testing.T) {
	lines, rest := verdicts(tried, "ERROR: No failure-id group in '^x'")
	if lines[0].Verdict != "" || rest != "ERROR: No failure-id group in '^x'" {
		t.Fatalf("%v %q", lines, rest)
	}
}

func TestTheTesterAnswersEachLineWithItsVerdict(t *testing.T) {
	s, _, tools, _ := server(t)
	tools.said = said
	body, _ := json.Marshal(map[string]any{"filter": "app", "text": strings.Join(tried, "\n")})
	code, out := do(t, s, "POST", "/api/regex", string(body))
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, out)
	}
	lines := out["lines"].([]any)
	if len(lines) != 5 || lines[2].(map[string]any)["verdict"] != "ignored" || lines[3].(map[string]any)["text"] != tried[3] {
		t.Fatalf("%v", lines)
	}
	if strings.Contains(out["output"].(string), "Matched line(s)") {
		t.Fatalf("%v", out["output"])
	}
}

func TestAFilesLastLinesAreRead(t *testing.T) {
	s, base := logsServer(t)
	code, out := do(t, s, "GET", "/api/logs"+filepath.Join(base, "data/logs/app.log")+"?tail=1", "")
	if code != http.StatusOK || jsonOf(out["lines"]) != `["two"]` {
		t.Fatalf("%d %v", code, out)
	}
	code, _, doc := v1(t, s, "GET", "/api/v1/log-files"+filepath.Join(base, "data/logs/app.log")+"?page[size]=5", "", readScope)
	attrs := doc["data"].(map[string]any)["attributes"].(map[string]any)
	if code != http.StatusOK || jsonOf(attrs["lines"]) != `["one","two"]` || attrs["name"] != "app.log" {
		t.Fatalf("%d %v", code, doc)
	}
}
