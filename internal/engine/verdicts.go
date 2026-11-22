package engine

import (
	"strings"
)

// RegexLine is a line the tester tried, and what the filter made of it.
type RegexLine struct {
	Text string `json:"text"`
	// Verdict is "matched", "ignored" or "missed"; "" where fail2ban-regex did not say, as when
	// it stopped on an error before reading the lines.
	Verdict string `json:"verdict"`
}

// The headings fail2ban-regex prints each kind of line under, given --print-all-….
var verdictOf = map[string]string{
	"|- Matched line(s):": "matched",
	"|- Ignored line(s):": "ignored",
	"|- Missed line(s):":  "missed",
}

// verdicts says what fail2ban-regex made of each line it was given, from the lines it printed
// under each heading: by text, in order, as the same text twice is the same verdict twice. It
// also hands back what fail2ban-regex said without those lines, which the lines now carry.
func verdicts(tried []string, output string) ([]RegexLine, string) {
	said := map[string]map[string]int{}
	var rest []string
	current := ""
	for line := range strings.SplitSeq(output, "\n") {
		if v, ok := verdictOf[line]; ok {
			current = v
			if said[v] == nil {
				said[v] = map[string]int{}
			}
			continue
		}
		if current != "" {
			if text, ok := strings.CutPrefix(line, "|  "); ok {
				said[current][strings.TrimRight(text, "\r")]++
				continue
			}
			if line == "`-" {
				current = ""
				continue
			}
			current = ""
		}
		rest = append(rest, line)
	}
	lines := make([]RegexLine, len(tried))
	for i, text := range tried {
		lines[i].Text = text
		for _, v := range []string{"matched", "ignored", "missed"} {
			if said[v][text] > 0 {
				said[v][text]--
				lines[i].Verdict = v
				break
			}
		}
	}
	return lines, strings.TrimRight(strings.Join(rest, "\n"), "\n")
}

// linesOf is a sample's lines as fail2ban-regex reads them: without their line ends.
func linesOf(b []byte) []string {
	text := strings.TrimSuffix(string(b), "\n")
	if text == "" {
		return []string{}
	}
	out := strings.Split(text, "\n")
	for i := range out {
		out[i] = strings.TrimRight(out[i], "\r")
	}
	return out
}
