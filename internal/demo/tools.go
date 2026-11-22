package demo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"f2b/internal/engine"
)

// tools stand in for fail2ban-client and fail2ban-regex: the same questions, answered by reading
// the composed configuration in Go.
type tools struct {
	d *daemon
}

func (t tools) Check(ctx context.Context, dir string) engine.Result {
	for _, sub := range []string{".", "jail.d", "filter.d", "action.d"} {
		if _, err := readDir(filepath.Join(dir, sub)); err != nil {
			return engine.Result{Output: "ERROR   Failed during configuration: " + err.Error()}
		}
	}
	defs, err := readJails(dir)
	if err != nil {
		return engine.Result{Output: "ERROR   Failed during configuration: " + err.Error()}
	}
	for _, def := range defs {
		name, _, _ := strings.Cut(def.filter, "[")
		if !exists(filepath.Join(dir, "filter.d", name+".conf")) && !exists(filepath.Join(dir, "filter.d", name+".local")) {
			return engine.Result{Output: fmt.Sprintf("ERROR   Found no accessible config files for 'filter.d/%s' under %s\nERROR   Unable to read the filter '%s'\nERROR   Errors in jail '%s'.\nERROR   Failed during configuration: Have not found any filter for jail %s", name, dir, def.filter, def.name, def.name)}
		}
		if len(def.logs) == 0 {
			return engine.Result{Output: fmt.Sprintf("ERROR   Failed during configuration: Have not found any log file for %s jail", def.name)}
		}
		for _, p := range def.logs {
			if m, _ := filepath.Glob(p); len(m) == 0 {
				return engine.Result{Output: fmt.Sprintf("ERROR   No file(s) found for glob %s\nERROR   Failed during configuration: Have not found any log file for %s jail", p, def.name)}
			}
		}
	}
	return engine.Result{OK: true, Output: "OK: configuration test is successful"}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Actions is none, as the demo's fail2ban runs none.
func (t tools) Actions(ctx context.Context, dir string) (map[string][]string, error) {
	return map[string][]string{}, nil
}

func (t tools) Reload(ctx context.Context, dir string) engine.Result {
	if err := t.d.reload(dir); err != nil {
		return engine.Result{Output: "ERROR   " + err.Error()}
	}
	return engine.Result{OK: true, Output: "OK"}
}

var dates = []*regexp.Regexp{
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?`),
	regexp.MustCompile(`[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`\b1\d{9}(?:\.\d+)?\b`),
}

// tags are fail2ban's, rewritten as Go's named groups.
var tags = strings.NewReplacer(
	"<HOST>", `(?P<host>[0-9A-Fa-f.:]+|[\w.-]+)`,
	"<ADDR>", `(?P<ip>[0-9A-Fa-f.:]+)`,
	"<IP4>", `(?P<ip4>\d+\.\d+\.\d+\.\d+)`,
	"<IP6>", `(?P<ip6>[0-9A-Fa-f:]+)`,
	"<F-USER>", `(?P<user>`, "</F-USER>", `)`,
	"<F-ID>", `(?P<fid>`, "</F-ID>", `)`,
)

// Regex reads failregex and ignoreregex from the filter, takes each line's date out as fail2ban
// does, and matches with Go's regexp. Its output is shaped like fail2ban-regex's, and says it is
// not.
func (t tools) Regex(ctx context.Context, dir, log, filter string) engine.Result {
	start := time.Now()
	name, _, _ := strings.Cut(filter, "[")
	keys := map[string]string{}
	found := false
	for _, f := range []string{"common.conf", name + ".conf", name + ".local"} {
		b, err := os.ReadFile(filepath.Join(dir, "filter.d", f))
		if err != nil {
			continue
		}
		found = found || f != "common.conf"
		secs, err := parseINI(f, string(b))
		if err != nil {
			return engine.Result{Output: "ERROR: " + err.Error()}
		}
		for _, s := range secs {
			for k, v := range s.keys {
				keys[k] = v
			}
		}
	}
	if !found {
		return engine.Result{Output: fmt.Sprintf("ERROR: Unable to find a corresponding filter file for %s", filter)}
	}
	compile := func(key string) ([]*regexp.Regexp, []string, error) {
		var res []*regexp.Regexp
		var srcs []string
		for _, src := range strings.Split(keys[key], "\n") {
			src = strings.TrimSpace(src)
			if src == "" {
				continue
			}
			re, err := regexp.Compile(tags.Replace(expand(src, keys)))
			if err != nil {
				return nil, nil, fmt.Errorf("the demo matches with Go's regexp, which cannot read %q: %v. fail2ban's own may well read it", src, err)
			}
			res, srcs = append(res, re), append(srcs, src)
		}
		return res, srcs, nil
	}
	fail, failSrc, err := compile("failregex")
	if err != nil {
		return engine.Result{Output: "ERROR: " + err.Error()}
	}
	ignore, ignoreSrc, err := compile("ignoreregex")
	if err != nil {
		return engine.Result{Output: "ERROR: " + err.Error()}
	}
	b, err := os.ReadFile(log)
	if err != nil {
		return engine.Result{Output: "ERROR: " + err.Error()}
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	hits := make([]int, len(fail))
	ignoreHits := make([]int, len(ignore))
	var matched, ignored, missed []string
lines:
	for _, line := range lines {
		text := line
		for _, d := range dates {
			if loc := d.FindStringIndex(text); loc != nil {
				text = text[:loc[0]] + text[loc[1]:]
				break
			}
		}
		for i, re := range ignore {
			if re.MatchString(text) {
				ignoreHits[i]++
				ignored = append(ignored, line)
				continue lines
			}
		}
		for i, re := range fail {
			if re.MatchString(text) {
				hits[i]++
				matched = append(matched, line)
				continue lines
			}
		}
		missed = append(missed, line)
	}

	var o strings.Builder
	fmt.Fprintf(&o, "(The demo's stand-in for fail2ban-regex: it matches with Go's regexp.)\n\n")
	fmt.Fprintf(&o, "Running tests\n=============\n\n")
	fmt.Fprintf(&o, "Use   failregex filter file : %s, basedir: %s\n", filter, dir)
	fmt.Fprintf(&o, "Use         log file : %s\nUse         encoding : UTF-8\n\n\n", log)
	fmt.Fprintf(&o, "Results\n=======\n\n")
	fmt.Fprintf(&o, "Failregex: %d total\n|-  #) [# of hits] regular expression\n", len(matched))
	for i, src := range failSrc {
		fmt.Fprintf(&o, "|  %2d) [%d] %s\n", i+1, hits[i], src)
	}
	fmt.Fprintf(&o, "`-\n\nIgnoreregex: %d total\n", len(ignored))
	if len(ignoreSrc) > 0 {
		fmt.Fprintf(&o, "|-  #) [# of hits] regular expression\n")
		for i, src := range ignoreSrc {
			fmt.Fprintf(&o, "|  %2d) [%d] %s\n", i+1, ignoreHits[i], src)
		}
		fmt.Fprintf(&o, "`-\n")
	}
	fmt.Fprintf(&o, "\nLines: %d lines, %d ignored, %d matched, %d missed\n", len(lines), len(ignored), len(matched), len(missed))
	fmt.Fprintf(&o, "[processed in %.2f sec]\n\n", time.Since(start).Seconds())
	// Every line, under what was made of it, as fail2ban-regex prints them given --print-all-….
	for _, group := range []struct {
		heading string
		lines   []string
	}{{"Matched", matched}, {"Ignored", ignored}, {"Missed", missed}} {
		if len(group.lines) == 0 {
			continue
		}
		fmt.Fprintf(&o, "|- %s line(s):\n", group.heading)
		for _, l := range group.lines {
			fmt.Fprintf(&o, "|  %s\n", l)
		}
		fmt.Fprintf(&o, "`-\n")
	}
	return engine.Result{OK: true, Output: o.String()}
}
