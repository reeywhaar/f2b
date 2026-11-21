package demo

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// section is one bracketed part of an INI file, in the loose sense fail2ban reads: keys,
// values that carry on over indented lines, comments with # or ;.
type section struct {
	name string
	keys map[string]string
}

// parseINI reads a file the way the demo needs to: well enough to find jails and filters, and to
// say where a line is not INI at all, as fail2ban's parser would.
func parseINI(path, content string) ([]section, error) {
	var out []section
	var cur *section
	var key string
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";"):
			continue
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			out = append(out, section{name: strings.TrimSpace(trimmed[1 : len(trimmed)-1]), keys: map[string]string{}})
			cur, key = &out[len(out)-1], ""
		case (line[0] == ' ' || line[0] == '\t') && cur != nil && key != "":
			cur.keys[key] += "\n" + trimmed
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				k, v, ok = strings.Cut(line, ":")
			}
			if !ok || cur == nil {
				return nil, fmt.Errorf("Source contains parsing errors: %q\n\t[line %2d]: %q", path, i+1, line)
			}
			key = strings.TrimSpace(k)
			cur.keys[key] = strings.TrimSpace(v)
		}
	}
	return out, nil
}

// readDir parses every file in a composed directory's subdirectory, in the order fail2ban would.
func readDir(dir string) (map[string][]section, error) {
	out := map[string][]section{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out, nil
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		secs, err := parseINI(p, string(b))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = secs
	}
	return out, nil
}

var interpolation = regexp.MustCompile(`%\(([^)]+)\)s`)

// expand replaces %(name)s from the keys given, a few times over for references to references.
func expand(s string, keys map[string]string) string {
	for range 5 {
		next := interpolation.ReplaceAllStringFunc(s, func(m string) string {
			name := interpolation.FindStringSubmatch(m)[1]
			if v, ok := keys[name]; ok {
				return v
			}
			return m
		})
		if next == s {
			break
		}
		s = next
	}
	return s
}
