package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Programs runs fail2ban's own programs.
type Programs struct {
	Client string
	Tester string
}

// outputMax bounds what is kept of a program's output. fail2ban-regex prints every line it
// tried, sorted by what it made of each, and is given more: twenty thousand lines of a busy log.
const (
	outputMax      = 512 << 10
	regexOutputMax = 32 << 20
)

const (
	checkTimeout  = time.Minute
	reloadTimeout = 2 * time.Minute
	regexTimeout  = time.Minute
)

func (p Programs) Check(ctx context.Context, dir string) Result {
	return run(ctx, checkTimeout, p.Client, "-c", dir, "--test")
}

func (p Programs) Reload(ctx context.Context, dir string) Result {
	return run(ctx, reloadTimeout, p.Client, "-c", dir, "reload")
}

func (p Programs) Actions(ctx context.Context, dir string) (map[string][]string, error) {
	res := run(ctx, checkTimeout, p.Client, "-c", dir, "-d")
	if !res.OK {
		return nil, fmt.Errorf("reading the actions the configuration gives each jail: %s", res.Output)
	}
	return actionsIn(res.Output), nil
}

// addaction is a jail given an action, in the commands fail2ban-client -d prints.
var addaction = regexp.MustCompile(`(?m)^\['set', '([^']+)', 'addaction', '([^']+)'`)

func actionsIn(dump string) map[string][]string {
	out := map[string][]string{}
	for _, m := range addaction.FindAllStringSubmatch(dump, -1) {
		out[m[1]] = append(out[m[1]], m[2])
	}
	return out
}

// Regex runs without resolving names: a tester waiting on DNS for each host it matched is a
// tester nobody waits for. It prints every line, under what it made of it, which is how each line
// is told matched, ignored or missed.
func (p Programs) Regex(ctx context.Context, dir, log, filter string) Result {
	return runCapped(ctx, regexTimeout, regexOutputMax, p.Tester, "-c", dir, "--raw",
		"--print-all-matched", "--print-all-ignored", "--print-all-missed", log, filter)
}

func run(parent context.Context, timeout time.Duration, name string, args ...string) Result {
	return runCapped(parent, timeout, outputMax, name, args...)
}

func runCapped(parent context.Context, timeout time.Duration, most int, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out := capped{max: most}
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	text := strings.TrimRight(out.String(), "\n")
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return Result{Output: text + fmt.Sprintf("\n\n%s did not finish within %s and was stopped.", name, timeout)}
	case err != nil && text == "":
		return Result{Output: fmt.Sprintf("%s failed: %v", name, err)}
	}
	return Result{OK: err == nil, Output: text}
}

// capped keeps the first max bytes and says so when there was more.
type capped struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room < len(p) {
		if room > 0 {
			c.Buffer.Write(p[:room])
		}
		c.over = true
		return len(p), nil
	}
	return c.Buffer.Write(p)
}

func (c *capped) String() string {
	if c.over {
		return c.Buffer.String() + "\n… (the rest is cut)"
	}
	return c.Buffer.String()
}
