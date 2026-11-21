package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Programs runs fail2ban's own programs.
type Programs struct {
	Client string
	Tester string
}

// outputMax bounds what is kept of a program's output: fail2ban-regex over a busy log can print
// every line it matched.
const outputMax = 512 << 10

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

// Regex runs without resolving names: a tester waiting on DNS for each host it matched is a
// tester nobody waits for.
func (p Programs) Regex(ctx context.Context, dir, log, filter string) Result {
	return run(ctx, regexTimeout, p.Tester, "-c", dir, "--raw", "--print-all-matched", log, filter)
}

func run(parent context.Context, timeout time.Duration, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out capped
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

// capped keeps the first outputMax bytes and says so when there was more.
type capped struct {
	bytes.Buffer
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := outputMax - c.Len(); room < len(p) {
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
