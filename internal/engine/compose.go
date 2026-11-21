package engine

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Change is one file as it would be after a save: its new content, or nil for deleted.
type Change struct {
	Kind    Kind
	Name    string
	Content *string
}

// Composer builds the directory fail2ban is run with: the package's configuration, without the
// jails it enables on its own, what is edited laid over it, and what the engine depends on last.
type Composer struct {
	// Stock is the package's /etc/fail2ban. Missing, there is nothing under what is edited, which
	// is what the demo runs with.
	Stock string
	Files *Files
	// Socket, PidFile and Database are fail2ban's, wherever the engine keeps them.
	Socket   string
	PidFile  string
	Database string
}

// Compose writes the directory at dst, replacing whatever was there.
func (c *Composer) Compose(dst string, change *Change) error {
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("clearing %s: %w", dst, err)
	}
	if err := c.copyStock(dst); err != nil {
		return err
	}
	for _, k := range kinds {
		if err := os.MkdirAll(filepath.Join(dst, dirOf[k]), 0o755); err != nil {
			return err
		}
	}
	files, err := c.Files.List()
	if err != nil {
		return err
	}
	for _, f := range files {
		if change != nil && f.Kind == change.Kind && f.Name == change.Name {
			continue
		}
		if err := copyFile(c.Files.path(f.Kind, f.Name), filepath.Join(dst, dirOf[f.Kind], f.Name)); err != nil {
			return err
		}
	}
	if change != nil && change.Content != nil {
		if err := os.WriteFile(filepath.Join(dst, dirOf[change.Kind], change.Name), []byte(*change.Content), 0o644); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(dst, "fail2ban.d"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dst, "fail2ban.d", "00-f2b.conf"), []byte(defaults), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dst, "fail2ban.d", "zz-f2b.local"), []byte(c.forced()), 0o644)
}

// defaults are read before fail2ban.local, under DEFAULT, so anything it says wins.
//
// Ninety days of bans rather than fail2ban's one, so the history has something to show.
// allowipv6 is fail2ban's own default, said so that it stops warning that nobody did.
const defaults = `# Written by f2b. fail2ban.local overrides any of it.
[DEFAULT]
dbpurgeage = 90d
allowipv6 = auto
`

// forced is read last, under Definition, which beats DEFAULT wherever it was set: the engine
// reads fail2ban's log from its output, and talks to it on this socket.
func (c *Composer) forced() string {
	return fmt.Sprintf(`# Written by f2b, last of all: the engine depends on these.
[Definition]
logtarget = STDOUT
socket = %s
pidfile = %s
dbfile = %s
`, c.Socket, c.PidFile, c.Database)
}

// copyStock copies the package's tree, leaving out jail.d and fail2ban.d: the package enables
// an sshd jail reading /var/log/messages, and anything set there is the edited files' to say.
func (c *Composer) copyStock(dst string) error {
	if c.Stock == "" {
		return os.MkdirAll(dst, 0o755)
	}
	if _, err := os.Stat(c.Stock); errors.Is(err, fs.ErrNotExist) {
		return os.MkdirAll(dst, 0o755)
	}
	return filepath.WalkDir(c.Stock, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(c.Stock, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		top, _, nested := strings.Cut(rel, string(filepath.Separator))
		if nested && (top == "jail.d" || top == "fail2ban.d") {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return copyFile(p, target)
	})
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Stock lists the package's filters and actions and its top-level files, read-only, for
// reference and for overriding.
type StockList struct {
	Filters []string `json:"filters"`
	Actions []string `json:"actions"`
	Other   []string `json:"other"`
}

func (c *Composer) StockList() (StockList, error) {
	out := StockList{Filters: []string{}, Actions: []string{}, Other: []string{}}
	if c.Stock == "" {
		return out, nil
	}
	read := func(dir string, into *[]string) error {
		entries, err := os.ReadDir(filepath.Join(c.Stock, dir))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Type().IsRegular() && (strings.HasSuffix(e.Name(), ".conf") || strings.HasSuffix(e.Name(), ".local")) {
				*into = append(*into, e.Name())
			}
		}
		return nil
	}
	if err := read("filter.d", &out.Filters); err != nil {
		return out, err
	}
	if err := read("action.d", &out.Actions); err != nil {
		return out, err
	}
	if err := read("", &out.Other); err != nil {
		return out, err
	}
	return out, nil
}

// StockFile reads one of them: "filter.d/sshd.conf", or "jail.conf".
func (c *Composer) StockFile(rel string) (string, error) {
	dir, name := filepath.Split(rel)
	dir = strings.TrimSuffix(dir, "/")
	if (dir != "" && dir != "filter.d" && dir != "action.d") || !namePattern.MatchString(name) {
		return "", fmt.Errorf("%w: there is no stock file %s", ErrNotFound, rel)
	}
	if c.Stock == "" {
		return "", fmt.Errorf("%w: there is no stock file %s", ErrNotFound, rel)
	}
	b, err := os.ReadFile(filepath.Join(c.Stock, dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%w: there is no stock file %s", ErrNotFound, rel)
	}
	if err != nil {
		return "", err
	}
	return string(b), nil
}
