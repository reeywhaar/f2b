package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Kind is which of fail2ban's places a file goes in.
type Kind string

const (
	Jails    Kind = "jails"
	Filters  Kind = "filters"
	Actions  Kind = "actions"
	Settings Kind = "settings"
)

var kinds = []Kind{Jails, Filters, Actions, Settings}

// dirOf is where a kind's files are, under the configuration directory. Settings are the
// top-level files themselves.
var dirOf = map[Kind]string{Jails: "jail.d", Filters: "filter.d", Actions: "action.d", Settings: ""}

// settingsFiles are the top-level files fail2ban reads after its own: everything else at the top
// is the package's, and an edit there would be overwritten by the next image.
var settingsFiles = []string{"fail2ban.local", "jail.local", "paths-overrides.local"}

// ContentMax bounds a file. The longest stock filter is a few kilobytes.
const ContentMax = 256 << 10

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,95}\.(local|conf)$`)

// ErrInvalid is a request that cannot be carried out as asked; its text says why.
var ErrInvalid = errors.New("invalid")

// ErrNotFound is a file that is not there.
var ErrNotFound = errors.New("not found")

// ErrConflict is a file that changed since it was read.
var ErrConflict = errors.New("conflict")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
}

// ParseKind reads a kind from a request.
func ParseKind(s string) (Kind, error) {
	k := Kind(s)
	if slices.Contains(kinds, k) {
		return k, nil
	}
	return "", invalid("%q is not a kind of file; there are jails, filters, actions and settings", s)
}

// CheckName refuses a name that is not a file fail2ban would read in that place.
func CheckName(k Kind, name string) error {
	if k == Settings {
		if !slices.Contains(settingsFiles, name) {
			return invalid("%q is not a settings file; there are %s", name, strings.Join(settingsFiles, ", "))
		}
		return nil
	}
	if !namePattern.MatchString(name) {
		return invalid("%q is not a file name fail2ban reads: letters, digits, dots, dashes and underscores, ending in .local or .conf", name)
	}
	return nil
}

// File is one edited file.
type File struct {
	Kind     Kind   `json:"kind"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
	Version  string `json:"version"`
	// Sections are the bracketed names in it other than DEFAULT and INCLUDES: in a jail file, the
	// jails it defines.
	Sections []string `json:"sections"`
}

// Files is the edited configuration on disk.
type Files struct {
	Root string
}

func (fs_ *Files) path(k Kind, name string) string {
	return filepath.Join(fs_.Root, dirOf[k], name)
}

// Ensure makes the directories, so a first start has somewhere to put things.
func (fs_ *Files) Ensure() error {
	for _, k := range kinds {
		if err := os.MkdirAll(filepath.Join(fs_.Root, dirOf[k]), 0o755); err != nil {
			return fmt.Errorf("making the configuration directory: %w", err)
		}
	}
	return nil
}

// List is every file of every kind, in order of kind and then name. Anything else in the
// directories is ignored, and so is not handed to fail2ban either.
func (fs_ *Files) List() ([]File, error) {
	out := []File{}
	for _, k := range kinds {
		entries, err := os.ReadDir(filepath.Join(fs_.Root, dirOf[k]))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("listing %s: %w", k, err)
		}
		for _, e := range entries {
			if !e.Type().IsRegular() || CheckName(k, e.Name()) != nil {
				continue
			}
			f, _, err := fs_.Read(k, e.Name())
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// Read is one file and what is in it.
func (fs_ *Files) Read(k Kind, name string) (File, string, error) {
	if err := CheckName(k, name); err != nil {
		return File{}, "", err
	}
	p := fs_.path(k, name)
	info, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return File{}, "", fmt.Errorf("%w: there is no %s %s", ErrNotFound, singular(k), name)
	}
	if err != nil {
		return File{}, "", fmt.Errorf("reading %s: %w", name, err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return File{}, "", fmt.Errorf("reading %s: %w", name, err)
	}
	return File{
		Kind:     k,
		Name:     name,
		Size:     info.Size(),
		Modified: info.ModTime().Unix(),
		Version:  VersionOf(string(b)),
		Sections: sections(string(b)),
	}, string(b), nil
}

// Current is a file's version, or "" when there is none.
func (fs_ *Files) Current(k Kind, name string) (string, error) {
	_, content, err := fs_.Read(k, name)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return VersionOf(content), nil
}

// Write replaces a file whole: written beside it and renamed over, so fail2ban never reads half.
func (fs_ *Files) Write(k Kind, name, content string) error {
	p := fs_.path(k, name)
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-"+name+"-*")
	if err != nil {
		return fmt.Errorf("writing %s: %w", name, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", name, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", name, err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return fmt.Errorf("writing %s: %w", name, err)
	}
	return nil
}

func (fs_ *Files) Delete(k Kind, name string) error {
	if err := os.Remove(fs_.path(k, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("deleting %s: %w", name, err)
	}
	return nil
}

// VersionOf names a file's content, so a save can say which content it was made against.
func VersionOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:8])
}

var sectionPattern = regexp.MustCompile(`(?m)^[ \t]*\[([^\]\r\n]+)\]`)

func sections(content string) []string {
	out := []string{}
	for _, m := range sectionPattern.FindAllStringSubmatch(content, -1) {
		name := strings.TrimSpace(m[1])
		switch strings.ToUpper(name) {
		case "DEFAULT", "INCLUDES":
			continue
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

func singular(k Kind) string {
	switch k {
	case Jails:
		return "jail file"
	case Filters:
		return "filter"
	case Actions:
		return "action"
	default:
		return "settings file"
	}
}

var keyLine = regexp.MustCompile(`^([A-Za-z_][\w.-]*)[ \t]*[=:][ \t]*(.*)$`)

// FilterOf is the filter a jail names in content, without its options, or the jail's own name,
// which is what fail2ban takes when none is named. A filter named under DEFAULT counts too.
func FilterOf(content, jail string) string {
	var section, own, fallback string
	for _, line := range strings.Split(content, "\n") {
		if m := sectionPattern.FindStringSubmatch(line); m != nil {
			section = strings.TrimSpace(m[1])
			continue
		}
		m := keyLine.FindStringSubmatch(line)
		if m == nil || m[1] != "filter" {
			continue
		}
		v, _, _ := strings.Cut(strings.TrimSpace(m[2]), "[")
		switch {
		case section == jail:
			own = v
		case strings.EqualFold(section, "DEFAULT"):
			fallback = v
		}
	}
	for _, v := range []string{own, fallback} {
		if v != "" && !strings.Contains(v, "%(") {
			return v
		}
	}
	return jail
}
