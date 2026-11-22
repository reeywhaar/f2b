package engine

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"f2b/internal/reply"
)

// LogPlaces are where the engine reads logs from, to list them and for the tester: each mount in
// its container that is read-only, which is how a deploy hands it logs, and the directory of each
// log a running jail reads. Never the data directory, or one holding it: the session key and the
// tokens are there, and a read token trying a filter must not read them.
type LogPlaces struct {
	// Mounts are the read-only mounts, found once at start.
	Mounts []string
	// Data is the data directory.
	Data string

	mu      sync.Mutex
	readers map[string][]string
	at      time.Time
}

// readersFor is how long the logs the running jails read are kept, rather than asked for again:
// asking is a handful of calls on fail2ban's socket for each jail, and a picker going through
// directories asks for each one.
const readersFor = 10 * time.Second

// ReadOnlyMounts are the mounts in this container that are read-only and are not the kernel's or
// the runtime's: a deploy's log directories. None where there is no mountinfo, as on a Mac
// running the demo.
func ReadOnlyMounts() []string {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	return readOnlyMounts(string(b))
}

var (
	// kernelFS are the kernel's own filesystems, and the image's.
	kernelFS = map[string]bool{
		"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "devpts": true,
		"mqueue": true, "securityfs": true, "debugfs": true, "tracefs": true, "bpf": true,
		"pstore": true, "configfs": true, "fusectl": true, "binfmt_misc": true, "nsfs": true,
		"autofs": true, "hugetlbfs": true, "devtmpfs": true, "overlay": true,
	}
	// notLogs are where the kernel and the container runtime mount what is not a log: Docker
	// mounts parts of /proc and /sys read-only, and a compose file's secrets under /run/secrets.
	notLogs = []string{"/proc", "/sys", "/dev", "/run/secrets"}
)

// readOnlyMounts reads /proc/self/mountinfo: "36 35 98:0 /src /mnt/point ro,relatime shared:1 -
// ext4 /dev/sda1 rw". The fifth field is where it is mounted, the sixth this mount's own options,
// and the first after the "-" its filesystem.
func readOnlyMounts(info string) []string {
	var out []string
	for line := range strings.SplitSeq(info, "\n") {
		f := strings.Fields(line)
		sep := slices.Index(f, "-")
		if sep < 6 || sep+1 >= len(f) {
			continue
		}
		point, opts, fs := unescapeMount(f[4]), strings.Split(f[5], ","), f[sep+1]
		if !slices.Contains(opts, "ro") || kernelFS[fs] || point == "/" {
			continue
		}
		if slices.ContainsFunc(notLogs, func(p string) bool { return within(point, p) }) {
			continue
		}
		if !slices.Contains(out, point) {
			out = append(out, point)
		}
	}
	return out
}

// unescapeMount undoes mountinfo's octal escapes: a space in a path is \040.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// within is whether p is dir or inside it.
func within(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}

// LogEntry is a directory or a file among the logs.
type LogEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Dir      bool   `json:"dir"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
	// Jails are the running jails that read it.
	Jails []string `json:"jails"`
	// Source is, for a place logs are read from, why: "mount" for a read-only mount, "jail" for
	// where a running jail reads a log.
	Source string `json:"source,omitempty"`
}

// readers is each log the running jails read, and which jails read it. Kept a while; when
// fail2ban is not running, none.
func (s *Server) readers(ctx context.Context) map[string][]string {
	p := &s.Logs
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if p.readers != nil && now().Sub(p.at) < readersFor {
		return p.readers
	}
	out := map[string][]string{}
	if jails, err := s.Daemon.Jails(ctx); err == nil {
		for _, j := range jails {
			for _, l := range j.Logs {
				out[filepath.Clean(l)] = append(out[filepath.Clean(l)], j.Name)
			}
		}
		p.readers, p.at = out, now()
	}
	return out
}

// logRoots are the places logs are read from, as entries, and the logs the running jails read.
// A place inside another is the other. A jail's log in the data directory, or in one holding it,
// is a place on its own, without the directory around it.
func (s *Server) logRoots(ctx context.Context) ([]LogEntry, map[string][]string) {
	readers := s.readers(ctx)
	data, err := filepath.Abs(s.Logs.Data)
	if err != nil || s.Logs.Data == "" {
		data = "/"
	}
	var roots []LogEntry
	add := func(p, source string) {
		p = filepath.Clean(p)
		if !filepath.IsAbs(p) || slices.ContainsFunc(roots, func(r LogEntry) bool { return within(p, r.Path) }) {
			return
		}
		info, err := os.Stat(p)
		if err != nil || !(info.IsDir() || info.Mode().IsRegular()) {
			return
		}
		roots = slices.DeleteFunc(roots, func(r LogEntry) bool { return within(r.Path, p) })
		roots = append(roots, entryOf(p, p, info, readers, source))
	}
	for _, m := range s.Logs.Mounts {
		if !within(data, m) {
			add(m, "mount")
		}
	}
	for l := range readers {
		if d := filepath.Dir(l); !within(data, d) {
			add(d, "jail")
		} else {
			add(l, "jail")
		}
	}
	slices.SortFunc(roots, func(a, b LogEntry) int { return strings.Compare(a.Path, b.Path) })
	return roots, readers
}

func entryOf(name, p string, info fs.FileInfo, readers map[string][]string, source string) LogEntry {
	e := LogEntry{Name: name, Path: p, Dir: info.IsDir(), Modified: info.ModTime().Unix(), Jails: readers[p], Source: source}
	if !e.Dir {
		e.Size = info.Size()
	}
	if e.Jails == nil {
		e.Jails = []string{}
	}
	return e
}

// inLogs opens the place p is in, and says where p is inside it. What is opened through an
// os.Root stays inside it: a link in a log directory to the session key is not followed.
func (s *Server) inLogs(ctx context.Context, p string) (*os.Root, string, map[string][]string, error) {
	if !filepath.IsAbs(p) {
		return nil, "", nil, invalid("%q is not an absolute path", p)
	}
	p = filepath.Clean(p)
	roots, readers := s.logRoots(ctx)
	for _, r := range roots {
		if !within(p, r.Path) {
			continue
		}
		dir, rel := r.Path, "."
		if !r.Dir {
			dir, rel = filepath.Dir(r.Path), filepath.Base(r.Path)
		} else if p != r.Path {
			rel, _ = filepath.Rel(r.Path, p)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return nil, "", nil, fmt.Errorf("%w: %s cannot be read here: %v", ErrNotFound, p, errors.Unwrap(err))
		}
		return root, rel, readers, nil
	}
	places := make([]string, 0, len(roots))
	for _, r := range roots {
		places = append(places, r.Path)
	}
	list := "there are none"
	if len(places) > 0 {
		list = "they are " + strings.Join(places, ", ")
	}
	return nil, "", nil, fmt.Errorf("%w: %s is not among the logs. The engine reads logs from what is mounted into it read-only and from where the running jails read theirs, and %s", ErrNotFound, p, list)
}

// logEntriesMax is how many entries of one directory are listed.
const logEntriesMax = 2000

// logDir is the entry at p, and what is in it when it is a directory: directories first, then
// files, each by name. Only directories and files: a socket or a device in a log directory is
// nothing to read. more says there were more than logEntriesMax.
func (s *Server) logDir(ctx context.Context, p string) (LogEntry, []LogEntry, bool, error) {
	root, rel, readers, err := s.inLogs(ctx, p)
	if err != nil {
		return LogEntry{}, nil, false, err
	}
	defer root.Close()
	p = filepath.Clean(p)
	info, err := root.Stat(rel)
	if err != nil {
		return LogEntry{}, nil, false, fmt.Errorf("%w: there is no %s", ErrNotFound, p)
	}
	entry := entryOf(filepath.Base(p), p, info, readers, "")
	if !info.IsDir() {
		return entry, []LogEntry{}, false, nil
	}
	d, err := root.Open(rel)
	if err != nil {
		return LogEntry{}, nil, false, fmt.Errorf("%w: %s cannot be read here: %v", ErrNotFound, p, errors.Unwrap(err))
	}
	defer d.Close()
	names, err := d.ReadDir(-1)
	if err != nil && len(names) == 0 {
		return LogEntry{}, nil, false, fmt.Errorf("%w: %s cannot be read here: %v", ErrNotFound, p, errors.Unwrap(err))
	}
	entries := []LogEntry{}
	for _, n := range names {
		// Stat through the root follows a link only while it stays inside.
		info, err := root.Stat(filepath.Join(rel, n.Name()))
		if err != nil || !(info.IsDir() || info.Mode().IsRegular()) {
			continue
		}
		entries = append(entries, entryOf(n.Name(), filepath.Join(p, n.Name()), info, readers, ""))
	}
	slices.SortFunc(entries, func(a, b LogEntry) int {
		if a.Dir != b.Dir {
			if a.Dir {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	more := len(entries) > logEntriesMax
	if more {
		entries = entries[:logEntriesMax]
	}
	return entry, entries, more, nil
}

// openLog opens a file among the logs to read.
func (s *Server) openLog(ctx context.Context, p string) (*os.File, error) {
	root, rel, _, err := s.inLogs(ctx, p)
	if err != nil {
		// Not found among the logs is a path the tester will not read, which is a request it
		// cannot carry out: the same words, as invalid.
		if errors.Is(err, ErrNotFound) {
			return nil, invalid("%s", strings.TrimPrefix(err.Error(), ErrNotFound.Error()+": "))
		}
		return nil, err
	}
	defer root.Close()
	info, err := root.Stat(rel)
	if err != nil {
		return nil, invalid("%s cannot be read here: %v", p, errors.Unwrap(err))
	}
	if !info.Mode().IsRegular() {
		return nil, invalid("%s is not a file", p)
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, invalid("%s cannot be read here: %v", p, errors.Unwrap(err))
	}
	return f, nil
}

// copyTail copies the last n lines of a log, so a tester run over a log of gigabytes reads what
// it was asked to. A log ending .gz, as a rotated one does, is read through.
func copyTail(f *os.File, to string, n int) error {
	var b []byte
	var err error
	if strings.HasSuffix(f.Name(), ".gz") {
		b, err = tailGzip(f, n)
	} else {
		b, err = tailPlain(f, n)
	}
	if err != nil {
		return err
	}
	all := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return os.WriteFile(to, append(bytes.Join(all, []byte("\n")), '\n'), 0o644)
}

func tailPlain(f *os.File, n int) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// Enough for n lines of a busy access log; a log of longer lines yields fewer.
	window := int64(n) * 1024
	off := max(info.Size()-window, 0)
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, window))
	if err != nil {
		return nil, err
	}
	// Started mid-line: the first is a piece of one.
	if off > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return b, nil
}

// gzipMax is how much of a compressed log is read for its end, uncompressed: one has to be read
// from its start.
const gzipMax = 512 << 20

func tailGzip(f *os.File, n int) ([]byte, error) {
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, invalid("%s ends .gz and is not gzip: %v", f.Name(), err)
	}
	defer z.Close()
	r := bufio.NewReader(io.LimitReader(z, gzipMax))
	ring := make([][]byte, n)
	seen := 0
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			ring[seen%n] = line
			seen++
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, invalid("%s cannot be read through: %v", f.Name(), err)
		}
	}
	var b bytes.Buffer
	for i := max(seen-n, 0); i < seen; i++ {
		b.Write(ring[i%n])
	}
	return b.Bytes(), nil
}

func (s *Server) logRootList(w http.ResponseWriter, r *http.Request) {
	roots, _ := s.logRoots(r.Context())
	reply.JSON(w, http.StatusOK, map[string]any{"roots": roots})
}

func (s *Server) logEntry(w http.ResponseWriter, r *http.Request) {
	entry, entries, more, err := s.logDir(r.Context(), "/"+r.PathValue("path"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply.JSON(w, http.StatusOK, map[string]any{"entry": entry, "entries": entries, "more": more})
}
