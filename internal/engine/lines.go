package engine

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

// Line is one line of fail2ban's log.
type Line struct {
	Seq  int64  `json:"seq"`
	Text string `json:"text"`
}

// Lines is fail2ban's log: the latest lines in memory for the interface, every line appended to
// a file in the data directory, and passed on to the container's own output.
//
// Sequence numbers start over with the process; Epoch says which run they belong to, so a reader
// holding a number from before a restart starts over too.
type Lines struct {
	mu    sync.Mutex
	ring  []Line
	start int
	next  int64
	epoch string

	path string
	file *os.File
	size int64
	out  io.Writer
}

const (
	// ringSize is how many lines the interface can scroll back through.
	ringSize = 5000
	// fileMax is where the file is rotated, once, to .1.
	fileMax = 10 << 20
	// lineMax cuts a runaway line rather than holding it whole.
	lineMax = 8 << 10
)

// OpenLines starts from the end of the file at path, if there is one.
func OpenLines(path string, out io.Writer) (*Lines, error) {
	l := &Lines{
		ring:  make([]Line, 0, ringSize),
		epoch: strconv.FormatInt(time.Now().UnixNano(), 36),
		path:  path,
		out:   out,
	}
	if path == "" {
		return l, nil
	}
	if b, err := tail(path, 1000); err == nil {
		for _, s := range bytes.Split(b, []byte("\n")) {
			if len(s) > 0 {
				l.push(string(s))
			}
		}
	}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Lines) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("opening fail2ban's log: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.file, l.size = f, info.Size()
	return nil
}

// Add records one line.
func (l *Lines) Add(text string) {
	if len(text) > lineMax {
		text = text[:lineMax] + "…"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.push(text)
	if l.out != nil {
		fmt.Fprintln(l.out, text)
	}
	if l.file == nil {
		return
	}
	n, err := fmt.Fprintln(l.file, text)
	l.size += int64(n)
	if err == nil && l.size > fileMax {
		l.file.Close()
		l.file = nil
		os.Rename(l.path, l.path+".1")
		l.open()
	}
}

// Note records something the engine itself has to say, dated as fail2ban dates its own lines.
func (l *Lines) Note(level, msg string) {
	l.Add(time.Now().UTC().Format("2006-01-02 15:04:05,000") + " f2b.engine              [" + strconv.Itoa(os.Getpid()) + "]: " + level + " " + msg)
}

func (l *Lines) push(text string) {
	line := Line{Seq: l.next, Text: text}
	l.next++
	if len(l.ring) < ringSize {
		l.ring = append(l.ring, line)
		return
	}
	l.ring[l.start] = line
	l.start = (l.start + 1) % ringSize
}

// Since is up to limit lines after seq, the latest ones when seq is negative, and the number to
// ask after next time.
func (l *Lines) Since(after int64, limit int) (lines []Line, epoch string, last int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines = []Line{}
	n := len(l.ring)
	for i := range n {
		line := l.ring[(l.start+i)%n]
		if after >= 0 && line.Seq <= after {
			continue
		}
		lines = append(lines, line)
	}
	if after < 0 && len(lines) > limit {
		lines = lines[len(lines)-limit:]
	} else if len(lines) > limit {
		lines = lines[:limit]
	}
	last = l.next - 1
	if len(lines) > 0 {
		last = lines[len(lines)-1].Seq
	}
	return lines, l.epoch, last
}

// Feed reads r line by line into the log until it ends.
func (l *Lines) Feed(r io.Reader) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		l.Add(s.Text())
	}
}

// Epoch names this run of the engine, which sequence numbers count from.
func (l *Lines) Epoch() string { return l.epoch }

func (l *Lines) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// tail is roughly the last n lines of a file, read from its end.
func tail(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const window = 256 << 10
	offset := max(info.Size()-window, 0)
	buf := make([]byte, info.Size()-offset)
	if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return nil, err
	}
	if offset > 0 {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return bytes.Join(lines, []byte("\n")), nil
}
