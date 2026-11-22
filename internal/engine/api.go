package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"f2b/internal/app"
	"f2b/internal/f2bsock"
	"f2b/internal/history"
	"f2b/internal/reply"
)

// Server is the engine's API, on a socket only the web reaches. It trusts whoever connects:
// reaching the socket takes the data directory, which is already everything.
type Server struct {
	Files    *Files
	Composer *Composer
	Daemon   Daemon
	Tools    Tools
	History  *history.DB
	Lines    *Lines
	Log      *slog.Logger
	// Live is the configuration fail2ban runs with; Scratch is where a change is tried first.
	Live    string
	Scratch string
	Now     func() time.Time

	// mu holds one change to the configuration at a time, from the first check to the reload.
	mu  sync.Mutex
	mux *http.ServeMux
}

// Handler wires the routes.
func (s *Server) Handler() http.Handler {
	if s.Now == nil {
		s.Now = time.Now
	}
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", s.healthz)
	m.HandleFunc("GET /api/engine", s.engine)
	m.HandleFunc("POST /api/engine/restart", s.restart)
	m.HandleFunc("GET /api/jails", s.jails)
	m.HandleFunc("GET /api/bans", s.bans)
	m.HandleFunc("POST /api/bans", s.ban)
	m.HandleFunc("DELETE /api/bans/{ip}", s.unban)
	m.HandleFunc("GET /api/history", s.history)
	m.HandleFunc("GET /api/stats", s.stats)
	m.HandleFunc("GET /api/files", s.listFiles)
	m.HandleFunc("GET /api/files/{kind}/{name}", s.getFile)
	m.HandleFunc("PUT /api/files/{kind}/{name}", s.putFile)
	m.HandleFunc("DELETE /api/files/{kind}/{name}", s.deleteFile)
	m.HandleFunc("GET /api/files/{kind}/{name}/references", s.references)
	m.HandleFunc("POST /api/files/{kind}/{name}/rename", s.rename)
	m.HandleFunc("POST /api/check", s.check)
	m.HandleFunc("GET /api/stock", s.stockList)
	m.HandleFunc("GET /api/stock/{path...}", s.stockFile)
	m.HandleFunc("POST /api/regex", s.regex)
	m.HandleFunc("GET /api/log", s.log)
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		reply.Refuse(w, http.StatusNotFound, reply.CodeNotFound, "There is no such endpoint. docs/api.md lists them all.")
	})
	s.mux = m
	return m
}

// PrepareLive composes the configuration fail2ban runs with from what is on disk now. The
// supervisor calls it before every start.
func (s *Server) PrepareLive() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Composer.Compose(s.Live)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	reply.JSON(w, http.StatusOK, map[string]any{"ok": true, "fail2ban": s.Daemon.State().State})
}

func (s *Server) engine(w http.ResponseWriter, r *http.Request) {
	reply.JSON(w, http.StatusOK, map[string]any{"version": app.Version, "fail2ban": s.Daemon.State()})
}

func (s *Server) restart(w http.ResponseWriter, r *http.Request) {
	s.Log.Info("fail2ban restart asked for")
	s.Lines.Note("NOTICE", "restarting fail2ban, as asked")
	s.Daemon.Restart()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) jails(w http.ResponseWriter, r *http.Request) {
	jails, err := s.Daemon.Jails(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The file a jail is defined in: the first that names it, among jail files and then settings.
	files, _ := s.Files.List()
	where := map[string]*FileRef{}
	for _, k := range []Kind{Jails, Settings} {
		for _, f := range files {
			if f.Kind != k {
				continue
			}
			for _, sec := range f.Sections {
				if where[sec] == nil {
					where[sec] = &FileRef{Kind: f.Kind, Name: f.Name}
				}
			}
		}
	}
	for i := range jails {
		j := &jails[i]
		j.File, j.Filter = where[j.Name], j.Name
		if j.File != nil {
			if _, content, err := s.Files.Read(j.File.Kind, j.File.Name); err == nil {
				j.Filter = FilterOf(content, j.Name)
			}
		}
	}
	reply.JSON(w, http.StatusOK, map[string]any{"jails": jails})
}

// CurrentBan is a ban in force: fail2ban's word that it is, with the database's of when it
// began and how long it lasts, where the database has them.
type CurrentBan struct {
	history.Ban
	// Until is when it ends, in Unix seconds, or 0 for never or not known.
	Until int64 `json:"until"`
}

func (s *Server) bans(w http.ResponseWriter, r *http.Request) {
	banned, err := s.Daemon.Banned(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	latest, err := s.History.Latest(r.Context())
	if err != nil {
		s.Log.Warn("the bans in force could not be dated", "error", err.Error())
		latest = map[history.Key]history.Ban{}
	}
	out := []CurrentBan{}
	for jail, ips := range banned {
		for _, ip := range ips {
			b := CurrentBan{Ban: history.Ban{Jail: jail, IP: ip, Matches: []string{}}}
			if known, ok := latest[history.Key{Jail: jail, IP: ip}]; ok {
				b.Ban = known
				if known.Duration > 0 {
					b.Until = known.At + known.Duration
				}
			}
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At != out[j].At {
			return out[i].At > out[j].At
		}
		return out[i].IP < out[j].IP
	})
	reply.JSON(w, http.StatusOK, map[string]any{"bans": out})
}

func parseAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if a, err := netip.ParseAddr(raw); err == nil {
		return a.Unmap().String(), nil
	}
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked().String(), nil
	}
	return "", invalid("%q is not an address or a range of them", raw)
}

func (s *Server) ban(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Jail string `json:"jail"`
		IP   string `json:"ip"`
	}
	if !reply.Decode(w, r, &req) {
		return
	}
	ip, err := parseAddress(req.IP)
	if err == nil && req.Jail == "" {
		err = invalid("a ban is in a jail; name one")
	}
	if err == nil {
		err = s.Daemon.Ban(r.Context(), req.Jail, ip)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Log.Info("banned by hand", "jail", req.Jail, "ip", ip)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) unban(w http.ResponseWriter, r *http.Request) {
	ip, err := parseAddress(r.PathValue("ip"))
	jail := r.URL.Query().Get("jail")
	if err == nil {
		err = s.Daemon.Unban(r.Context(), jail, ip)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Log.Info("unbanned by hand", "jail", jail, "ip", ip)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	bans, next, err := s.History.List(r.Context(), history.Query{
		Jail: q.Get("jail"), IP: strings.TrimSpace(q.Get("ip")), Before: before, Limit: limit,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply.JSON(w, http.StatusOK, map[string]any{"bans": bans, "next": next})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days < 1 || days > 366 {
		days = 30
	}
	st, err := s.History.Stats(r.Context(), days, s.Now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply.JSON(w, http.StatusOK, st)
}

func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	files, err := s.Files.List()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply.JSON(w, http.StatusOK, map[string]any{"files": files})
}

func (s *Server) target(r *http.Request) (Kind, string, error) {
	k, err := ParseKind(r.PathValue("kind"))
	if err != nil {
		return "", "", err
	}
	name := r.PathValue("name")
	return k, name, CheckName(k, name)
}

func (s *Server) getFile(w http.ResponseWriter, r *http.Request) {
	k, name, err := s.target(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, content, err := s.Files.Read(k, name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply.JSON(w, http.StatusOK, map[string]any{"file": f, "content": content})
}

// Applied is what a save, a delete or a rename did: the file as it now is, the other files it
// changed with it, and what the reload said.
type Applied struct {
	File   *File     `json:"file"`
	Also   []FileRef `json:"also"`
	Reload Result    `json:"reload"`
}

func (s *Server) putFile(w http.ResponseWriter, r *http.Request) {
	k, name, err := s.target(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Content string `json:"content"`
		// Version is the one the change was made against, or "" for a new file.
		Version string `json:"version"`
	}
	if !reply.Decode(w, r, &req) {
		return
	}
	if len(req.Content) > ContentMax {
		s.fail(w, r, invalid("that file is over %d KB", ContentMax>>10))
		return
	}
	out, err := s.Apply(r.Context(), Change{Kind: k, Name: name, Content: &req.Content}, req.Version)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply.JSON(w, http.StatusOK, out)
}

func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request) {
	k, name, err := s.target(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Apply(r.Context(), Change{Kind: k, Name: name}, r.URL.Query().Get("version"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply.JSON(w, http.StatusOK, out)
}

// referencesTo is every jail file, jail.local among them, that names this filter or action, and
// how it would read with the name changed.
func (s *Server) referencesTo(k Kind, name, to string) ([]planned, error) {
	keys := refKeys[k]
	if keys == nil {
		return nil, nil
	}
	files, err := s.Files.List()
	if err != nil {
		return nil, err
	}
	var out []planned
	for _, f := range files {
		if f.Kind != Jails && !(f.Kind == Settings && f.Name == "jail.local") {
			continue
		}
		_, content, err := s.Files.Read(f.Kind, f.Name)
		if err != nil {
			return nil, err
		}
		if Mentions(content, keys, bare(name)) == 0 {
			continue
		}
		rewritten := Rewrite(content, keys, bare(name), bare(to))
		out = append(out, planned{Change{Kind: f.Kind, Name: f.Name, Content: &rewritten}, f.Version})
	}
	return out, nil
}

func (s *Server) references(w http.ResponseWriter, r *http.Request) {
	k, name, err := s.target(r)
	if err == nil {
		_, _, err = s.Files.Read(k, name)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	refs, err := s.referencesTo(k, name, name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := []FileRef{}
	for _, p := range refs {
		out = append(out, FileRef{Kind: p.Kind, Name: p.Name})
	}
	reply.JSON(w, http.StatusOK, map[string]any{"files": out})
}

// rename moves a file to a new name, and with references, changes the jails that name it to name
// the new one: all checked as one change, so fail2ban never sees a jail naming what is gone.
func (s *Server) rename(w http.ResponseWriter, r *http.Request) {
	k, name, err := s.target(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		To         string `json:"to"`
		Version    string `json:"version"`
		References bool   `json:"references"`
	}
	if !reply.Decode(w, r, &req) {
		return
	}
	switch {
	case k == Settings:
		err = invalid("settings files are read by their names, and keep them")
	case req.To == name:
		err = invalid("that is the name it has")
	default:
		err = CheckName(k, req.To)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_, content, err := s.Files.Read(k, name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	plan := []planned{
		{Change{Kind: k, Name: req.To, Content: &content}, ""},
		{Change{Kind: k, Name: name}, req.Version},
	}
	if req.References {
		refs, err := s.referencesTo(k, name, req.To)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		plan = append(plan, refs...)
	}
	out, err := s.applyAll(r.Context(), plan)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Log.Info("file renamed", "kind", k, "from", name, "to", req.To, "references", len(out.Also))
	reply.JSON(w, http.StatusOK, out)
}

// rejected is fail2ban refusing a configuration, in its own words.
type rejected struct{ output string }

func (e *rejected) Error() string { return "fail2ban refused this configuration" }

// Apply checks a change against everything else, and only then writes it and reloads fail2ban.
// A refused change leaves the disk as it was.
func (s *Server) Apply(ctx context.Context, c Change, version string) (Applied, error) {
	return s.applyAll(ctx, []planned{{c, version}})
}

// planned is one change, and the version of the file it was made against: "" for a file that
// is not there yet.
type planned struct {
	Change
	Version string
}

// applyAll checks every change together, writes them, and reloads once: a rename, and the jails
// it names, are one change to fail2ban.
func (s *Server) applyAll(ctx context.Context, plan []planned) (Applied, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	changes := make([]Change, len(plan))
	for i, p := range plan {
		current, err := s.Files.Current(p.Kind, p.Name)
		if err != nil {
			return Applied{}, err
		}
		switch {
		case p.Content == nil && current == "":
			return Applied{}, fmt.Errorf("%w: there is no %s %s", ErrNotFound, singular(p.Kind), p.Name)
		case p.Version == "" && current != "":
			return Applied{}, fmt.Errorf("%w: there is already a %s %s", ErrConflict, singular(p.Kind), p.Name)
		case p.Version != current:
			return Applied{}, fmt.Errorf("%w: that file changed since it was opened; open %s again to see how", ErrConflict, p.Name)
		}
		changes[i] = p.Change
	}

	if err := s.Composer.Compose(s.Scratch, changes...); err != nil {
		return Applied{}, err
	}
	defer os.RemoveAll(s.Scratch)
	if res := s.Tools.Check(ctx, s.Scratch); !res.OK {
		return Applied{}, &rejected{output: res.Output}
	}

	// What is written goes before what is deleted, so a rename never leaves the name gone and
	// nothing in its place.
	out := Applied{Also: []FileRef{}}
	for _, c := range changes {
		if c.Content == nil {
			continue
		}
		if err := s.Files.Write(c.Kind, c.Name, *c.Content); err != nil {
			return Applied{}, err
		}
		f, _, err := s.Files.Read(c.Kind, c.Name)
		if err != nil {
			return Applied{}, err
		}
		if out.File == nil {
			out.File = &f
		} else {
			out.Also = append(out.Also, FileRef{Kind: f.Kind, Name: f.Name})
		}
		s.Log.Info("file saved", "kind", c.Kind, "name", c.Name, "version", f.Version)
	}
	for _, c := range changes {
		if c.Content != nil {
			continue
		}
		if err := s.Files.Delete(c.Kind, c.Name); err != nil {
			return Applied{}, err
		}
		s.Log.Info("file deleted", "kind", c.Kind, "name", c.Name)
	}
	what := changes[0].Name

	if err := s.Composer.Compose(s.Live); err != nil {
		return out, err
	}
	if s.Daemon.State().State != Running {
		s.Lines.Note("NOTICE", "starting fail2ban with the configuration just saved")
		s.Daemon.Restart()
		out.Reload = Result{OK: true, Output: "fail2ban was not running, so it is being started with this configuration. The log says how that goes."}
		return out, nil
	}
	out.Reload = s.Tools.Reload(ctx, s.Live)
	if !out.Reload.OK {
		s.Lines.Note("ERROR", "the reload after a change to "+what+" failed")
		s.Log.Warn("reload failed", "name", what)
		return out, nil
	}
	s.Lines.Note("NOTICE", "configuration reloaded after a change to "+what)
	// Only a jail or a setting says which actions a jail has.
	if !slices.ContainsFunc(changes, func(c Change) bool { return c.Kind == Jails || c.Kind == Settings }) {
		return out, nil
	}
	if jails := s.adrift(ctx); len(jails) > 0 {
		list := strings.Join(jails, ", ")
		s.Lines.Note("NOTICE", "restarting fail2ban: its reload left "+list+" without the actions configured")
		s.Log.Warn("reload left jails without their actions; restarting fail2ban", "jails", list)
		s.Daemon.Restart()
		out.Reload.Output += "\n\nThe reload left " + list + " without the actions configured, so fail2ban is restarting, which starts them. Its bans come back from its database."
	}
	return out, nil
}

// adrift names the running jails whose actions are not the ones the live configuration gives
// them. fail2ban 1.1's reload drops an action a jail gains under a new name, as changing its
// banaction does, and only a restart starts it.
func (s *Server) adrift(ctx context.Context) []string {
	want, err := s.Tools.Actions(ctx, s.Live)
	if err != nil {
		s.Log.Warn("the configured actions could not be read", "error", err)
		return nil
	}
	have, err := s.Daemon.Actions(ctx)
	if err != nil {
		s.Log.Warn("the running actions could not be read", "error", err)
		return nil
	}
	var out []string
	for jail, acts := range have {
		if !slices.Equal(slices.Sorted(slices.Values(acts)), slices.Sorted(slices.Values(want[jail]))) {
			out = append(out, jail)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind    string  `json:"kind"`
		Name    string  `json:"name"`
		Content *string `json:"content"`
	}
	if !reply.Decode(w, r, &req) {
		return
	}
	k, err := ParseKind(req.Kind)
	if err == nil {
		err = CheckName(k, req.Name)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	dir, err := os.MkdirTemp(filepath.Dir(s.Scratch), "check-")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer os.RemoveAll(dir)
	if err := s.Composer.Compose(dir, Change{Kind: k, Name: req.Name, Content: req.Content}); err != nil {
		s.fail(w, r, err)
		return
	}
	reply.JSON(w, http.StatusOK, s.Tools.Check(r.Context(), dir))
}

func (s *Server) stockList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Composer.StockList()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply.JSON(w, http.StatusOK, list)
}

func (s *Server) stockFile(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	content, err := s.Composer.StockFile(p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply.JSON(w, http.StatusOK, map[string]any{"path": p, "content": content})
}

// Regex limits: how many lines from the end of a log are tried, by default and at most.
const (
	regexLines    = 2000
	regexLinesMax = 20000
)

var filterArg = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]*(\[[^\]\r\n]*\])?$`)

// RegexSummary is fail2ban-regex's count of the lines it read.
type RegexSummary struct {
	Lines   int64 `json:"lines"`
	Ignored int64 `json:"ignored"`
	Matched int64 `json:"matched"`
	Missed  int64 `json:"missed"`
}

var summaryLine = regexp.MustCompile(`Lines: (\d+) lines, (\d+) ignored, (\d+) matched, (\d+) missed`)

func (s *Server) regex(w http.ResponseWriter, r *http.Request) {
	var req struct {
		// Filter is a filter's name, as a jail names it: "sshd", or "sshd[mode=aggressive]".
		Filter string `json:"filter"`
		// Content is the filter file as it is in the editor, unsaved, when it is one.
		File    string  `json:"file"`
		Content *string `json:"content"`
		// Log is a file to read the end of, or Text the lines themselves.
		Log   string `json:"log"`
		Text  string `json:"text"`
		Lines int    `json:"lines"`
	}
	if !reply.Decode(w, r, &req) {
		return
	}
	if !filterArg.MatchString(req.Filter) {
		s.fail(w, r, invalid("%q is not a filter's name, which is letters, digits, dots, dashes and underscores, and options in brackets", req.Filter))
		return
	}
	var changes []Change
	if req.Content != nil {
		if err := CheckName(Filters, req.File); err != nil {
			s.fail(w, r, err)
			return
		}
		changes = append(changes, Change{Kind: Filters, Name: req.File, Content: req.Content})
	}
	lines := req.Lines
	if lines <= 0 {
		lines = regexLines
	}
	lines = min(lines, regexLinesMax)

	dir, err := os.MkdirTemp(filepath.Dir(s.Scratch), "regex-")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer os.RemoveAll(dir)
	if err := s.Composer.Compose(filepath.Join(dir, "etc"), changes...); err != nil {
		s.fail(w, r, err)
		return
	}
	sample := filepath.Join(dir, "sample.log")
	switch {
	case req.Log != "" && req.Text != "":
		err = invalid("a log file or lines, not both")
	case req.Log != "":
		err = copyTail(req.Log, sample, lines)
	case req.Text != "":
		err = os.WriteFile(sample, []byte(pasted(req.Text)), 0o644)
	default:
		err = invalid("name a log file, or paste lines to try")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res := s.Tools.Regex(r.Context(), filepath.Join(dir, "etc"), sample, req.Filter)
	out := map[string]any{"ok": res.OK, "output": res.Output, "summary": nil}
	if m := summaryLine.FindStringSubmatch(res.Output); m != nil {
		n := func(i int) int64 { v, _ := strconv.ParseInt(m[i], 10, 64); return v }
		out["summary"] = RegexSummary{Lines: n(1), Ignored: n(2), Matched: n(3), Missed: n(4)}
	}
	reply.JSON(w, http.StatusOK, out)
}

// pasted is lines as fail2ban-regex will count them: it reads a file as it tails one, and a last
// line with no newline after it is a line still being written, which it leaves for later. One
// line pasted on its own is exactly that.
func pasted(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return text
}

// copyTail copies the last n lines of a log, so a tester run over a log of gigabytes reads what
// it was asked to.
func copyTail(from, to string, n int) error {
	if !filepath.IsAbs(from) {
		return invalid("%q is not an absolute path", from)
	}
	info, err := os.Stat(from)
	if err != nil {
		return invalid("%s cannot be read here: %v", from, errors.Unwrap(err))
	}
	if !info.Mode().IsRegular() {
		return invalid("%s is not a file", from)
	}
	f, err := os.Open(from)
	if err != nil {
		return invalid("%s cannot be read here: %v", from, errors.Unwrap(err))
	}
	defer f.Close()
	// Enough for n lines of a busy access log; a log of longer lines yields fewer.
	window := int64(n) * 1024
	off := max(info.Size()-window, 0)
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, window))
	if err != nil {
		return err
	}
	// Started mid-line: the first is a piece of one.
	if off > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	all := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return os.WriteFile(to, append(bytes.Join(all, []byte("\n")), '\n'), 0o644)
}

func (s *Server) log(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after := int64(-1)
	if v := q.Get("after"); v != "" {
		after, _ = strconv.ParseInt(v, 10, 64)
	}
	// A cursor from another run of the engine counts from the start of this one.
	if q.Get("epoch") != "" && q.Get("epoch") != s.Lines.Epoch() {
		after = -1
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > ringSize {
		limit = 1000
	}
	lines, epoch, last := s.Lines.Since(after, limit)
	reply.JSON(w, http.StatusOK, map[string]any{"epoch": epoch, "lines": lines, "last": last})
}

// fail maps an error onto a status and a code, in the one place that does.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var refused *f2bsock.Error
	var rej *rejected
	switch {
	case errors.As(err, &rej):
		reply.JSON(w, http.StatusUnprocessableEntity, reply.Refusal{
			Code: reply.CodeRejected, Message: "fail2ban refused this configuration, and nothing was saved.", Output: rej.output,
		})
	case errors.Is(err, ErrInvalid):
		reply.Refuse(w, http.StatusBadRequest, reply.CodeInvalid, sentence(err, ErrInvalid))
	case errors.Is(err, ErrNotFound):
		reply.Refuse(w, http.StatusNotFound, reply.CodeNotFound, sentence(err, ErrNotFound))
	case errors.Is(err, ErrConflict):
		reply.Refuse(w, http.StatusConflict, reply.CodeConflict, sentence(err, ErrConflict))
	case errors.Is(err, f2bsock.ErrUnreachable):
		reply.Refuse(w, http.StatusServiceUnavailable, reply.CodeFail2ban, "fail2ban is not answering: it is starting, or it stopped. The log says which.")
	case errors.As(err, &refused):
		reply.Refuse(w, http.StatusUnprocessableEntity, reply.CodeFail2ban, capitalize(refused.Message)+".")
	case errors.Is(err, context.Canceled):
	default:
		s.Log.Error("request failed with an error nothing here explains", "method", r.Method, "path", r.URL.Path, "error", err.Error())
		reply.Refuse(w, http.StatusInternalServerError, reply.CodeInternal, "Something went wrong in the engine. Its log says what.")
	}
}

// sentence is the error's text without its kind, written for whoever reads it.
func sentence(err, kind error) string {
	msg := strings.TrimPrefix(err.Error(), kind.Error()+": ")
	return capitalize(msg) + "."
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
