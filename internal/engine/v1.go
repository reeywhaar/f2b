package engine

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"f2b/internal/app"
	"f2b/internal/history"
	"f2b/internal/reply"
)

// /api/v1 is the API for scripts and agents: JSON:API 1.1, described by openapi.json. It is the
// same engine as /api, the interface's, in another shape; each of its routes says whether a
// read token may take it.

//go:embed openapi.json
var openAPI []byte

type v1Route struct {
	Method, Path string
	// Write is whether it changes anything: a read token is refused it.
	Write  bool
	handle http.HandlerFunc
}

func (s *Server) v1Routes() []v1Route {
	return []v1Route{
		{"GET", "/api/v1/engine", false, s.v1Engine},
		{"POST", "/api/v1/engine/restart", true, s.v1Restart},
		{"GET", "/api/v1/jails", false, s.v1Jails},
		{"GET", "/api/v1/jails/{name}", false, s.v1Jail},
		{"GET", "/api/v1/bans", false, s.v1Bans},
		{"POST", "/api/v1/bans", true, s.v1Ban},
		{"DELETE", "/api/v1/jails/{jail}/bans/{ip}", true, s.v1Unban},
		{"GET", "/api/v1/history", false, s.v1History},
		{"GET", "/api/v1/stats", false, s.v1Stats},
		{"GET", "/api/v1/files", false, s.v1Files},
		{"POST", "/api/v1/files", true, s.v1CreateFile},
		{"GET", "/api/v1/files/{kind}/{name}", false, s.v1File},
		{"PATCH", "/api/v1/files/{kind}/{name}", true, s.v1SaveFile},
		{"DELETE", "/api/v1/files/{kind}/{name}", true, s.v1DeleteFile},
		{"POST", "/api/v1/files/{kind}/{name}/rename", true, s.v1RenameFile},
		// Both change nothing: trying a filter or a file is inspecting it.
		{"POST", "/api/v1/config-checks", false, s.v1Check},
		{"POST", "/api/v1/regex-tests", false, s.v1Regex},
		{"GET", "/api/v1/log-files", false, s.v1LogFiles},
		{"GET", "/api/v1/log-files/{path...}", false, s.v1LogFile},
		{"GET", "/api/v1/stock", false, s.v1Stock},
		{"GET", "/api/v1/stock/{path...}", false, s.v1StockFile},
		{"GET", "/api/v1/log", false, s.v1Log},
	}
}

func (s *Server) handleV1(m *http.ServeMux) {
	for _, rt := range s.v1Routes() {
		m.HandleFunc(rt.Method+" "+rt.Path, s.v1(rt))
	}
	m.HandleFunc("GET /api/v1/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(openAPI)
	})
	m.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		refuseDoc(w, http.StatusNotFound, reply.CodeNotFound, "There is no such endpoint. /api/v1/openapi.json lists them all.", nil)
	})
}

func (s *Server) v1(rt v1Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch status, why := mediaRefusal(r); status {
		case http.StatusUnsupportedMediaType:
			refuseDoc(w, status, reply.CodeUnsupportedMediaType, why, nil)
			return
		case http.StatusNotAcceptable:
			refuseDoc(w, status, reply.CodeNotAcceptable, why, nil)
			return
		}
		if rt.Write && r.Header.Get(app.ScopeHeader) == app.ScopeRead {
			refuseDoc(w, http.StatusForbidden, reply.CodeForbidden, "This token can read, and this changes something. It takes a token that can read and write.", nil)
			return
		}
		rt.handle(w, r)
	}
}

// self is a link to a resource under /api/v1, each segment escaped: an address range's slash
// stays inside its segment.
func self(segments ...string) *links {
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return &links{Self: "/api/v1/" + strings.Join(segments, "/")}
}

// typed checks a request's resource type, which JSON:API answers with 409 when it is not this
// endpoint's.
func typed(w http.ResponseWriter, got, want string) bool {
	if got != want {
		refuseDoc(w, http.StatusConflict, reply.CodeConflict, "This endpoint takes resources of type "+want+".", nil)
		return false
	}
	return true
}

// ifMatch is the version a write names in If-Match, or false having said why there is none.
func ifMatch(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := strings.TrimPrefix(strings.TrimSpace(r.Header.Get("If-Match")), "W/")
	v = strings.Trim(v, `"`)
	if v == "" {
		refuseDoc(w, http.StatusPreconditionRequired, reply.CodePreconditionRequired, "Send If-Match with the version the change was made against: the file's ETag.", nil)
		return "", false
	}
	return v, true
}

func pageSize(raw string, fallback, most int) int {
	n, _ := strconv.Atoi(raw)
	if n <= 0 {
		return fallback
	}
	return min(n, most)
}

// The engine.

func (s *Server) v1Engine(w http.ResponseWriter, r *http.Request) {
	writeDoc(w, http.StatusOK, document{Data: resource{
		Type: "engine", ID: "engine",
		Attributes: map[string]any{"version": app.Version, "fail2ban": s.Daemon.State()},
		Links:      self("engine"),
	}})
}

func (s *Server) v1Restart(w http.ResponseWriter, r *http.Request) {
	s.restartAsked()
	writeDoc(w, http.StatusAccepted, document{Meta: map[string]any{
		"message": "fail2ban is restarting. GET /api/v1/engine says when it is running again.",
	}})
}

// Jails.

type jailAttributes struct {
	FailedNow   int64    `json:"failedNow"`
	FailedTotal int64    `json:"failedTotal"`
	BannedNow   int64    `json:"bannedNow"`
	BannedTotal int64    `json:"bannedTotal"`
	Logs        []string `json:"logs"`
	FindTime    int64    `json:"findTime"`
	BanTime     int64    `json:"banTime"`
	MaxRetry    int64    `json:"maxRetry"`
	Filter      string   `json:"filter"`
}

func jailResource(j Jail) resource {
	var file *identifier
	if j.File != nil {
		file = &identifier{Type: "files", ID: fileID(j.File.Kind, j.File.Name)}
	}
	if j.Logs == nil {
		j.Logs = []string{}
	}
	return resource{
		Type: "jails", ID: j.Name,
		Attributes: jailAttributes{
			FailedNow: j.FailedNow, FailedTotal: j.FailedTotal, BannedNow: j.BannedNow, BannedTotal: j.BannedTotal,
			Logs: j.Logs, FindTime: j.FindTime, BanTime: j.BanTime, MaxRetry: j.MaxRetry, Filter: j.Filter,
		},
		Relationships: map[string]relationship{"file": {Data: file}},
		Links:         self("jails", j.Name),
	}
}

func (s *Server) v1Jails(w http.ResponseWriter, r *http.Request) {
	jails, err := s.jailList(r.Context())
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	data := make([]resource, 0, len(jails))
	for _, j := range jails {
		data = append(data, jailResource(j))
	}
	writeDoc(w, http.StatusOK, document{Data: data, Links: &links{Self: "/api/v1/jails"}})
}

func (s *Server) v1Jail(w http.ResponseWriter, r *http.Request) {
	jails, err := s.jailList(r.Context())
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	name := r.PathValue("name")
	for _, j := range jails {
		if j.Name == name {
			writeDoc(w, http.StatusOK, document{Data: jailResource(j)})
			return
		}
	}
	refuseDoc(w, http.StatusNotFound, reply.CodeNotFound, "No jail named "+name+" is running.", nil)
}

// Bans in force, and the history.

type banAttributes struct {
	IP       string   `json:"ip"`
	At       int64    `json:"at"`
	Duration int64    `json:"duration"`
	Until    *int64   `json:"until,omitempty"`
	Count    int64    `json:"count"`
	Failures int64    `json:"failures"`
	Matches  []string `json:"matches"`
}

func jailOf(name string) map[string]relationship {
	return map[string]relationship{"jail": {Data: &identifier{Type: "jails", ID: name}}}
}

func banResource(b CurrentBan) resource {
	return resource{
		Type: "bans", ID: b.Jail + "/" + b.IP,
		Attributes: banAttributes{
			IP: b.IP, At: b.At, Duration: b.Duration, Until: &b.Until, Count: b.Count, Failures: b.Failures, Matches: b.Matches,
		},
		Relationships: jailOf(b.Jail),
		Links:         self("jails", b.Jail, "bans", b.IP),
	}
}

func (s *Server) v1Bans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.currentBans(r.Context())
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	q := r.URL.Query()
	jail, ip := q.Get("filter[jail]"), strings.TrimSpace(q.Get("filter[ip]"))
	data := []resource{}
	for _, b := range bans {
		if (jail == "" || b.Jail == jail) && (ip == "" || b.IP == ip) {
			data = append(data, banResource(b))
		}
	}
	writeDoc(w, http.StatusOK, document{Data: data, Links: &links{Self: r.URL.RequestURI()}})
}

func (s *Server) v1Ban(w http.ResponseWriter, r *http.Request) {
	var req in[struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		Attributes struct {
			IP string `json:"ip"`
		} `json:"attributes"`
		Relationships struct {
			Jail relationship `json:"jail"`
		} `json:"relationships"`
	}]
	if !decodeDoc(w, r, &req) || !typed(w, req.Data.Type, "bans") {
		return
	}
	if req.Data.ID != "" {
		refuseDoc(w, http.StatusForbidden, reply.CodeForbidden, "A ban's id is its jail and its address; send no id.", nil)
		return
	}
	jail := ""
	if d := req.Data.Relationships.Jail.Data; d != nil && d.Type == "jails" {
		jail = d.ID
	}
	ip, err := s.banByHand(r.Context(), jail, req.Data.Attributes.IP)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	// As fail2ban now has it, which the database dates once its observer has written the ban.
	made := CurrentBan{Ban: history.Ban{Jail: jail, IP: ip, At: time.Now().Unix(), Matches: []string{}}}
	if bans, err := s.currentBans(r.Context()); err == nil {
		for _, b := range bans {
			if b.Jail == jail && b.IP == ip {
				made = b
			}
		}
	}
	res := banResource(made)
	w.Header().Set("Location", res.Links.Self)
	writeDoc(w, http.StatusCreated, document{Data: res})
}

func (s *Server) v1Unban(w http.ResponseWriter, r *http.Request) {
	if err := s.unbanByHand(r.Context(), r.PathValue("jail"), r.PathValue("ip")); err != nil {
		s.failDoc(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) v1History(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("page[before]"), 10, 64)
	size := pageSize(q.Get("page[size]"), 50, 500)
	bans, next, err := s.History.List(r.Context(), history.Query{
		Jail: q.Get("filter[jail]"), IP: strings.TrimSpace(q.Get("filter[ip]")), Before: before, Limit: size,
	})
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	data := make([]resource, 0, len(bans))
	for _, b := range bans {
		data = append(data, resource{
			Type: "history-bans", ID: strconv.FormatInt(b.ID, 10),
			Attributes: banAttributes{
				IP: b.IP, At: b.At, Duration: b.Duration, Count: b.Count, Failures: b.Failures, Matches: b.Matches,
			},
			Relationships: jailOf(b.Jail),
		})
	}
	l := &links{Self: r.URL.RequestURI()}
	if next != 0 {
		nq := url.Values{}
		for _, k := range []string{"filter[jail]", "filter[ip]"} {
			if v := q.Get(k); v != "" {
				nq.Set(k, v)
			}
		}
		nq.Set("page[before]", strconv.FormatInt(next, 10))
		nq.Set("page[size]", strconv.Itoa(size))
		l.Next = "/api/v1/history?" + nq.Encode()
	}
	writeDoc(w, http.StatusOK, document{Data: data, Links: l})
}

func (s *Server) v1Stats(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("filter[days]"))
	if days < 1 || days > 366 {
		days = 30
	}
	st, err := s.History.Stats(r.Context(), days, s.Now())
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	writeDoc(w, http.StatusOK, document{Data: resource{Type: "stats", ID: "stats", Attributes: st}, Links: &links{Self: r.URL.RequestURI()}})
}

// Files.

func fileID(k Kind, name string) string { return string(k) + "/" + name }

// fileAttributes is a file, and its content where one file is asked for.
type fileAttributes struct {
	File
	Content *string `json:"content,omitempty"`
}

func fileResource(f File, content *string) resource {
	return resource{
		Type: "files", ID: fileID(f.Kind, f.Name),
		Attributes: fileAttributes{File: f, Content: content},
		Links:      self("files", string(f.Kind), f.Name),
	}
}

// appliedMeta is what a write did besides: the other files it changed, and what the reload said.
func appliedMeta(out Applied) map[string]any {
	return map[string]any{"also": out.Also, "reload": out.Reload}
}

func (s *Server) v1Files(w http.ResponseWriter, r *http.Request) {
	var only Kind
	if raw := r.URL.Query().Get("filter[kind]"); raw != "" {
		k, err := ParseKind(raw)
		if err != nil {
			s.failDoc(w, r, err)
			return
		}
		only = k
	}
	files, err := s.Files.List()
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	data := []resource{}
	for _, f := range files {
		if only == "" || f.Kind == only {
			data = append(data, fileResource(f, nil))
		}
	}
	writeDoc(w, http.StatusOK, document{Data: data, Links: &links{Self: r.URL.RequestURI()}})
}

func (s *Server) v1File(w http.ResponseWriter, r *http.Request) {
	k, name, err := s.target(r)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	f, content, err := s.Files.Read(k, name)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+f.Version+`"`)
	writeDoc(w, http.StatusOK, document{Data: fileResource(f, &content)})
}

func (s *Server) v1CreateFile(w http.ResponseWriter, r *http.Request) {
	var req in[struct {
		Type       string `json:"type"`
		Attributes struct {
			Kind    string `json:"kind"`
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"attributes"`
	}]
	if !decodeDoc(w, r, &req) || !typed(w, req.Data.Type, "files") {
		return
	}
	a := req.Data.Attributes
	k, err := ParseKind(a.Kind)
	if err == nil {
		err = CheckName(k, a.Name)
	}
	if err == nil && len(a.Content) > ContentMax {
		err = invalid("that file is over %d KB", ContentMax>>10)
	}
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	out, err := s.Apply(r.Context(), Change{Kind: k, Name: a.Name, Content: &a.Content}, "")
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	res := fileResource(*out.File, &a.Content)
	w.Header().Set("Location", res.Links.Self)
	w.Header().Set("ETag", `"`+out.File.Version+`"`)
	writeDoc(w, http.StatusCreated, document{Data: res, Meta: appliedMeta(out)})
}

func (s *Server) v1SaveFile(w http.ResponseWriter, r *http.Request) {
	k, name, err := s.target(r)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	ver, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var req in[struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		Attributes struct {
			Content *string `json:"content"`
		} `json:"attributes"`
	}]
	if !decodeDoc(w, r, &req) || !typed(w, req.Data.Type, "files") {
		return
	}
	if req.Data.ID != fileID(k, name) {
		refuseDoc(w, http.StatusConflict, reply.CodeConflict, "The resource's id is "+fileID(k, name)+", as its address says.", nil)
		return
	}
	content := req.Data.Attributes.Content
	switch {
	case content == nil:
		err = invalid("send the file's whole content, as attributes.content")
	case len(*content) > ContentMax:
		err = invalid("that file is over %d KB", ContentMax>>10)
	}
	if err == nil {
		// A write against a version is a write to a file that is there.
		if current, cerr := s.Files.Current(k, name); cerr != nil {
			err = cerr
		} else if current == "" {
			err = fmt.Errorf("%w: there is no %s %s", ErrNotFound, singular(k), name)
		}
	}
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	out, err := s.Apply(r.Context(), Change{Kind: k, Name: name, Content: content}, ver)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+out.File.Version+`"`)
	writeDoc(w, http.StatusOK, document{Data: fileResource(*out.File, content), Meta: appliedMeta(out)})
}

func (s *Server) v1DeleteFile(w http.ResponseWriter, r *http.Request) {
	k, name, err := s.target(r)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	ver, ok := ifMatch(w, r)
	if !ok {
		return
	}
	out, err := s.Apply(r.Context(), Change{Kind: k, Name: name}, ver)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	writeDoc(w, http.StatusOK, document{Meta: appliedMeta(out)})
}

func (s *Server) v1RenameFile(w http.ResponseWriter, r *http.Request) {
	k, name, err := s.target(r)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	ver, ok := ifMatch(w, r)
	if !ok {
		return
	}
	// An action rather than a resource: what it takes is meta, as JSON:API has it.
	var req struct {
		JSONAPI *jsonapiObject `json:"jsonapi"`
		Meta    struct {
			To         string `json:"to"`
			References bool   `json:"references"`
		} `json:"meta"`
	}
	if !decodeDoc(w, r, &req) {
		return
	}
	out, err := s.renameFile(r.Context(), k, name, req.Meta.To, ver, req.Meta.References)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	_, content, err := s.Files.Read(k, req.Meta.To)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	res := fileResource(*out.File, &content)
	w.Header().Set("Location", res.Links.Self)
	writeDoc(w, http.StatusOK, document{Data: res, Meta: appliedMeta(out)})
}

// Trying a file or a filter, which saves nothing: a result has no address to go back to, and its
// id is a digest of what was tried.

func (s *Server) v1Check(w http.ResponseWriter, r *http.Request) {
	var req in[struct {
		Type       string `json:"type"`
		Attributes struct {
			Kind    string  `json:"kind"`
			Name    string  `json:"name"`
			Content *string `json:"content"`
		} `json:"attributes"`
	}]
	if !decodeDoc(w, r, &req) || !typed(w, req.Data.Type, "config-checks") {
		return
	}
	a := req.Data.Attributes
	res, err := s.checkChange(r.Context(), a.Kind, a.Name, a.Content)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	tried, _ := json.Marshal(a)
	writeDoc(w, http.StatusOK, document{Data: resource{
		Type: "config-checks", ID: VersionOf(string(tried)),
		Attributes: map[string]any{"kind": a.Kind, "name": a.Name, "ok": res.OK, "output": res.Output},
	}})
}

func (s *Server) v1Regex(w http.ResponseWriter, r *http.Request) {
	var req in[struct {
		Type       string       `json:"type"`
		Attributes RegexRequest `json:"attributes"`
	}]
	if !decodeDoc(w, r, &req) || !typed(w, req.Data.Type, "regex-tests") {
		return
	}
	res, err := s.runRegex(r.Context(), req.Data.Attributes)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	tried, _ := json.Marshal(req.Data.Attributes)
	writeDoc(w, http.StatusOK, document{Data: resource{
		Type: "regex-tests", ID: VersionOf(string(tried)),
		Attributes: map[string]any{"filter": req.Data.Attributes.Filter, "ok": res.OK, "output": res.Output, "summary": res.Summary},
	}})
}

// fail2ban's own files.

func (s *Server) v1Stock(w http.ResponseWriter, r *http.Request) {
	list, err := s.Composer.StockList()
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	data := []resource{}
	add := func(dir, group string, names []string) {
		for _, n := range names {
			p := n
			if dir != "" {
				p = dir + "/" + n
			}
			data = append(data, resource{
				Type: "stock-files", ID: p,
				Attributes: map[string]any{"path": p, "group": group},
				Links:      &links{Self: "/api/v1/stock/" + p},
			})
		}
	}
	add("filter.d", "filters", list.Filters)
	add("action.d", "actions", list.Actions)
	add("", "other", list.Other)
	writeDoc(w, http.StatusOK, document{Data: data, Links: &links{Self: "/api/v1/stock"}})
}

func (s *Server) v1StockFile(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	content, err := s.Composer.StockFile(p)
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	writeDoc(w, http.StatusOK, document{Data: resource{
		Type: "stock-files", ID: p,
		Attributes: map[string]any{"path": p, "content": content},
		Links:      &links{Self: "/api/v1/stock/" + p},
	}})
}

// The logs the engine can read: the places, or what is in one directory of them.

func logResource(e LogEntry) resource {
	return resource{Type: "log-files", ID: e.Path, Attributes: e, Links: self(append([]string{"log-files"}, strings.Split(strings.TrimPrefix(e.Path, "/"), "/")...)...)}
}

func (s *Server) v1LogFiles(w http.ResponseWriter, r *http.Request) {
	var list []LogEntry
	var meta map[string]any
	if dir := r.URL.Query().Get("filter[dir]"); dir != "" {
		_, entries, more, err := s.logDir(r.Context(), dir)
		if err != nil {
			s.failDoc(w, r, err)
			return
		}
		list, meta = entries, map[string]any{"more": more}
	} else {
		list, _ = s.logRoots(r.Context())
	}
	data := make([]resource, 0, len(list))
	for _, e := range list {
		data = append(data, logResource(e))
	}
	doc := document{Data: data, Links: &links{Self: "/api/v1/log-files"}}
	if meta != nil {
		doc.Meta = meta
	}
	writeDoc(w, http.StatusOK, doc)
}

func (s *Server) v1LogFile(w http.ResponseWriter, r *http.Request) {
	entry, _, _, err := s.logDir(r.Context(), "/"+r.PathValue("path"))
	if err != nil {
		s.failDoc(w, r, err)
		return
	}
	writeDoc(w, http.StatusOK, document{Data: logResource(entry)})
}

// The log, followed by page[after] from where the last page ended.

func (s *Server) v1Log(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after := int64(-1)
	if v := q.Get("page[after]"); v != "" {
		after, _ = strconv.ParseInt(v, 10, 64)
	}
	// A cursor from another run of the engine counts from the start of this one.
	if e := q.Get("page[epoch]"); e != "" && e != s.Lines.Epoch() {
		after = -1
	}
	lines, epoch, last := s.Lines.Since(after, pageSize(q.Get("page[size]"), 1000, ringSize))
	data := make([]resource, 0, len(lines))
	for _, l := range lines {
		data = append(data, resource{Type: "log-lines", ID: epoch + "-" + strconv.FormatInt(l.Seq, 10), Attributes: l})
	}
	next := url.Values{"page[epoch]": {epoch}, "page[after]": {strconv.FormatInt(last, 10)}}
	writeDoc(w, http.StatusOK, document{
		Data:  data,
		Meta:  map[string]any{"epoch": epoch, "last": last},
		Links: &links{Self: r.URL.RequestURI(), Next: "/api/v1/log?" + next.Encode()},
	})
}
