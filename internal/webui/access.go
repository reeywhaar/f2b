package webui

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"f2b/internal/app"
	"f2b/internal/reply"
)

// agentAccess makes an agent access link. A signed-in browser's only, as a token is: a person
// letting an agent in, and never an agent handing itself another.
func (s *Server) agentAccess(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Scope string `json:"scope"`
	}
	if !reply.Decode(w, r, &req) {
		return
	}
	code, tok, ends, err := s.tokens.AgentAccess(req.Scope)
	switch {
	case errors.Is(err, errTokenInvalid):
		reply.Refuse(w, http.StatusBadRequest, reply.CodeInvalid, sentence(err, errTokenInvalid))
		return
	case err != nil:
		s.log.Error("an agent's token could not be issued", "error", err.Error())
		reply.Refuse(w, http.StatusInternalServerError, reply.CodeInternal, "The token could not be written down, so no link was made.")
		return
	}
	s.log.Info("agent access issued", "name", tok.Name, "scope", tok.Scope, "ip", s.clientIP(r))
	reply.JSON(w, http.StatusCreated, map[string]any{
		"url": s.base(r) + "/agent-access/" + code, "token": tok, "linkEnds": ends,
	})
}

// accessPage is what an agent access link opens: markdown, for an agent to read with whatever it
// fetches pages with, served as plain text, which every browser shows, so the link can be looked
// at before it is handed over.
//
// A link that shows nothing, never one or no longer, is one line for fail2ban, as a refused token
// is, and spends the same budget: a code is a credential, and guessing at one is guessing.
func (s *Server) accessPage(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Referrer-Policy", "no-referrer")
	ip := s.clientIP(r)
	text, tok, ends, ok := s.tokens.OpenAccess(r.PathValue("code"))
	if !ok {
		s.log.Warn("link refused", "ip", ip)
		if !s.loginIP.allow(ip) {
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintln(w, "Too many links refused from here. Wait a minute.")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, "This agent access link has stopped showing its token, or was never one of this server's. Ask whoever sent it for a new one.")
		return
	}
	s.log.Info("agent access opened", "name", tok.Name, "ip", ip)
	fmt.Fprint(w, accessBrief(s.base(r), s.cfg.Label, text, tok, ends))
}

// base is this server's address: F2B_PUBLIC_URL, or else the one the request came to.
func (s *Server) base(r *http.Request) string {
	if s.cfg.PublicURL != "" {
		return s.cfg.PublicURL
	}
	scheme := "https"
	if !s.cfg.Secure {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// accessBrief is the page: what the agent has been let into, what the token may do there, where
// things are, and the token.
//
// The token is below the opening lines. A chat that previews a pasted link shows its first lines,
// and those say what this is and when it stops, not the secret.
func accessBrief(base, label, text string, tok TokenView, linkEnds int64) string {
	at := func(u int64) string { return time.Unix(u, 0).UTC().Format(time.RFC3339) }
	writes := tok.Scope == app.ScopeWrite
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	p("# f2b: access for an agent\n\n")
	p("This page stops showing the token at %s, five minutes after it was made. Write down the token, "+
		"and whatever else you need from here, now. The token works until %s.\n\n", at(linkEnds), at(tok.Expires))
	where := "a fail2ban"
	if label != "" {
		where = "the fail2ban on " + label
	}
	what := "read what it does"
	if writes {
		what = "read what it does and change it"
	}
	p("Somebody has let you into f2b, the dashboard of %s, to %s: its jails, its bans, their history, "+
		"its configuration and the logs it reads.\n\n", where, what)

	p("- Instance: %s\n", base)
	p("- API: %s/api/v1, in JSON:API. Every route, with what it takes and what it answers, is in "+
		"%s/api/v1/openapi.json: read it before the first request. Send and accept "+
		"`application/vnd.api+json`.\n", base, base)
	if writes {
		p("- This token reads and writes. It takes every route: besides reading, it bans and unbans, " +
			"saves, renames and deletes fail2ban's files, and restarts fail2ban.\n")
	} else {
		p("- This token reads. It takes every route whose `x-f2b-scope` is `read`: every GET, trying a " +
			"filter (`POST /api/v1/regex-tests`) and checking a file (`POST /api/v1/config-checks`), which " +
			"change nothing. Anything else is `403`.\n")
	}

	p("\n## Where things are\n\n")
	p("- The jails, with the logs each reads and how quickly it bans: `GET /api/v1/jails`. Bans in " +
		"force: `GET /api/v1/bans`; past ones: `GET /api/v1/history`.\n")
	p("- fail2ban's own log: `GET /api/v1/log`.\n")
	p("- fail2ban's configuration: `GET /api/v1/files`, one at `GET /api/v1/files/{kind}/{name}`, as " +
		"`jails/sshd.local`. fail2ban's own files, which these override: `GET /api/v1/stock`.\n")
	p("- The logs it can read: `GET /api/v1/log-files`, `?filter[path]=auth` to find one, and " +
		"`GET /api/v1/log-files/var/log/auth.log?page[size]=200` for a file's last lines.\n")
	p("- A filter is tried before it is saved: `POST /api/v1/regex-tests`, with the filter's text as " +
		"`content`, over a log or lines of your own. It is fail2ban-regex, and says which lines match.\n")
	if writes {
		p("- A file is changed with `PATCH`, its `ETag` in `If-Match`. fail2ban checks every save first: " +
			"one it would refuse is `422 config_rejected`, with its own words, and nothing is written; one " +
			"it accepts is written, and fail2ban reloads with it.\n")
		p("- A ban is real: it goes into this host's firewall, and a wrong one shuts somebody out. Ban, " +
			"unban, delete a file or restart fail2ban when you are asked to, not on your own.\n")
	}

	p("\n## The token\n\n")
	p("It works until %s, thirty minutes after this link was made, and is then gone. For more time, ask "+
		"for a new link. The server's log names each request it makes %s.\n\n", at(tok.Expires), tok.Name)
	p("```\n%s\n```\n\n", text)
	p("```sh\n")
	p("export F2B=%s\n", base)
	p("export TOKEN=%s\n\n", text)
	p("curl -sS -H \"Authorization: Bearer $TOKEN\" \"$F2B/api/v1/jails\"\n")
	p("```\n")
	return b.String()
}
