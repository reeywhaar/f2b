// Package webui is the web: the interface, the sign-in, and the way through to the engine.
//
// It knows nothing of fail2ban. Every /api request past the sign-in is passed to the engine's
// socket as it came, so the API the interface uses is the engine's, documented once.
package webui

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
	"time"

	"f2b/internal/app"
	"f2b/internal/config"
	"f2b/internal/reply"
)

// Server holds what every handler needs. Rate limiters belong on it, not at package level: two
// instances in one process would otherwise share one budget.
type Server struct {
	cfg      *config.Web
	log      *slog.Logger
	sessions *Sessions
	spa      *SPA
	engine   *httputil.ReverseProxy
	mux      *http.ServeMux

	loginAll *limiter
	loginIP  *limiter
}

// engineTimeout is how long an answer from the engine is waited for. A save reloads fail2ban,
// which with many jails takes a while.
const engineTimeout = 3 * time.Minute

func New(cfg *config.Web, log *slog.Logger, sessions *Sessions, spa *SPA) *Server {
	s := &Server{
		cfg:      cfg,
		log:      log,
		sessions: sessions,
		spa:      spa,
		mux:      http.NewServeMux(),
		loginAll: newLimiter(30, 2*time.Second),
		loginIP:  newLimiter(5, 20*time.Second),
	}
	socket := cfg.Layout.Socket
	s.engine = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "engine"
			pr.Out.Host = "engine"
			// The engine has no use for the browser's cookie, and is better off never seeing it.
			pr.Out.Header.Del("Cookie")
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
			ResponseHeaderTimeout: engineTimeout,
			MaxIdleConns:          4,
			IdleConnTimeout:       time.Minute,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() != nil {
				return
			}
			s.log.Warn("the engine did not answer", "path", r.URL.Path, "error", err.Error())
			reply.Refuse(w, http.StatusBadGateway, reply.CodeEngine,
				"The engine is not answering. Is the f2b-engine container running, with the same data volume?")
		},
	}

	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		reply.JSON(w, http.StatusOK, map[string]any{"ok": true, "version": app.Version})
	})
	s.mux.HandleFunc("POST /api/auth/login", s.login)
	s.mux.Handle("POST /api/auth/logout", s.requireSession(s.logout))
	s.mux.Handle("POST /api/auth/logout-everywhere", s.requireSession(s.logoutEverywhere))
	s.mux.Handle("GET /api/auth/me", s.requireSession(s.me))
	s.mux.Handle("/api/", s.requireSession(s.engine.ServeHTTP))
	s.mux.Handle("/", s.gate(spa))
	return s
}

// login checks the password the environment names, and issues a cookie.
//
// Two buckets, with two jobs: the global one bounds how fast anybody guesses at all, and the
// per-address one stops one caller working through a list.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !reply.Decode(w, r, &req) {
		return
	}
	ip := s.clientIP(r)
	if !s.loginAll.allow("") || !s.loginIP.allow(ip) {
		reply.Refuse(w, http.StatusTooManyRequests, reply.CodeRateLimited, "Too many sign-in attempts. Wait a minute.")
		return
	}
	// Compared over digests, so how long a refusal takes says nothing of the password's length.
	x, y := sha256.Sum256([]byte(req.Password)), sha256.Sum256([]byte(s.cfg.Password))
	if subtle.ConstantTimeCompare(x[:], y[:]) != 1 {
		// One line per wrong password, for fail2ban; see docs/deploy.md. Never the password.
		s.log.Warn("password refused", "ip", ip)
		reply.Refuse(w, http.StatusUnauthorized, reply.CodeUnauthenticated, "That password is not the one.")
		return
	}
	s.sessions.Issue(w)
	s.log.Info("signed in", "ip", ip)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Clear(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logoutEverywhere(w http.ResponseWriter, r *http.Request) {
	if err := s.sessions.Rotate(); err != nil {
		s.log.Error("the session key could not be replaced", "error", err.Error())
		reply.Refuse(w, http.StatusInternalServerError, reply.CodeInternal, "The session key could not be replaced, so nobody was signed out.")
		return
	}
	s.sessions.Clear(w)
	s.log.Info("every browser signed out", "ip", s.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	reply.JSON(w, http.StatusOK, map[string]any{"ok": true, "version": app.Version})
}

// requireSession admits a request that carries a live session, and nothing else.
//
// Never a redirect: a 302 to an HTML page is the least useful thing a fetch can receive. The
// island reads the 401 and navigates itself.
func (s *Server) requireSession(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.sessions.Valid(w, r) {
			reply.Refuse(w, http.StatusUnauthorized, reply.CodeUnauthenticated, "Sign in first.")
			return
		}
		next(w, r)
	})
}

const signInPath = "/login"

// gate decides who gets which document, before the bundle loads: a signed-out visitor handed the
// application shell would see every panel in it fail. Only shells are gated; a file is served to
// anybody, which is what lets the sign-in page load its own stylesheet.
func (s *Server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sh := s.spa.shellFor(r.URL.Path)
		if sh == nil {
			next.ServeHTTP(w, r)
			return
		}
		signedIn := s.sessions.Valid(w, r)
		switch {
		case !signedIn && !sh.public:
			redirect(w, r, signInPath)
		case signedIn && r.URL.Path == signInPath:
			redirect(w, r, "/")
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// redirect sends a navigation elsewhere, uncached, or a browser would keep redirecting after the
// sign-in that fixed it.
func redirect(w http.ResponseWriter, r *http.Request, to string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, to, http.StatusFound)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sv := &served{ResponseWriter: w}
	defer s.logRequest(r, sv, start)
	s.guard(s.mux).ServeHTTP(sv, r)
}

// served is what a request's line in the log says: the status it was answered with.
type served struct {
	http.ResponseWriter
	status int
}

func (sv *served) WriteHeader(code int) {
	if sv.status == 0 {
		sv.status = code
	}
	sv.ResponseWriter.WriteHeader(code)
}

func (sv *served) Write(b []byte) (int, error) {
	if sv.status == 0 {
		sv.status = http.StatusOK
	}
	return sv.ResponseWriter.Write(b)
}

func (sv *served) Unwrap() http.ResponseWriter { return sv.ResponseWriter }

// logRequest says what was changed and how it was answered: writes at info, reads at debug, so
// the interface polling the log every few seconds does not fill this one. Not the query, and not
// the bundle's files or the health check.
func (s *Server) logRequest(r *http.Request, sv *served, start time.Time) {
	path := r.URL.Path
	if !strings.HasPrefix(path, "/api/") {
		return
	}
	status := cmp.Or(sv.status, http.StatusOK)
	level := slog.LevelDebug
	switch {
	case status >= 500:
		level = slog.LevelWarn
	case r.Method != http.MethodGet:
		level = slog.LevelInfo
	}
	s.log.Log(r.Context(), level, "request answered",
		"method", r.Method, "path", path, "status", status, "took", time.Since(start).Round(100*time.Microsecond))
}

// guard is the CSRF defense: SameSite on the cookie, Sec-Fetch-Site, and a declared content
// type. It leans on this origin being the only one the browser talks to.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		// A browser sets this; a script cannot forge it.
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			reply.Refuse(w, http.StatusForbidden, reply.CodeForbidden, "That request came from somewhere else.")
			return
		}
		// Only when a body is present: a write with nothing to say carries none.
		if r.ContentLength != 0 && !reply.IsJSON(r.Header.Get("Content-Type")) {
			reply.Refuse(w, http.StatusUnsupportedMediaType, reply.CodeUnsupportedMediaType, "Send application/json.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP is who sent the request: the address fail2ban bans.
//
// X-Forwarded-For is read only from a trusted peer, right to left: each proxy appends who it
// accepted, so the first hop that is not a trusted proxy is the caller, and everything left of it
// is whatever the caller sent. From any other peer it is the caller's own claim, and believing it
// would let a stranger name the address that gets banned. See docs/deploy.md.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return r.RemoteAddr
	}
	peer = peer.Unmap()
	trusted := s.cfg.TrustedProxies
	if !trusted.Trusts(peer) {
		return peer.String()
	}
	client := peer
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		client = hop.Unmap()
		if !trusted.Trusts(client) {
			break
		}
	}
	return client.String()
}
