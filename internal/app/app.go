// Package app holds what this program is, as distinct from what it was told.
//
// The line against internal/config: whether an operator can change it without rebuilding.
package app

import "path/filepath"

const Name = "f2b"

// Version is stamped at link time:
//
//	-ldflags "-X f2b/internal/app.Version=$(git rev-parse --short HEAD)"
var Version = "dev"

// ListenAddr is the web's, fixed inside its container. The engine listens on no port at all.
const ListenAddr = ":80"

// WebDir is where the web image puts the built bundle.
const WebDir = "/srv/web"

// StockDir is fail2ban's own configuration, as the engine image's package installed it.
const StockDir = "/etc/fail2ban"

// RunDir is the engine's own: the configuration fail2ban is run with, its socket and its pid.
// Inside the container, so each start begins from nothing.
const RunDir = "/run/f2b"

// ScopeHeader is what the web says a request to /api/v1 may do, having checked who sent it:
// ScopeRead or ScopeWrite. The web always sets it, over whatever came in; a request without it
// came to the socket from somebody else, whom the socket trusts as it trusts the web.
const (
	ScopeHeader = "F2B-Scope"
	ScopeRead   = "read"
	ScopeWrite  = "write"
)

// Layout is where everything lives in the data directory, which both containers mount.
type Layout struct {
	Data string
	// Config is what is edited: jail.d, filter.d, action.d and fail2ban.local.
	Config string
	// Database is fail2ban's own, its bans and their history.
	Database string
	// Log is fail2ban's log, as the engine captured it.
	Log string
	// Socket is the engine's API, which the web reaches across the two containers.
	Socket string
	// SessionKey signs the web's cookies.
	SessionKey string
	// Tokens are the API tokens the web has issued: a digest of each, never the token.
	Tokens string
}

func LayoutOf(data string) Layout {
	return Layout{
		Data:       data,
		Config:     filepath.Join(data, "fail2ban"),
		Database:   filepath.Join(data, "fail2ban.sqlite3"),
		Log:        filepath.Join(data, "fail2ban.log"),
		Socket:     filepath.Join(data, "engine.sock"),
		SessionKey: filepath.Join(data, "session.key"),
		Tokens:     filepath.Join(data, "tokens.json"),
	}
}
