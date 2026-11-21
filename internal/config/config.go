// Package config is the environment, parsed once. See README.md.
package config

import (
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"f2b/internal/app"
)

// Environment variables read by this package.
const (
	// DataDirEnv is the directory both containers mount: what is edited, fail2ban's database and
	// log, and the socket between them.
	DataDirEnv = "F2B_DATA_DIR"

	// LogLevelEnv sets the slog level: debug, info, warn or error.
	LogLevelEnv = "F2B_LOG_LEVEL"

	// PasswordEnv is the one sign-in there is.
	PasswordEnv = "ADMIN_PASSWORD"

	// PublicURLEnv is the address a browser opens. Only its scheme is read: an http one sends
	// the session cookie without Secure. Unset, https is assumed, which is what a proxy in front
	// serves.
	PublicURLEnv = "F2B_PUBLIC_URL"

	// TrustedProxiesEnv is whose X-Forwarded-For is believed: addresses and ranges, "private"
	// for the private and loopback ranges, or "none". Unset, "private".
	TrustedProxiesEnv = "F2B_TRUSTED_PROXIES"
)

const DefaultDataDir = "/data"

// Common is what both commands read.
type Common struct {
	Layout   app.Layout
	LogLevel slog.Level
}

// Web is what the web reads besides.
type Web struct {
	Common
	Password string
	// Secure is whether the cookie is sent only over https.
	Secure bool
	// TrustedProxies are the peers whose X-Forwarded-For says who the caller is.
	TrustedProxies Proxies
}

// LoadCommon reads what both commands share. Errors are written for somebody looking at a
// container that refused to start.
func LoadCommon() (Common, error) {
	c := Common{Layout: app.LayoutOf(DefaultDataDir), LogLevel: slog.LevelInfo}
	if dir := strings.TrimSpace(os.Getenv(DataDirEnv)); dir != "" {
		c.Layout = app.LayoutOf(dir)
	}
	// A startup error rather than a fall back to info: a level that quietly works is one nobody
	// finds until the log lacks what they came for.
	if v := strings.TrimSpace(os.Getenv(LogLevelEnv)); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(strings.ToLower(v))); err != nil {
			return c, fmt.Errorf("%s: %q is not a level (debug, info, warn, error)", LogLevelEnv, v)
		}
	}
	return c, nil
}

// LoadWeb reads the web's environment.
func LoadWeb() (*Web, error) {
	common, err := LoadCommon()
	if err != nil {
		return nil, err
	}
	w := &Web{
		Common: common,
		// Untrimmed: a password may begin or end with a space, and whoever set it meant it.
		Password: os.Getenv(PasswordEnv),
		Secure:   true,
	}
	if w.Password == "" {
		return nil, fmt.Errorf("%s is required: it is the password the interface is signed in with", PasswordEnv)
	}
	if len(w.Password) < 8 {
		return nil, fmt.Errorf("%s is %d characters, and it has to be at least 8", PasswordEnv, len(w.Password))
	}
	if raw := strings.TrimSpace(os.Getenv(PublicURLEnv)); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("%s: %q should be an http:// or https:// address, e.g. https://f2b.example.com", PublicURLEnv, raw)
		}
		w.Secure = u.Scheme == "https"
	}
	proxies := strings.TrimSpace(os.Getenv(TrustedProxiesEnv))
	if proxies == "" {
		proxies = "private"
	}
	if w.TrustedProxies, err = ParseProxies(proxies); err != nil {
		return nil, err
	}
	return w, nil
}

// Proxies are the addresses a request may come through and still name its caller.
type Proxies []netip.Prefix

// Trusts reports whether addr is one of them.
func (p Proxies) Trusts(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range p {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// private is what "private" stands for: where a proxy on the same host or Docker network
// connects from.
var private = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8", "::1/128"}

// ParseProxies reads a list of addresses, ranges, "private" and "none", split by commas or spaces.
func ParseProxies(raw string) (Proxies, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	var out Proxies
	for _, f := range fields {
		switch {
		case f == "none":
			if len(fields) > 1 {
				return nil, fmt.Errorf("%s: \"none\" goes alone, not with %q", TrustedProxiesEnv, raw)
			}
			return Proxies{}, nil
		case f == "private":
			for _, r := range private {
				out = append(out, netip.MustParsePrefix(r))
			}
		case strings.Contains(f, "/"):
			prefix, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("%s: %q is not a range", TrustedProxiesEnv, f)
			}
			out = append(out, prefix.Masked())
		default:
			addr, err := netip.ParseAddr(f)
			if err != nil {
				return nil, fmt.Errorf("%s: %q is not an address, a range, \"private\" or \"none\"", TrustedProxiesEnv, f)
			}
			addr = addr.Unmap()
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return out, nil
}
