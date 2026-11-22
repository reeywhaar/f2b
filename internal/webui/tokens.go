package webui

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"f2b/internal/app"
)

// An API token is f2b_, an id, _, and a secret. The id finds it; the secret is checked against a
// digest, the only form it is kept in, so tokens.json leaked is no token leaked.
const tokenPrefix = "f2b_"

// tokenNameMax keeps a name to what fits in a row of the list and a line of the log.
const tokenNameMax = 60

// usedEvery is how stale a token's last use may be on disk. Kept to the minute in memory and
// written at most this often, so an agent polling every second is not a write every second.
const usedEvery = time.Minute

// Lifetimes are what a token's two expiries are chosen from; "never" turns one off.
var Lifetimes = map[string]time.Duration{
	"1d": 24 * time.Hour, "1w": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
	"90d": 90 * 24 * time.Hour, "180d": 180 * 24 * time.Hour, "1y": 365 * 24 * time.Hour,
	"never": 0,
}

var (
	errTokenInvalid = errors.New("invalid")
	errTokenTaken   = errors.New("taken")
)

// Token is one API token as kept.
type Token struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Scope string `json:"scope"`
	// Created and LastUsed are Unix seconds; LastUsed is 0 until it is.
	Created  int64 `json:"created"`
	LastUsed int64 `json:"lastUsed"`
	// Expires is when it ends however it is used, or 0 for never.
	Expires int64 `json:"expires"`
	// Idle is how many seconds it lasts unused, or 0 for as long as it likes.
	Idle int64  `json:"idle"`
	Hash string `json:"hash"`
}

// ends is when it stops working: the sooner of its expiry and its time unused, or 0 for never.
func (t Token) ends() int64 {
	end := t.Expires
	if t.Idle > 0 {
		idle := max(t.LastUsed, t.Created) + t.Idle
		if end == 0 || idle < end {
			end = idle
		}
	}
	return end
}

// TokenView is a token as the interface lists it: no digest, and when it ends worked out.
type TokenView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Scope    string `json:"scope"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"lastUsed"`
	Expires  int64  `json:"expires"`
	Idle     int64  `json:"idle"`
	// Ends is when it stops working at the latest, unused from now, or 0 for never.
	Ends    int64 `json:"ends"`
	Expired bool  `json:"expired"`
}

// Tokens are the API tokens the web has issued, in one file the web alone writes.
type Tokens struct {
	path string
	now  func() time.Time

	mu    sync.Mutex
	list  []Token
	saved map[string]int64
}

func OpenTokens(path string) (*Tokens, error) {
	t := &Tokens{path: path, now: time.Now, saved: map[string]int64{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the API tokens: %w", err)
	}
	if err := json.Unmarshal(b, &t.list); err != nil {
		return nil, fmt.Errorf("reading the API tokens in %s: %w", path, err)
	}
	for _, tok := range t.list {
		t.saved[tok.ID] = tok.LastUsed
	}
	return t, nil
}

func (t *Tokens) view(tok Token, now int64) TokenView {
	end := tok.ends()
	return TokenView{
		ID: tok.ID, Name: tok.Name, Scope: tok.Scope, Created: tok.Created, LastUsed: tok.LastUsed,
		Expires: tok.Expires, Idle: tok.Idle, Ends: end, Expired: end != 0 && now >= end,
	}
}

// List is every token, newest first.
func (t *Tokens) List() []TokenView {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().Unix()
	out := make([]TokenView, 0, len(t.list))
	for _, tok := range t.list {
		out = append(out, t.view(tok, now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out
}

// Issue makes a token, and returns it with its whole text, which is never available again.
func (t *Tokens) Issue(name, scope, expiresIn, idleFor string) (TokenView, string, error) {
	name = strings.TrimSpace(name)
	life, okLife := Lifetimes[expiresIn]
	idle, okIdle := Lifetimes[idleFor]
	switch {
	case name == "" || len([]rune(name)) > tokenNameMax:
		return TokenView{}, "", fmt.Errorf("%w: a token's name is 1 to %d characters", errTokenInvalid, tokenNameMax)
	case strings.ContainsFunc(name, unicode.IsControl):
		return TokenView{}, "", fmt.Errorf("%w: a token's name is one line", errTokenInvalid)
	case scope != app.ScopeRead && scope != app.ScopeWrite:
		return TokenView{}, "", fmt.Errorf("%w: a token reads, or reads and writes: scope is %q or %q", errTokenInvalid, app.ScopeRead, app.ScopeWrite)
	case !okLife || !okIdle:
		return TokenView{}, "", fmt.Errorf("%w: a token expires after 1d, 1w, 30d, 90d, 180d, 1y or never", errTokenInvalid)
	}

	id := make([]byte, 8)
	secret := make([]byte, 32)
	rand.Read(id)
	rand.Read(secret)
	text := base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(text))
	now := t.now()
	tok := Token{
		ID: hex.EncodeToString(id), Name: name, Scope: scope, Created: now.Unix(),
		Idle: int64(idle / time.Second), Hash: hex.EncodeToString(digest[:]),
	}
	if life > 0 {
		tok.Expires = now.Add(life).Unix()
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, other := range t.list {
		if strings.EqualFold(other.Name, name) {
			return TokenView{}, "", fmt.Errorf("%w: there is a token named %s already; the log names a token's use by its name", errTokenTaken, other.Name)
		}
	}
	next := append(slices.Clone(t.list), tok)
	if err := t.write(next); err != nil {
		return TokenView{}, "", err
	}
	t.list = next
	t.saved[tok.ID] = 0
	return t.view(tok, now.Unix()), tokenPrefix + tok.ID + "_" + text, nil
}

// Revoke ends a token at once, and reports whether there was one.
func (t *Tokens) Revoke(id string) (TokenView, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, tok := range t.list {
		if tok.ID != id {
			continue
		}
		next := slices.Delete(slices.Clone(t.list), i, i+1)
		if err := t.write(next); err != nil {
			return TokenView{}, true, err
		}
		t.list = next
		delete(t.saved, id)
		return t.view(tok, t.now().Unix()), true, nil
	}
	return TokenView{}, false, nil
}

// Verify is the token a request's text is, if it is one that still works, and notes its use.
func (t *Tokens) Verify(text string) (Token, bool) {
	rest, ok := strings.CutPrefix(text, tokenPrefix)
	if !ok {
		return Token{}, false
	}
	// The id is hex and has no underscore; the secret, base64url, may.
	id, secret, ok := strings.Cut(rest, "_")
	if !ok {
		return Token{}, false
	}
	digest := sha256.Sum256([]byte(secret))
	want := hex.EncodeToString(digest[:])

	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().Unix()
	for i := range t.list {
		tok := &t.list[i]
		if tok.ID != id {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(tok.Hash), []byte(want)) != 1 {
			return Token{}, false
		}
		if end := tok.ends(); end != 0 && now >= end {
			return Token{}, false
		}
		tok.LastUsed = now
		if now-t.saved[id] >= int64(usedEvery/time.Second) {
			// A use not written down is a token that may expire unused a minute early; a token
			// refused because the disk is full would be worse.
			if t.write(t.list) == nil {
				t.saved[id] = now
			}
		}
		return *tok, true
	}
	return Token{}, false
}

// write puts list on disk whole, beside the file and then over it, as the session key is.
func (t *Tokens) write(list []Token) error {
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(t.path), 0o755); err != nil {
		return fmt.Errorf("writing the API tokens: %w", err)
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing the API tokens: %w", err)
	}
	if err := os.Rename(tmp, t.path); err != nil {
		return fmt.Errorf("writing the API tokens: %w", err)
	}
	return nil
}
