package webui

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CookieName is the one cookie this sets.
const CookieName = "f2b_session"

const (
	// sessionLife is how long a sign-in lasts without a visit.
	sessionLife = 30 * 24 * time.Hour
	// sessionRefresh is how often a visit moves the end on, so not every request sets a cookie.
	sessionRefresh = 24 * time.Hour
)

// Sessions are signed cookies: when one ends and a MAC over that and the password. Nothing is
// stored per sign-in, so there is no database; the key is the one thing kept, in the data
// directory, and replacing it signs every browser out. So does changing the password.
type Sessions struct {
	path     string
	password [32]byte
	secure   bool
	now      func() time.Time

	mu  sync.RWMutex
	key []byte
}

func NewSessions(path, password string, secure bool) (*Sessions, error) {
	s := &Sessions{path: path, password: sha256.Sum256([]byte(password)), secure: secure, now: time.Now}
	key, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && len(key) != 32) {
		return s, s.Rotate()
	}
	if err != nil {
		return nil, fmt.Errorf("reading the session key: %w", err)
	}
	s.key = key
	return s, nil
}

// Rotate replaces the key, which ends every session there is.
func (s *Sessions) Rotate() error {
	key := make([]byte, 32)
	rand.Read(key)
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("writing the session key: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return fmt.Errorf("writing the session key: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("writing the session key: %w", err)
	}
	s.mu.Lock()
	s.key = key
	s.mu.Unlock()
	return nil
}

func (s *Sessions) mac(until int64) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := hmac.New(sha256.New, s.key)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(until))
	m.Write([]byte("f2b session\x00"))
	m.Write(b[:])
	m.Write(s.password[:])
	return m.Sum(nil)
}

// Issue signs a browser in.
func (s *Sessions) Issue(w http.ResponseWriter) {
	until := s.now().Add(sessionLife).Unix()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(until))
	value := base64.RawURLEncoding.EncodeToString(append(b[:], s.mac(until)...))
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Expires:  time.Unix(until, 0),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// Valid reports whether a request carries a live session, and moves its end on when due.
func (s *Sessions) Valid(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 8+sha256.Size {
		s.Clear(w)
		return false
	}
	until := int64(binary.BigEndian.Uint64(raw[:8]))
	if !hmac.Equal(raw[8:], s.mac(until)) || s.now().Unix() >= until {
		s.Clear(w)
		return false
	}
	if time.Unix(until, 0).Sub(s.now()) < sessionLife-sessionRefresh {
		s.Issue(w)
	}
	return true
}

func (s *Sessions) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}
