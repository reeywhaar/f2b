// Package reply is how both servers answer: JSON, and one shape for every refusal.
package reply

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Refusal codes. The code is the contract; the message is not, and nothing may match on it.
const (
	CodeInvalid              = "invalid"
	CodeUnauthenticated      = "unauthenticated"
	CodeNotFound             = "not_found"
	CodeConflict             = "conflict"
	CodeForbidden            = "forbidden"
	CodeUnsupportedMediaType = "unsupported_media_type"
	CodeBodyTooLarge         = "body_too_large"
	CodeRateLimited          = "rate_limited"
	// CodeRejected is fail2ban refusing a configuration; output says what it said.
	CodeRejected = "config_rejected"
	// CodeFail2ban is fail2ban refusing a command, or not answering one.
	CodeFail2ban = "fail2ban"
	// CodeEngine is the web unable to reach the engine.
	CodeEngine   = "engine_unreachable"
	CodeInternal = "internal"
)

// Refusal is the shape of every refusal.
//
// Ok is for a caller reading the body without the status line. Output is what a program said,
// for a refusal that is one.
type Refusal struct {
	Ok      bool   `json:"ok"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Output  string `json:"output,omitempty"`
}

// BodyMax bounds a JSON request: a file is at most a quarter of a megabyte, and pasted log lines
// for the filter tester a few.
const BodyMax = 4 << 20

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// Refuse is the only place a refusal is written. The message names the limit or the value; a
// refusal a caller cannot act on is a bug.
func Refuse(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, Refusal{Code: code, Message: message})
}

// Decode reads a JSON body into v, refusing anything it does not recognize: a caller's typo'd
// field is a refusal saying so rather than an ignored intention.
func Decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, BodyMax))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var over *http.MaxBytesError
		if errors.As(err, &over) {
			Refuse(w, http.StatusRequestEntityTooLarge, CodeBodyTooLarge, fmt.Sprintf("That request body is over %d MB.", BodyMax>>20))
			return false
		}
		Refuse(w, http.StatusBadRequest, CodeInvalid, "That request body is not the JSON this expects: "+err.Error())
		return false
	}
	return true
}

// IsJSON is whether a Content-Type names JSON.
func IsJSON(ct string) bool {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct) == "application/json"
}
