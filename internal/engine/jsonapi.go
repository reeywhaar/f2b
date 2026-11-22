package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"f2b/internal/f2bsock"
	"f2b/internal/reply"
)

// MediaType is JSON:API's, which /api/v1 speaks both ways.
const MediaType = "application/vnd.api+json"

// document is a JSON:API top-level document. Data is a resource, a slice of them, or absent.
type document struct {
	JSONAPI jsonapiObject `json:"jsonapi"`
	Data    any           `json:"data,omitempty"`
	Errors  []apiError    `json:"errors,omitempty"`
	Meta    any           `json:"meta,omitempty"`
	Links   *links        `json:"links,omitempty"`
}

type jsonapiObject struct {
	Version string `json:"version"`
}

var v11 = jsonapiObject{Version: "1.1"}

type resource struct {
	Type          string                  `json:"type"`
	ID            string                  `json:"id"`
	Attributes    any                     `json:"attributes,omitempty"`
	Relationships map[string]relationship `json:"relationships,omitempty"`
	Links         *links                  `json:"links,omitempty"`
}

// relationship is a to-one one: a resource's identifier, or null.
type relationship struct {
	Data *identifier `json:"data"`
}

type identifier struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type links struct {
	Self string `json:"self,omitempty"`
	Next string `json:"next,omitempty"`
}

// apiError is one error object. Code is the same contract as the plain API's refusal codes;
// meta.output is what a program said, for a refusal that is one.
type apiError struct {
	Status string         `json:"status"`
	Code   string         `json:"code"`
	Title  string         `json:"title"`
	Detail string         `json:"detail,omitempty"`
	Meta   map[string]any `json:"meta,omitempty"`
}

func writeDoc(w http.ResponseWriter, status int, doc document) {
	doc.JSONAPI = v11
	w.Header().Set("Content-Type", MediaType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(doc)
}

func refuseDoc(w http.ResponseWriter, status int, code, detail string, meta map[string]any) {
	writeDoc(w, status, document{Errors: []apiError{{
		Status: strconv.Itoa(status), Code: code, Title: http.StatusText(status), Detail: detail, Meta: meta,
	}}})
}

// plainMedia is whether a media type is JSON:API's with no parameters but ext and profile, the
// only ones the spec lets a server accept.
func plainMedia(value string) bool {
	mt, params, err := mime.ParseMediaType(value)
	if err != nil || mt != MediaType {
		return false
	}
	for k := range params {
		if k != "ext" && k != "profile" {
			return false
		}
	}
	return true
}

// mediaRefusal is why JSON:API's rules on media types refuse a request, or "".
//
// A body is in JSON:API's media type, or 415. An Accept that names JSON:API's only with
// parameters it cannot honor is 406; one that names it bare, or names it not at all, is answered.
func mediaRefusal(r *http.Request) (int, string) {
	if r.ContentLength != 0 && r.Body != nil && r.Body != http.NoBody {
		if !plainMedia(r.Header.Get("Content-Type")) {
			return http.StatusUnsupportedMediaType, "Send " + MediaType + ", with no parameters but ext and profile."
		}
	}
	named, plain := false, false
	for _, v := range r.Header.Values("Accept") {
		for _, part := range strings.Split(v, ",") {
			mt, _, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil || mt != MediaType {
				continue
			}
			named = true
			plain = plain || plainMedia(strings.TrimSpace(part))
		}
	}
	if named && !plain {
		return http.StatusNotAcceptable, "Accept " + MediaType + " with no parameters but ext and profile."
	}
	return 0, ""
}

// in is a request's document: data, and meta for what is not a resource's attribute.
type in[T any] struct {
	JSONAPI *jsonapiObject `json:"jsonapi"`
	Data    T              `json:"data"`
	Meta    map[string]any `json:"meta"`
}

// decodeDoc reads a JSON:API request document, refusing anything it does not recognize, as the
// plain API does: a caller's typo'd field is a refusal saying so.
func decodeDoc(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, reply.BodyMax))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var over *http.MaxBytesError
		if errors.As(err, &over) {
			refuseDoc(w, http.StatusRequestEntityTooLarge, reply.CodeBodyTooLarge, fmt.Sprintf("That request body is over %d MB.", reply.BodyMax>>20), nil)
			return false
		}
		refuseDoc(w, http.StatusBadRequest, reply.CodeInvalid, "That request body is not the JSON:API document this expects: "+err.Error(), nil)
		return false
	}
	return true
}

// failDoc is Server.fail in JSON:API's words: the same errors, the same statuses and codes.
func (s *Server) failDoc(w http.ResponseWriter, r *http.Request, err error) {
	var refused *f2bsock.Error
	var rej *rejected
	switch {
	case errors.As(err, &rej):
		refuseDoc(w, http.StatusUnprocessableEntity, reply.CodeRejected, "fail2ban refused this configuration, and nothing was saved.", map[string]any{"output": rej.output})
	case errors.Is(err, ErrInvalid):
		refuseDoc(w, http.StatusBadRequest, reply.CodeInvalid, sentence(err, ErrInvalid), nil)
	case errors.Is(err, ErrNotFound):
		refuseDoc(w, http.StatusNotFound, reply.CodeNotFound, sentence(err, ErrNotFound), nil)
	case errors.Is(err, ErrStale):
		refuseDoc(w, http.StatusPreconditionFailed, reply.CodePreconditionFailed, sentence(err, ErrConflict), nil)
	case errors.Is(err, ErrConflict):
		refuseDoc(w, http.StatusConflict, reply.CodeConflict, sentence(err, ErrConflict), nil)
	case errors.Is(err, f2bsock.ErrUnreachable):
		refuseDoc(w, http.StatusServiceUnavailable, reply.CodeFail2ban, "fail2ban is not answering: it is starting, or it stopped. The log says which.", nil)
	case errors.As(err, &refused):
		refuseDoc(w, http.StatusUnprocessableEntity, reply.CodeFail2ban, capitalize(refused.Message)+".", nil)
	case errors.Is(err, context.Canceled):
	default:
		s.Log.Error("request failed with an error nothing here explains", "method", r.Method, "path", r.URL.Path, "error", err.Error())
		refuseDoc(w, http.StatusInternalServerError, reply.CodeInternal, "Something went wrong in the engine. Its log says what.", nil)
	}
}
