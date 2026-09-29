// Package httpx holds the small helpers every handler uses: JSON in, JSON out,
// and an error shape the Next.js client already understands.
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
)

// Error mirrors FastAPI's {"detail": "..."} so web/src/lib/api.ts keeps working
// unchanged -- it reads `.detail` off a failed response.
type Error struct {
	Detail string `json:"detail"`
}

func JSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("response encode failed", "event", "http.encode_failed", "err", err)
	}
}

func Fail(w http.ResponseWriter, status int, detail string) {
	JSON(w, status, Error{Detail: detail})
}

// Decode reads a JSON body with a size cap, rejecting unknown fields so a
// typo in a client payload surfaces as an error instead of a silent default.
func Decode(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid request body")
	}
	return nil
}

// DecodeOptional is Decode for endpoints where the body may legitimately be
// absent. An empty body leaves dst at its zero value; malformed JSON is still
// an error.
//
// Needed because Content-Length cannot be trusted: the Next.js proxy strips it
// and forwards chunked, so a present body can report a length of -1.
func DecodeOptional(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // no body at all
		}
		return errors.New("invalid request body")
	}
	return nil
}
