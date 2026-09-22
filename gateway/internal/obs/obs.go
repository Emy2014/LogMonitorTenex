// Package obs provides structured logging and request instrumentation.
//
// It keeps v1's two load-bearing decisions: one structured line per request
// with a correlation id, and metrics keyed on the route pattern rather than the
// concrete path -- the difference between a metric with eight label values and
// one with a new value per analysis ever created.
package obs

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

const RequestIDHeader = "X-Request-ID"

type ctxKey int

const requestIDKey ctxKey = iota

func NewLogger(level string) *slog.Logger {
	lvl := slog.LevelInfo
	switch level {
	case "DEBUG", "debug":
		lvl = slog.LevelDebug
	case "WARNING", "warn":
		lvl = slog.LevelWarn
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

// Middleware assigns a request id, times the request and emits one line.
//
// Health and metrics are skipped: Cloud Run polls health every few seconds and
// an access log for it is pure noise that also distorts the latency histogram.
func Middleware(log *slog.Logger) func(http.Handler) http.Handler {
	skip := map[string]bool{"/api/health": true, "/api/metrics": true}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Honour an upstream id so a request can be followed from the
			// Next.js proxy through to here as one trace.
			id := r.Header.Get(RequestIDHeader)
			if id == "" {
				id = uuid.NewString()
			}
			ctx := context.WithValue(r.Context(), requestIDKey, id)
			w.Header().Set(RequestIDHeader, id)

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(sw, r.WithContext(ctx))

			if skip[r.URL.Path] {
				return
			}
			ms := float64(time.Since(start).Microseconds()) / 1000.0
			pattern := r.Pattern
			if pattern == "" {
				pattern = r.URL.Path
			}

			// INFO for normal traffic, WARN for 4xx, ERROR for 5xx, so severity
			// alone is a useful filter.
			level := slog.LevelInfo
			switch {
			case sw.status >= 500:
				level = slog.LevelError
			case sw.status >= 400:
				level = slog.LevelWarn
			}
			log.Log(r.Context(), level, "http request",
				"event", "http.request",
				"request_id", id,
				"method", r.Method,
				"route", pattern,
				"status", sw.status,
				"duration_ms", ms,
			)
		})
	}
}
