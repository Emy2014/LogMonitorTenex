package httpx

import "net/http"

// SecurityHeaders sets the response headers that cost nothing and close real
// gaps. HSTS is emitted only over TLS -- sending it over plain http is
// meaningless, and in local development it would pin localhost to https in the
// browser for a year.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		// This service returns JSON only; nothing it serves should ever be
		// allowed to load a script or be framed.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
