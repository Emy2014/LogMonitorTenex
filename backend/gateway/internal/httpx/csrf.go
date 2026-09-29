package httpx

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

const (
	CSRFCookieName = "logmonitor_csrf"
	CSRFHeaderName = "X-CSRF-Token"
)

// CSRF implements double-submit: a readable cookie whose value must be echoed
// back in a header. An attacker's page can cause a request to be sent with the
// victim's cookies, but same-origin policy stops it reading the cookie, so it
// cannot populate the header.
//
// SameSite=Lax on the session cookie already blocks most cross-site form posts,
// but "most" is doing a lot of work there: it does not cover every browser in
// use, and POST /api/grants is precisely the endpoint where a forged request
// would matter.
//
// Login and register are NOT exempt. Login CSRF is a real attack -- forcing a
// victim into the attacker's session, so everything they subsequently upload
// lands in an account the attacker controls.
func CSRF(secure bool, exempt map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ensureCSRFCookie(w, r, secure)

			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if exempt[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			sent := r.Header.Get(CSRFHeaderName)
			if sent == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(token)) != 1 {
				Fail(w, http.StatusForbidden, "Missing or invalid CSRF token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ensureCSRFCookie returns the request's CSRF token, minting one when absent.
//
// Not HttpOnly, by design: the frontend has to read it to echo it back. That is
// safe because the token's job is to prove same-origin script access, not to be
// a secret from the page itself.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request, secure bool) string {
	if c, err := r.Cookie(CSRFCookieName); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   12 * 3600,
	})
	return token
}
