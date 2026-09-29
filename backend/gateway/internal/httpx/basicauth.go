package httpx

import (
	"crypto/subtle"
	"net/http"
)

// BasicAuth is a coarse shared-credential gate in front of everything.
//
// It is explicitly NOT the security boundary -- per-user authentication and the
// authz resolver are. It exists so that opportunistic scanners never reach the
// real login endpoint at all, which shrinks the attack surface without
// pretending to replace anything.
//
// Note the placement problem it does not solve on its own: the browser talks to
// Next.js, whose proxy calls this service server-side. A gate here alone would
// be satisfied invisibly by the proxy and never challenge a browser, so the
// same gate also lives in web/src/middleware.ts. This one covers direct access
// to the API port.
func BasicAuth(enabled bool, user, passHash string, verify func(pw, hash string) (bool, error), exempt map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if exempt[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			gotUser, gotPass, ok := r.BasicAuth()
			if !ok {
				challenge(w)
				return
			}

			// Constant-time on the username too. Comparing it with == leaks its
			// length and prefix through timing, and there is no reason to
			// treat it as less sensitive than the password.
			userOK := subtle.ConstantTimeCompare([]byte(gotUser), []byte(user)) == 1
			passOK, err := verify(gotPass, passHash)
			if err != nil || !passOK || !userOK {
				challenge(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="LogMonitor", charset="UTF-8"`)
	Fail(w, http.StatusUnauthorized, "Not authenticated")
}
