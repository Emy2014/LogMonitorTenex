package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

// verify stands in for auth.VerifyPassword; the real one is argon2id.
func verify(pw, hash string) (bool, error) { return pw == hash, nil }

func TestBasicAuthChallengesWithoutCredentials(t *testing.T) {
	h := BasicAuth(true, "ops", "s3cret", verify, nil)(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/uploads", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	// Without this header the browser never shows its credential prompt, so
	// the gate would just look like a broken site.
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("want a Basic challenge, got %q", got)
	}
}

func TestBasicAuthRejectsWrongCredentials(t *testing.T) {
	h := BasicAuth(true, "ops", "s3cret", verify, nil)(okHandler())
	for _, tc := range []struct{ user, pass string }{
		{"ops", "wrong"}, {"wrong", "s3cret"}, {"", ""}, {"ops", ""},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/uploads", nil)
		req.SetBasicAuth(tc.user, tc.pass)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%q/%q: want 401, got %d", tc.user, tc.pass, rec.Code)
		}
	}
}

func TestBasicAuthAcceptsCorrectCredentials(t *testing.T) {
	h := BasicAuth(true, "ops", "s3cret", verify, nil)(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/uploads", nil)
	req.SetBasicAuth("ops", "s3cret")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

// The container healthcheck runs unauthenticated; gating it would make the
// service report itself permanently unhealthy.
func TestBasicAuthExemptsHealth(t *testing.T) {
	h := BasicAuth(true, "ops", "s3cret", verify, map[string]bool{"/api/health": true})(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health must be reachable without credentials, got %d", rec.Code)
	}
}

func TestBasicAuthDisabledIsPassThrough(t *testing.T) {
	h := BasicAuth(false, "", "", verify, nil)(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/uploads", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 when disabled, got %d", rec.Code)
	}
}

// --- CSRF -------------------------------------------------------------------

func TestCSRFIssuesTokenOnSafeRequest(t *testing.T) {
	h := CSRF(false, nil)(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/uploads", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET must pass, got %d", rec.Code)
	}
	var token string
	for _, c := range rec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			token = c.Value
			// The frontend has to read this to echo it back.
			if c.HttpOnly {
				t.Error("the CSRF cookie must not be HttpOnly")
			}
		}
	}
	if len(token) < 32 {
		t.Fatalf("want a token of real length, got %q", token)
	}
}

func TestCSRFRejectsUnsafeRequestWithoutToken(t *testing.T) {
	h := CSRF(false, nil)(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/grants", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

func TestCSRFRejectsMismatchedToken(t *testing.T) {
	h := CSRF(false, nil)(okHandler())
	req := httptest.NewRequest("POST", "/api/grants", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: strings.Repeat("a", 43)})
	req.Header.Set(CSRFHeaderName, strings.Repeat("b", 43))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a header that does not match the cookie must be refused, got %d", rec.Code)
	}
}

func TestCSRFAcceptsMatchingToken(t *testing.T) {
	h := CSRF(false, nil)(okHandler())
	token := strings.Repeat("a", 43)
	req := httptest.NewRequest("POST", "/api/grants", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req.Header.Set(CSRFHeaderName, token)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

// Login is NOT exempt: forcing a victim into the attacker's session is a real
// attack, and everything they upload afterwards lands in the wrong account.
func TestCSRFCoversLogin(t *testing.T) {
	h := CSRF(false, map[string]bool{"/api/health": true})(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/auth/login", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login must require a CSRF token, got %d", rec.Code)
	}
}

// --- headers ----------------------------------------------------------------

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	SecurityHeaders(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/api/health", nil))

	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// Over plain http, HSTS is meaningless and in local development it would
	// pin localhost to https in the browser for a year.
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS must not be sent over plain http, got %q", got)
	}
}

func TestHSTSSentBehindTLSTerminatingProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/health", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	SecurityHeaders(okHandler()).ServeHTTP(rec, req)

	if got := rec.Header().Get("Strict-Transport-Security"); !strings.Contains(got, "max-age=") {
		t.Fatalf("want HSTS behind an https proxy, got %q", got)
	}
}
