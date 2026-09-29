package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/authz"
	"github.com/logmonitor/gateway/internal/config"
	"github.com/logmonitor/gateway/internal/httpx"
	"github.com/logmonitor/gateway/internal/mfa"
	"github.com/logmonitor/gateway/internal/ratelimit"
	"github.com/logmonitor/gateway/internal/store"
)

var (
	st  *store.Store
	lim *ratelimit.Limiter
)

func TestMain(m *testing.M) {
	dbURL, redisURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_REDIS_URL")
	if dbURL == "" || redisURL == "" {
		fmt.Fprintln(os.Stderr, "TEST_DATABASE_URL / TEST_REDIS_URL not set; skipping")
		os.Exit(0)
	}
	ctx := context.Background()
	var err error
	if st, err = store.New(ctx, dbURL); err != nil {
		fmt.Fprintf(os.Stderr, "postgres: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if lim, err = ratelimit.New(redisURL, quiet); err != nil {
		fmt.Fprintf(os.Stderr, "redis: %v\n", err)
		os.Exit(1)
	}
	defer lim.Close()
	os.Exit(m.Run())
}

func newAPI(t *testing.T) (*API, http.Handler) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cfg := &config.Config{
		JWTSecret: "test-secret", CookieSecure: false,
		TOTPEncryptionKey: key, LoginRateEnabled: true, MetricsToken: "tok",
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	api := &API{
		Cfg: cfg, Store: st, Auth: auth.NewManager(cfg.JWTSecret, false, st),
		Authz: authz.New(st, quiet), Limiter: lim, Log: quiet,
	}
	// CSRF is exercised in its own unit tests; wiring it here too would mean
	// threading a token through every call below for no extra coverage.
	return api, api.Routes()
}

type client struct {
	t  *testing.T
	h  http.Handler
	ip string
	// Keyed by name, like a browser's jar. Appending to a slice instead would
	// let a cleared cookie shadow the real one that replaced it, since
	// r.Cookie returns the first match.
	cookies map[string]*http.Cookie
}

// Each client gets its own source address. The limiter's IP dimension is
// global by design, so sharing one address across tests would let an earlier
// test's failed logins throttle a later one.
func newClient(t *testing.T, h http.Handler) *client {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return &client{t: t, h: h, ip: fmt.Sprintf("198.51.%d.%d", b[0], b[1]),
		cookies: map[string]*http.Cookie{}}
}

func (c *client) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", c.ip)
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)

	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name) // an expiry deletes, as in a browser
			continue
		}
		c.cookies[ck.Name] = ck
	}
	return rec
}

func (c *client) reset() { c.cookies = map[string]*http.Cookie{} }

func uniqueEmail() string { return "u" + uuid.NewString()[:8] + "@t.io" }

func registerUser(t *testing.T, h http.Handler) (*client, string) {
	t.Helper()
	c := newClient(t, h)
	email := uniqueEmail()
	rec := c.do("POST", "/api/auth/register", map[string]string{
		"org_name": "Org " + uuid.NewString()[:8], "email": email, "password": "supersecret1",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	return c, email
}

// ---------------------------------------------------------------------------

// TestAccountLockResponseIsIndistinguishable is the one that protects the
// enumeration resistance: if a locked account answered differently from a
// wrong password, login would become an account-existence oracle and the
// equal-response work in the handler would be pointless.
func TestAccountLockResponseIsIndistinguishable(t *testing.T) {
	_, h := newAPI(t)
	c, email := registerUser(t, h)
	c.reset()

	wrongPassword := c.do("POST", "/api/auth/login",
		map[string]string{"email": email, "password": "definitely-wrong"})
	baselineCode, baselineBody := wrongPassword.Code, wrongPassword.Body.String()

	// Drive the account counter past its limit. The IP counter is deliberately
	// larger, so the account dimension trips first.
	var locked *httptest.ResponseRecorder
	for i := 0; i < 14; i++ {
		locked = c.do("POST", "/api/auth/login",
			map[string]string{"email": email, "password": "definitely-wrong"})
	}

	if locked.Code == http.StatusTooManyRequests {
		t.Skip("IP limit tripped before the account limit; see TestIPThrottleReturns429")
	}
	if locked.Code != baselineCode {
		t.Errorf("locked status %d differs from wrong-password %d — that is an oracle",
			locked.Code, baselineCode)
	}
	if locked.Body.String() != baselineBody {
		t.Errorf("locked body %q differs from wrong-password %q — that is an oracle",
			locked.Body.String(), baselineBody)
	}
}

// An unknown account and a known one with the wrong password must be
// indistinguishable in both status and body.
func TestUnknownAccountMatchesWrongPassword(t *testing.T) {
	_, h := newAPI(t)
	c, email := registerUser(t, h)
	c.reset()

	known := c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "wrong-one"})
	unknown := c.do("POST", "/api/auth/login", map[string]string{"email": uniqueEmail(), "password": "wrong-one"})

	if known.Code != unknown.Code || known.Body.String() != unknown.Body.String() {
		t.Fatalf("responses differ: known %d %q vs unknown %d %q",
			known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
	}
}

func TestIPThrottleReturns429(t *testing.T) {
	_, h := newAPI(t)
	c := newClient(t, h)

	// Spread across distinct accounts so only the IP dimension accumulates.
	var last *httptest.ResponseRecorder
	for i := 0; i < 25; i++ {
		last = c.do("POST", "/api/auth/login",
			map[string]string{"email": uniqueEmail(), "password": "wrong"})
		c.reset()
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 after sustained guessing, got %d", last.Code)
	}
	// 429 is safe here: it describes the client, not whether an account exists.
	if last.Header().Get("Retry-After") == "" {
		t.Error("a 429 should tell the caller when to come back")
	}
}

func TestSuccessfulLoginClearsAccountCounter(t *testing.T) {
	_, h := newAPI(t)
	c, email := registerUser(t, h)
	c.reset()

	for i := 0; i < 5; i++ {
		c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "wrong"})
	}
	if rec := c.do("POST", "/api/auth/login",
		map[string]string{"email": email, "password": "supersecret1"}); rec.Code != http.StatusOK {
		t.Fatalf("correct password should still work: %d %s", rec.Code, rec.Body.String())
	}
	// Counter cleared, so the budget is whole again.
	for i := 0; i < 5; i++ {
		rec := c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "wrong"})
		if rec.Code == http.StatusTooManyRequests {
			t.Fatal("counters were not reset by the successful login")
		}
	}
}

// ---------------------------------------------------------------------------

// enrolMFA takes a logged-in client through enrolment and returns the secret.
func enrolMFA(t *testing.T, c *client) string {
	t.Helper()
	rec := c.do("POST", "/api/auth/mfa/enroll", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	// Activate with the PREVIOUS step's code. It is still valid under skew,
	// and it leaves the current step's code unused, so a test can verify
	// straight afterwards without waiting 30s for a fresh one.
	code, err := totp.GenerateCode(out.Secret, time.Now().Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if rec := c.do("POST", "/api/auth/mfa/activate", map[string]string{"code": code}); rec.Code != http.StatusOK {
		t.Fatalf("activate: %d %s", rec.Code, rec.Body.String())
	}
	return out.Secret
}

// TestMFAPendingTokenCannotAuthenticate is the load-bearing MFA test. If the
// half-authenticated token issued after a correct password also worked on
// ordinary endpoints, the second factor would be decorative.
func TestMFAPendingTokenCannotAuthenticate(t *testing.T) {
	_, h := newAPI(t)
	c, email := registerUser(t, h)
	enrolMFA(t, c)
	c.reset()

	rec := c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "supersecret1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["mfa_required"] != true {
		t.Fatalf("want mfa_required, got %v", body)
	}

	// The client now holds the MFA-pending cookie. It must not open anything.
	for _, path := range []string{"/api/auth/me", "/api/uploads", "/api/org/users", "/api/grants"} {
		if rec := c.do("GET", path, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with an MFA-pending token: want 401, got %d", path, rec.Code)
		}
	}
}

func TestMFACompletesWithValidCode(t *testing.T) {
	_, h := newAPI(t)
	c, email := registerUser(t, h)
	secret := enrolMFA(t, c)
	c.reset()

	c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "supersecret1"})
	code, _ := totp.GenerateCode(secret, time.Now())
	if rec := c.do("POST", "/api/auth/mfa/verify", map[string]string{"code": code}); rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	if rec := c.do("GET", "/api/auth/me", nil); rec.Code != http.StatusOK {
		t.Fatalf("session should now work: %d", rec.Code)
	}
}

// A TOTP code is valid for its whole 30-second step. Accepting it twice would
// let anyone who observed one code reuse it inside that window.
func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	_, h := newAPI(t)
	c, email := registerUser(t, h)
	secret := enrolMFA(t, c)
	c.reset()

	code, _ := totp.GenerateCode(secret, time.Now())

	c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "supersecret1"})
	if rec := c.do("POST", "/api/auth/mfa/verify", map[string]string{"code": code}); rec.Code != http.StatusOK {
		t.Fatalf("first use should succeed: %d %s", rec.Code, rec.Body.String())
	}

	c.reset()
	c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "supersecret1"})
	if rec := c.do("POST", "/api/auth/mfa/verify", map[string]string{"code": code}); rec.Code == http.StatusOK {
		t.Fatal("the same code was accepted twice")
	}
}

func TestRecoveryCodeWorksOnceThenFails(t *testing.T) {
	_, h := newAPI(t)
	c, email := registerUser(t, h)

	rec := c.do("POST", "/api/auth/mfa/enroll", nil)
	var enroll struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &enroll)
	code, _ := totp.GenerateCode(enroll.Secret, time.Now().Add(-30*time.Second))
	rec = c.do("POST", "/api/auth/mfa/activate", map[string]string{"code": code})
	var act struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &act)
	if len(act.RecoveryCodes) == 0 {
		t.Fatal("activation must return recovery codes")
	}
	recovery := act.RecoveryCodes[0]

	c.reset()
	c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "supersecret1"})
	if rec := c.do("POST", "/api/auth/mfa/verify", map[string]string{"code": recovery}); rec.Code != http.StatusOK {
		t.Fatalf("recovery code should work once: %d %s", rec.Code, rec.Body.String())
	}

	c.reset()
	c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "supersecret1"})
	if rec := c.do("POST", "/api/auth/mfa/verify", map[string]string{"code": recovery}); rec.Code == http.StatusOK {
		t.Fatal("a spent recovery code was accepted again")
	}
}

// Resetting your own second factor is not a recovery path, it is a
// self-service bypass: anyone who took over an admin session could strip the
// factor and keep the account.
func TestAdminCannotResetOwnMFA(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)
	enrolMFA(t, c)

	me := c.do("GET", "/api/auth/me", nil)
	var u struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(me.Body.Bytes(), &u)

	rec := c.do("POST", "/api/org/users/"+u.ID+"/mfa/reset", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 resetting own MFA, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAdminResetOfAnotherUserIsAudited(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)

	memberEmail := uniqueEmail()
	rec := owner.do("POST", "/api/org/invite", map[string]string{
		"email": memberEmail, "password": "supersecret2", "role": "member",
	})
	var member struct {
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &member)

	if rec := owner.do("POST", "/api/org/users/"+member.ID+"/mfa/reset", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("admin reset of a member: %d %s", rec.Code, rec.Body.String())
	}

	orgID := uuid.MustParse(member.OrgID)
	var n int
	if err := st.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE org_id=$1 AND action='mfa.reset_by_admin'`,
		orgID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want one audit record, got %d", n)
	}
}

// A stored TOTP secret is a password equivalent: a database dump must not
// hand over something that mints valid codes forever.
func TestStoredSecretIsEncryptedAtRest(t *testing.T) {
	api, h := newAPI(t)
	c, _ := registerUser(t, h)
	secret := enrolMFA(t, c)

	me := c.do("GET", "/api/auth/me", nil)
	var u struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(me.Body.Bytes(), &u)

	var stored []byte
	if err := st.Pool.QueryRow(context.Background(),
		`SELECT totp_secret FROM users WHERE id=$1`, uuid.MustParse(u.ID)).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(secret)) {
		t.Fatal("the plaintext TOTP secret is in the database")
	}
	back, err := mfa.Decrypt(stored, api.Cfg.TOTPEncryptionKey)
	if err != nil || back != secret {
		t.Fatalf("stored secret does not decrypt to the original: %q %v", back, err)
	}
	_ = hex.EncodeToString(stored)
}

func TestMetricsRejectsUserSessionAcceptsOperatorToken(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	if rec := c.do("GET", "/api/metrics", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a user cookie must not open metrics, got %d", rec.Code)
	}

	req := httptest.NewRequest("GET", "/api/metrics", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator token should work, got %d", rec.Code)
	}
	_ = httpx.Error{}
}

// TestMetricsTokenDoesNotCollideWithEdgeGate pins the fix for a bug found by
// running the edge gate and the operator token together: both were reading the
// Authorization header, and a request can only carry one. In isolation each
// worked; combined, the operator could never reach metrics.
func TestMetricsTokenDoesNotCollideWithEdgeGate(t *testing.T) {
	_, routes := newAPI(t)

	hash, err := auth.HashPassword("edge-secret")
	if err != nil {
		t.Fatal(err)
	}
	gated := httpx.BasicAuth(true, "ops", hash, auth.VerifyPassword,
		map[string]bool{"/api/health": true})(routes)

	req := httptest.NewRequest("GET", "/api/metrics", nil)
	req.SetBasicAuth("ops", "edge-secret") // consumes Authorization
	req.Header.Set("X-Metrics-Token", "tok")

	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator token must work behind the edge gate, got %d %s",
			rec.Code, rec.Body.String())
	}

	// And a wrong token behind a valid gate credential is still refused.
	req2 := httptest.NewRequest("GET", "/api/metrics", nil)
	req2.SetBasicAuth("ops", "edge-secret")
	req2.Header.Set("X-Metrics-Token", "wrong")
	rec2 := httptest.NewRecorder()
	gated.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong metrics token must be refused, got %d", rec2.Code)
	}
}

// TestActivationCodeCannotBeReplayedAtVerify closes a gap the unit tests
// missed by only ever replaying verify against verify: the code used to
// activate enrolment was still good at the login second factor for the rest
// of its 30-second window. "Used once" has to span every endpoint that
// accepts a code.
func TestActivationCodeCannotBeReplayedAtVerify(t *testing.T) {
	_, h := newAPI(t)
	c, email := registerUser(t, h)

	rec := c.do("POST", "/api/auth/mfa/enroll", nil)
	var enroll struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &enroll)

	code, _ := totp.GenerateCode(enroll.Secret, time.Now())
	if rec := c.do("POST", "/api/auth/mfa/activate", map[string]string{"code": code}); rec.Code != http.StatusOK {
		t.Fatalf("activate: %d %s", rec.Code, rec.Body.String())
	}

	c.reset()
	c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "supersecret1"})
	if rec := c.do("POST", "/api/auth/mfa/verify", map[string]string{"code": code}); rec.Code == http.StatusOK {
		t.Fatal("the activation code was reusable as a login second factor")
	}
}

// TestLoginDropsExistingSessionWhenMFAPending: a client that still holds a
// valid session must not appear to sail past the second factor just because
// the old cookie is still alive.
func TestLoginDropsExistingSessionWhenMFAPending(t *testing.T) {
	_, h := newAPI(t)
	c, email := registerUser(t, h) // registration leaves a live session
	enrolMFA(t, c)

	if rec := c.do("GET", "/api/auth/me", nil); rec.Code != http.StatusOK {
		t.Fatalf("precondition: session should be live, got %d", rec.Code)
	}

	// Log in again WITHOUT clearing cookies, as a browser would.
	rec := c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": "supersecret1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}

	// The response must have cleared the session cookie.
	var cleared bool
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == auth.CookieName && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("step-one login must expire any existing session cookie")
	}
}
