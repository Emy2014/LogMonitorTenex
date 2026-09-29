package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/logmonitor/gateway/internal/store"
)

const (
	CookieName    = "logmonitor_session"
	MFACookieName = "logmonitor_mfa"
	TokenTTL      = 12 * time.Hour
	// Long enough to fetch a code from a phone, short enough that an
	// intercepted half-authenticated token is near-worthless.
	MFATokenTTL = 5 * time.Minute

	// A token's purpose is checked on every use. Without this, the token
	// issued after a correct password but BEFORE the second factor would
	// authenticate every other endpoint -- which would make MFA decorative.
	PurposeSession = "session"
	PurposeMFA     = "mfa_pending"
)

var ErrUnauthenticated = errors.New("unauthenticated")

// Claims carries org and role alongside the subject so the common authorization
// questions can be answered without a database round trip. The user row is
// still loaded per request -- a role revoked mid-session must take effect
// immediately, and a token that outlives the revocation would not.
type Claims struct {
	OrgID   string `json:"org"`
	Role    string `json:"role"`
	Purpose string `json:"pur"`
	jwt.RegisteredClaims
}

type Manager struct {
	secret       []byte
	cookieSecure bool
	store        *store.Store
}

func NewManager(secret string, cookieSecure bool, s *store.Store) *Manager {
	return &Manager{secret: []byte(secret), cookieSecure: cookieSecure, store: s}
}

func (m *Manager) Issue(u *store.User) (string, error) {
	return m.issue(u, PurposeSession, TokenTTL)
}

// IssueMFAPending mints a token that authorises nothing except completing the
// second factor.
func (m *Manager) IssueMFAPending(u *store.User) (string, error) {
	return m.issue(u, PurposeMFA, MFATokenTTL)
}

func (m *Manager) issue(u *store.User, purpose string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		OrgID:   u.OrgID.String(),
		Role:    string(u.Role),
		Purpose: purpose,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
}

func (m *Manager) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		// v1 omitted Secure entirely. Over plain http in development that flag
		// would stop the cookie being stored at all, hence the config knob.
		Secure:   m.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(TokenTTL.Seconds()),
	})
}

func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: m.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func (m *Manager) parse(token string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		// Pin the algorithm. Accepting whatever the token declares is how a
		// signed token gets swapped for an unsigned one.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return claims, nil
}

type ctxKey int

const userKey ctxKey = iota

// UserFrom returns the authenticated user placed by Require.
func UserFrom(ctx context.Context) *store.User {
	u, _ := ctx.Value(userKey).(*store.User)
	return u
}

// Require authenticates the request or responds 401.
func (m *Manager) Require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil {
			unauthorized(w)
			return
		}
		claims, err := m.parse(c.Value)
		if err != nil {
			unauthorized(w)
			return
		}
		// A half-authenticated token must never satisfy an ordinary request.
		if claims.Purpose != PurposeSession {
			unauthorized(w)
			return
		}
		id, err := uuid.Parse(claims.Subject)
		if err != nil {
			unauthorized(w)
			return
		}
		// Re-read the user every request: the token says what was true when it
		// was issued, the row says what is true now.
		u, err := m.store.UserByID(r.Context(), id)
		if err != nil {
			unauthorized(w)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	}
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"detail":"Not authenticated"}`))
}

// SetMFACookie stores the half-authenticated token. Always HttpOnly and always
// short-lived; it is cleared the moment the second factor succeeds or fails.
func (m *Manager) SetMFACookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: MFACookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: m.cookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: int(MFATokenTTL.Seconds()),
	})
}

func (m *Manager) ClearMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: MFACookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: m.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// PendingUser resolves the user behind an MFA-pending cookie, rejecting a
// full session token presented in its place.
func (m *Manager) PendingUser(r *http.Request) (*store.User, error) {
	c, err := r.Cookie(MFACookieName)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	claims, err := m.parse(c.Value)
	if err != nil || claims.Purpose != PurposeMFA {
		return nil, ErrUnauthenticated
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return m.store.UserByID(r.Context(), id)
}
