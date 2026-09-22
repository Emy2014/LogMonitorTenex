package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/httpx"
	"github.com/logmonitor/gateway/internal/store"
)

type registerRequest struct {
	OrgName  string `json:"org_name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
	OrgID string `json:"org_id"`
}

func toUserResponse(u *store.User) userResponse {
	return userResponse{ID: u.ID.String(), Email: u.Email, Role: string(u.Role), OrgID: u.OrgID.String()}
}

const minPasswordLen = 10

// One message for every credential failure. The value is referenced rather
// than repeated so the responses cannot drift apart later.
const invalidCredentials = "Invalid email or password"

// A real argon2id hash of an unguessable value, verified against when the
// account does not exist so the timing matches the real path.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// register creates an organization and its owner. There is no self-service
// path into an existing org: joining one requires an invite from its admin,
// otherwise anyone who guessed a slug could enrol themselves as a tenant.
func (a *API) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := httpx.Decode(w, r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	req.OrgName = strings.TrimSpace(req.OrgName)
	if req.OrgName == "" || !strings.Contains(req.Email, "@") {
		httpx.Fail(w, http.StatusBadRequest, "Organization name and a valid email are required")
		return
	}
	if len(req.Password) < minPasswordLen {
		httpx.Fail(w, http.StatusBadRequest, "Password must be at least 10 characters")
		return
	}

	slug := slugify(req.OrgName)
	if slug == "" {
		httpx.Fail(w, http.StatusBadRequest, "Organization name must contain letters or digits")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		a.Log.Error("hash failed", "event", "auth.hash_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not create account")
		return
	}

	_, user, err := a.Store.CreateOrgWithOwner(r.Context(), req.OrgName, slug, req.Email, hash)
	switch {
	case errors.Is(err, store.ErrEmailTaken):
		httpx.Fail(w, http.StatusConflict, "That email is already registered")
		return
	case errors.Is(err, store.ErrSlugTaken):
		httpx.Fail(w, http.StatusConflict, "An organization with that name already exists")
		return
	case err != nil:
		a.Log.Error("register failed", "event", "auth.register_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not create account")
		return
	}

	token, err := a.Auth.Issue(user)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not create session")
		return
	}
	a.Auth.SetCookie(w, token)
	a.Log.Info("organization registered", "event", "auth.registered",
		"org_id", user.OrgID, "user_id", user.ID)
	httpx.JSON(w, http.StatusCreated, toUserResponse(user))
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httpx.Decode(w, r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	email := strings.TrimSpace(req.Email)
	ip := clientIP(r)

	// Throttle before doing any work. argon2id is deliberately expensive, so
	// an unthrottled login endpoint is also a CPU amplification target.
	if a.Limiter != nil && a.Cfg.LoginRateEnabled {
		switch d := a.Limiter.Check(r.Context(), ip, email); {
		case d.IPThrottled:
			// 429 is safe here: it describes the client, and says nothing
			// about whether any particular account exists.
			if d.RetryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(d.RetryAfter.Seconds())+1))
			}
			a.Log.Warn("login throttled by IP", "event", "auth.throttled", "ip", ip)
			httpx.Fail(w, http.StatusTooManyRequests, "Too many attempts. Try again shortly.")
			return
		case d.AccountLocked:
			// Byte-identical to a wrong password, on purpose. A distinct
			// "locked" response would be an account-existence oracle and
			// would undo the equal-response handling below.
			a.Log.Warn("login attempt on a locked account", "event", "auth.locked", "ip", ip)
			httpx.Fail(w, http.StatusUnauthorized, invalidCredentials)
			return
		}
	}

	user, err := a.Store.UserByEmail(r.Context(), email)
	if err != nil {
		// Same response and roughly the same cost as a wrong password: a
		// distinguishable "no such user" turns login into an account oracle.
		_, _ = auth.VerifyPassword(req.Password, dummyHash)
		a.recordLoginFailure(r, ip, email)
		httpx.Fail(w, http.StatusUnauthorized, invalidCredentials)
		return
	}

	ok, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !ok {
		a.recordLoginFailure(r, ip, user.Email)
		httpx.Fail(w, http.StatusUnauthorized, invalidCredentials)
		return
	}

	state, err := a.Store.MFAState(r.Context(), user.ID)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not complete sign in")
		return
	}

	// Correct password but MFA still outstanding: issue a token that
	// authorises nothing but the second-factor exchange.
	if state.Enabled {
		pending, err := a.Auth.IssueMFAPending(user)
		if err != nil {
			httpx.Fail(w, http.StatusInternalServerError, "Could not create session")
			return
		}
		// Drop any session the caller already held. Re-authenticating should
		// not leave a fully-privileged cookie alive alongside a
		// half-authenticated one -- and without this, a client that still had
		// a valid session would appear to sail past the second factor.
		a.Auth.ClearCookie(w)
		a.Auth.SetMFACookie(w, pending)
		httpx.JSON(w, http.StatusOK, map[string]any{"mfa_required": true})
		return
	}

	// Org policy says MFA is mandatory and this user has not enrolled. Let them
	// in, but say so, so the UI can force enrolment rather than stranding them.
	if state.OrgRequire {
		a.completeLogin(w, r, user)
		return
	}

	a.completeLogin(w, r, user)
}

// completeLogin issues the real session and clears the throttle counters.
func (a *API) completeLogin(w http.ResponseWriter, r *http.Request, user *store.User) {
	token, err := a.Auth.Issue(user)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not create session")
		return
	}
	a.Auth.ClearMFACookie(w)
	a.Auth.SetCookie(w, token)
	if a.Limiter != nil {
		a.Limiter.Reset(r.Context(), user.Email)
	}

	state, _ := a.Store.MFAState(r.Context(), user.ID)
	httpx.JSON(w, http.StatusOK, map[string]any{
		"id": user.ID.String(), "email": user.Email,
		"role": string(user.Role), "org_id": user.OrgID.String(),
		"mfa_enabled":  state.Enabled,
		"mfa_required": state.OrgRequire && !state.Enabled,
	})
}

func (a *API) recordLoginFailure(r *http.Request, ip, account string) {
	if a.Limiter != nil && a.Cfg.LoginRateEnabled {
		a.Limiter.RecordFailure(r.Context(), ip, account)
	}
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	a.Auth.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// me returns the caller plus the context the app shell needs, so the UI does
// not have to fan out to three endpoints on every page load.
func (a *API) me(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	out := map[string]any{
		"id": caller.ID.String(), "email": caller.Email,
		"role": string(caller.Role), "org_id": caller.OrgID.String(),
	}
	if org, err := a.Store.OrgByID(r.Context(), caller.OrgID); err == nil {
		out["org_name"] = org.Name
		out["org_slug"] = org.Slug
	}
	if state, err := a.Store.MFAState(r.Context(), caller.ID); err == nil {
		out["mfa_enabled"] = state.Enabled
		out["org_require_mfa"] = state.OrgRequire
	}
	httpx.JSON(w, http.StatusOK, out)
}
