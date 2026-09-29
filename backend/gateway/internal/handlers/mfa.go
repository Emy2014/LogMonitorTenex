package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/httpx"
	"github.com/logmonitor/gateway/internal/mfa"
	"github.com/logmonitor/gateway/internal/store"
)

// enrollMFA stages a secret and returns the provisioning URI plus fresh
// recovery codes. Nothing is enabled until activateMFA confirms a real code,
// so abandoning enrolment here leaves the account exactly as it was.
func (a *API) enrollMFA(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	if len(a.Cfg.TOTPEncryptionKey) != 32 {
		httpx.Fail(w, http.StatusServiceUnavailable, "Multi-factor authentication is not configured on this server")
		return
	}

	secret, uri, err := mfa.GenerateSecret(caller.Email)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not start enrolment")
		return
	}
	sealed, err := mfa.Encrypt(secret, a.Cfg.TOTPEncryptionKey)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not start enrolment")
		return
	}
	if err := a.Store.StagePendingSecret(r.Context(), caller.ID, sealed); err != nil {
		a.Log.Error("stage secret failed", "event", "mfa.stage_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not start enrolment")
		return
	}

	httpx.JSON(w, http.StatusOK, map[string]any{
		"provisioning_uri": uri,
		"secret":           secret, // shown once, for manual entry
	})
}

type codeRequest struct {
	Code string `json:"code"`
}

// activateMFA confirms enrolment and hands back the recovery codes, shown once.
func (a *API) activateMFA(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())

	var req codeRequest
	if err := httpx.Decode(w, r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}

	state, err := a.Store.MFAState(r.Context(), caller.ID)
	if err != nil || state.Secret == nil {
		httpx.Fail(w, http.StatusBadRequest, "Start enrolment first")
		return
	}
	secret, err := mfa.Decrypt(state.Secret, a.Cfg.TOTPEncryptionKey)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not read the stored secret")
		return
	}
	ok, step, _ := mfa.Validate(req.Code, secret)
	if !ok {
		httpx.Fail(w, http.StatusBadRequest, "That code is not valid")
		return
	}
	// Burn the step here as well as in verify. Otherwise the code just used to
	// activate could be replayed against the login second factor for the
	// remainder of its 30-second window -- "used once" has to mean once
	// across every endpoint that accepts a code, not once per endpoint.
	if fresh, err := a.Limiter.Consume(r.Context(),
		fmt.Sprintf("totp:%s:%s", caller.ID, step), 90*time.Second); err == nil && !fresh {
		httpx.Fail(w, http.StatusBadRequest, "That code has already been used")
		return
	}

	codes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not generate recovery codes")
		return
	}
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		h, err := auth.HashPassword(mfa.NormalizeRecoveryCode(c))
		if err != nil {
			httpx.Fail(w, http.StatusInternalServerError, "Could not store recovery codes")
			return
		}
		hashes = append(hashes, h)
	}
	if err := a.Store.ActivateMFA(r.Context(), caller.ID, hashes); err != nil {
		a.Log.Error("activate failed", "event", "mfa.activate_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not enable multi-factor authentication")
		return
	}

	actor := caller.ID
	a.audit(r, caller.OrgID, &actor, "mfa.enabled", "user", &actor, nil)
	httpx.JSON(w, http.StatusOK, map[string]any{
		"enabled":        true,
		"recovery_codes": codes, // the only time these are ever returned
	})
}

// verifyMFA is step two of login. It accepts the MFA-pending cookie only.
func (a *API) verifyMFA(w http.ResponseWriter, r *http.Request) {
	user, err := a.Auth.PendingUser(r)
	if err != nil {
		httpx.Fail(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	var req codeRequest
	if err := httpx.Decode(w, r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}

	state, err := a.Store.MFAState(r.Context(), user.ID)
	if err != nil || !state.Enabled || state.Secret == nil {
		httpx.Fail(w, http.StatusBadRequest, "Multi-factor authentication is not enabled")
		return
	}
	secret, err := mfa.Decrypt(state.Secret, a.Cfg.TOTPEncryptionKey)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not read the stored secret")
		return
	}

	if ok, step, _ := mfa.Validate(req.Code, secret); ok {
		// A code stays valid for its whole 30s step, so accepting it twice
		// would let anyone who observed one reuse it inside that window.
		fresh, err := a.Limiter.Consume(r.Context(),
			fmt.Sprintf("totp:%s:%s", user.ID, step), 90*time.Second)
		if err == nil && !fresh {
			a.Log.Warn("TOTP code replayed", "event", "mfa.replay", "user_id", user.ID)
			httpx.Fail(w, http.StatusUnauthorized, "That code has already been used")
			return
		}
		a.completeLogin(w, r, user)
		return
	}

	if a.burnRecoveryCode(r, user, req.Code) {
		actor := user.ID
		a.audit(r, user.OrgID, &actor, "mfa.recovery_code_used", "user", &actor, nil)
		a.completeLogin(w, r, user)
		return
	}

	a.Limiter.RecordFailure(r.Context(), clientIP(r), user.Email)
	httpx.Fail(w, http.StatusUnauthorized, "That code is not valid")
}

// burnRecoveryCode tests the input against each unused hash.
func (a *API) burnRecoveryCode(r *http.Request, user *store.User, input string) bool {
	candidate := mfa.NormalizeRecoveryCode(input)
	if candidate == "" {
		return false
	}
	hashes, err := a.Store.UnusedRecoveryHashes(r.Context(), user.ID)
	if err != nil {
		return false
	}
	for id, h := range hashes {
		ok, err := auth.VerifyPassword(candidate, h)
		if err != nil || !ok {
			continue
		}
		// Burn under a used_at IS NULL guard, so two concurrent requests
		// cannot both spend the same code.
		return a.Store.BurnRecoveryCode(r.Context(), id) == nil
	}
	return false
}

// disableMFA requires a current code, so a hijacked session cannot quietly
// strip the second factor off an account.
func (a *API) disableMFA(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())

	var req codeRequest
	if err := httpx.Decode(w, r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	state, err := a.Store.MFAState(r.Context(), caller.ID)
	if err != nil || !state.Enabled {
		httpx.Fail(w, http.StatusBadRequest, "Multi-factor authentication is not enabled")
		return
	}
	if state.OrgRequire {
		httpx.Fail(w, http.StatusForbidden, "Your organization requires multi-factor authentication")
		return
	}
	secret, err := mfa.Decrypt(state.Secret, a.Cfg.TOTPEncryptionKey)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not read the stored secret")
		return
	}
	if ok, _, _ := mfa.Validate(req.Code, secret); !ok && !a.burnRecoveryCode(r, caller, req.Code) {
		httpx.Fail(w, http.StatusUnauthorized, "That code is not valid")
		return
	}

	if err := a.Store.DisableMFA(r.Context(), caller.ID); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not disable multi-factor authentication")
		return
	}
	actor := caller.ID
	a.audit(r, caller.OrgID, &actor, "mfa.disabled", "user", &actor, nil)
	w.WriteHeader(http.StatusNoContent)
}

// resetMemberMFA lets an admin clear a colleague's second factor after an
// out-of-band identity check (lost phone, no recovery codes).
//
// An admin may NOT reset their own. That would not be a recovery path, it
// would be a self-service bypass of the control -- anyone who takes over an
// admin session could strip the factor and keep the account.
func (a *API) resetMemberMFA(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	if !caller.Role.IsAdmin() {
		httpx.Fail(w, http.StatusForbidden, "Only an administrator can reset multi-factor authentication")
		return
	}

	targetID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "id must be a uuid")
		return
	}
	if targetID == caller.ID {
		httpx.Fail(w, http.StatusForbidden,
			"You cannot reset your own second factor; ask another administrator")
		return
	}

	target, err := a.Store.UserByID(r.Context(), targetID)
	if err != nil || target.OrgID != caller.OrgID {
		httpx.Fail(w, http.StatusNotFound, "No such user in this organization")
		return
	}
	if err := a.Store.DisableMFA(r.Context(), target.ID); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not reset multi-factor authentication")
		return
	}

	actor := caller.ID
	a.audit(r, caller.OrgID, &actor, "mfa.reset_by_admin", "user", &target.ID,
		map[string]any{"target_email": target.Email})
	a.Log.Warn("admin reset a member's second factor",
		"event", "mfa.admin_reset", "actor", caller.ID, "target", target.ID)
	w.WriteHeader(http.StatusNoContent)
}

// setOrgMFAPolicy turns the org-wide requirement on or off.
func (a *API) setOrgMFAPolicy(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	if !caller.Role.IsAdmin() {
		httpx.Fail(w, http.StatusForbidden, "Only an administrator can change this policy")
		return
	}
	var req struct {
		RequireMFA bool `json:"require_mfa"`
	}
	if err := httpx.Decode(w, r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.Store.SetOrgRequireMFA(r.Context(), caller.OrgID, req.RequireMFA); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not update the policy")
		return
	}
	actor := caller.ID
	a.audit(r, caller.OrgID, &actor, "org.mfa_policy_changed", "organization", &caller.OrgID,
		map[string]any{"require_mfa": req.RequireMFA})
	httpx.JSON(w, http.StatusOK, map[string]any{"require_mfa": req.RequireMFA})
}
