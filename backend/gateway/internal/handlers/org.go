package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/httpx"
	"github.com/logmonitor/gateway/internal/store"
)

func (a *API) listOrgUsers(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	users, err := a.Store.ListOrgUsers(r.Context(), caller.OrgID)
	if err != nil {
		a.Log.Error("list org users failed", "event", "org.list_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not list users")
		return
	}
	out := make([]userResponse, 0, len(users))
	for i := range users {
		out = append(out, toUserResponse(&users[i]))
	}
	httpx.JSON(w, http.StatusOK, out)
}

type inviteRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// inviteMember adds a user to the caller's organization.
//
// This creates the account with a password directly rather than emailing a
// link, because there is no mail transport in this system. The seam is here:
// swap the body for a signed invite token when one exists.
func (a *API) inviteMember(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	if !caller.Role.IsAdmin() {
		httpx.Fail(w, http.StatusForbidden, "Only an administrator can invite members")
		return
	}

	var req inviteRequest
	if err := httpx.Decode(w, r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if !strings.Contains(req.Email, "@") {
		httpx.Fail(w, http.StatusBadRequest, "A valid email is required")
		return
	}
	if len(req.Password) < minPasswordLen {
		httpx.Fail(w, http.StatusBadRequest, "Password must be at least 10 characters")
		return
	}

	role := store.Role(req.Role)
	switch role {
	case "":
		role = store.RoleMember
	case store.RoleMember, store.RoleAdmin:
		// fine
	case store.RoleOwner:
		// Only an owner may mint another owner; an admin promoting themselves a
		// peer owner would be a privilege escalation.
		if caller.Role != store.RoleOwner {
			httpx.Fail(w, http.StatusForbidden, "Only the organization owner can create another owner")
			return
		}
	default:
		httpx.Fail(w, http.StatusBadRequest, "Role must be one of: member, admin, owner")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "Could not create account")
		return
	}

	user, err := a.Store.CreateMember(r.Context(), caller.OrgID, req.Email, hash, role)
	if errors.Is(err, store.ErrEmailTaken) {
		httpx.Fail(w, http.StatusConflict, "That email is already registered")
		return
	}
	if err != nil {
		a.Log.Error("invite failed", "event", "org.invite_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not create account")
		return
	}

	actor, id := caller.ID, user.ID
	if err := a.Store.Audit(r.Context(), caller.OrgID, &actor, "member.invited", "user", &id,
		map[string]any{"email": user.Email, "role": string(user.Role)}); err != nil {
		a.Log.Error("audit write failed", "event", "audit.failed", "action", "member.invited", "err", err)
	}

	httpx.JSON(w, http.StatusCreated, toUserResponse(user))
}
