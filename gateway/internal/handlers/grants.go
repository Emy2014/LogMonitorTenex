package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/authz"
	"github.com/logmonitor/gateway/internal/httpx"
	"github.com/logmonitor/gateway/internal/store"
)

type grantRequest struct {
	SubjectUserID string     `json:"subject_user_id"`
	UploadID      *string    `json:"upload_id"` // omitted/null = org-wide
	Level         string     `json:"level"`
	ExpiresAt     *time.Time `json:"expires_at"`
}

func (a *API) listGrants(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	grants, err := a.Store.ListGrants(r.Context(), caller.OrgID)
	if err != nil {
		a.Log.Error("list grants failed", "event", "grants.list_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not list grants")
		return
	}

	// A member has no business seeing who else an admin shared things with;
	// they see only grants they issued or hold.
	if !caller.Role.IsAdmin() {
		filtered := grants[:0]
		for _, g := range grants {
			if g.GrantedBy == caller.ID || g.SubjectUserID == caller.ID {
				filtered = append(filtered, g)
			}
		}
		grants = filtered
	}
	httpx.JSON(w, http.StatusOK, grants)
}

// createGrant issues or updates a grant.
//
// Who may grant what: an upload's owner may share that upload; an admin may
// additionally issue standing org-wide grants. Nobody may grant across orgs,
// and nobody may grant a level they could not themselves justify.
func (a *API) createGrant(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())

	var req grantRequest
	if err := httpx.Decode(w, r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}

	level, ok := authz.ParseLevel(req.Level)
	if !ok {
		httpx.Fail(w, http.StatusBadRequest, "level must be one of: summary, dashboard, full")
		return
	}

	subjectID, err := uuid.Parse(req.SubjectUserID)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "subject_user_id must be a uuid")
		return
	}
	subject, err := a.Store.UserByID(r.Context(), subjectID)
	// Cross-org subjects are reported as not-found rather than forbidden: the
	// caller should not learn that a user id exists in some other tenant.
	if err != nil || subject.OrgID != caller.OrgID {
		httpx.Fail(w, http.StatusNotFound, "No such user in this organization")
		return
	}
	var uploadID *uuid.UUID
	if req.UploadID != nil {
		id, err := uuid.Parse(*req.UploadID)
		if err != nil {
			httpx.Fail(w, http.StatusBadRequest, "upload_id must be a uuid")
			return
		}
		up, err := a.Store.UploadByID(r.Context(), id)
		if err != nil || up.OrgID != caller.OrgID {
			httpx.Fail(w, http.StatusNotFound, "Upload not found")
			return
		}
		// Only the owner or an admin may share a given upload.
		if up.UserID != caller.ID && !caller.Role.IsAdmin() {
			httpx.Fail(w, http.StatusForbidden, "Only the uploader or an administrator can share this upload")
			return
		}
		if up.UserID == subject.ID {
			httpx.Fail(w, http.StatusBadRequest, "That user already owns this upload")
			return
		}
		uploadID = &id
	} else if !caller.Role.IsAdmin() {
		httpx.Fail(w, http.StatusForbidden, "Only an administrator can issue an organization-wide grant")
		return
	}

	// Checked after the permission rules above, not before: whether the caller
	// is allowed to grant at all is the more important question, and answering
	// the convenience one first would report a permission failure as a
	// validation error.
	if subject.ID == caller.ID {
		httpx.Fail(w, http.StatusBadRequest, "You already have access to your own data")
		return
	}

	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		httpx.Fail(w, http.StatusBadRequest, "expires_at is in the past")
		return
	}

	grant, err := a.Store.UpsertGrant(r.Context(), store.AccessGrant{
		OrgID:         caller.OrgID,
		UploadID:      uploadID,
		SubjectUserID: subject.ID,
		Level:         level.String(),
		GrantedBy:     caller.ID,
		ExpiresAt:     req.ExpiresAt,
	})
	if err != nil {
		a.Log.Error("grant upsert failed", "event", "grants.create_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not create grant")
		return
	}

	actor := caller.ID
	scope := "org"
	if uploadID != nil {
		scope = "upload"
	}
	if err := a.Store.Audit(r.Context(), caller.OrgID, &actor, "grant.created", "access_grant", &grant.ID,
		map[string]any{"subject": subject.ID.String(), "level": grant.Level, "scope": scope}); err != nil {
		a.Log.Error("audit write failed", "event", "audit.failed", "action", "grant.created", "err", err)
	}

	a.Log.Info("access granted", "event", "grants.created", "org_id", caller.OrgID,
		"actor", caller.ID, "subject", subject.ID, "level", grant.Level, "scope", scope)
	httpx.JSON(w, http.StatusCreated, grant)
}

func (a *API) deleteGrant(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "id must be a uuid")
		return
	}

	grant, err := a.Store.GrantByID(r.Context(), caller.OrgID, id)
	if err != nil {
		httpx.Fail(w, http.StatusNotFound, "Grant not found")
		return
	}
	// Revocable by whoever issued it, or by any admin.
	if grant.GrantedBy != caller.ID && !caller.Role.IsAdmin() {
		httpx.Fail(w, http.StatusForbidden, "Only the granter or an administrator can revoke this")
		return
	}

	if err := a.Store.DeleteGrant(r.Context(), caller.OrgID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Fail(w, http.StatusNotFound, "Grant not found")
			return
		}
		httpx.Fail(w, http.StatusInternalServerError, "Could not revoke grant")
		return
	}

	actor := caller.ID
	if err := a.Store.Audit(r.Context(), caller.OrgID, &actor, "grant.revoked", "access_grant", &id,
		map[string]any{"subject": grant.SubjectUserID.String(), "level": grant.Level}); err != nil {
		a.Log.Error("audit write failed", "event", "audit.failed", "action", "grant.revoked", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listUploads(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	uploads, err := a.Store.ListVisibleUploads(r.Context(), caller)
	if err != nil {
		a.Log.Error("list uploads failed", "event", "uploads.list_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not list uploads")
		return
	}
	httpx.JSON(w, http.StatusOK, uploads)
}
