// Package authz answers one question: what may this caller see of this upload?
//
// Every handler that touches upload-scoped data goes through Require. The point
// of concentrating it here is that the awkward parts -- admin break-glass and
// its audit record, the 404-vs-403 distinction, expiry -- are decided once
// rather than re-derived, slightly differently, in each handler.
package authz

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"

	"github.com/logmonitor/gateway/internal/store"
)

// Level is the access tier. The ordering is the permission lattice: a caller
// holding a level may do anything defined for a lower one.
type Level int

const (
	LevelNone Level = iota
	LevelSummary
	LevelDashboard
	LevelFull
)

func ParseLevel(s string) (Level, bool) {
	switch s {
	case "summary":
		return LevelSummary, true
	case "dashboard":
		return LevelDashboard, true
	case "full":
		return LevelFull, true
	}
	return LevelNone, false
}

func (l Level) String() string {
	switch l {
	case LevelSummary:
		return "summary"
	case LevelDashboard:
		return "dashboard"
	case LevelFull:
		return "full"
	}
	return "none"
}

var (
	// ErrNotFound is returned when the caller may not know the upload exists.
	// Cross-org and same-org-no-access both map here on purpose: a 403 would
	// confirm that a given id is real, which is itself a disclosure.
	ErrNotFound = errors.New("upload not found")
	// ErrForbidden means the caller has some access, just not enough.
	ErrForbidden = errors.New("insufficient access level")
)

type Resolver struct {
	store *store.Store
	log   *slog.Logger
}

func New(s *store.Store, log *slog.Logger) *Resolver {
	return &Resolver{store: s, log: log}
}

// Resolve reports the caller's effective tier over an upload, without applying
// any requirement. Used for shaping a response (which panels to include),
// never as the sole gate on a read -- that is Require's job.
func (r *Resolver) Resolve(ctx context.Context, caller *store.User, uploadID uuid.UUID) (Level, *store.Upload, error) {
	up, err := r.store.UploadByID(ctx, uploadID)
	if err != nil {
		return LevelNone, nil, ErrNotFound
	}

	// Another organization's upload does not exist as far as this caller is
	// concerned. Checked before anything else, so no later branch can leak it.
	if up.OrgID != caller.OrgID {
		return LevelNone, nil, ErrNotFound
	}

	// The uploader always holds full access to their own file.
	if up.UserID == caller.ID {
		return LevelFull, up, nil
	}

	best := LevelNone
	if lvl, ok, err := r.store.BestGrantFor(ctx, caller.ID, caller.OrgID, uploadID); err != nil {
		return LevelNone, nil, err
	} else if ok {
		if parsed, valid := ParseLevel(lvl); valid {
			best = parsed
		}
	}

	// An admin sees org-wide aggregates and summaries by default, because
	// oversight is their job -- but not raw log lines, which are employee
	// browsing history. Raw access is available via break-glass in Require.
	if caller.Role.IsAdmin() && best < LevelDashboard {
		best = LevelDashboard
	}

	if best == LevelNone {
		return LevelNone, nil, ErrNotFound
	}
	return best, up, nil
}

// Require enforces a minimum tier and returns the caller's effective level.
//
// An admin who falls short is escalated rather than refused, and the escalation
// is written to the audit log. Refusing outright would make real incident
// response impossible; allowing it silently is what would make this
// surveillance software. The audit record is the difference.
func (r *Resolver) Require(ctx context.Context, caller *store.User, uploadID uuid.UUID, need Level) (Level, *store.Upload, error) {
	level, up, err := r.Resolve(ctx, caller, uploadID)
	if err != nil {
		return LevelNone, nil, err
	}
	if level >= need {
		return level, up, nil
	}

	if !caller.Role.IsAdmin() {
		return level, up, ErrForbidden
	}

	actor := caller.ID
	id := uploadID
	if auditErr := r.store.Audit(ctx, caller.OrgID, &actor,
		"breakglass.raw_access", "upload", &id, map[string]any{
			"granted_level":  level.String(),
			"required_level": need.String(),
			"role":           string(caller.Role),
			"upload_owner":   up.UserID.String(),
		}); auditErr != nil {
		// The audit record is the entire justification for allowing this. If it
		// cannot be written, the access does not happen.
		r.log.Error("break-glass audit write failed; denying access",
			"event", "authz.audit_failed", "upload_id", uploadID, "err", auditErr)
		return level, up, ErrForbidden
	}

	r.log.Warn("admin break-glass access to raw log data",
		"event", "authz.breakglass", "upload_id", uploadID,
		"actor", caller.ID, "org_id", caller.OrgID)
	return need, up, nil
}
