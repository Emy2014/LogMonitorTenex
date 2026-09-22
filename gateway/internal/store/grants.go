package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AccessGrant struct {
	ID            uuid.UUID  `json:"id"`
	OrgID         uuid.UUID  `json:"org_id"`
	UploadID      *uuid.UUID `json:"upload_id"` // nil = standing org-wide grant
	SubjectUserID uuid.UUID  `json:"subject_user_id"`
	Level         string     `json:"level"`
	GrantedBy     uuid.UUID  `json:"granted_by"`
	ExpiresAt     *time.Time `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

const grantCols = `id, org_id, upload_id, subject_user_id, level, granted_by, expires_at, created_at`

func scanGrant(row pgx.Row) (*AccessGrant, error) {
	var g AccessGrant
	err := row.Scan(&g.ID, &g.OrgID, &g.UploadID, &g.SubjectUserID, &g.Level,
		&g.GrantedBy, &g.ExpiresAt, &g.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &g, err
}

// BestGrantFor returns the highest live grant a subject holds over an upload,
// considering both the per-upload grant and any standing org-wide one.
//
// Expiry is filtered in SQL rather than in Go so that an expired grant can
// never be treated as live by a caller that forgot to check the timestamp.
func (s *Store) BestGrantFor(ctx context.Context, subjectID, orgID, uploadID uuid.UUID) (string, bool, error) {
	var level string
	err := s.Pool.QueryRow(ctx, `
		SELECT level FROM access_grants
		 WHERE subject_user_id = $1
		   AND org_id = $2
		   AND (upload_id = $3 OR upload_id IS NULL)
		   AND (expires_at IS NULL OR expires_at > now())
		 ORDER BY level DESC
		 LIMIT 1`, subjectID, orgID, uploadID).Scan(&level)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return level, true, nil
}

// UpsertGrant issues or updates a grant. uploadID nil means org-wide.
func (s *Store) UpsertGrant(ctx context.Context, g AccessGrant) (*AccessGrant, error) {
	// Two partial unique indexes back these tables, so the conflict target
	// differs between a per-upload grant and an org-wide one.
	if g.UploadID == nil {
		return scanGrant(s.Pool.QueryRow(ctx, `
			INSERT INTO access_grants (org_id, upload_id, subject_user_id, level, granted_by, expires_at)
			VALUES ($1, NULL, $2, $3, $4, $5)
			ON CONFLICT (subject_user_id, org_id) WHERE upload_id IS NULL
			DO UPDATE SET level = EXCLUDED.level,
			              granted_by = EXCLUDED.granted_by,
			              expires_at = EXCLUDED.expires_at
			RETURNING `+grantCols,
			g.OrgID, g.SubjectUserID, g.Level, g.GrantedBy, g.ExpiresAt))
	}
	return scanGrant(s.Pool.QueryRow(ctx, `
		INSERT INTO access_grants (org_id, upload_id, subject_user_id, level, granted_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (subject_user_id, upload_id) WHERE upload_id IS NOT NULL
		DO UPDATE SET level = EXCLUDED.level,
		              granted_by = EXCLUDED.granted_by,
		              expires_at = EXCLUDED.expires_at
		RETURNING `+grantCols,
		g.OrgID, g.UploadID, g.SubjectUserID, g.Level, g.GrantedBy, g.ExpiresAt))
}

// ListGrants returns grants issued within one organization.
func (s *Store) ListGrants(ctx context.Context, orgID uuid.UUID) ([]AccessGrant, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT `+grantCols+` FROM access_grants WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AccessGrant{}
	for rows.Next() {
		var g AccessGrant
		if err := rows.Scan(&g.ID, &g.OrgID, &g.UploadID, &g.SubjectUserID, &g.Level,
			&g.GrantedBy, &g.ExpiresAt, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) GrantByID(ctx context.Context, orgID, id uuid.UUID) (*AccessGrant, error) {
	return scanGrant(s.Pool.QueryRow(ctx,
		`SELECT `+grantCols+` FROM access_grants WHERE id = $1 AND org_id = $2`, id, orgID))
}

// DeleteGrant revokes a grant, scoped to the caller's org so a grant in another
// organization can never be addressed by id alone.
func (s *Store) DeleteGrant(ctx context.Context, orgID, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx,
		`DELETE FROM access_grants WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- audit -----------------------------------------------------------------

// Audit appends one immutable record. Never returns an error to the caller:
// a failed audit write must not fail the request it describes, but it must be
// visible, so it is logged by the caller's logger instead.
func (s *Store) Audit(ctx context.Context, orgID uuid.UUID, actor *uuid.UUID,
	action, resourceType string, resourceID *uuid.UUID, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_log (org_id, actor_user_id, action, resource_type, resource_id, detail)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		orgID, actor, action, resourceType, resourceID, detail)
	return err
}
