package store

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// uploadFields is the column order every upload query selects and every scan
// reads, so the two cannot drift. Qualified with uploadCols when a join makes
// a bare column name ambiguous.
var uploadFields = []string{
	"id", "org_id", "user_id", "filename", "byte_size",
	"line_count", "parsed_count", "format", "object_key", "created_at",
}

var uploadCols = strings.Join(uploadFields, ", ")

// uploadColsFor qualifies the same list with a table alias.
func uploadColsFor(alias string) string {
	return alias + "." + strings.Join(uploadFields, ", "+alias+".")
}

// uploadDest is the scan target list for uploadFields, in the same order.
func uploadDest(u *Upload) []any {
	return []any{&u.ID, &u.OrgID, &u.UserID, &u.Filename, &u.ByteSize,
		&u.LineCount, &u.ParsedCount, &u.Format, &u.ObjectKey, &u.CreatedAt}
}

func scanUpload(row pgx.Row) (*Upload, error) {
	var u Upload
	err := row.Scan(uploadDest(&u)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (s *Store) UploadByID(ctx context.Context, id uuid.UUID) (*Upload, error) {
	return scanUpload(s.Pool.QueryRow(ctx,
		`SELECT `+uploadCols+` FROM uploads WHERE id = $1`, id))
}

// UploadListItem is an upload as the list shows it: the row plus the state of
// its most recent analysis, so the page can say "analysing" or show the risk
// without a request per upload.
type UploadListItem struct {
	Upload
	AnalysisID     *uuid.UUID `json:"analysis_id"`
	AnalysisStatus *string    `json:"analysis_status"`
	OverallRisk    *string    `json:"overall_risk"`
}

// ListVisibleUploads returns the uploads a caller may see at all: their own,
// plus any covered by a live grant, plus -- for an admin -- every upload in
// their organization.
//
// The visibility rule is expressed once, in SQL, so the list endpoint and the
// per-upload resolver cannot drift apart and start disagreeing about what
// exists.
func (s *Store) ListVisibleUploads(ctx context.Context, caller *User) ([]UploadListItem, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT `+uploadColsFor("u")+`,
		       la.id, la.status::text, la.overall_risk::text
		  FROM uploads u
		  LEFT JOIN LATERAL (
		        SELECT a.id, a.status, a.overall_risk
		          FROM analyses a
		         WHERE a.upload_id = u.id
		         ORDER BY a.created_at DESC
		         LIMIT 1
		  ) la ON true
		 WHERE u.org_id = $1
		   AND (
		        u.user_id = $2
		     OR $3::bool
		     OR EXISTS (
		            SELECT 1 FROM access_grants g
		             WHERE g.subject_user_id = $2
		               AND g.org_id = u.org_id
		               AND (g.upload_id = u.id OR g.upload_id IS NULL)
		               AND (g.expires_at IS NULL OR g.expires_at > now())
		        )
		   )
		 ORDER BY u.created_at DESC`,
		caller.OrgID, caller.ID, caller.Role.IsAdmin())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []UploadListItem{}
	for rows.Next() {
		var u UploadListItem
		dest := append(uploadDest(&u.Upload), &u.AnalysisID, &u.AnalysisStatus, &u.OverallRisk)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
