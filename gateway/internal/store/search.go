package store

import (
	"context"

	"github.com/google/uuid"
)

type SearchHit struct {
	AnomalyID   uuid.UUID `json:"anomaly_id"`
	AnalysisID  uuid.UUID `json:"analysis_id"`
	UploadID    uuid.UUID `json:"upload_id"`
	Filename    string    `json:"filename"`
	Kind        string    `json:"kind"`
	Severity    string    `json:"severity"`
	Urgency     string    `json:"urgency"`
	Confidence  float64   `json:"confidence"`
	Explanation string    `json:"explanation"`
	Rank        float64   `json:"rank"`
}

// visibilityClause restricts findings to uploads the caller may see.
//
// The same rule as ListVisibleUploads, deliberately written once more against
// this join rather than duplicated by hand: search is exactly the endpoint
// where a missing predicate quietly returns another tenant's findings.
const visibilityClause = `
	  up.org_id = $1
	  AND (
	       up.user_id = $2
	    OR $3::bool
	    OR EXISTS (
	           SELECT 1 FROM access_grants g
	            WHERE g.subject_user_id = $2
	              AND g.org_id = up.org_id
	              AND (g.upload_id = up.id OR g.upload_id IS NULL)
	              AND (g.expires_at IS NULL OR g.expires_at > now())
	       )
	  )`

// SearchFindingsText ranks findings by full-text relevance.
//
// Always available: it needs no embedding provider, so search works on a
// default install rather than being dark until someone configures an API key.
//
// The query is matched against both indexed forms: the stemmed English text,
// which keeps a hostname whole, and the punctuation-split form, which lets a
// partial hostname match. Searching "cdn-telemetry-sync" should find
// cdn-telemetry-sync.net, and against the English vector alone it does not.
func (s *Store) SearchFindingsText(ctx context.Context, caller *User, query string, limit int) ([]SearchHit, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT an.id, a.id, up.id, up.filename, an.kind, an.severity::text,
		       an.urgency::text, an.confidence, an.explanation,
		       ts_rank(an.search,
		               websearch_to_tsquery('english', $4)
		            || plainto_tsquery('simple', regexp_replace($4, '[^a-zA-Z0-9]+', ' ', 'g'))
		       ) AS rank
		  FROM anomalies an
		  JOIN analyses a  ON a.id = an.analysis_id
		  JOIN uploads  up ON up.id = a.upload_id
		 WHERE `+visibilityClause+`
		   AND an.search @@ (
		         websearch_to_tsquery('english', $4)
		      || plainto_tsquery('simple', regexp_replace($4, '[^a-zA-Z0-9]+', ' ', 'g'))
		   )
		 ORDER BY rank DESC, an.confidence DESC
		 LIMIT $5`,
		caller.OrgID, caller.ID, caller.Role.IsAdmin(), query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanHits(rows)
}

// SearchFindingsVector ranks findings by embedding similarity.
//
// Cosine distance, so lower is closer; rank is reported as 1-distance to keep
// "higher is better" consistent with the text path.
func (s *Store) SearchFindingsVector(ctx context.Context, caller *User, embedding string, limit int) ([]SearchHit, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT an.id, a.id, up.id, up.filename, an.kind, an.severity::text,
		       an.urgency::text, an.confidence, an.explanation,
		       1 - (fe.embedding <=> CAST($4 AS vector)) AS rank
		  FROM finding_embeddings fe
		  JOIN anomalies an ON an.id = fe.anomaly_id
		  JOIN analyses a   ON a.id = an.analysis_id
		  JOIN uploads  up  ON up.id = a.upload_id
		 WHERE `+visibilityClause+`
		 ORDER BY fe.embedding <=> CAST($4 AS vector)
		 LIMIT $5`,
		caller.OrgID, caller.ID, caller.Role.IsAdmin(), embedding, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanHits(rows)
}

// HasEmbeddings reports whether similarity search has anything to search.
func (s *Store) HasEmbeddings(ctx context.Context, orgID uuid.UUID) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM finding_embeddings WHERE org_id = $1 LIMIT 1`, orgID).Scan(&n)
	return n > 0, err
}

type rowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func scanHits(rows rowScanner) ([]SearchHit, error) {
	out := []SearchHit{}
	for rows.Next() {
		var h SearchHit
		if err := rows.Scan(&h.AnomalyID, &h.AnalysisID, &h.UploadID, &h.Filename,
			&h.Kind, &h.Severity, &h.Urgency, &h.Confidence, &h.Explanation,
			&h.Rank); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
