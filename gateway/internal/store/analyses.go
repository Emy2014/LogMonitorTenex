package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Analysis struct {
	ID                 uuid.UUID  `json:"id"`
	OrgID              uuid.UUID  `json:"org_id"`
	UploadID           uuid.UUID  `json:"upload_id"`
	Status             string     `json:"status"`
	Scope              string     `json:"scope"`
	BaselineWindowDays *int       `json:"baseline_window_days"`
	OverallRisk        *string    `json:"overall_risk"`
	Summary            *string    `json:"summary"`
	Timeline           any        `json:"timeline"`
	Model              *string    `json:"model"`
	InputTokens        *int       `json:"input_tokens"`
	OutputTokens       *int       `json:"output_tokens"`
	Error              *string    `json:"error"`
	CreatedAt          time.Time  `json:"created_at"`
	StartedAt          *time.Time `json:"started_at"`
	FinishedAt         *time.Time `json:"finished_at"`
}

type Anomaly struct {
	ID             uuid.UUID `json:"id"`
	Kind           string    `json:"kind"`
	Severity       string    `json:"severity"`
	Urgency        string    `json:"urgency"`
	ActionRequired bool      `json:"action_required"`
	ActionLabel    *string   `json:"action_label"`
	Confidence     float64   `json:"confidence"`
	Explanation    string    `json:"explanation"`
	Recommendation *string   `json:"recommendation"`
	EntryIDs       []int64   `json:"entry_ids"`
}

const analysisCols = `id, org_id, upload_id, status::text, scope::text,
	baseline_window_days, overall_risk::text, summary, timeline, model,
	input_tokens, output_tokens, error, created_at, started_at, finished_at`

func scanAnalysis(row pgx.Row) (*Analysis, error) {
	var a Analysis
	err := row.Scan(&a.ID, &a.OrgID, &a.UploadID, &a.Status, &a.Scope,
		&a.BaselineWindowDays, &a.OverallRisk, &a.Summary, &a.Timeline, &a.Model,
		&a.InputTokens, &a.OutputTokens, &a.Error, &a.CreatedAt, &a.StartedAt,
		&a.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &a, err
}

// CreateAnalysis queues one. scope='history' carries a window; 'file' must not,
// which the schema's CHECK constraint enforces.
func (s *Store) CreateAnalysis(ctx context.Context, orgID, uploadID uuid.UUID,
	scope string, window *int) (*Analysis, error) {
	return scanAnalysis(s.Pool.QueryRow(ctx, `
		INSERT INTO analyses (org_id, upload_id, scope, baseline_window_days)
		VALUES ($1, $2, $3::analysis_scope, $4)
		RETURNING `+analysisCols, orgID, uploadID, scope, window))
}

func (s *Store) AnalysisByID(ctx context.Context, id uuid.UUID) (*Analysis, error) {
	return scanAnalysis(s.Pool.QueryRow(ctx,
		`SELECT `+analysisCols+` FROM analyses WHERE id = $1`, id))
}

// LatestAnalysisFor returns the most recent analysis of an upload, which is
// what the UI polls after starting one.
func (s *Store) LatestAnalysisFor(ctx context.Context, uploadID uuid.UUID) (*Analysis, error) {
	return scanAnalysis(s.Pool.QueryRow(ctx,
		`SELECT `+analysisCols+` FROM analyses WHERE upload_id = $1
		 ORDER BY created_at DESC LIMIT 1`, uploadID))
}

// Anomalies returns an analysis's findings, most urgent first.
//
// Ordered by urgency before severity: an analyst triages on what needs doing
// now, not on what is worst in the abstract.
func (s *Store) Anomalies(ctx context.Context, analysisID uuid.UUID) ([]Anomaly, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, kind, severity::text, urgency::text, action_required,
		       action_label, confidence, explanation, recommendation, entry_ids
		  FROM anomalies
		 WHERE analysis_id = $1
		 ORDER BY urgency DESC, severity DESC, confidence DESC`, analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Anomaly{}
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.Kind, &a.Severity, &a.Urgency, &a.ActionRequired,
			&a.ActionLabel, &a.Confidence, &a.Explanation, &a.Recommendation,
			&a.EntryIDs); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountEntries is what decides how many shards an analysis fans out into.
func (s *Store) CountEntries(ctx context.Context, uploadID uuid.UUID) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM log_entries WHERE upload_id = $1`, uploadID).Scan(&n)
	return n, err
}

// ProcessingStats powers the dashboard's processing panel: percentiles over
// persisted per-stage timings rather than an in-process registry that resets
// on every restart.
func (s *Store) ProcessingStats(ctx context.Context, sc Scope) ([]map[string]any, error) {
	clause, args := sc.where("created_at", 1)
	rows, err := s.Pool.Query(ctx, `
		SELECT stage,
		       count(*),
		       percentile_disc(0.50) WITHIN GROUP (ORDER BY duration_ms),
		       percentile_disc(0.95) WITHIN GROUP (ORDER BY duration_ms),
		       percentile_disc(0.99) WITHIN GROUP (ORDER BY duration_ms)
		  FROM analysis_timings
		 WHERE `+clause+`
		 GROUP BY stage
		 ORDER BY stage`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var stage string
		var n int64
		var p50, p95, p99 float64
		if err := rows.Scan(&stage, &n, &p50, &p95, &p99); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"stage": stage, "count": n,
			"p50_ms": p50, "p95_ms": p95, "p99_ms": p99,
		})
	}
	return out, rows.Err()
}

// FailAnalysis records a terminal failure, used when queueing itself fails.
func (s *Store) FailAnalysis(ctx context.Context, id uuid.UUID, message string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE analyses SET status = 'failed', error = $2, finished_at = now()
		 WHERE id = $1`, id, message)
	return err
}
