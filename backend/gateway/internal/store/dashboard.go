package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Scope decides whose data a dashboard query covers. A member always sees
// only their own; an admin may widen to the organization.
type Scope struct {
	OrgID  uuid.UUID
	UserID *uuid.UUID // nil = org-wide (admins only; the handler enforces that)
	From   time.Time
	To     time.Time
}

// where builds the shared predicate. Written once because every dashboard
// query needs exactly the same tenancy filter, and one of them getting it
// wrong is a cross-tenant leak.
func (s Scope) where(tsCol string, argOffset int) (string, []any) {
	args := []any{s.OrgID, s.From, s.To}
	clause := fmt.Sprintf("org_id = $%d AND %s >= $%d AND %s < $%d",
		argOffset, tsCol, argOffset+1, tsCol, argOffset+2)
	if s.UserID != nil {
		args = append(args, *s.UserID)
		clause += fmt.Sprintf(" AND user_id = $%d", argOffset+3)
	}
	return clause, args
}

// whereNoTime is the tenancy predicate without the time bounds, for questions
// about what data exists at all rather than what falls in a window.
func (s Scope) whereNoTime(argOffset int) (string, []any) {
	args := []any{s.OrgID}
	clause := fmt.Sprintf("org_id = $%d", argOffset)
	if s.UserID != nil {
		args = append(args, *s.UserID)
		clause += fmt.Sprintf(" AND user_id = $%d", argOffset+1)
	}
	return clause, args
}

type Summary struct {
	Requests     int64    `json:"requests"`
	Errors       int64    `json:"errors"`
	SuccessRate  *float64 `json:"success_rate"`
	BytesIn      int64    `json:"bytes_in"`
	BytesOut     int64    `json:"bytes_out"`
	CacheHits    int64    `json:"cache_hits"`
	CacheTotal   int64    `json:"cache_total"`
	CacheHitRate *float64 `json:"cache_hit_rate"`
	LatencyP50   *int     `json:"latency_p50_ms"`
	LatencyP95   *int     `json:"latency_p95_ms"`
	LatencyP99   *int     `json:"latency_p99_ms"`
	Hosts        int64    `json:"hosts"`
	Uploads      int64    `json:"uploads"`
	// The span the caller's data actually covers, ignoring the requested
	// window. Uploaded proxy logs are historical exports, often months old,
	// so a dashboard defaulting to "last 30 days" shows nothing and looks
	// broken. The UI uses this to pick a window that contains data.
	DataStart *time.Time `json:"data_start"`
	DataEnd   *time.Time `json:"data_end"`
	// True until ingest writes its first rollup row. The UI uses this to tell
	// "nothing happened in this window" apart from "nothing has ever loaded".
	Empty bool `json:"empty"`
}

// DashboardSummary aggregates one window from the rollup table.
func (s *Store) DashboardSummary(ctx context.Context, sc Scope) (Summary, error) {
	clause, args := sc.where("bucket_start", 1)
	var out Summary

	err := s.Pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(requests),0), COALESCE(SUM(errors),0),
		       COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0),
		       COALESCE(SUM(cache_hits),0), COALESCE(SUM(cache_total),0),
		       COUNT(DISTINCT host)
		  FROM entry_rollups
		 WHERE grain = 'hour' AND `+clause, args...,
	).Scan(&out.Requests, &out.Errors, &out.BytesIn, &out.BytesOut,
		&out.CacheHits, &out.CacheTotal, &out.Hosts)
	if err != nil {
		return out, err
	}

	// Percentiles come from the rows, not from the rollups.
	//
	// The rollups hold an exact percentile per bucket, and there is no correct
	// way to combine those into an overall figure. Taking MAX -- which this
	// did -- reports the worst bucket as though it were the whole window: a
	// single hour of upstream timeouts made the headline p50 read 19 seconds
	// against a true median of 32ms. That is not an approximation, it is the
	// wrong statistic.
	//
	// One indexed, partition-pruned scan is affordable for three numbers, and
	// it is right. If it ever stops being affordable, the answer is a t-digest
	// sketch column in the rollups, not a cheaper wrong answer.
	latClause, latArgs := sc.where("ts", 1)
	if err := s.Pool.QueryRow(ctx, `
		SELECT percentile_disc(0.50) WITHIN GROUP (ORDER BY latency_ms),
		       percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms),
		       percentile_disc(0.99) WITHIN GROUP (ORDER BY latency_ms)
		  FROM log_entries
		 WHERE `+latClause+` AND latency_ms IS NOT NULL`, latArgs...,
	).Scan(&out.LatencyP50, &out.LatencyP95, &out.LatencyP99); err != nil {
		return out, err
	}

	uClause, uArgs := sc.where("created_at", 1)
	if err := s.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM uploads WHERE `+uClause, uArgs...).Scan(&out.Uploads); err != nil {
		return out, err
	}

	// Deliberately unbounded in time, but still scoped to the same tenant.
	spanClause, spanArgs := sc.whereNoTime(1)
	if err := s.Pool.QueryRow(ctx,
		`SELECT MIN(bucket_start), MAX(bucket_start) FROM entry_rollups WHERE `+spanClause,
		spanArgs...).Scan(&out.DataStart, &out.DataEnd); err != nil {
		return out, err
	}

	if out.Requests > 0 {
		r := float64(out.Requests-out.Errors) / float64(out.Requests)
		out.SuccessRate = &r
	}
	if out.CacheTotal > 0 {
		c := float64(out.CacheHits) / float64(out.CacheTotal)
		out.CacheHitRate = &c
	}
	out.Empty = out.Requests == 0 && out.Uploads == 0
	return out, nil
}

type SeriesPoint struct {
	Bucket     time.Time `json:"bucket"`
	Requests   int64     `json:"requests"`
	Errors     int64     `json:"errors"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	CacheHits  int64     `json:"cache_hits"`
	CacheTotal int64     `json:"cache_total"`
	LatencyP50 *int      `json:"latency_p50_ms"`
	LatencyP95 *int      `json:"latency_p95_ms"`
	LatencyP99 *int      `json:"latency_p99_ms"`
}

// DashboardSeries returns one row per time bucket, already aggregated across
// hosts. Reading rollups rather than log_entries is what keeps a chart to a
// few hundred rows instead of millions.
func (s *Store) DashboardSeries(ctx context.Context, sc Scope, grain string) ([]SeriesPoint, error) {
	if grain != "minute" && grain != "hour" {
		grain = "hour"
	}
	clause, args := sc.where("bucket_start", 2)
	// Same offset, so the same $n: one set of bind parameters serves both
	// halves of the query, against each table's own timestamp column.
	latClause, _ := sc.where("ts", 2)
	args = append([]any{grain}, args...)

	// Counts and sums come from the rollups, which is what they are for.
	// Percentiles come from the rows, for the same reason as in the summary:
	// a bucket's rollup holds one percentile per host, and combining those
	// with MAX reports the worst host rather than the bucket. The chart and
	// the headline tile have to agree, and both have to be right.
	rows, err := s.Pool.Query(ctx, `
		WITH counts AS (
			SELECT bucket_start,
			       SUM(requests) AS requests, SUM(errors) AS errors,
			       SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
			       SUM(cache_hits) AS cache_hits, SUM(cache_total) AS cache_total
			  FROM entry_rollups
			 WHERE grain = $1::rollup_grain AND `+clause+`
			 GROUP BY bucket_start
		), latency AS (
			-- $1::text, not bare $1: the other half of this query casts the
			-- same parameter to rollup_grain, so the driver infers that type
			-- and date_trunc has no overload for it.
			SELECT date_trunc($1::text, ts) AS bucket_start,
			       percentile_disc(0.50) WITHIN GROUP (ORDER BY latency_ms) AS p50,
			       percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95,
			       percentile_disc(0.99) WITHIN GROUP (ORDER BY latency_ms) AS p99
			  FROM log_entries
			 WHERE `+latClause+` AND latency_ms IS NOT NULL
			 GROUP BY 1
		)
		SELECT c.bucket_start, c.requests, c.errors, c.bytes_in, c.bytes_out,
		       c.cache_hits, c.cache_total, l.p50, l.p95, l.p99
		  FROM counts c
		  LEFT JOIN latency l ON l.bucket_start = c.bucket_start
		 ORDER BY c.bucket_start`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SeriesPoint{}
	for rows.Next() {
		var p SeriesPoint
		if err := rows.Scan(&p.Bucket, &p.Requests, &p.Errors, &p.BytesIn, &p.BytesOut,
			&p.CacheHits, &p.CacheTotal, &p.LatencyP50, &p.LatencyP95, &p.LatencyP99); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type TopRow struct {
	Label    string `json:"label"`
	Requests int64  `json:"requests"`
	Errors   int64  `json:"errors"`
	Bytes    int64  `json:"bytes"`
}

// allowed dimensions -> column. A map rather than string interpolation: this
// value reaches SQL, and a parameter cannot stand in for an identifier.
var topDimensions = map[string]string{
	"host":     "host",
	"url":      "url",
	"user":     "username",
	"ip":       "host(client_ip)",
	"category": "category",
}

// DashboardTop ranks one dimension. Reads log_entries rather than rollups,
// because rollups only carry host -- the per-user and per-IP breakdowns need
// the row level, which the (org_id, user_id, ts) index and partition pruning
// keep affordable.
func (s *Store) DashboardTop(ctx context.Context, sc Scope, dimension string, limit int) ([]TopRow, error) {
	col, ok := topDimensions[dimension]
	if !ok {
		return nil, fmt.Errorf("unknown dimension %q", dimension)
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	clause, args := sc.where("ts", 1)

	rows, err := s.Pool.Query(ctx, `
		SELECT `+col+`::text AS label,
		       COUNT(*),
		       COUNT(*) FILTER (WHERE resp_code >= 400),
		       COALESCE(SUM(COALESCE(req_bytes,0) + COALESCE(resp_bytes,0)), 0)
		  FROM log_entries
		 WHERE `+clause+` AND `+col+` IS NOT NULL
		 GROUP BY label
		 ORDER BY 2 DESC
		 LIMIT `+fmt.Sprint(limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []TopRow{}
	for rows.Next() {
		var r TopRow
		if err := rows.Scan(&r.Label, &r.Requests, &r.Errors, &r.Bytes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type FindingCount struct {
	Severity string `json:"severity"`
	Urgency  string `json:"urgency"`
	Count    int64  `json:"count"`
}

// FindingBreakdown powers the severity x urgency matrix.
func (s *Store) FindingBreakdown(ctx context.Context, sc Scope) ([]FindingCount, error) {
	args := []any{sc.OrgID, sc.From, sc.To}
	userFilter := ""
	if sc.UserID != nil {
		args = append(args, *sc.UserID)
		userFilter = " AND up.user_id = $4"
	}

	rows, err := s.Pool.Query(ctx, `
		SELECT an.severity::text, an.urgency::text, COUNT(*)
		  FROM anomalies an
		  JOIN analyses a  ON a.id = an.analysis_id
		  JOIN uploads  up ON up.id = a.upload_id
		 WHERE a.org_id = $1 AND a.created_at >= $2 AND a.created_at < $3`+userFilter+`
		 GROUP BY 1, 2`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []FindingCount{}
	for rows.Next() {
		var f FindingCount
		if err := rows.Scan(&f.Severity, &f.Urgency, &f.Count); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

type AuditEntry struct {
	ID           uuid.UUID  `json:"id"`
	ActorUserID  *uuid.UUID `json:"actor_user_id"`
	ActorEmail   *string    `json:"actor_email"`
	Action       string     `json:"action"`
	ResourceType string     `json:"resource_type"`
	ResourceID   *uuid.UUID `json:"resource_id"`
	Detail       any        `json:"detail"`
	CreatedAt    time.Time  `json:"created_at"`
}

// ListAudit returns the organization's audit trail, newest first.
func (s *Store) ListAudit(ctx context.Context, orgID uuid.UUID, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT al.id, al.actor_user_id, u.email, al.action, al.resource_type,
		       al.resource_id, al.detail, al.created_at
		  FROM audit_log al
		  LEFT JOIN users u ON u.id = al.actor_user_id
		 WHERE al.org_id = $1
		 ORDER BY al.created_at DESC
		 LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.ActorUserID, &e.ActorEmail, &e.Action,
			&e.ResourceType, &e.ResourceID, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type StatusBreakdown struct {
	Code     int     `json:"code"`
	Class    string  `json:"class"`
	Reason   *string `json:"reason"`
	Requests int64   `json:"requests"`
	Share    float64 `json:"share"`
	P95Ms    *int    `json:"latency_p95_ms"`
}

// StatusCodes returns the response-code breakdown for a window.
//
// Answers the question "errors: 312" cannot: which codes, why, and whether
// they were slow. A 502 after 30 seconds is an upstream timeout; a 403 in 5ms
// is policy. Counting them together loses both.
func (s *Store) StatusCodes(ctx context.Context, sc Scope) ([]StatusBreakdown, error) {
	clause, args := sc.where("bucket_start", 1)
	rows, err := s.Pool.Query(ctx, `
		SELECT resp_code,
		       SUM(requests),
		       (array_agg(reason ORDER BY requests DESC)
		            FILTER (WHERE reason IS NOT NULL))[1],
		       MAX(latency_p95)
		  FROM status_rollups
		 WHERE `+clause+`
		 GROUP BY resp_code
		 ORDER BY resp_code`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []StatusBreakdown{}
	var total int64
	for rows.Next() {
		var b StatusBreakdown
		if err := rows.Scan(&b.Code, &b.Requests, &b.Reason, &b.P95Ms); err != nil {
			return nil, err
		}
		b.Class = statusClass(b.Code)
		total += b.Requests
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if total > 0 {
			out[i].Share = float64(out[i].Requests) / float64(total)
		}
	}
	return out, nil
}

func statusClass(code int) string {
	switch {
	case code >= 500:
		return "server_error"
	case code >= 400:
		return "client_error"
	case code >= 300:
		return "redirect"
	default:
		return "success"
	}
}

// ActionItem is one row of the worklist. Deliberately only what the panel
// renders: the anomaly's own id, its triage fields, and where it came from.
type ActionItem struct {
	AnomalyID      uuid.UUID `json:"anomaly_id"`
	Filename       string    `json:"filename"`
	Kind           string    `json:"kind"`
	Severity       string    `json:"severity"`
	Urgency        string    `json:"urgency"`
	Confidence     float64   `json:"confidence"`
	Explanation    string    `json:"explanation"`
	Recommendation *string   `json:"recommendation"`
	Entries        int       `json:"entries"`
}

// ActionPlan returns findings ordered by what to do first.
//
// Ordered on urgency before severity, which is the opposite of how findings
// are usually listed and is the point: severity says how bad something is,
// urgency says whether it can wait. A blocked threat is high severity and low
// urgency because the proxy already stopped it, while exfiltration in progress
// is both. Sorting by severity alone puts the handled thing above the
// happening thing.
func (s *Store) ActionPlan(ctx context.Context, caller *User, limit int) ([]ActionItem, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT an.id, up.filename, an.kind, an.severity::text, an.urgency::text,
		       an.confidence, an.explanation, an.recommendation,
		       COALESCE(array_length(an.entry_ids, 1), 0)
		  FROM anomalies an
		  JOIN analyses a  ON a.id = an.analysis_id
		  JOIN uploads  up ON up.id = a.upload_id
		 WHERE `+visibilityClause+`
		 ORDER BY an.urgency DESC, an.severity DESC, an.confidence DESC
		 LIMIT $4`,
		caller.OrgID, caller.ID, caller.Role.IsAdmin(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ActionItem{}
	for rows.Next() {
		var i ActionItem
		if err := rows.Scan(&i.AnomalyID, &i.Filename, &i.Kind, &i.Severity,
			&i.Urgency, &i.Confidence, &i.Explanation, &i.Recommendation,
			&i.Entries); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
