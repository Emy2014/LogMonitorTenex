package store

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/logmonitor/gateway/internal/parser"
)

// IngestBatch writes parsed entries and the rollups derived from them.
//
// One transaction for both: a COPY that lands without its rollups would leave
// the dashboard permanently disagreeing with the events table, and there is no
// reconciliation job to notice.
type IngestBatch struct {
	UploadID uuid.UUID
	OrgID    uuid.UUID
	UserID   uuid.UUID
}

// CopyEntries bulk-loads entries via COPY.
//
// pgx's CopyFrom streams, so memory stays flat no matter how many rows arrive
// -- which is the whole reason the byte path lives in Go.
func (s *Store) CopyEntries(ctx context.Context, tx pgx.Tx, b IngestBatch, entries []parser.Entry) (int64, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	rows := make([][]any, 0, len(entries))
	for _, e := range entries {
		var ip any
		if e.ClientIP != "" {
			if addr, err := netip.ParseAddr(e.ClientIP); err == nil {
				ip = addr.String()
			}
		}
		rows = append(rows, []any{
			b.UploadID, b.OrgID, b.UserID, e.LineNo,
			e.TS, ip, nullable(e.Username), nullable(e.Host), nullable(e.URL),
			nullable(e.Category), nullable(e.Action), e.ReqBytes, e.RespBytes,
			nullable(e.UserAgent), nullable(e.ThreatName), e.Raw,
			e.RespCode, nullable(e.Method), e.LatencyMS, nullable(e.CacheStatus),
			nullable(e.Reason),
		})
	}

	return tx.CopyFrom(ctx,
		pgx.Identifier{"log_entries"},
		[]string{
			"upload_id", "org_id", "user_id", "line_no",
			"ts", "client_ip", "username", "host", "url",
			"category", "action", "req_bytes", "resp_bytes",
			"user_agent", "threat_name", "raw",
			"resp_code", "method", "latency_ms", "cache_status", "reason",
		},
		pgx.CopyFromRows(rows))
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// EnsurePartitions creates the monthly partitions covering an upload's span.
//
// Must run BEFORE the COPY: once a row for a month has landed in the DEFAULT
// partition, Postgres refuses to create a partition that would have claimed
// it, and the table is stuck that way.
func (s *Store) EnsurePartitions(ctx context.Context, tx pgx.Tx, from, to *time.Time) error {
	if from == nil || to == nil {
		return nil
	}
	_, err := tx.Exec(ctx, `SELECT ensure_log_partitions($1, $2)`, *from, *to)
	return err
}

// BuildRollups derives every aggregate table an upload feeds: the minute and
// hour entry rollups, and the per-status-code rollups.
//
// One entry point, so ingest's contract stays "copy the rows, then derive
// everything from them" and the next rollup table is a change in here rather
// than another call at the handler.
//
// Computed with percentile_disc over the raw rows, so each bucket's percentile
// is exact for that bucket. Merging buckets across a range is approximate --
// stated rather than hidden, and adequate for a dashboard.
func (s *Store) BuildRollups(ctx context.Context, tx pgx.Tx, b IngestBatch) error {
	for _, grain := range []string{"minute", "hour"} {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO entry_rollups (
				org_id, user_id, upload_id, host, grain, bucket_start,
				requests, bytes_in, bytes_out, errors,
				cache_hits, cache_total,
				latency_p50, latency_p95, latency_p99, latency_count)
			SELECT
				org_id, user_id, upload_id,
				COALESCE(host, ''),
				'%s'::rollup_grain,
				date_trunc('%s', ts),
				COUNT(*),
				COALESCE(SUM(resp_bytes), 0),
				COALESCE(SUM(req_bytes), 0),
				COUNT(*) FILTER (WHERE resp_code >= 400),
				COUNT(*) FILTER (WHERE cache_status IS NOT NULL
				                   AND upper(cache_status) LIKE '%%HIT%%'),
				COUNT(*) FILTER (WHERE cache_status IS NOT NULL),
				percentile_disc(0.50) WITHIN GROUP (ORDER BY latency_ms)
					FILTER (WHERE latency_ms IS NOT NULL),
				percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms)
					FILTER (WHERE latency_ms IS NOT NULL),
				percentile_disc(0.99) WITHIN GROUP (ORDER BY latency_ms)
					FILTER (WHERE latency_ms IS NOT NULL),
				COUNT(*) FILTER (WHERE latency_ms IS NOT NULL)
			  FROM log_entries
			 WHERE upload_id = $1 AND ts IS NOT NULL
			 GROUP BY org_id, user_id, upload_id, COALESCE(host, ''), date_trunc('%s', ts)
			ON CONFLICT (org_id, user_id, upload_id, grain, bucket_start, host)
			DO UPDATE SET
				requests = EXCLUDED.requests, bytes_in = EXCLUDED.bytes_in,
				bytes_out = EXCLUDED.bytes_out, errors = EXCLUDED.errors,
				cache_hits = EXCLUDED.cache_hits, cache_total = EXCLUDED.cache_total,
				latency_p50 = EXCLUDED.latency_p50, latency_p95 = EXCLUDED.latency_p95,
				latency_p99 = EXCLUDED.latency_p99, latency_count = EXCLUDED.latency_count
		`, grain, grain, grain), b.UploadID); err != nil {
			return fmt.Errorf("rollup %s: %w", grain, err)
		}
	}
	return s.buildStatusRollups(ctx, tx, b)
}

// buildStatusRollups aggregates per response code, so the error breakdown is a
// rollup read rather than a scan over raw rows.
//
// One code can carry several reasons in a bucket, and the column holds one for
// display: MIN picks it deterministically, which is all the panel needs. The
// count is what it is actually built on.
func (s *Store) buildStatusRollups(ctx context.Context, tx pgx.Tx, b IngestBatch) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO status_rollups (
			org_id, user_id, upload_id, bucket_start, resp_code, reason,
			requests, latency_p95)
		SELECT org_id, user_id, upload_id,
		       date_trunc('hour', ts),
		       resp_code,
		       MIN(reason) FILTER (WHERE reason IS NOT NULL),
		       COUNT(*),
		       percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms)
		           FILTER (WHERE latency_ms IS NOT NULL)
		  FROM log_entries
		 WHERE upload_id = $1 AND ts IS NOT NULL AND resp_code IS NOT NULL
		 GROUP BY org_id, user_id, upload_id, date_trunc('hour', ts), resp_code
		ON CONFLICT (org_id, user_id, upload_id, bucket_start, resp_code)
		DO UPDATE SET requests = EXCLUDED.requests,
		              reason = EXCLUDED.reason,
		              latency_p95 = EXCLUDED.latency_p95`, b.UploadID)
	return err
}

// CreateUpload inserts the upload row inside the ingest transaction.
func (s *Store) CreateUpload(ctx context.Context, tx pgx.Tx, u *Upload) error {
	return tx.QueryRow(ctx, `
		INSERT INTO uploads (id, org_id, user_id, filename, byte_size,
		                     line_count, parsed_count, format, object_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING created_at`,
		u.ID, u.OrgID, u.UserID, u.Filename, u.ByteSize,
		u.LineCount, u.ParsedCount, u.Format, u.ObjectKey,
	).Scan(&u.CreatedAt)
}

// Begin exposes a transaction to the ingest handler, which needs partitions,
// COPY, the upload row and rollups to land together or not at all.
func (s *Store) Begin(ctx context.Context) (pgx.Tx, error) { return s.Pool.Begin(ctx) }
