-- Pre-aggregated buckets. This is what every dashboard panel reads.
--
-- The old timeline endpoint computed buckets on the fly with
-- to_timestamp(floor(extract(epoch FROM ts) / n) * n) GROUP BY, over an
-- unindexed column, on every request. That is fine for a 2,700-line sample and
-- untenable past a few million rows.

CREATE TYPE rollup_grain AS ENUM ('minute', 'hour');

CREATE TABLE entry_rollups (
    org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upload_id     uuid NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    host          text NOT NULL DEFAULT '',   -- '' rather than NULL so it can sit in the PK
    grain         rollup_grain NOT NULL,
    bucket_start  timestamptz NOT NULL,

    requests      bigint NOT NULL,
    bytes_in      bigint NOT NULL DEFAULT 0,  -- resp_bytes: inbound to the client
    bytes_out     bigint NOT NULL DEFAULT 0,  -- req_bytes: outbound from the client
    errors        bigint NOT NULL DEFAULT 0,  -- resp_code >= 400
    cache_hits    bigint NOT NULL DEFAULT 0,
    cache_total   bigint NOT NULL DEFAULT 0,  -- rows that reported a cache status at all

    -- Exact for this bucket; approximate when merged across a range. Adequate
    -- for a dashboard. If exact range merges are ever needed, add a t-digest
    -- sketch column alongside these -- the schema has room.
    latency_p50   integer,
    latency_p95   integer,
    latency_p99   integer,
    latency_count bigint NOT NULL DEFAULT 0,  -- rows that carried a latency at all

    PRIMARY KEY (org_id, user_id, upload_id, grain, bucket_start, host)
);

-- The dashboard's main access path: one org+user's series over a time range.
CREATE INDEX entry_rollups_series_idx
    ON entry_rollups (org_id, user_id, grain, bucket_start);

-- Org-wide baselines (scope = 'history') read this, and only this -- never raw
-- rows. That is what keeps an org-wide baseline from exposing one user's log
-- lines to another user's analysis.
CREATE INDEX entry_rollups_org_baseline_idx
    ON entry_rollups (org_id, grain, bucket_start);

CREATE INDEX entry_rollups_host_idx
    ON entry_rollups (org_id, user_id, host, bucket_start);
