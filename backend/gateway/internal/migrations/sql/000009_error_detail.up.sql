-- Detail behind a failed request.
--
-- "errors" as a single count answers how many but never which, and 401, 404
-- and 502 need completely different responses: a credential problem, a broken
-- link, an upstream outage. Counting them together hides the only thing an
-- analyst wants to know.

-- The proxy's own explanation, e.g. "Blocked - Malicious Content",
-- "Authentication Required". Already present in NSS feeds and previously
-- discarded by the parser.
ALTER TABLE log_entries ADD COLUMN reason text;

-- Per status code, so the breakdown is a rollup read rather than a scan over
-- raw rows.
CREATE TABLE status_rollups (
    org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upload_id     uuid NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    bucket_start  timestamptz NOT NULL,
    resp_code     integer NOT NULL,
    -- The dominant reason for this code in this bucket, for display. Not a
    -- key: one code can carry several reasons and the count is what matters.
    reason        text,
    requests      bigint NOT NULL,
    -- Slow failures and fast failures mean different things: a 502 after 30
    -- seconds is an upstream timeout, a 403 in 5ms is policy.
    latency_p95   integer,
    PRIMARY KEY (org_id, user_id, upload_id, bucket_start, resp_code)
);

CREATE INDEX status_rollups_series_idx
    ON status_rollups (org_id, user_id, bucket_start);
CREATE INDEX status_rollups_code_idx
    ON status_rollups (org_id, resp_code, bucket_start);
