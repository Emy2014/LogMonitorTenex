-- Uploads and the partitioned event table.

CREATE TABLE uploads (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename      text NOT NULL,          -- display only; never touches the filesystem
    byte_size     bigint NOT NULL,
    line_count    integer NOT NULL DEFAULT 0,
    parsed_count  integer NOT NULL DEFAULT 0,
    format        text NOT NULL,          -- parser registry key, e.g. 'zscaler_nss'
    object_key    text NOT NULL,          -- org/user/YYYY/MM/DD/<id>.log.zst in the bucket
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX uploads_org_user_created_idx ON uploads (org_id, user_id, created_at DESC);

-- log_entries is RANGE-partitioned on event time.
--
-- Deliberately NO primary key. A PK on a partitioned table must contain the
-- partition key, and a PK column cannot be NULL -- which would force every
-- unparsed line to carry an invented timestamp. The parser's rule is that a
-- line it cannot read still becomes a row with only `raw` set, and that rule is
-- worth more here than a uniqueness constraint the identity sequence already
-- guarantees in practice. Rows with ts IS NULL land in the DEFAULT partition.
CREATE TABLE log_entries (
    id            bigint GENERATED ALWAYS AS IDENTITY,
    upload_id     uuid NOT NULL,
    org_id        uuid NOT NULL,
    user_id       uuid NOT NULL,
    line_no       integer NOT NULL,

    ts            timestamptz,            -- partition key; NULL => DEFAULT partition
    client_ip     inet,
    username      text,
    host          text,
    url           text,
    category      text,
    action        text,
    req_bytes     bigint,
    resp_bytes    bigint,
    user_agent    text,
    threat_name   text,
    raw           text NOT NULL,

    -- Fields the old parser discarded. These are what make the dashboard's
    -- success rate, latency percentiles and cache hit rate genuinely
    -- log-derived rather than invented.
    resp_code     integer,
    method        text,
    latency_ms    integer,
    cache_status  text
) PARTITION BY RANGE (ts);

-- Declared on the parent; Postgres propagates them to every partition.
CREATE INDEX log_entries_org_user_ts_idx ON log_entries (org_id, user_id, ts);
CREATE INDEX log_entries_upload_idx      ON log_entries (upload_id);
CREATE INDEX log_entries_org_host_ts_idx ON log_entries (org_id, host, ts);
CREATE INDEX log_entries_id_idx          ON log_entries (id);

CREATE TABLE log_entries_default PARTITION OF log_entries DEFAULT;

-- Create the monthly partitions covering [from_ts, to_ts], idempotently.
--
-- Must be called BEFORE inserting rows for a new month: once a row for that
-- month has landed in the DEFAULT partition, Postgres refuses to create a
-- partition that would have claimed it. The gateway calls this with an
-- upload's min/max timestamp before it starts COPY.
CREATE FUNCTION ensure_log_partitions(from_ts timestamptz, to_ts timestamptz)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    m      date := date_trunc('month', from_ts)::date;
    stop   date := date_trunc('month', to_ts)::date;
    part   text;
BEGIN
    IF from_ts IS NULL OR to_ts IS NULL THEN
        RETURN;                            -- an upload with no parseable timestamps
    END IF;
    WHILE m <= stop LOOP
        part := format('log_entries_%s', to_char(m, 'YYYY_MM'));
        IF to_regclass(part) IS NULL THEN
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF log_entries FOR VALUES FROM (%L) TO (%L)',
                part, m, (m + interval '1 month')::date
            );
        END IF;
        m := (m + interval '1 month')::date;
    END LOOP;
END;
$$;

-- Pre-create a working window so ordinary uploads never pay for DDL.
SELECT ensure_log_partitions('2024-01-01'::timestamptz, '2027-12-01'::timestamptz);
