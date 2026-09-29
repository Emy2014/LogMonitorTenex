-- Analyses, findings, and how long the work took.

CREATE TYPE analysis_status AS ENUM ('queued', 'running', 'done', 'failed');
CREATE TYPE severity        AS ENUM ('info', 'low', 'medium', 'high', 'critical');

-- How soon, as opposed to how bad. Kept independent of severity because they
-- are different questions: a critical finding the proxy already blocked is
-- low urgency, and a medium finding still in progress is not.
CREATE TYPE urgency_level   AS ENUM ('monitor', 'this_week', 'today', 'immediate');

-- What the analysis was measured against. Recorded per analysis so a result can
-- always state its own baseline -- 'unusual' is meaningless without one.
CREATE TYPE analysis_scope  AS ENUM ('file', 'history');

CREATE TABLE analyses (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    upload_id             uuid NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    status                analysis_status NOT NULL DEFAULT 'queued',

    scope                 analysis_scope NOT NULL DEFAULT 'file',
    baseline_window_days  integer,        -- NULL when scope = 'file'

    overall_risk          severity,
    summary               text,
    timeline              jsonb,          -- display-only narrative
    model                 text,
    input_tokens          integer,
    output_tokens         integer,
    error                 text,

    created_at            timestamptz NOT NULL DEFAULT now(),
    started_at            timestamptz,
    finished_at           timestamptz,
    -- Set while a worker holds the job; the reaper requeues anything stale.
    heartbeat_at          timestamptz,

    CONSTRAINT baseline_window_matches_scope CHECK (
        (scope = 'file'    AND baseline_window_days IS NULL) OR
        (scope = 'history' AND baseline_window_days IS NOT NULL)
    )
);

CREATE INDEX analyses_upload_idx ON analyses (upload_id, created_at DESC);
CREATE INDEX analyses_org_idx    ON analyses (org_id, created_at DESC);
-- Drives the reaper: find jobs that stopped reporting in.
CREATE INDEX analyses_stale_idx  ON analyses (status, heartbeat_at)
    WHERE status IN ('queued', 'running');

CREATE TABLE anomalies (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id      uuid NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    kind             text NOT NULL,
    severity         severity NOT NULL,
    urgency          urgency_level NOT NULL,
    action_required  boolean NOT NULL DEFAULT false,
    action_label     text,
    confidence       double precision NOT NULL,
    explanation      text NOT NULL,
    recommendation   text,
    -- Points at log_entries.id. No FK: log_entries is partitioned and has no
    -- primary key to reference, and the UI only needs these to highlight rows.
    entry_ids        bigint[] NOT NULL DEFAULT '{}'
);

CREATE INDEX anomalies_analysis_idx ON anomalies (analysis_id);
CREATE INDEX anomalies_triage_idx   ON anomalies (analysis_id, urgency DESC, severity DESC);

-- Per-stage timings, persisted rather than left in an in-process registry that
-- resets on every restart. This is what the dashboard's p50/p95/p99 read from.
CREATE TABLE analysis_timings (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    analysis_id         uuid NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    org_id              uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage               text NOT NULL,     -- parse | map | reduce | evidence | llm | persist | total
    duration_ms         double precision NOT NULL,
    queue_wait_ms       double precision,
    worker_cpu_percent  double precision,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX analysis_timings_scope_idx ON analysis_timings (org_id, user_id, stage, created_at DESC);
