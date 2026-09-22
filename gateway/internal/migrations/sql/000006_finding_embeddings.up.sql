-- Semantic search over findings. Numbers stay in SQL; this answers "like what?".

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE finding_embeddings (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    analysis_id  uuid NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    -- NULL for a rolled-up (owner, host, hour) bucket summary rather than a finding.
    anomaly_id   uuid REFERENCES anomalies(id) ON DELETE CASCADE,
    kind         text NOT NULL,
    bucket_key   text,
    content      text NOT NULL,          -- the text that was embedded, for display
    embedding    vector(1024) NOT NULL,  -- voyage-3
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Every search filters org_id first, then ANN-orders within it.
CREATE INDEX finding_embeddings_scope_idx ON finding_embeddings (org_id, user_id);
CREATE INDEX finding_embeddings_hnsw_idx
    ON finding_embeddings USING hnsw (embedding vector_cosine_ops);
