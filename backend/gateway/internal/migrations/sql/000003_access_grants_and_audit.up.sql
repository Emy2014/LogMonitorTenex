-- Sharing and accountability.

CREATE TABLE access_grants (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- NULL means a standing, org-wide grant issued by an admin. A concrete id
    -- means one upload shared by its owner.
    upload_id        uuid REFERENCES uploads(id) ON DELETE CASCADE,
    subject_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    level            access_level NOT NULL,
    granted_by       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at       timestamptz,          -- NULL = does not expire
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- One grant per (subject, upload) and one per (subject, org-wide). Two partial
-- indexes rather than one constraint, because NULL upload_id would otherwise
-- never collide with itself and an admin could stack duplicate org-wide grants.
CREATE UNIQUE INDEX access_grants_upload_uniq
    ON access_grants (subject_user_id, upload_id) WHERE upload_id IS NOT NULL;
CREATE UNIQUE INDEX access_grants_orgwide_uniq
    ON access_grants (subject_user_id, org_id) WHERE upload_id IS NULL;

CREATE INDEX access_grants_lookup_idx
    ON access_grants (subject_user_id, org_id, upload_id);

-- Append-only. Every grant issued or revoked, and every time an admin reads raw
-- log lines they were not granted (break-glass). Raw proxy logs are employee
-- browsing history; an admin being able to read them is necessary for incident
-- response, and doing it unrecorded is what would make this surveillance.
CREATE TABLE audit_log (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id   uuid REFERENCES users(id) ON DELETE SET NULL,
    action          text NOT NULL,        -- 'grant.created', 'breakglass.raw_access', ...
    resource_type   text NOT NULL,
    resource_id     uuid,
    detail          jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_org_created_idx ON audit_log (org_id, created_at DESC);
CREATE INDEX audit_log_actor_idx       ON audit_log (actor_user_id, created_at DESC);
