-- Organizations, users and the role/tier vocabulary.
--
-- Replaces Base.metadata.create_all(). Schema is now owned by SQL files rather
-- than by SQLAlchemy models, because two languages write these tables: the Go
-- gateway (uploads, log_entries, rollups) and the Python worker (findings,
-- embeddings). A language-neutral source of truth is the only workable option.

CREATE EXTENSION IF NOT EXISTS citext;

-- How much of an upload a principal may see. Strictly nested:
-- summary < dashboard < full. Ordering is load-bearing -- authz compares tiers
-- with <, so the enum order IS the permission lattice.
CREATE TYPE access_level AS ENUM ('summary', 'dashboard', 'full');

-- Role within an organization.
CREATE TYPE org_role AS ENUM ('member', 'admin', 'owner');

CREATE TABLE organizations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL,
    slug        citext NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- citext rather than lowercasing at the call site: the old code normalised
    -- in Python, which only works as long as every writer remembers to.
    email          citext NOT NULL UNIQUE,
    password_hash  text NOT NULL,
    role           org_role NOT NULL DEFAULT 'member',
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX users_org_id_idx ON users (org_id);
