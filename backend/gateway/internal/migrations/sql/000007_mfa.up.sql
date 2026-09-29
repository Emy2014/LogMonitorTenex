-- Multi-factor authentication.

ALTER TABLE users
    -- AES-GCM ciphertext, never the bare secret. A TOTP secret is a password
    -- equivalent: anyone holding it can mint valid codes forever.
    ADD COLUMN totp_secret        bytea,
    ADD COLUMN totp_enabled       boolean NOT NULL DEFAULT false,
    ADD COLUMN totp_confirmed_at  timestamptz;

-- An enrolment that was started but never confirmed must not gate login, or a
-- half-finished setup locks the user out of their own account.
ALTER TABLE users
    ADD CONSTRAINT totp_enabled_requires_secret
    CHECK (NOT totp_enabled OR (totp_secret IS NOT NULL AND totp_confirmed_at IS NOT NULL));

-- Org-wide policy. Admins turn this on; it is read at login.
ALTER TABLE organizations
    ADD COLUMN require_mfa boolean NOT NULL DEFAULT false;

CREATE TABLE mfa_recovery_codes (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- argon2id, same as a password: these ARE credentials, and a leaked table
    -- of plaintext recovery codes is a leaked table of second factors.
    code_hash   text NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Unused codes for one user, which is the only lookup this table serves.
CREATE INDEX mfa_recovery_codes_unused_idx
    ON mfa_recovery_codes (user_id) WHERE used_at IS NULL;
