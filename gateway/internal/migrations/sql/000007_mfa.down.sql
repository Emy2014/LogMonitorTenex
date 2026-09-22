DROP TABLE IF EXISTS mfa_recovery_codes;
ALTER TABLE organizations DROP COLUMN IF EXISTS require_mfa;
ALTER TABLE users DROP CONSTRAINT IF EXISTS totp_enabled_requires_secret;
ALTER TABLE users
    DROP COLUMN IF EXISTS totp_confirmed_at,
    DROP COLUMN IF EXISTS totp_enabled,
    DROP COLUMN IF EXISTS totp_secret;
