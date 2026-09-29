DROP TABLE IF EXISTS status_rollups;
ALTER TABLE log_entries DROP COLUMN IF EXISTS reason;
