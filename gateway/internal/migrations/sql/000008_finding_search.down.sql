DROP INDEX IF EXISTS anomalies_analysis_lookup_idx;
DROP INDEX IF EXISTS anomalies_search_idx;
ALTER TABLE anomalies DROP COLUMN IF EXISTS search;
