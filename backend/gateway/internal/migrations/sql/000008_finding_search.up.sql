-- Full-text search over findings.
--
-- Complements pgvector rather than competing with it. Embeddings answer "like
-- what?" and need an embedding provider; this answers "containing what?" and
-- needs nothing. With no provider configured the product still has working
-- search, which matters because a security tool whose search is dark until
-- someone buys an API key is a security tool with no search.
--
-- Two vectors, because one is not enough for this data:
--
--   english  stems the prose, and keeps a hostname whole. Postgres tokenises
--            cdn-telemetry-sync.net as a single `host` lexeme, so searching
--            the full hostname works and searching part of it does not.
--   simple   the same text with punctuation replaced by spaces, so cdn,
--            telemetry, sync and net are separate lexemes and a partial
--            hostname matches.
--
-- An analyst reaching for "the telemetry host" should not have to remember the
-- exact FQDN, which is why both are indexed.

ALTER TABLE anomalies
    ADD COLUMN search tsvector
    GENERATED ALWAYS AS (
        setweight(to_tsvector('english', coalesce(kind, '')),           'A') ||
        setweight(to_tsvector('english', coalesce(explanation, '')),    'B') ||
        setweight(to_tsvector('english', coalesce(recommendation, '')), 'C') ||
        setweight(to_tsvector('simple',
            regexp_replace(
                coalesce(kind, '') || ' ' || coalesce(explanation, '') || ' ' ||
                coalesce(recommendation, ''),
                '[^a-zA-Z0-9]+', ' ', 'g')), 'D')
    ) STORED;

-- GIN rather than GiST: this is read far more than written, which is what GIN
-- is for, and a generated column means there is no trigger to keep in step.
CREATE INDEX anomalies_search_idx ON anomalies USING gin (search);

-- Every search filters to one organization first, then ranks within it.
CREATE INDEX anomalies_analysis_lookup_idx ON anomalies (analysis_id, id);
