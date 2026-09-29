-- AKAC 0.4 knowledge lifecycle (ADR-007): quarantine, retention, legal hold and
-- erasure. Applied once by the migration runner; never edit after release.
-- Independent of 004 and 007: it applies to a fresh database and to one that
-- already has 004 and 007.
--
-- 1. akac_knowledge gains nullable lifecycle columns. NULL everywhere keeps 0.3
--    behavior. `lifecycle` is 'quarantined' or 'erased'; an erased row MUST hold
--    no content (tombstone), which the CHECK below enforces in the database.
-- 2. Reverse provenance (descendants of a record) is traversed with a recursive
--    query over `sources @> '[{"id": ...}]'`, served by a GIN jsonb_path_ops
--    index. `sources` stays the single source of truth; there is no edge table
--    that could drift from it (ADR-007), so nothing needs backfilling and the
--    table keeps its forced row-level security from migration 001.
-- 3. A partial index serves the retention job.
-- 4. `revoked_at` marks a security-admin revocation that a later document
--    version cannot undo (only reinstate clears it).

ALTER TABLE akac_knowledge
  ADD COLUMN lifecycle text CHECK (lifecycle IS NULL OR lifecycle IN ('quarantined', 'erased')),
  ADD COLUMN lifecycle_at bigint CHECK (lifecycle_at IS NULL OR lifecycle_at >= 0),
  ADD COLUMN quarantine_reason text CHECK (quarantine_reason IS NULL
    OR quarantine_reason IN ('suspected_poisoning', 'scanner', 'scanner_unavailable', 'memory_review', 'incident')),
  ADD COLUMN retain_until bigint CHECK (retain_until IS NULL OR retain_until >= 0),
  ADD COLUMN legal_holds text[] CHECK (legal_holds IS NULL OR cardinality(legal_holds) <= 64),
  ADD COLUMN revoked_at bigint CHECK (revoked_at IS NULL OR revoked_at >= 0);
ALTER TABLE akac_knowledge ADD CONSTRAINT akac_knowledge_tombstone
  CHECK (lifecycle IS DISTINCT FROM 'erased' OR (content = '' AND NOT active));

CREATE INDEX akac_knowledge_sources ON akac_knowledge USING gin (sources jsonb_path_ops);
CREATE INDEX akac_knowledge_retention ON akac_knowledge (tenant, id) WHERE retain_until IS NOT NULL;
