-- AKAC 0.6 knowledge semantics (ADR-022, spec/AKAC-0.6.md).
-- Applied once by the migration runner; never edit after release. Needs the tables of
-- 001-006 and 010 (akac_knowledge, akac_containers, akac_destinations,
-- akac_tenant_settings).
--
-- 1. akac_knowledge: modality (descriptive), tags and residency (R186, R187),
--    model lineage of derived content (R191, JSON {id, version}), and the time
--    an erasure was requested while a legal hold blocked it (R194). The
--    quarantine reason gains 'poisoned', 'ancestor_revoked' and 'model_recall'.
--    Session-scoped (ephemeral) records are never stored (R190); there is no
--    column for them and the adapter refuses to write one.
-- 2. akac_containers: tags and residency every descendant carries.
-- 3. akac_destinations: region (R187).
-- 4. akac_tenant_settings: lineage_depth (R182).
-- 5. akac_combination_rules: tenant combination rules (R188), keyed by (tenant, id)
--    with forced row-level security like every tenant table.
--
-- NULL everywhere keeps 0.5 behaviour. The runtime role needs SELECT, INSERT and
-- UPDATE on akac_combination_rules (records are never deleted; deactivate instead).

ALTER TABLE akac_knowledge
  ADD COLUMN modality text CHECK (modality IS NULL OR modality IN ('text', 'image', 'audio', 'video', 'table', 'code', 'other')),
  ADD COLUMN tags text[] CHECK (tags IS NULL OR cardinality(tags) <= 32),
  ADD COLUMN residency text[] CHECK (residency IS NULL OR cardinality(residency) <= 32),
  ADD COLUMN model jsonb CHECK (model IS NULL OR (jsonb_typeof(model) = 'object' AND jsonb_typeof(model->'id') = 'string'
    AND jsonb_typeof(model->'version') = 'string')),
  ADD COLUMN erasure_requested_at bigint CHECK (erasure_requested_at IS NULL OR erasure_requested_at >= 0);
ALTER TABLE akac_knowledge DROP CONSTRAINT IF EXISTS akac_knowledge_quarantine_reason_check;
ALTER TABLE akac_knowledge ADD CONSTRAINT akac_knowledge_quarantine_reason CHECK (quarantine_reason IS NULL
  OR quarantine_reason IN ('suspected_poisoning', 'scanner', 'scanner_unavailable', 'memory_review', 'incident',
    'poisoned', 'ancestor_revoked', 'model_recall'));
CREATE INDEX akac_knowledge_model ON akac_knowledge (tenant, (model->>'id'), id) WHERE model IS NOT NULL;
CREATE INDEX akac_knowledge_erasure_pending ON akac_knowledge (tenant, id) WHERE erasure_requested_at IS NOT NULL;

ALTER TABLE akac_containers
  ADD COLUMN tags text[] CHECK (tags IS NULL OR cardinality(tags) <= 32),
  ADD COLUMN residency text[] CHECK (residency IS NULL OR cardinality(residency) <= 32);

ALTER TABLE akac_destinations
  ADD COLUMN region text CHECK (region IS NULL OR region ~ '^[A-Z][A-Z0-9-]{1,15}$');

ALTER TABLE akac_tenant_settings
  ADD COLUMN lineage_depth integer CHECK (lineage_depth IS NULL OR lineage_depth BETWEEN 1 AND 127);

CREATE TABLE akac_combination_rules (
  id text NOT NULL,
  tenant text NOT NULL,
  tags_a text[] NOT NULL CHECK (cardinality(tags_a) BETWEEN 1 AND 32),
  tags_b text[] NOT NULL CHECK (cardinality(tags_b) BETWEEN 1 AND 32),
  effect text NOT NULL CHECK (effect IN ('deny', 'uplift')),
  uplift_to text CHECK (uplift_to IS NULL OR uplift_to IN ('public', 'internal', 'confidential', 'restricted')),
  active boolean NOT NULL,
  PRIMARY KEY (tenant, id),
  CHECK (effect = 'uplift' OR uplift_to IS NULL)
);
ALTER TABLE akac_combination_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE akac_combination_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY akac_tenant_isolation ON akac_combination_rules
  USING (tenant = current_setting('akac.tenant', true))
  WITH CHECK (tenant = current_setting('akac.tenant', true));
