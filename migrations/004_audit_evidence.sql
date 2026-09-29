-- AKAC 0.4 decision and audit evidence (ADR-006). Applied once by the migration
-- runner; never edit after release.
--
-- 1. Audit entries gain the format 2 evidence columns. Existing (format 1) rows
--    keep NULL there and keep verifying with their original hash rule; the hash
--    chain continues across the format change (reference/audit.ts).
-- 2. akac_audit_node stores, per tenant stream, every complete perfect subtree of
--    the RFC 9162 Merkle tree over the stream: level 0 holds the leaf hash of each
--    entry, H(0x00 || JCS(entry)), at index sequence - 1; level k + 1 index i holds
--    H(0x01 || node(k, 2i) || node(k, 2i + 1)). A node never changes once written,
--    so appends add O(log n) rows and proofs read O(log^2 n) rows without touching
--    entry content. The table is append-only like akac_audit and tenant-isolated.
-- 3. Nodes are backfilled here for every existing entry, set-based.

ALTER TABLE akac_audit
  ADD COLUMN format_version smallint CHECK (format_version IS NULL OR format_version = 2),
  ADD COLUMN decision_id text,
  ADD COLUMN reason_code text,
  ADD COLUMN policy_digest text CHECK (policy_digest IS NULL OR policy_digest ~ '^[0-9a-f]{64}$'),
  ADD COLUMN obligations jsonb,
  ADD COLUMN run_id text,
  ADD COLUMN trace_id text CHECK (trace_id IS NULL OR trace_id ~ '^[0-9a-f]{32}$');
ALTER TABLE akac_audit ADD CONSTRAINT akac_audit_format_2 CHECK (format_version IS NULL
  OR (decision_id IS NOT NULL AND reason_code IS NOT NULL AND policy_digest IS NOT NULL
    AND obligations IS NOT NULL AND jsonb_typeof(obligations) = 'array'));
-- Auditors correlate a caller-visible decision id with its entry.
CREATE INDEX akac_audit_decision ON akac_audit (tenant, decision_id) WHERE decision_id IS NOT NULL;

CREATE TABLE akac_audit_node (
  tenant text NOT NULL,
  level smallint NOT NULL CHECK (level BETWEEN 0 AND 62),
  idx bigint NOT NULL CHECK (idx >= 0),
  hash text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (tenant, level, idx)
);
CREATE TRIGGER akac_audit_node_immutable BEFORE UPDATE OR DELETE ON akac_audit_node
  FOR EACH ROW EXECUTE FUNCTION akac_audit_append_only();
CREATE TRIGGER akac_audit_node_no_truncate BEFORE TRUNCATE ON akac_audit_node
  FOR EACH STATEMENT EXECUTE FUNCTION akac_audit_append_only();
ALTER TABLE akac_audit_node ENABLE ROW LEVEL SECURITY;
ALTER TABLE akac_audit_node FORCE ROW LEVEL SECURITY;
CREATE POLICY akac_tenant_isolation ON akac_audit_node
  USING (tenant = current_setting('akac.tenant', true)) WITH CHECK (tenant = current_setting('akac.tenant', true));

-- Backfill across all tenants. The migration role owns the tables; forced RLS is
-- lifted for the owner inside this transaction only and restored below.
ALTER TABLE akac_audit NO FORCE ROW LEVEL SECURITY;
ALTER TABLE akac_audit_node NO FORCE ROW LEVEL SECURITY;

-- Leaves of format 1 entries: RFC 8785 (JCS) text of the entry including its hash.
-- Members in UTF-16 code unit order; to_json(text) escapes exactly as ECMAScript
-- JSON.stringify does for the characters PostgreSQL text can hold; integers are
-- plain decimals. reference/audit.ts auditLeaf() computes the same bytes.
INSERT INTO akac_audit_node (tenant, level, idx, hash)
SELECT tenant, 0, sequence - 1, encode(sha256('\x00'::bytea || convert_to(
  '{"actor":' || to_json(actor)::text
  || ',"decision":' || to_json(decision)::text
  || ',"epoch":' || epoch::text
  || ',"hash":' || to_json(hash)::text
  || ',"operation":' || to_json(operation)::text
  || ',"policyVersion":' || to_json(policy_version)::text
  || ',"previous":' || to_json(previous)::text
  || ',"reason":' || to_json(reason)::text
  || ',"sequence":' || sequence::text
  || ',"tenant":' || to_json(tenant)::text
  || ',"time":' || time::text || '}', 'UTF8')), 'hex')
FROM akac_audit;

DO $$
DECLARE
  lvl integer := 0;
  added bigint;
BEGIN
  LOOP
    INSERT INTO akac_audit_node (tenant, level, idx, hash)
    SELECT l.tenant, lvl + 1, l.idx / 2, encode(sha256('\x01'::bytea || decode(l.hash, 'hex') || decode(r.hash, 'hex')), 'hex')
    FROM akac_audit_node l JOIN akac_audit_node r ON r.tenant = l.tenant AND r.level = l.level AND r.idx = l.idx + 1
    WHERE l.level = lvl AND l.idx % 2 = 0;
    GET DIAGNOSTICS added = ROW_COUNT;
    EXIT WHEN added = 0;
    lvl := lvl + 1;
  END LOOP;
END
$$;

ALTER TABLE akac_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE akac_audit_node FORCE ROW LEVEL SECURITY;
