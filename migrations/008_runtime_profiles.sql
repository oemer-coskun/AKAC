-- AKAC 0.5 draft runtime containment contract (ADR-012). Applied once by the
-- migration runner; never edit after release. Independent of 004-007: it needs
-- only the tables of 001-003, so it applies to a fresh database and to one that
-- already has every earlier migration.
--
-- 1. akac_runtime_profiles: tenant-scoped runtime profile policies keyed by
--    (tenant, id) with forced row-level security, like every tenant table. One
--    real column per containment domain holds an operator-reviewed profile id;
--    NULL means the policy names no profile for that domain. AKAC stores ids
--    only, never vendor runtime policy.
-- 2. akac_audit.execution_id / runtime_revision: optional evidence correlation
--    members of audit format 2 (reference/audit.ts). NULL for every existing
--    row, which keeps its hash and Merkle leaf unchanged.

CREATE TABLE akac_runtime_profiles (
  id text NOT NULL,
  tenant text NOT NULL,
  classification text NOT NULL CHECK (classification IN ('public', 'internal', 'confidential', 'restricted')),
  destination_class text CHECK (destination_class IS NULL
    OR destination_class IN ('internal-user', 'internal-service', 'model-provider', 'tool', 'external')),
  profile_network text CHECK (profile_network IS NULL OR profile_network ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$'),
  profile_filesystem text CHECK (profile_filesystem IS NULL OR profile_filesystem ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$'),
  profile_tool text CHECK (profile_tool IS NULL OR profile_tool ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$'),
  profile_credential text CHECK (profile_credential IS NULL OR profile_credential ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$'),
  active boolean NOT NULL,
  PRIMARY KEY (tenant, id),
  CHECK (num_nonnulls(profile_network, profile_filesystem, profile_tool, profile_credential) >= 1)
);

ALTER TABLE akac_runtime_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE akac_runtime_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY akac_tenant_isolation ON akac_runtime_profiles
  USING (tenant = current_setting('akac.tenant', true))
  WITH CHECK (tenant = current_setting('akac.tenant', true));

ALTER TABLE akac_audit
  ADD COLUMN execution_id text CHECK (execution_id IS NULL OR execution_id ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$'),
  ADD COLUMN runtime_revision text CHECK (runtime_revision IS NULL OR runtime_revision ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$');
-- Auditors correlate an agent execution with its decisions.
CREATE INDEX akac_audit_execution ON akac_audit (tenant, execution_id) WHERE execution_id IS NOT NULL;
