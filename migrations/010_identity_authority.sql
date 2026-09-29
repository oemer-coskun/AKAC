-- AKAC 0.6 identity and authority (ADR-019, spec/AKAC-0.6.md).
-- Applied once by the migration runner; never edit after release. Needs only the
-- tables of 001-004 and 008 (akac_grants, akac_audit).
--
-- 1. akac_grants.heartbeat_ttl_ms / last_heartbeat_at: heartbeat-bound runs
--    (R147). break_glass: emergency grants (R149); NULL for every other grant.
-- 2. akac_risk_signals: one risk signal per (tenant, id), id = SHA-256 of
--    (source, principal) (R151).
-- 3. akac_tenant_settings: approval quorums, approval lifetime and risk caps; one
--    row per tenant (id = tenant).
-- 4. akac_approvals: pending and decided approvals of sensitive administrative
--    operations (R153..R157). The payload holds the operation's arguments.
-- 5. akac_audit.actor_chain / break_glass: optional audit format 2 members (R145,
--    R150). NULL for every existing row, which keeps its hash and Merkle leaf.
-- 6. akac_actors.runtime_for: the agent ids whose runs a runtime principal may keep
--    alive by heartbeat (R147). NULL: none.
--
-- Every new table is tenant-scoped with forced row-level security. The runtime role
-- needs SELECT, INSERT and UPDATE on the new tables (records are never deleted).

ALTER TABLE akac_grants
  ADD COLUMN heartbeat_ttl_ms bigint CHECK (heartbeat_ttl_ms IS NULL OR heartbeat_ttl_ms BETWEEN 1000 AND 86400000),
  ADD COLUMN last_heartbeat_at bigint CHECK (last_heartbeat_at IS NULL OR last_heartbeat_at >= 0),
  ADD COLUMN break_glass boolean CHECK (break_glass IS NULL OR break_glass),
  ADD CONSTRAINT akac_grants_break_glass CHECK (break_glass IS NULL OR (parent IS NULL AND actions = ARRAY['read']::text[]
    AND NOT ('*' = ANY(resources)) AND cardinality(resources) BETWEEN 1 AND 64 AND expires_at - not_before <= 7200000));

ALTER TABLE akac_actors
  ADD COLUMN runtime_for text[] CHECK (runtime_for IS NULL OR cardinality(runtime_for) <= 256);

CREATE TABLE akac_risk_signals (
  id text NOT NULL CHECK (id ~ '^[a-f0-9]{64}$'),
  tenant text NOT NULL,
  principal text NOT NULL CHECK (principal ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$'),
  level text NOT NULL CHECK (level IN ('none', 'low', 'medium', 'high', 'critical')),
  source text NOT NULL CHECK (source ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$'),
  issued_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  event text CHECK (event IS NULL OR event ~ '^https://schemas\.openid\.net/secevent/(caep|risc)/event-type/[a-z][a-z-]{0,63}$'),
  PRIMARY KEY (tenant, id),
  CHECK (expires_at > issued_at)
);
CREATE INDEX akac_risk_signals_principal ON akac_risk_signals (tenant, principal);
ALTER TABLE akac_risk_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE akac_risk_signals FORCE ROW LEVEL SECURITY;
CREATE POLICY akac_tenant_isolation ON akac_risk_signals
  USING (tenant = current_setting('akac.tenant', true))
  WITH CHECK (tenant = current_setting('akac.tenant', true));

CREATE TABLE akac_tenant_settings (
  id text NOT NULL,
  tenant text NOT NULL,
  approval_quorum jsonb CHECK (approval_quorum IS NULL OR jsonb_typeof(approval_quorum) = 'object'),
  approval_ttl_ms bigint CHECK (approval_ttl_ms IS NULL OR approval_ttl_ms BETWEEN 300000 AND 604800000),
  risk_caps jsonb CHECK (risk_caps IS NULL OR jsonb_typeof(risk_caps) = 'object'),
  PRIMARY KEY (tenant, id),
  CHECK (id = tenant)
);
ALTER TABLE akac_tenant_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE akac_tenant_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY akac_tenant_isolation ON akac_tenant_settings
  USING (tenant = current_setting('akac.tenant', true))
  WITH CHECK (tenant = current_setting('akac.tenant', true));

CREATE TABLE akac_approvals (
  id text NOT NULL,
  tenant text NOT NULL,
  class text NOT NULL CHECK (class IN ('break_glass', 'label_widening', 'role_widening', 'sod_relaxation', 'runtime_profile', 'destination_widening', 'settings')),
  operation text NOT NULL CHECK (operation ~ '^[a-z_]{1,64}$'),
  requester text NOT NULL,
  payload jsonb NOT NULL,
  digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
  approvers text[] NOT NULL,
  required integer NOT NULL CHECK (required BETWEEN 1 AND 8),
  external boolean NOT NULL,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'executed', 'rejected')),
  executed_at bigint,
  PRIMARY KEY (tenant, id),
  CHECK (expires_at > created_at),
  CHECK (NOT (requester = ANY(approvers))),
  CHECK ((status = 'executed') = (executed_at IS NOT NULL))
);
CREATE INDEX akac_approvals_pending ON akac_approvals (tenant, created_at) WHERE status = 'pending';
ALTER TABLE akac_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE akac_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY akac_tenant_isolation ON akac_approvals
  USING (tenant = current_setting('akac.tenant', true))
  WITH CHECK (tenant = current_setting('akac.tenant', true));

ALTER TABLE akac_audit
  ADD COLUMN actor_chain text[] CHECK (actor_chain IS NULL OR cardinality(actor_chain) BETWEEN 1 AND 5),
  ADD COLUMN break_glass boolean CHECK (break_glass IS NULL OR break_glass);
CREATE INDEX akac_audit_break_glass ON akac_audit (tenant, sequence) WHERE break_glass;
