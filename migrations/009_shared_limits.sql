-- AKAC 0.6 shared operational state for several gateway instances (ADR-016).
-- Applied once by the migration runner; never edit after release. Needs only 001.
--
-- 1. akac_rate_limits: one fixed-window counter per (tenant, scope, bucket). The
--    bucket is a SHA-256 digest of the caller identity (never a token); the window
--    is computed from the database clock so instances with skewed clocks agree.
-- 2. akac_idempotency_keys: admin Idempotency-Key records per (tenant, owner, key).
--    owner is a SHA-256 digest of the administrator identity. An in-flight claim has
--    no status and a short lease (expires_at), so a crashed instance cannot block a
--    key for long; a completed record keeps its status and JSON body until expiry.
--
-- Both tables are tenant-scoped with forced row-level security, like every tenant
-- table: the runtime role only ever sees the rows of the tenant it set in
-- akac.tenant. Expired rows are deleted by the gateway itself, per tenant, in
-- bounded batches (adapters/postgres-ha.ts); no job needs to bypass RLS.
-- The runtime role needs SELECT, INSERT, UPDATE and DELETE on both tables.

CREATE TABLE akac_rate_limits (
  tenant text NOT NULL,
  scope text NOT NULL CHECK (scope ~ '^[a-z][a-z0-9_-]{0,31}$'),
  bucket text NOT NULL CHECK (bucket ~ '^[a-f0-9]{64}$'),
  window_index bigint NOT NULL CHECK (window_index >= 0),
  count bigint NOT NULL CHECK (count >= 0),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant, scope, bucket)
);
CREATE INDEX akac_rate_limits_expiry ON akac_rate_limits (tenant, expires_at);

ALTER TABLE akac_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE akac_rate_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY akac_tenant_isolation ON akac_rate_limits
  USING (tenant = current_setting('akac.tenant', true))
  WITH CHECK (tenant = current_setting('akac.tenant', true));

CREATE TABLE akac_idempotency_keys (
  tenant text NOT NULL,
  owner text NOT NULL CHECK (owner ~ '^[a-f0-9]{64}$'),
  key text NOT NULL CHECK (key ~ '^[A-Za-z0-9._:-]{1,128}$'),
  fingerprint text NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
  status integer CHECK (status IS NULL OR status BETWEEN 100 AND 599),
  body jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant, owner, key),
  CHECK (status IS NOT NULL OR body IS NULL)
);
CREATE INDEX akac_idempotency_keys_expiry ON akac_idempotency_keys (tenant, expires_at);

ALTER TABLE akac_idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE akac_idempotency_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY akac_tenant_isolation ON akac_idempotency_keys
  USING (tenant = current_setting('akac.tenant', true))
  WITH CHECK (tenant = current_setting('akac.tenant', true));
