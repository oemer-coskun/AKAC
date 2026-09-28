-- AKAC 0.3 normalized, tenant-partitioned schema. Applied once by the migration
-- runner (adapters/postgres.ts) under an advisory lock; never edit after release.
-- Every tenant table carries a `tenant` column, is indexed by it and is protected
-- by FORCE ROW LEVEL SECURITY keyed on the transaction-local `akac.tenant` setting.

CREATE TABLE akac_settings (
  key text PRIMARY KEY,
  value text NOT NULL
);
INSERT INTO akac_settings (key, value) VALUES ('policyVersion', 'akac-reference/0.3.0');

CREATE TABLE akac_epochs (
  tenant text PRIMARY KEY,
  epoch bigint NOT NULL CHECK (epoch >= 0)
);

CREATE TABLE akac_actors (
  id text PRIMARY KEY,
  tenant text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('user', 'agent', 'service')),
  roles text[] NOT NULL,
  projects text[] NOT NULL,
  clearance text NOT NULL CHECK (clearance IN ('public', 'internal', 'confidential', 'restricted')),
  active boolean NOT NULL
);
CREATE INDEX akac_actors_tenant ON akac_actors (tenant, id);

CREATE TABLE akac_roles (
  id text PRIMARY KEY,
  tenant text NOT NULL,
  inherits text[] NOT NULL,
  active boolean NOT NULL
);
CREATE INDEX akac_roles_tenant ON akac_roles (tenant, id);

CREATE TABLE akac_groups (
  id text PRIMARY KEY,
  tenant text NOT NULL,
  members text[] NOT NULL,
  roles text[] NOT NULL,
  active boolean NOT NULL
);
CREATE INDEX akac_groups_tenant ON akac_groups (tenant, id);
CREATE INDEX akac_groups_members ON akac_groups USING gin (members);

CREATE TABLE akac_constraints (
  id text PRIMARY KEY,
  tenant text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('static', 'dynamic')),
  roles text[] NOT NULL,
  cardinality integer NOT NULL CHECK (cardinality >= 2)
);
CREATE INDEX akac_constraints_tenant ON akac_constraints (tenant, id);

CREATE TABLE akac_containers (
  id text PRIMARY KEY,
  tenant text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('knowledge-base', 'folder')),
  parent text,
  classification text NOT NULL CHECK (classification IN ('public', 'internal', 'confidential', 'restricted')),
  reader_roles text[] NOT NULL,
  readers text[] NOT NULL,
  projects text[] NOT NULL,
  active boolean NOT NULL,
  CHECK ((kind = 'knowledge-base') = (parent IS NULL))
);
CREATE INDEX akac_containers_tenant ON akac_containers (tenant, id);
CREATE INDEX akac_containers_parent ON akac_containers (tenant, parent);

CREATE TABLE akac_knowledge (
  id text PRIMARY KEY,
  tenant text NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  kind text NOT NULL CHECK (kind IN ('document', 'memory', 'artifact')),
  origin text NOT NULL CHECK (origin IN ('human', 'system', 'model')),
  content text NOT NULL,
  classification text NOT NULL CHECK (classification IN ('public', 'internal', 'confidential', 'restricted')),
  projects text[] NOT NULL,
  reader_roles text[] NOT NULL,
  readers text[] NOT NULL,
  sources jsonb NOT NULL CHECK (jsonb_typeof(sources) = 'array'),
  active boolean NOT NULL,
  access_expires_at bigint,
  container text,
  CHECK (kind = 'document' OR origin = 'model')
);
CREATE INDEX akac_knowledge_tenant ON akac_knowledge (tenant, id);
CREATE INDEX akac_knowledge_container ON akac_knowledge (tenant, container);
CREATE INDEX akac_knowledge_classification ON akac_knowledge (tenant, classification);

CREATE TABLE akac_grants (
  id text PRIMARY KEY,
  tenant text NOT NULL,
  subject text NOT NULL,
  agent text NOT NULL,
  actions text[] NOT NULL,
  resources text[] NOT NULL,
  purposes text[] NOT NULL,
  not_before bigint NOT NULL,
  expires_at bigint NOT NULL,
  active boolean NOT NULL,
  parent text,
  active_roles text[]
);
CREATE INDEX akac_grants_tenant ON akac_grants (tenant, id);
CREATE INDEX akac_grants_parent ON akac_grants (tenant, parent);
CREATE INDEX akac_grants_subject ON akac_grants (tenant, subject);

CREATE TABLE akac_contexts (
  id text PRIMARY KEY,
  tenant text NOT NULL,
  subject text NOT NULL,
  agent text NOT NULL,
  grant_id text NOT NULL,
  purpose text NOT NULL,
  sources jsonb NOT NULL CHECK (jsonb_typeof(sources) = 'array'),
  expires_at bigint NOT NULL,
  policy_version text NOT NULL,
  epoch bigint NOT NULL,
  active boolean NOT NULL
);
CREATE INDEX akac_contexts_binding ON akac_contexts (tenant, subject, agent, grant_id);

-- One hash-chained stream per tenant. The head row makes appends and readiness
-- O(1) instead of scanning history.
CREATE TABLE akac_audit (
  tenant text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= 1),
  time bigint NOT NULL,
  actor text NOT NULL,
  operation text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('allow', 'deny')),
  reason text NOT NULL,
  policy_version text NOT NULL,
  epoch bigint NOT NULL,
  previous text NOT NULL,
  hash text NOT NULL,
  PRIMARY KEY (tenant, sequence)
);
CREATE TABLE akac_audit_head (
  tenant text PRIMARY KEY,
  sequence bigint NOT NULL,
  hash text NOT NULL
);

-- Append-only for every role that cannot drop the trigger (the runtime role).
CREATE FUNCTION akac_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'akac_audit is append-only';
END
$$;
CREATE TRIGGER akac_audit_immutable BEFORE UPDATE OR DELETE ON akac_audit
  FOR EACH ROW EXECUTE FUNCTION akac_audit_append_only();
CREATE TRIGGER akac_audit_no_truncate BEFORE TRUNCATE ON akac_audit
  FOR EACH STATEMENT EXECUTE FUNCTION akac_audit_append_only();

-- Tenant isolation. An unset `akac.tenant` matches no row. FORCE applies the
-- policy to the table owner too; superusers and BYPASSRLS roles still bypass it,
-- so the runtime role MUST be neither.
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['akac_epochs', 'akac_actors', 'akac_roles', 'akac_groups', 'akac_constraints',
    'akac_containers', 'akac_knowledge', 'akac_grants', 'akac_contexts', 'akac_audit', 'akac_audit_head']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY akac_tenant_isolation ON %I USING (tenant = current_setting(''akac.tenant'', true)) WITH CHECK (tenant = current_setting(''akac.tenant'', true))', t);
  END LOOP;
END
$$;
