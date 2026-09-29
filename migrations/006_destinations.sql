-- AKAC 0.4 destination profiles (ADR-008). Applied once by the migration runner;
-- never edit after release. Independent of 004, 005 and 007: it applies to a
-- fresh database and to one that already has 005 and 007.
--
-- 1. akac_destinations: tenant-scoped egress profiles keyed by (tenant, id) with
--    forced row-level security, like every tenant table since 001/003.
-- 2. akac_actors.destination: optional reference to a profile. NULL keeps 0.3
--    recipient behaviour (a user is the implicit internal-user destination).
--    There is deliberately no foreign key: an unknown or deleted profile must
--    deny at decision time (fail closed), not block administration.
-- 3. akac_grants.destinations / max_results: optional run restrictions. NULL
--    keeps 0.3 behaviour.

CREATE TABLE akac_destinations (
  id text NOT NULL,
  tenant text NOT NULL,
  class text NOT NULL CHECK (class IN ('internal-user', 'internal-service', 'model-provider', 'tool', 'external')),
  max_classification text NOT NULL CHECK (max_classification IN ('public', 'internal', 'confidential', 'restricted')),
  purposes text[] NOT NULL CHECK (cardinality(purposes) <= 64),
  active boolean NOT NULL,
  PRIMARY KEY (tenant, id),
  CHECK (id NOT IN ('internal-user', 'internal-service', 'model-provider', 'tool', 'external'))
);

ALTER TABLE akac_destinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE akac_destinations FORCE ROW LEVEL SECURITY;
CREATE POLICY akac_tenant_isolation ON akac_destinations
  USING (tenant = current_setting('akac.tenant', true))
  WITH CHECK (tenant = current_setting('akac.tenant', true));

ALTER TABLE akac_actors ADD COLUMN destination text;
CREATE INDEX akac_actors_destination ON akac_actors (tenant, destination) WHERE destination IS NOT NULL;

ALTER TABLE akac_grants
  ADD COLUMN destinations text[] CHECK (destinations IS NULL OR cardinality(destinations) BETWEEN 1 AND 64),
  ADD COLUMN max_results integer CHECK (max_results IS NULL OR max_results BETWEEN 1 AND 64);
