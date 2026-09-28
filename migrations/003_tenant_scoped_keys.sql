-- AKAC 0.3 tenant-scoped record keys (ADR-005). Applied once by the migration
-- runner; never edit after release.
--
-- Migration 001 keyed every tenant table by `id` alone. A record id was therefore
-- global: an upsert with another tenant's id either failed under row-level
-- security (an existence signal across tenants) or, for a role that bypasses
-- RLS, moved the row into the writing tenant. From here on the key is
-- (tenant, id): the same id in two tenants is two unrelated rows, and the
-- adapter's `ON CONFLICT (tenant, id)` upsert never rewrites `tenant`.
--
-- The (tenant, id) primary key index replaces the former (tenant, id) secondary
-- indexes. Vector chunk tables (002) are already keyed by (tenant, chunk_id).

DO $$
DECLARE
  t text;
  pk text;
BEGIN
  FOREACH t IN ARRAY ARRAY['akac_actors', 'akac_roles', 'akac_groups', 'akac_constraints',
    'akac_containers', 'akac_knowledge', 'akac_grants', 'akac_contexts']
  LOOP
    SELECT conname INTO pk FROM pg_constraint WHERE conrelid = to_regclass(t) AND contype = 'p';
    IF pk IS NULL THEN
      RAISE EXCEPTION 'AKAC migration 003: % has no primary key', t;
    END IF;
    EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', t, pk);
    EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I PRIMARY KEY (tenant, id)', t, t || '_pkey');
  END LOOP;
END
$$;

DROP INDEX akac_actors_tenant;
DROP INDEX akac_roles_tenant;
DROP INDEX akac_groups_tenant;
DROP INDEX akac_constraints_tenant;
DROP INDEX akac_containers_tenant;
DROP INDEX akac_knowledge_tenant;
DROP INDEX akac_grants_tenant;
