# Migrating reference 0.2 to 0.3

1. Stop new agent runs, drain in-flight operations and back up the database,
   including the `akac_state` row and its audit history. Test restore first.
2. PostgreSQL: run the gateway (or `migrate()` from `adapters/postgres.ts`) with
   `AKAC_MIGRATION_DATABASE_URL` pointing at the schema owner, and `DATABASE_URL`
   at a runtime role that is neither superuser nor `BYPASSRLS`. The runner
   applies `migrations/`, imports the 0.2 row once and renames it
   `akac_state_legacy`. Keep that table: it holds the original global audit
   chain, verifiable with `verifyLegacyAudit`. Never edit an applied migration;
   the runner refuses mismatched checksums.
3. SQLite/memory: `akac-state/0.1` is upgraded on load. Both stores are partitioned
   per tenant; SQLite splits a whole-state `akac_state` row into one
   `akac_tenant_state` row per tenant when the file is first opened (back it up
   first) and keeps the former audit array as `legacyAudits` in `akac_state`.
   A transaction sees and may write only its own tenant.
3a. PostgreSQL databases created by an earlier 0.3 build are at migration 002;
   the runner applies `003_tenant_scoped_keys` (record keys become
   `(tenant, id)`) on the next start or `npm run migrate`. With `DATABASE_URL`
   the gateway now refuses a superuser or `BYPASSRLS` runtime role at start-up;
   set `AKAC_PG_ALLOW_BYPASS_RLS=true` only for local development.
   `DELETE /admin/v1/knowledge/{id}` now requires `kb-admin`.
4. Upgrade effects: documents get `origin: "system"`, memory and artifacts
   `origin: "model"`; every tenant inherits the former global epoch; roles,
   groups, containers and constraints start empty, so 0.2 role strings keep
   their flat meaning. Existing contexts carry the 0.2 core revision and deny;
   provision fresh runs.
5. Library API changes: `Store.transaction(tenant, fn)` receives a `Tx`
   (`tx.state`, `tx.load(need)`, `tx.complete`); stores implement `ready(tenant?)`
   and `auditLog(tenant, after?, limit?)`; `Engine.revoke(tenant, admin, type, id)`
   takes the tenant first; `Decision` denials carry `category`. Administrative
   upserts go through `ControlPlane` (`reference/control.ts`).
6. Audit checkpoints are per tenant: `scripts/checkpoint.ts KEY TENANT KEY_ID OUT`.
   Re-anchor rollback floors per tenant stream.
7. Before adding role records, audit which role names are in use: creating a
   record gives the name a hierarchy, and deactivating it removes the role from
   every holder. Add SoD constraints only after reviewing current holders; a new
   static constraint denies existing violators immediately.
