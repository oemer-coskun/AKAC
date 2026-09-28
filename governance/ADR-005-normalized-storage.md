# ADR 005: normalized, tenant-partitioned storage

Status: accepted for reference 0.3.0, amended after an internal adversarial
review (items 8–11 and the consequences below); external security review
outstanding.

## Context

Through 0.2 every store loaded the complete state, for all tenants, as one JSON
document under one global lock. Throughput was bounded by a single row, one
tenant's traffic delayed every other tenant, a revocation advanced a global epoch
that invalidated every tenant's contexts, and the audit chain was one global
sequence. Nothing below the application separated tenants.

## Decision

1. **Tenant-scoped transactions.** `Store.transaction(tenant, fn)` hands the
   engine a `Tx` whose `state` may be a partial snapshot. The engine hydrates the
   closure a decision can reach (`reference/hydrate.ts`) and then calls the pure,
   synchronous `decide()`/`visible()` over it. Missing records deny as before.
   Where a missing record could *remove* a restriction (group memberships, role
   records, SoD constraints, run contexts), an incomplete load aborts the
   transaction instead of deciding (see item 8).
2. **Normalized PostgreSQL schema** (`migrations/001_normalized_schema.sql`): one
   table per record type, real columns for ids, tenant, kind, lifecycle, version,
   parent, classification and expiry, `text[]` for identifier lists, JSONB only
   for source references. Closures load with bounded recursive queries.
3. **Row-level security.** Every tenant table has `ENABLE` and `FORCE ROW LEVEL
   SECURITY` with a policy on `current_setting('akac.tenant', true)`, set with
   transaction-local `set_config` at the start of each transaction. An unset
   tenant sees no rows. The runtime role must be neither superuser nor
   `BYPASSRLS`. With `requireRls` (the gateway default whenever `DATABASE_URL` is
   set) the store checks the role after migration: a bypassing role fails every
   transaction and readiness, and `reference/server.ts` exits at start-up
   (`PostgresStore.verify()`). `AKAC_PG_ALLOW_BYPASS_RLS=true` disables the check
   for local development only; it is logged as a warning and refused with
   `NODE_ENV=production`. The adapter additionally refuses to flush a record whose
   tenant differs from the transaction's, and every load filters by tenant.
4. **Per-tenant serialization.** `pg_advisory_xact_lock(hashtextextended(tenant, 0))`
   linearizes one tenant's authorize–act–audit transactions while tenants run in
   parallel. Migrations use a separate two-key advisory lock.
5. **Per-tenant epochs and audit streams.** Revocation advances only the
   revoking tenant's epoch. Each tenant is an audit stream with a head row, so
   appends and readiness are O(1)/bounded (tail window of 256 verified against
   the head). The audit table is append-only via trigger for roles that cannot
   drop it.
6. **Write-back by change detection.** The store keeps the serialized form of
   every loaded row and, at commit, upserts only new or changed rows and appends
   audit entries beyond the loaded head. Records are never deleted.
7. **Versioned migrations.** A runner applies `migrations/NNN_name.sql` in order
   inside one advisory-locked transaction, records them in
   `akac_schema_migrations` with SHA-256 checksums (line endings normalized), and
   refuses to start when an applied migration was edited or is unknown. A 0.2
   `akac_state` row is imported once and renamed `akac_state_legacy`, preserving
   its original global audit chain unmodified.
8. **Loads never truncate.** Every bounded load (`adapters/postgres.ts`
   `BOUNDS`) either returns everything requested, including the closure it names,
   or throws `BudgetExceeded`. Closures return one row per *name* (a `LEFT JOIN`
   against the name set), so a role name without a record counts toward the bound:
   previously the role closure capped names but counted rows, a name beyond the cap
   was silently dropped, hydration marked it as loaded, and an inactive role could
   read as a flat active role. The engine turns `BudgetExceeded` into an audited
   `DEFERRED:BUDGET_EXCEEDED` denial in the same transaction (only reads preceded
   it); the control plane audits it (and any other transaction failure, as
   `DEFERRED:STORE_ERROR`) best effort in a follow-up transaction and rethrows.
   Hydration does not request roles of inactive groups or juniors of inactive
   roles, which never contribute to a closure.
9. **Tenant-scoped keys** (`migrations/003_tenant_scoped_keys.sql`). Every tenant
   table is keyed by `(tenant, id)`; upserts use `ON CONFLICT (tenant, id)` and
   never update `tenant`. Before, ids were global primary keys: a writer that
   bypasses RLS could move another tenant's row into its own tenant, and an RLS
   role got a row-level-security error (an unaudited 503 that revealed the id
   existed elsewhere). Migrations 001 and 002 are unchanged; 003 applies to fresh
   databases and to databases already at 002.
10. **Memory and SQLite stores are tenant-partitioned.** Rather than rejecting a
   foreign id (which would still reveal that it exists), both stores keep one
   snapshot per tenant: `MemoryStore` in a map, `SqliteStore` in one row per
   tenant (`akac_tenant_state`; a whole-state `akac_state` row written by an earlier
   version is split once when the file is opened, and `akac_state` keeps only the
   policy version and any retained 0.1 audit chain). A transaction sees only its
   own tenant (`complete: true` for that tenant; `load` is a no-op) and a write of
   another tenant's record, epoch or audit entry is refused. They remain
   single-node developer modes.
11. **Bounded content.** The lexical fallback measures content before loading it
   (`Need.corpusBytes`; `RETRIEVAL.contentBytes`, 64 MiB, overridable per engine)
   and denies above it. Index reconciliation reads document metadata only
   (`Tx.catalog`) and loads content for the documents it re-indexes, 32 per
   transaction.

## Consequences

- Tenants no longer contend for one lock or share a revocation blast radius.
- Record ids are scoped to their tenant in every store. The same id in two
  tenants is two unrelated records, and a request with another tenant's id gets
  exactly the answer an unused id would get.
- Each decision issues several round trips; latency depends on the network path
  to the database. Knowledge content is loaded with the source closure; a
  separate content table is future work.
- The lexical retrieval fallback still reads up to 1,001 tenant records (at most
  64 MiB of content); a `CandidateSource` (for example, a partitioned vector index)
  replaces it.
- Administrative holder checks (a new static constraint or a widened role must not
  invalidate a currently valid principal) load every active principal of the
  tenant (at most 2,048), every group (at most 1,024) and their role closure (at
  most 512 names per load); a larger tenant gets a
  deferred, audited failure for those two operations only. Reductions of
  authority never need the scan and always succeed.
- A decision whose closure exceeds a bound is denied (`defer`) rather than decided
  over partial data; operators see `DEFERRED:BUDGET_EXCEEDED` in the audit stream.
- Contexts accumulate per run; a run exceeding 512 contexts aborts rather than
  deciding over an incomplete manifest.
- Migrations must run as the schema owner, never as the runtime role. Superuser
  connections bypass row-level security and are acceptable only for development.
