# ADR 016: several instances, key custody and verified operations

Status: proposed for AKAC 0.6 (draft). No external review has taken place.
Requirements: [AKAC 0.6](../spec/AKAC-0.6.md) (R136..R142).
Guides: [HA.md](../docs/HA.md), [KEY-CUSTODY.md](../docs/KEY-CUSTODY.md),
[OPERATIONS.md](../docs/OPERATIONS.md), [PERFORMANCE.md](../docs/PERFORMANCE.md).

## Context

The Helm chart runs two to six replicas, yet rate limits and admin Idempotency-Key
records were per process (R103 documented it), retention and reconcile could run on
several replicas or CronJob pods at once, checkpoint keys were files in the pod, the
chart had no alert rules or verification job, and neither performance nor retrieval
quality on a real embedding model had been measured.

## Decision

1. **Seams, not a cluster.** `reference/limits.ts` defines `RateLimitStore`,
   `IdempotencyStore` and `JobLock` with per-process implementations; the listeners take
   them as options. `adapters/postgres-ha.ts` implements them over the database the
   gateway already needs. `AKAC_SHARED_STATE=postgres` is the default when `DATABASE_URL`
   is set, `memory` otherwise. No new infrastructure (Redis, etcd) is introduced.
2. **Migration 009.** `akac_rate_limits` (one row per tenant, scope and identity digest;
   window index from the database clock) and `akac_idempotency_keys` (in-flight lease,
   completed record with status and JSON body, expiry). Both are tenant-scoped with forced
   RLS; expired rows are deleted by the gateway per tenant in bounded batches, so no job
   needs to bypass RLS.
3. **Fail closed.** A shared-store error refuses the request (503) and is counted
   (`akac_rate_limit_rejections_total{reason="unavailable"}`); there is no silent
   fallback to per-process state.
4. **Leader-free job serialization.** Retention and reconcile take a session advisory
   lock `pg_try_advisory_lock(1095450948, hashtext(job/tenant))` (the migration lock is
   `(1095450947, 3)`). A second run skips instead of queueing; the admin routes answer 409
   and audit `DENIED:CONFLICT`. PostgreSQL releases the lock when the session ends.
5. **Key custody by interface.** `reference/custody.ts` defines `CheckpointSigner`; the
   file key becomes `FileCheckpointSigner`, and `VaultTransitSigner` is an example KMS
   adapter (HTTP, injected `fetch`, pinned key version and public key, every signature
   verified before use). Rotation is a keyring (`active`, `retired` with a window,
   `revoked`). Anchoring is a `CheckpointAnchor` hook with a file implementation; network
   publishing (for example through `bonus/transparency-export`) is documented, not
   shipped, because core code must not import bonus modules (ADR-010).
6. **Verification as a job.** `scripts/checkpoint.ts verify` checks chain, recomputed
   root, stored tree and anchored checkpoints (with a keyring). The chart schedules it
   (CronJob) and ships a PrometheusRule with SLO burn-rate alerts. A backup/restore drill
   runs in CI and uploads its evidence.
7. **Measure, then publish.** `bench/` (no new root dependencies) measures decision and
   retrieval latency and the cost of the documented bounds; `bench/quality/` measures
   recall and filter mismatches with a pinned open embedding model in its own lockfile.
   Published figures come only from the GitHub-hosted runner (`bench.yml`), with the
   machine description; local numbers are labelled as such.

## Alternatives considered

- *Leader election* (Kubernetes Lease or a leader row): rejected for jobs that are
  idempotent per tenant; a try-lock per (job, tenant) needs no leader, no renewal and
  parallelizes across tenants.
- *Redis for limits*: rejected; one more stateful dependency with its own isolation
  model, while PostgreSQL already enforces tenant RLS.
- *Sliding windows or token buckets*: deferred; fixed windows keep R101 semantics
  (`Retry-After` = end of window) and one upsert per request.
- *AWS KMS / PKCS#11 adapters*: not shipped; format 2 checkpoints are Ed25519, and an
  adapter is only useful where the product offers Ed25519 signatures. The interface is
  the same.

## Consequences

- Each rate-limited request costs two database round trips per budget (set tenant,
  upsert); an agent request has two budgets. Single-node deployments can keep `memory`.
- Concurrency caps (32 agent, 16 admin, 64 AuthZEN) stay per process by design.
- Advisory locks are local to one PostgreSQL primary; after a failover a job that still
  runs against the old primary is not serialized with one on the new primary.
- A restore to a point before the last anchored checkpoint makes verification fail by
  design (a rollback); HA.md describes how to record such an incident.
- No availability, latency or recovery figure is claimed; SLO targets and RPO/RTO are
  operator choices supported by the drill, the benchmarks and the alerts.
