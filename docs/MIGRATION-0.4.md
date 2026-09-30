# Migrating reference 0.3 to 0.4

Everything new in 0.4 is additive on the wire and off or restrictive by default, but the upgrade is not a no-op: the core revision changes (open contexts deny), the audit format changes for new entries, and PostgreSQL gains four migrations. Read the [changelog](../CHANGELOG.md) and [AKAC 0.4](../spec/AKAC-0.4.md) first. This guide describes what the repository's tests exercise; an upgrade of a real deployment has not been rehearsed by the project.

## Before you start

1. Back up the database (including audit history) and your latest audit checkpoints. Test the restore. There are no down migrations (see Rollback).
2. Stop new agent runs and drain in-flight operations. The version bump ends every open context, so nothing carries over.
3. Confirm the roles: `AKAC_MIGRATION_DATABASE_URL` for the schema owner, `DATABASE_URL` for a runtime role that is neither superuser nor `BYPASSRLS`. Passwords stay in files (`AKAC_*_PASSWORD_FILE`), never in URLs.

## Steps

1. **Deploy the 0.4 build and run the migrations.** `npm run migrate` (or start the gateway with `AKAC_AUTO_MIGRATE`) applies, in order and under the migration lock with checksum verification:

   | Migration | Effect |
   |---|---|
   | `004_audit_evidence.sql` | Adds the format 2 columns to `akac_audit` (NULL for existing rows), creates `akac_audit_node` (append-only, forced RLS) and backfills the Merkle nodes for every existing entry of every tenant in one transaction. Duration grows with audit history; run it in a maintenance window on large streams. |
   | `005_knowledge_lifecycle.sql` | Nullable lifecycle columns on `akac_knowledge` (`lifecycle`, `lifecycle_at`, `quarantine_reason`, `retain_until`, `legal_holds`, `revoked_at`), a CHECK that an erased row holds no content, a GIN index over `sources` for reverse provenance and a partial index for the retention job. |
   | `006_destinations.sql` | `akac_destinations` (key `(tenant, id)`, forced RLS), `akac_actors.destination`, `akac_grants.destinations` and `max_results`. No foreign key from actors to destinations. |
   | `007_token_binding.sql` | `akac_dpop_replay` (shared DPoP replay store; forced RLS with an unconditional policy; holds no tenant data). |

   Migrations 001-003 are unchanged and applied migrations are never edited. `006` is independent of `004`, `005` and `007`. Existing rows keep their 0.3 meaning: no lifecycle, no destination, no run restriction.
2. **Grant the runtime role** SELECT, INSERT, UPDATE and DELETE on `akac_dpop_replay` if you will use DPoP with the PostgreSQL replay store (`AKAC_DPOP_REPLAY`, default `postgres` when `DATABASE_URL` is set). The other tables follow the existing grants.
3. **SQLite and memory stores** upgrade on load; the state schema stays `akac-state/0.3`, destinations are absent from old snapshots and mean none.
4. **Provision fresh runs.** The core revision string (part of every context's policy revision) changes, so contexts created by 0.3 deny. Issue new grants and let agents open new contexts. Nothing else about identities, roles, groups or containers changes.
5. **Restart clients that compare results.** Agent results now carry `decisionId` (both outcomes) and allows carry `obligations`. Ignore `decisionId` when comparing whole results (it is random). A caller that acts on an allow must enforce every obligation or treat the decision as a deny; `ProtectedRuntime` does this for its own flow.

## Audit format and checkpoints

- New audit entries are format 2 (closed member set, hashed over the RFC 8785 form). Existing format 1 entries keep their hash rule; the first format 2 entry's `previous` is the last format 1 hash. A verifier selects the rule per entry and rejects a format 1 entry after a format 2 entry, so a 0.3 verifier cannot verify a stream that contains format 2 entries. Upgrade external verifiers together with the gateway.
- Format 1 checkpoints stay verifiable with `verifyCheckpoint`, but they sign only the last entry hash. Create format 2 checkpoints per tenant after the upgrade (`node scripts/checkpoint.ts PRIVATE_KEY_FILE TENANT KEY_ID OUTPUT`), store them independently, and check each new one against the previous with a consistency proof. Reset your rollback floors to tree sizes (a format 2 checkpoint's `treeSize` equals the sequence of the last covered entry).
- Optionally set `AKAC_CHECKPOINT_KEY_FILE` and `AKAC_CHECKPOINT_KEY_ID` so the admin listener can sign the tree head on request. That key is held by the serving process and attests only what the process saw; keep an offline key for independent evidence. In production the key file must not be accessible by others.
- Auditors can now read `GET /admin/v1/audit/checkpoint`, `/audit/proof` and `/audit/consistency`. The node table roughly doubles audit row count.

## Configuration changes

All are optional; none changes behavior unless set. The start-up validator reports every problem at once.

| Variable | Meaning |
|---|---|
| `AKAC_DPOP`, `AKAC_ADMIN_DPOP`, `AKAC_AUTHZEN_DPOP` | `off` (default), `optional`, `required` per listener. Refused with opaque credentials. |
| `AKAC_PUBLIC_URL`, `AKAC_ADMIN_PUBLIC_URL`, `AKAC_AUTHZEN_PUBLIC_URL` | Externally visible base URL clients sign; required when the listener's DPoP mode is on; https under `NODE_ENV=production`. The AuthZEN one also enables the metadata document. |
| `AKAC_DPOP_ALGS`, `AKAC_DPOP_SKEW_SECONDS`, `AKAC_DPOP_REPLAY` | Algorithm subset of `ES256,EdDSA,PS256`, accepted `iat` skew (1-300 s, default 60), replay store `memory` or `postgres`. |
| `AKAC_CHECKPOINT_KEY_FILE`, `AKAC_CHECKPOINT_KEY_ID` | Server-held Ed25519 checkpoint key and its id. |
| `AKAC_AUTHZEN_PORT` | Enables the AuthZEN listener (no default port; must differ from the other listener ports). The following variables require it. |
| `AKAC_AUTHZEN_HOST` | Bind address, default `127.0.0.1`. |
| `AKAC_AUTHZEN_CREDENTIALS_FILE` or `AKAC_AUTHZEN_JWT_CONFIG_FILE` | Exactly one; PEP bindings `{tenant, pep}`. Tokens must differ from every agent and admin token and the JWT audience must differ from theirs. |
| `AKAC_AUTHZEN_REASONS` | `none` (default) or `admin` (returns the closed reason code in `context.reason_admin`). |

The ingestion scanner (`Ingestor` options `scanner`, `scanFailure`, `scanTimeoutMs`) and memory review (`Engine` option `memoryReview`) are library options, not environment variables; without them 0.3 behavior applies (no scan, no review). The Compose file gains optional AuthZEN settings. Give the AuthZEN listener its own network policy and credential rotation.

## Using the new features after the upgrade

- **Lifecycle:** roles and routes in the retention and erasure guide. Erasure needs a `security-admin`; schedule the retention job (`scripts/retention.ts` or `POST /admin/v1/retention/apply`) only after you have decided which records carry `retainUntil`. A derived record inherits the earliest `retainUntil` of its sources on write, so review retention before ingesting derived records.
- **Destinations:** create profiles (`PUT /admin/v1/destinations/{id}`), give service principals a `destination`, optionally add `destinations` and `maxResults` to grants. A destination change advances the tenant epoch. Without any of these, releases behave as in 0.3. Egress must still be enforced by your proxy or gateway (the integration guide).
- **DPoP:** the token issuer must emit `cnf.jkt` first. Start with `optional` on the agent listener, then `required` on the admin listener. A token with `cnf` never works as a bearer token, even with DPoP `off`.
- **AuthZEN:** [AUTHZEN.md](AUTHZEN.md). PEPs must enforce `context.obligations` or treat the decision as a deny.

## Library API changes

- `Result` and `Decision` gain `decisionId`; allows gain `obligations`; control-plane results gain `decisionId`. Reason codes are a closed enumeration (`REASON_CODES`), and adding one is a specification change.
- `ControlPlane`, `Ingestor` and `Engine` gain lifecycle, destination and evaluation methods; store snapshots gain an optional `destinations` collection; `Knowledge` gains optional `lifecycle`, `retainUntil` and `legalHolds`; `Actor` gains `destination`; `Grant` gains `destinations` and `maxResults`.
- `scripts/checkpoint.ts` writes format 2; `scripts/retention.ts` is new. Test clients gain DPoP signing and AuthZEN calls.

## Rollback

Migrations have no down scripts, and 0.3 code cannot verify a stream that contains format 2 entries. The supported rollback is a restore of the pre-upgrade backup, followed by the 0.3 build; entries and decisions made under 0.4 are lost with it. Rolling the code back over a migrated database was not tested and should be assumed unsupported. Records quarantined, erased or held under 0.4 are not understood by 0.3, which does not know the `lifecycle` column: an erased record would read as an ordinary empty document, so do not roll back after using erasure without restoring. Before deciding to roll back, prefer disabling the new features (they are off by default) and keeping 0.4 running.

## Not covered

Erasure does not reach backups, replica history or storage remnants; take that into account before promising erasure (retention and erasure operations are part of the full package). Cache isolation ([R91-R99](../spec/AKAC-0.4.md)) needs work in your runtime and inference stack; nothing in the upgrade changes it.
