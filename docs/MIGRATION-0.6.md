# Migrating reference 0.5 to 0.6

0.6 is the largest release so far, but everything new is additive on the wire and either off or restrictive by default. The
upgrade is not a no-op: the core revision changes (open contexts deny), several behaviours are stricter, and the schema
gains three migrations. Read the [changelog](../CHANGELOG.md) first. **An upgrade of a real deployment has not been
rehearsed by the project, and rollback is untested and therefore unsupported** (see "Rollback").

## Before you start

1. Back up the database (including audit history) and your latest audit checkpoints, and test the restore
   (`node scripts/backup-drill.ts`). There are no down migrations.
2. Plan a maintenance window. Do not run a rolling upgrade across the version boundary: 0.5 and 0.6 replicas disagree on
   the core revision (contexts opened by one deny on the other), on the schema, and 0.5 verifiers reject new audit members.
   Stop new agent runs, drain in-flight operations, upgrade, then start runs again.
3. Confirm the roles: `AKAC_MIGRATION_DATABASE_URL` for the schema owner, `DATABASE_URL` for a runtime role that is neither
   superuser nor `BYPASSRLS`; passwords are files (`AKAC_*_PASSWORD_FILE`). The reference `deploy/postgres/init.sql` grants the
   runtime role the privileges on new tables through default privileges; with a custom role setup grant `SELECT, INSERT,
   UPDATE, DELETE` on the tables below yourself.
4. Node 24 (unchanged). Post-quantum checkpoint algorithms need the `node:crypto` of Node 24; nothing else changes.

## Steps

1. Run `npm run migrate` (or start with `AKAC_AUTO_MIGRATE`) as the schema owner. Migrations apply in order under an advisory
   lock; 001-008 are unchanged and 009-011 are new. Order matters: 010 needs the tables of 001-004 and 008, and 011 needs
   the `akac_tenant_settings` table of 010.

   | Migration | Adds |
   |---|---|
   | `009_shared_limits.sql` | `akac_rate_limits` and `akac_idempotency_keys` (tenant-scoped, forced RLS): rate windows and admin `Idempotency-Key` records shared by every replica |
   | `010_identity_authority.sql` | grant columns `heartbeat_ttl_ms`, `last_heartbeat_at`, `break_glass`; `akac_risk_signals`, `akac_tenant_settings`, `akac_approvals` |
   | `011_knowledge_semantics.sql` | `akac_knowledge` columns `modality`, `tags`, `residency`, `model`, `erasure_requested_at` and three more quarantine reasons; container `tags` and `residency`; destination `region`; `lineage_depth` in tenant settings; `akac_combination_rules` |

   All new columns are nullable and NULL keeps the 0.5 behaviour. SQLite and memory stores upgrade on load; snapshots
   without the new members mean none.
2. The `CORE_VERSION` bump (`akac-reference/0.6.0`) is part of every context's policy revision, so contexts opened by 0.5
   deny after the upgrade; provision fresh runs. Grants, roles and knowledge are untouched.
3. Shared state: with `DATABASE_URL` set, `AKAC_SHARED_STATE` now defaults to `postgres`, which needs migration 009 and the
   runtime privileges above. There is no silent fallback: when the shared store is unusable, requests fail closed (503). Set
   `AKAC_SHARED_STATE=memory` only to keep the 0.5 per-replica limits knowingly.
4. Upgrade external audit verifiers and SIEM parsers together with the gateway:
   - audit entries stay format 2, but may now carry the optional hash-covered members `actorChain`, `breakGlass` and
     `findings`; a 0.5 verifier rejects such entries. Entries without them are unchanged, and the chain across the upgrade
     verifies with a 0.6 verifier;
   - checkpoints stay format 2 (Ed25519) by default and stay readable by every 0.4+ verifier. Format 3
     (`akac-audit-checkpoint/3`) is written only when you set `AKAC_CHECKPOINT_ALG` to something other than `ed25519`; then
     every verifier and keyring must support that algorithm and the key id `<algorithm>:<label>`
     ([CRYPTO-AGILITY.md](CRYPTO-AGILITY.md)). Format 1 and 2 checkpoints remain valid.
5. The defaults keep 0.5 settings except the behaviour changes below. New settings are optional. If you set DPoP or JWT
   configuration, the credential file and JWT configuration are mutually exclusive per listener.

## Settings by security class

The following table describes public settings and operator obligations, not a private deployment recipe.
Tenant settings are applied with `PUT /admin/v1/settings`. "Required" follows
[SECURITY-CLASSES.md](profiles/SECURITY-CLASSES.md); nothing here has been reviewed by an external party.

| Setting | SK-1 | SK-2 | SK-3 | SK-4 |
|---|---|---|---|---|
| `AKAC_RUNTIME_OBLIGATIONS` | `deny` | `deny` | `deny`, or `trusted-enforcer` behind a tested enforcer | same as SK-3 |
| DPoP (`AKAC_DPOP`, `AKAC_ADMIN_DPOP`) | off | admin: recommended | `required` (JWT mode) | `required` |
| Shared state | memory (one replica) | `postgres` | `postgres` | `postgres` |
| Approval quorum (label, role, runtime profile, separation of duty, destination, settings) | 1 | recommended 2 for label and role | 2 | 2 (settings 3) |
| Break-glass | fixed quorum 2, read-only, at most 2 hours | same | same | same |
| Content encryption (`AKAC_CONTENT_ENCRYPTION`) | off | off | `provider` (KMS or HSM provider from an extension) | `provider` |
| Checkpoints (`AKAC_CHECKPOINT_SIGNER`, `AKAC_CHECKPOINT_ALG`) | Ed25519 | Ed25519 | `ed25519` from a Vault Transit key (`vault-transit`); hybrid once the KMS signs ML-DSA | `ed25519+ml-dsa-65` from an HSM signer (`extension`), or `slh-dsa-sha2-256s` by policy |
| Timing floor, volume budgets, backoff | off | optional | on | on, tighter |
| Denial hints (`AKAC_DENIAL_HINTS`) | off | off | off | off |
| Decision cache | off | optional | optional | off |
| Embedding anchors (vector retrieval) | off | optional | on | on |
| Lineage depth (`lineageDepth`, tenant setting) | default 16 | default 16 | default 16 | 8 |
| Restricted-tier database | no | optional | recommended | required (`retrieval.restrictedDatabase`) |
| Sweeper job (`sweeperJob`) | optional | on | on | on |

The Vault Transit signer signs Ed25519 only, so the SK-3 preset keeps KMS custody and a classical signature. A post-quantum
or hybrid key is either file-held (`AKAC_CHECKPOINT_KEY_FILE`) or held by a signer that an extension supplies
(`AKAC_CHECKPOINT_SIGNER=extension`, ADR-023), for example an HSM signer; the SK-4 preset requires the latter, and the stock
server refuses to start with it (exit code 2) rather than sign with a weaker key.
`AKAC_CONTENT_ENCRYPTION=provider` needs a key provider that an extension supplies; the stock server has none and refuses to
start with it, and the development-only `local` provider is refused when `NODE_ENV=production`.

## Behaviour changes to check before enabling traffic

| Change | Who is affected | What to do |
|---|---|---|
| A read-only `share` or `export` evaluation (`Engine.evaluate`, AuthZEN) without a destination is denied (`RECIPIENT`); a run whose Destination ids resolve to no active profile denies too (R121, R122) | Enforcement points and AuthZEN clients that sent `share`/`export` without `context.destination` | Send `context.destination`; create the destination profiles |
| The agent HTTP listener denies operations whose allow would carry a `runtime_profile` obligation (`UNSUPPORTED_OBLIGATION`), leaving no state and auditing the denial (R123) | Tenants with an active runtime profile policy | Run a tested runtime enforcer and set `AKAC_RUNTIME_OBLIGATIONS=trusted-enforcer` knowingly, or keep `deny`. Tenants without a policy are unaffected |
| The runtime revision is re-confirmed after the final release; a mismatch withholds the result (R124) | `ProtectedRuntime` users and custom enforcers | Make the enforcer report the applied revision after the release |
| A new version of an existing document that widens its label (lower classification, added reader or reader role, removed project, another container, removed or extended expiry, dropped source) needs `security-admin`; a `kb-admin` alone gets `CONFLICT` and nothing is stored (R126) | Ingestion pipelines that lowered labels with a `kb-admin` credential | Do it as a declassification by a `security-admin`; with a quorum above 1 it answers 202 `APPROVAL_REQUIRED` |
| Erasure clears the reader roles of a tombstone (R125); re-erasing an older tombstone clears them without moving its erasure time | Nothing normally; reports that listed tombstone readers | none |
| Vector retrieval pre-filters on the audience of the user **and** the agent; `akac_filter_mismatch_total` counts only real inconsistencies | Anyone comparing recall or the metric with 0.5 | Expect fewer wasted candidates; a third-party index that ignores `VectorQuery.agent` stays correct and only loses recall |
| An erasure requested while a legal hold blocks it stays pending (the request is answered 409 `CONFLICT` with `pending: true`, and `erasure_requested_at` is set) and is applied when the hold is lifted or by the sweeper job | Retention and erasure operators | Run the `sweeperJob` (or `POST /admin/v1/erasures/apply`); read the retention and erasure guide |
| Content whose effective `residency` is set is released only to destinations whose `region` is in it (`DENIED:RESIDENCY`); no residency, no change | Tenants that start setting residency | Set `region` on destination profiles first, then residency on records and containers |
| Derivations deeper than the lineage depth (default 16, tenant setting up to 127) deny (`DENIED:LINEAGE_DEPTH`); provenance cycles make a record invisible (R185) | Deep derivation chains; SK-4 sets 8 | Check the deepest generation in your data before lowering `lineageDepth` |
| Combination rules and the write-down rule deny runs that mix tag sets or write below their high-water mark; both need data (tags, rules) before they act | Tenants that adopt tags | Test rules in a staging tenant |
| Approvals: with a quorum above 1 a sensitive operation answers 202 `APPROVAL_REQUIRED` with the approval id, and needs N distinct `security-admin` identities; break-glass always needs 2 | Automation that wrote roles, constraints, destinations, runtime profiles or settings | Handle 202, or keep the default quorum 1 (the 0.5 behaviour) |
| Lifecycle changes through the admin API (quarantine, revoke, erase, new document version) trigger a background sweep of the record's lineage; lazy denial was already authoritative | Operators watching index churn | Expect follow-up index work; `POST /admin/v1/index/reconcile` remains the repair |
| Decisions taken with a token that carries an RFC 8693 `act` claim record `actorChain`; decisions under a break-glass grant record `breakGlass` | SIEM parsers | Accept the new optional members |
| The audit `findings` member and new metrics are added (for example hook outcomes, volume budgets, embedding drift) | Dashboards | Add the series; existing names are unchanged |

| 0.6b: making a principal a `security-admin` (role assignment, principal create or reactivation, group members or roles, role inheritance, SCIM) needs the highest approval quorum of any class, at least 2; the elevated principal never counts | Tenants with a single administrator; automation that grants `security-admin` | Provision the first two administrators out of band (seed or migration); SCIM answers 403 with the pending approval id |
| 0.6b: a `runtime` principal heartbeats only grants of agents listed in its `runtimeFor` (migration 010 column `akac_actors.runtime_for`) | Runtimes that send heartbeats | Set `runtimeFor` on each runtime principal (`PUT /admin/v1/actors/{id}`) |
| 0.6b: combination rules span every grant of the same user and agent within `AKAC_COMBINATION_WINDOW_MS` (default 300000, up to 30 days) | Tenants with combination rules | Expect denials where a forbidden pair was split across grants |
| 0.6b: with content encryption, content that cannot be opened because the key service is unavailable is unreadable (deferred denial, no writes), not erased | Operators of `AKAC_CONTENT_ENCRYPTION` | Make providers throw `KeyDestroyed` only for destroyed keys; watch `unreadable` events |

New roles: `runtime` (grant heartbeats) and `risk-ingest` (risk signals) are ordinary standing roles; nobody holds them until
you assign them.

## Enabling the new features (optional)

Everything else is off until you configure it: release filters and derive sanitizers (your own module; AKAC ships none), timing
floor, denial hints, volume budgets and backoff, decision cache, embedding anchors, content encryption, PQ checkpoints, tenant
settings and approval quorums. Change one group at a time; `.env.example` lists the variables. Embedding anchors need a persistent
baseline file and are never created implicitly: set `AKAC_ANCHOR_BOOTSTRAP=true` for the first start only (then remove it) or call
`POST /admin/v1/index/anchors/rebaseline` as a `security-admin`; until then vector retrieval is disabled (fail closed).

## Verification after the upgrade

1. `GET /ready` on every replica, then `node scripts/checkpoint.ts verify --tenant <t>` for each tenant: the chain across the
   version boundary and the RFC 9162 root must verify.
2. Open a context with a new run; issue a grant; run one allowed and one denied read; check the audit entries and, where enabled, the
   metrics for hooks, volume budgets and drift.
3. If you enabled a post-quantum checkpoint algorithm, verify a checkpoint with an independent verifier that you control before
   you rely on it.

## Rollback

There are no down migrations. Migrations 009-011 add tables and nullable columns and replace one CHECK constraint; 0.5 code has
not been run against a 0.6 schema, and 0.5 verifiers reject audit members and format 3 checkpoints written by 0.6. The only
path the project has reasoned about is: stop 0.6, restore the backup taken in "Before you start" and run the 0.5 build.
That path has not been tested end to end, so treat rollback as **unsupported**: rehearse the upgrade and the restore on a copy
of your data first, and expect to lose everything written after the backup (including audit entries and any approvals).
