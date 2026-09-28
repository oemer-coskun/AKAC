# Conformance profiles

All names below are draft project profiles, not external certifications.

| Profile | Required behavior | Reference status |
|---|---|---|
| AKAC-Core/0.1 | R01–R06, R11, R13; identity binding, RBAC/ABAC and bounded delegation | Implemented with trusted administrative ingestion |
| AKAC-Knowledge/0.1 | Core plus R07–R10 and source dependency semantics | Implemented for mediated text objects |
| AKAC-Lifecycle/0.1 | Knowledge plus R12, R14–R16 | Partial deployment profile: API mechanisms implemented; external runtime isolation must be supplied |

No profile claim implies automatic SSO, network sandboxing or provider-side deletion. This repository MUST NOT be described as a full production-conformant deployment without verifying the integration prerequisites.

## Running

`npm run conformance` emits JSON containing each portable vector and the actual/expected result. The fixture is defined in `examples/fixture.ts`; clock and mutations are in `conformance/vectors.json`. Other implementations can reproduce this fixture without using the reference engine. Follow with `npm test` for behavioral and transport checks.

An implementation report records: specification version, profile, implementation commit, environment, test-vector revision, results, unsupported obligations, trust assumptions and revocation semantics. A successful self-report is not independent certification.

## Traceability

| Requirements | Evidence |
|---|---|
| R01–R04 | Portable vectors; `core.test.ts` attack matrix and clearance matrix; HTTP forged-fields tests |
| R05 | Delegation narrowing, expiry and ancestor revocation tests |
| R06 | Prompt-as-content test; closed request schemas; separate administrative store |
| R07 | Authorized-first retrieval tests; no corpus-wide scoring statistics |
| R08–R09 | Mixed-source derivation and old-context omission tests |
| R10 | Recipient and cross-tenant release tests |
| R11–R12 | Source version, expiry during policy check, restart and concurrent revocation tests |
| R13 | OPA error/undefined/malformed response tests; unsupported declassification |
| R14 | Audit verification and transactional persistence tests |
| R15 | No declassification allow path; OPA and core deny |
| R16 | Complete run manifest in gateway; external process/model isolation remains a deployment prerequisite |

## AKAC-Hardened/0.2 draft profile

Extends the 0.1 lifecycle requirements with R17–R21. Reference mechanisms are
implemented; deployment conformance still depends on trusted identity provisioning,
complete mediation, provider isolation and external operational controls.

| Requirements | Evidence |
|---|---|
| R17 | `hardening.test.ts`: shared DAG, depth/node budgets and retrieval limits |
| R18 | OPA contract tests and context policy-revision invalidation |
| R19 | `jwt.test.ts`: valid binding, wrong issuer/audience/key/type, expiry, rotation and HTTP |
| R20 | Transitive logical source expiry tests |
| R21 | `runtime.test.ts`: provider denial, exact input and revocation during generation |
| Checkpoints | Signature, tampering, wrong key/stream, truncation and rollback-floor tests |
| Decision agreement | `interop.test.ts`: 1,001 TypeScript/Python cases and 500 clearance properties |

The Python evaluator implements decisions only. Same-project differential tests
do not satisfy an independent organizational implementation or security audit gate.

## AKAC-KB/0.3 draft profile

Extends AKAC-Hardened/0.2 with R22–R31 of [AKAC 0.3](AKAC-0.3.md). Portable
vectors live in `conformance/vectors-0.3.json` against `kbFixture()` in
`examples/fixture.ts`. Patch entries either set a field (`[collection, id, field,
value]`), replace a record (`[collection, id, record]`) or set a tenant epoch
(`["epochs", tenant, n]`). Decision vectors MAY pin an internal `code`; context
vectors (`kind: "context"`) check epoch and revision freshness.

| Requirements | Evidence |
|---|---|
| R22–R23 | Vectors KB-001–KB-007, KB-029; `kb.test.ts` cycles, depth/width budgets, inactive and cross-tenant roles and groups |
| R24 | Vectors KB-008–KB-016; control-plane rejection at assignment, group membership and grant issuance; holder-count refusal of constraints and role widening; reductions and SCIM deprovisioning of a violating user (`regressions.test.ts`) |
| R25 | Vectors KB-017–KB-028; container attacks; monotonic-restriction property with a broken-oracle meta-test; derivation property; transitive classification for supplemental policy and ingestion (`regressions.test.ts`) |
| R26 | Candidate-source tests: re-check, dropped and counted mismatches, other-tenant candidates, unavailable source; lexical content budget and batched reconcile (memory and PostgreSQL) |
| R27 | Vector KB-028; missing/unknown origin attacks; ingestion refuses model origin |
| R28 | Vectors KB-030–KB-033; per-tenant revocation in memory and PostgreSQL |
| R29 | Category tests; audit reasons; decision schema over every vector |
| R30 | `postgres.test.ts`: RLS for a non-bypass role, parallel tenants, migration idempotency and checksum refusal, legacy import, bounded readiness, non-truncating loads, inactive role behind 576 names, `(tenant, id)` keys for bypassing and RLS roles, migration 003 over a database at 002, start-up refusal of a bypassing role; tenant-partitioned memory/SQLite stores |
| R31 | Control-plane role separation, cross-tenant and agent administrators, audited denials, audited idempotent replays, `DEFERRED:STORE_ERROR` follow-up audit, kb-admin document removal with the real ingestor |
| Decision agreement | `interop.test.ts`: 1,000 0.2 cases, 1,500 hierarchy/SoD/container cases and every portable vector against the Python evaluator |

PostgreSQL evidence requires `AKAC_TEST_DATABASE_URL`; without it those tests
are reported as skipped. Row-level security evidence is only meaningful with a
runtime role that is neither superuser nor `BYPASSRLS`.
