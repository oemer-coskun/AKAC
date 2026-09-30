# Conformance profiles

All names below are draft project profiles, not external certifications. MUST, MUST NOT,
SHOULD and MAY are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when,
and only when, they appear in all capitals.

| Profile | Required behavior | Reference status |
|---|---|---|
| AKAC-Core/0.1 | R01–R06, R11, R13; identity binding, RBAC/ABAC and bounded delegation | Implemented with trusted administrative ingestion |
| AKAC-Knowledge/0.1 | Core plus R07–R10 and source dependency semantics | Implemented for mediated text objects |
| AKAC-Lifecycle/0.1 | Knowledge plus R12, R14–R16 | Partial deployment profile: API mechanisms implemented; external runtime isolation must be supplied |
| AKAC-Hardened/0.2 | Lifecycle/0.1 plus R17–R21 | Implemented; deployment conformance depends on external controls |
| AKAC-KB/0.3 | Hardened/0.2 plus R22–R31 ([AKAC 0.3](AKAC-0.3.md)) | Implemented; PostgreSQL evidence needs `AKAC_TEST_DATABASE_URL` |
| AKAC-Evidence/0.4 | KB/0.3 plus R32–R44 (decisions, obligations, audit evidence) | Implemented; draft |
| AKAC-Lifecycle/0.4 | Evidence/0.4 plus R45–R59 (quarantine, lineage, retention, legal hold, erasure) | Implemented as mechanisms; erasure from backups is not covered; draft |
| AKAC-Destinations/0.4 | Evidence/0.4 plus R60–R71 (destination profiles, run result limit) | Implemented as decisions; egress enforcement belongs to the integration; draft |
| AKAC-AuthZEN/0.4 | Evidence/0.4 plus R79–R90 (optional PDP facade; R72–R78 when DPoP is enabled) | Implemented; not tested against third-party enforcement points; draft |
| AKAC-RedTeam/0.4 | R100–R108 (runner semantics, adversarial vectors); checks on the implementation, adds no access rule | Implemented; draft |
| AKAC-RuntimeContainment/0.5 | Evidence/0.4 plus R109–R120 of [AKAC 0.5](AKAC-0.5.md) (runtime profile obligations, runtime enforcer contract, evidence correlation) | Implemented as decisions and the `ProtectedRuntime` enforcer seam; sandboxing and non-bypassability belong to the runtime and operator; draft |
| AKAC-Identity/0.6 | Evidence/0.4 plus R143–R158 of [AKAC 0.6](AKAC-0.6.md) (RFC 8693 actor chains, heartbeat-bound grants, break-glass, risk caps, approval quorum) | Implemented; SSF/CAEP receivers and approval workflows are connectors outside the core; draft |
| AKAC-CryptoAgility/0.6 | Evidence/0.4 plus R159–R166 (algorithm registry, checkpoint format 3, hybrid signatures, verifier policy, no downgrade) | Implemented for verification and local signing on Node 24 with OpenSSL 3.5; no FIPS-validated module is claimed; draft |
| AKAC-Release/0.6 | Evidence/0.4 plus R167–R181 (release filters, derive sanitizers, fail-closed hooks, hints, volume budgets, backoff, embedding anchors, decision cache) | Implemented as hooks with fail-closed defaults; no filter or sanitizer heuristics ship in the community edition; draft |
| AKAC-Knowledge/0.6 | KB/0.3 and Lifecycle/0.4 plus R182–R196 (lineage depth, modality, tags, residency, combination rules, session-scoped records, model lineage, write-down, cascade sweep, pending erasure, content encryption) | Implemented; the community edition ships a local development key provider only; draft |
| AKAC-Operations/0.6 | R136–R142 (shared rate windows and idempotency, serialized jobs, external checkpoint signers, verification across rotation, audit verification job) | Implemented; evidenced by tests, not portable vectors (deployment state); draft |

R121–R126 of [AKAC 0.6](AKAC-0.6.md) refine the Destinations/0.4, AuthZEN/0.4,
RuntimeContainment/0.5 and Lifecycle/0.4 profiles and are required by them from 0.6. R127–R131
govern the conformance material and how results are reported, and R132–R135 the formal model;
neither adds an access rule.

Sections R72–R78 (token binding, optional) and R91–R99 (cache isolation, operator obligations) of [AKAC 0.4](AKAC-0.4.md) are not separate profiles. The token binding requirements apply to a listener that enables DPoP and are covered by `tests/dpop.test.ts`; the cache isolation requirements are deployment obligations that the reference cannot enforce and no vector covers. Optional add-on modules are not part of any profile.

No profile claim implies automatic SSO, network sandboxing or provider-side deletion. This repository MUST NOT be described as a full production-conformant deployment without verifying the integration prerequisites.

## Running

`npm run conformance` emits JSON containing each portable vector and the actual/expected result. The fixture is the data file `examples/fixture.json` (validated by `schemas/fixture.json`, R127; `examples/fixture.ts` only loads it); clock and mutations are in the vector files. Other implementations can reproduce this fixture without using the reference engine; `implementations/python/` does so (`python -m akac conformance`). Follow with `npm test` for behavioral and transport checks.

The runner covers every vector file (`vectors.json`, `vectors-0.3.json`, `vectors-0.4.json`,
`vectors-authzen.json`, `vectors-destinations.json`, the scenario vectors `vectors-redteam.json`,
`vectors-runtime.json` for 0.5 and, for 0.6, `vectors-0.6-identity.json`,
`vectors-0.6-crypto.json`, `vectors-0.6-release.json` and `vectors-0.6-knowledge.json`),
classifies each vector with one of the four outcome classes SUCCESS, SAFE_BLOCK, FAILURE and
UNSAFE_SUCCESS, and applies the same hard gates to all profiles: no UNSAFE_SUCCESS, no FAILURE,
and no UNSAFE_SUCCESS among (at least one) tenant-boundary vectors ([R104–R108](AKAC-0.4.md),
details in the AKAC-RedTeam/0.4 section below). A non-zero exit code means a gate failed.

Counts of the reference 0.6.0 (local run of `npm run conformance`): 629 vectors, 232 SUCCESS,
397 SAFE_BLOCK, 0 FAILURE, 0 UNSAFE_SUCCESS; 19 cross-tenant vectors; all three gates pass. By
0.6 vector file: identity 38, crypto agility 110, release 49, knowledge 59; the runtime
containment file (59) includes the 0.6 additions for R121, R122 and R124.

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

## AKAC-Evidence/0.4 draft profile

Extends AKAC-KB/0.3 with R32–R44 of [AKAC 0.4](AKAC-0.4.md). Vectors:
`conformance/vectors-0.4.json` (profile `AKAC-Evidence/0.4-draft`): RFC 9162
Merkle roots over the eight-leaf test tree, RFC 8785 canonical form, audit format 2
entries and checkpoint format 2, obligations and reason codes. These are pure-function
vectors: a match is SUCCESS, a mismatch FAILURE.

| Requirements | Evidence |
|---|---|
| R32–R36 | `decisions.test.ts`: decision ids, closed reason codes, policy digest, non-distinguishing denials, obligations |
| R37 | `decisions.test.ts`, `opa.test.ts`: strict validation of policy obligations; `UNSUPPORTED_OBLIGATION`; unusable obligations member |
| R38 | `runtime.test.ts`, `decisions.test.ts`: enforcement of obligations, deadline abort, deny on unenforceable obligation |
| R39 | `decisions.test.ts`: valid and invalid W3C trace ids |
| R40–R41 | `evidence.test.ts`: format 2 hashing over the JCS form, rejection of non-JSON-subset values, chain continuation across formats, downgrade rejection |
| R42–R44 | `evidence.test.ts`, `admin-evidence.test.ts`: RFC 9162 trees, inclusion and consistency proofs verified with independent verifiers, checkpoint format 2, rollback and truncation; `evidence-postgres.test.ts`: stored nodes, migration 004 backfill equals the TypeScript leaves |

## AKAC-Lifecycle/0.4 draft profile

Extends AKAC-Evidence/0.4 with R45–R59. Vectors: cases `L01`–`L08` of
`conformance/vectors-0.4.json` (profile `AKAC-Lifecycle/0.4-draft`), which run
`decide()` over the knowledge-base fixture with patches; scenario vectors RT-010..013
cover delayed memory injection.

| Requirements | Evidence |
|---|---|
| R45–R46 | Vectors `L01`–`L08`; `lifecycle.test.ts`: lifecycle and transitive denial at every gate and retrieval path |
| R47–R49 | `lifecycle.test.ts`, `admin-lifecycle.test.ts`: quarantine and release roles and separation of duty, blast radius bounds and `truncated`, epoch advance |
| R50–R52 | `lifecycle.test.ts`: scanner verdicts, timeout and error as quarantine or reject, memory review, index hygiene |
| R53–R57 | `lifecycle.test.ts`, `lifecycle-postgres.test.ts`: cascade erasure, tombstones, legal hold in the lineage with count-only refusal, retention inheritance, retention job |
| R58–R59 | `lifecycle.test.ts`: bounded cascades deny with `BUDGET_EXCEEDED`, audit entries retained (R54, erased content never disclosed, is covered by the R45–R46 and R53 tests) |

## AKAC-Destinations/0.4 draft profile

Extends AKAC-Evidence/0.4 with R60–R71. Vectors: `conformance/vectors-destinations.json`
(profile `AKAC-Destinations/0.4-draft`), run by `conformance/run-destinations.ts`.
Expected allow or deny is stated per vector and classified as in the outcome table below.

| Requirements | Evidence |
|---|---|
| R60–R66 | Destination vectors; `destinations.test.ts`: tenant scope, profile gate, run restriction, legacy behavior, narrowing-only property, obligation intersection |
| R67 | `destinations.test.ts`, `authzen.test.ts`: read-only evaluation and `context.destination` |
| R68–R69 | `destinations.test.ts`: attenuation of `destinations` and `maxResults`, result limit |
| R70 | Enforcement boundary: integration contract (the integration guide); no vector |
| R71 | `admin-lifecycle.test.ts`, `destinations-postgres.test.ts`: administration, epoch advance, storage |

Egress itself (R70 is a decision, not a network control) is enforced by the
integration; no vector shows that bytes cannot leave by another path.

## AKAC-AuthZEN/0.4 draft profile

Extends AKAC-Evidence/0.4 with R79–R90 (and R72–R78 when the listener enables DPoP).
Vectors: `conformance/vectors-authzen.json` (profile `AKAC-AuthZEN/0.4-draft`),
run by `conformance/run-authzen.ts`. Only `decision: true` is an allow; `deny`,
`malformed` and `unsupported` MUST NOT be allowed. This profile is an implementation
profile of the OpenID AuthZEN Authorization API 1.0 (Final); it is not an AuthZEN
certification and was not tested with third-party enforcement points. The obligations
member is a draft-aligned AKAC extension.

| Requirements | Evidence |
|---|---|
| R79–R81, R89–R90 | `authzen.test.ts`, `config-authzen.test.ts`: separate listener, PEP authentication, tenant pinning, metadata, limits, start-up validation |
| R82–R84 | `authzen.test.ts`, AuthZEN vectors: mapping, message handling, parity with `decide()` over 400 generated requests |
| R85–R88 | `authzen.test.ts`: audit of every evaluation, response minimization, obligations, batch semantics |
| R72–R78 | `dpop.test.ts`, `dpop-postgres.test.ts` (PostgreSQL required) |

## AKAC-RuntimeContainment/0.5 draft profile

Requirements R109–R120 of [AKAC 0.5](AKAC-0.5.md)
([ADR-012](../governance/ADR-012-runtime-containment-contract.md)). Vectors:
`conformance/vectors-runtime.json`, run by `conformance/run-runtime.ts`, with the same
four outcome classes and gates. `profiles` vectors exercise the pure derivation
(classification thresholds, destination narrowing, conflicts, no policy, malformed
records, another tenant's policies); `engine` vectors the same through the engine
gates; `enforcer` vectors the `ProtectedRuntime` enforcer contract. An allow that
drops, changes or lowers an expected runtime obligation is UNSAFE_SUCCESS, and so is a
provider call where a denial before the provider is required.

| Requirements | Evidence |
|---|---|
| R109–R111 | Vectors RTC-P01..P21, RTC-E01..E15 (E12, E13: unknown destination merged over the run's classes, `internal-user` for users; E09..E11, E14, E15, P20, P21: R121, R122); `runtime-containment.test.ts` (supplemental policy conflicts, obligation merge, share/export without destination) |
| R112, R113 | Vectors RTC-R01..R13 (R08: provider-gate precedence; R10: same-tier conflict; R11, R12: revision drift, failed lease release; R13: drift after the final release, R124); `runtime-containment.test.ts` (apply order, exact profiles, enforcer timeout, serialized sandbox-wide executions, per-execution revision check) |
| R114, R115 | `runtime-containment.test.ts` (security-admin only, validation, epoch advance, bound, admin routes), `runtime-postgres.test.ts` (checks, forced RLS) |
| R117 | `runtime-containment.test.ts` (execution header, audit members, hash coverage, schemas, policy digest over the active set), `authzen.test.ts` (AuthZEN execution header), `runtime-postgres.test.ts` |
| R119 | `runtime-containment.test.ts` (a policy change ends open contexts) |
| R120 | `runtime-containment.test.ts` (AuthZEN `context.obligations`) |
| R116, R118 | Operator obligations; the checklist in [RUNTIME-CONTAINMENT.md](../docs/RUNTIME-CONTAINMENT.md); no vector can show them |

Broken-oracle evidence: `runtime-containment.test.ts` injects a derivation that drops
every profile, one that lowers the output label, and a runtime that calls the provider
without its enforcer, and asserts UNSAFE_SUCCESS and a non-zero exit code; a blanket-deny
derivation is FAILURE.

## Fixes from the review of 0.5.0 (R121–R126)

Requirements R121–R126 of [AKAC 0.6](AKAC-0.6.md)
([ADR-013](../governance/ADR-013-findings-and-semantics-fixes.md)); they only add denials, and
the vectors run with the outcome classes and gates of the profile they refine.

| Requirements | Evidence |
|---|---|
| R121 | Vectors Z21..Z23, RTC-E09..E11, RTC-E14, RTC-E15; `authzen.test.ts` (share/export without `context.destination` over HTTP, parity with decide()), `destinations.test.ts`, `runtime-containment.test.ts` |
| R122 | Vectors RTC-P20, RTC-P21; `runtime-containment.test.ts` |
| R123 | `runtime-containment.test.ts` (default deny, rollback and audit, `trusted-enforcer`, invalid mode, malformed caller list), `config.test.ts` (`AKAC_RUNTIME_OBLIGATIONS`) |
| R124 | Vector RTC-R13; `runtime-containment.test.ts` (withheld answer audited with execution id and revision) |
| R125 | `lifecycle.test.ts` (tombstone audience, projects kept, legacy tombstone) |
| R126 | `regressions-0.6.test.ts` (every widening kind refused for kb-admin, accepted with security-admin; security-admin limited to relabelling) |

## Conformance material (R127–R131) and formal model (R132–R135)

R127–R131 ([ADR-014](../governance/ADR-014-conformance-independence.md)): the fixture as data,
JSON value semantics, the runner contract of [IMPLEMENTATIONS.md](../docs/IMPLEMENTATIONS.md),
differential evidence and honest provenance. Evidence: `differential-vectors.test.ts` (every
vector file through the TypeScript and the Python implementation, identical results required),
`differential-fuzz.test.ts` (generated worlds with a fixed seed, minimized counterexample),
`interop.test.ts`, `coverage-gaps.test.ts` (R131). Both implementations were written by the
authors of the specification: the comparison is same-project evidence, not independent.

R132–R135 ([ADR-015](../governance/ADR-015-formal-model.md)): the TLA+ model in `formal/`, its
properties, broken configurations that violate each property and non-vacuity witnesses, checked
by `.github/workflows/formal.yml`; results and bounds in [FORMAL-MODEL.md](../docs/FORMAL-MODEL.md).
A bounded model-checking result is not a proof for unbounded systems and does not verify the
implementation.

## AKAC-Operations/0.6 draft profile

R136–R142 of [AKAC 0.6](AKAC-0.6.md) ([ADR-016](../governance/ADR-016-ha-and-operations.md)).
They concern deployment state (several gateway instances, key custody, audit verification), not
`decide()`, so they are evidenced by tests, not portable vectors; no outcome class applies. The
gate is the test suite: a failing test fails CI.

| Requirements | Evidence |
|---|---|
| R136–R139 | `ha.test.ts` (memory seams, 409 and 503 paths), `ha-postgres.test.ts` (two gateway instances on one database: shared windows, one concurrent winner, lease lapse, TTL sweep, forced RLS, job locks and a crashed holder; PostgreSQL required) |
| R140–R142 | `custody.test.ts` (mocked Vault Transit endpoint, pinned key version, key rotation, tamper detection, verification job); CI backup/restore drill (`scripts/backup-drill.ts`, R142 after restore) |

## AKAC-Identity/0.6 draft profile

R143–R158 of [AKAC 0.6](AKAC-0.6.md) ([ADR-019](../governance/ADR-019-identity-and-authority.md)).
Vectors: `conformance/vectors-0.6-identity.json` (profile `AKAC-Identity/0.6-draft`, 38 vectors),
run by `conformance/run-identity.ts` and by the Python implementation: `decide()` over the
knowledge-base fixture with patches. Outcome classes as for decision vectors: an allow where a
denial is expected (a lapsed heartbeat, a break-glass grant outside its bounds, a risk cap
ignored) is UNSAFE_SUCCESS; a wrong reason code is FAILURE.

| Requirements | Evidence |
|---|---|
| R143–R146 | `identity.test.ts` (RFC 8693 `act` and `may_act`, prior actors, impersonation, chain depth and shape, audit `actorChain`, delegation tokens refused on admin and PEP listeners) |
| R147, R148 | Vectors ID-H01..ID-H10; `identity.test.ts`, `identity-postgres.test.ts`, `regressions-0.6b.test.ts` (runtime binding) |
| R149, R150 | Vectors ID-B00..ID-B13; `identity.test.ts` (bounds, not delegable, audience clauses only, quorum 2, `breakGlass` in audit) |
| R151, R152 | Vectors ID-R01..ID-R14; `identity.test.ts` (caps, `critical`, malformed signals, recipients, sources, epoch advance, external provider fails closed) |
| R153–R156 | `identity.test.ts` (approval classes, distinct approvers, re-validation at execution, expiry, external gate only adds, settings tightening and relaxation) |
| R157 | `identity-postgres.test.ts` (migration 010, forced RLS, bounded loads; PostgreSQL required) |
| R158 | `regressions-0.6b.test.ts` (elevation to an approver role needs the highest quorum; the elevated principal cannot approve its own elevation) |

## AKAC-CryptoAgility/0.6 draft profile

R159–R166 of [AKAC 0.6](AKAC-0.6.md) ([ADR-021](../governance/ADR-021-crypto-agility-and-pq.md)).
Vectors: `conformance/vectors-0.6-crypto.json` (profile `AKAC-CryptoAgility/0.6-draft`, 110
vectors: 97 `checkpoint-v3`, 13 `checkpoint-history`), run by `conformance/run-crypto.ts`.
Verification-only known answers (public keys and signatures from discarded ephemeral keys).
Accepting a checkpoint is an allow: accepting a forged, relabelled, truncated, partial-hybrid,
policy-excluded or downgraded checkpoint is UNSAFE_SUCCESS; rejecting a valid one is FAILURE.
The reference requires Node 24 with OpenSSL 3.5 (ML-DSA, SLH-DSA); an algorithm the runtime
cannot execute is a FAILURE for the reference, and another implementation reports it as
NOT_APPLICABLE with the reason, never as a pass (R166, R130).

| Requirements | Evidence |
|---|---|
| R159 | Vectors `CRYPTO-unregistered-alg`, `CRYPTO-alg-none`, `CRYPTO-*-valid`; `crypto-agility.test.ts` |
| R160 | Vectors `CRYPTO-*-alg-relabelled`, `CRYPTO-*-truncated-signature`, `CRYPTO-*-tampered-root` and others; `crypto-agility.test.ts` (format 1 and 2 unchanged) |
| R161 | Vectors `CRYPTO-hybrid-*`; `crypto-agility.test.ts` |
| R162 | Vectors `CRYPTO-*-not-in-policy`, `CRYPTO-*-in-policy`; `crypto-agility.test.ts` |
| R163 | Vectors `CRYPTO-history-*` (downgrade, backdating bound, a failing member fails the set); `crypto-agility.test.ts` |
| R164–R166 | `crypto-agility.test.ts` (configuration, self-verification, key id prefix, key material never serialised, unavailable algorithms) |

## AKAC-Release/0.6 draft profile

R167–R181 of [AKAC 0.6](AKAC-0.6.md) ([ADR-020](../governance/ADR-020-release-and-retrieval-protection.md)).
Vectors: `conformance/vectors-0.6-release.json` (profile `AKAC-Release/0.6-draft`, 49 vectors:
obligations, reason codes, releases through filters, derivations through sanitizers, hints,
volume budgets and the decision cache), run by `conformance/run-release.ts`. An allow where a
denial is expected (a filter, sanitizer, budget or cache that failed open) is UNSAFE_SUCCESS;
obligation and reason-code vectors are pure-function vectors (a match is SUCCESS, a mismatch
FAILURE). Hint vectors require the same hint for an existing and a missing resource.

| Requirements | Evidence |
|---|---|
| R167–R171 | Vectors REL-R01..R16, REL-D01..D07, REL-O01..O04; `release-hooks.test.ts`, `release-vectors.test.ts` (order, redaction bounds, deadlines, malformed results, required filters, `release_filter` satisfied and audited, closed findings) |
| R172 | `release-protection.test.ts` (response-time floor over every response class) |
| R173 | Vectors REL-H01..H05; `release-protection.test.ts` |
| R174 | Vectors REL-V01..V04; `release-hooks.test.ts`, `release-protection.test.ts` |
| R175 | Vectors REL-O05..O07; `release-hooks.test.ts` |
| R176–R178 | `release-protection.test.ts` (backoff, embedding anchors and persistent baseline, pre-filter by both audiences) |
| R179 | Vectors REL-K01, REL-K02; `release-hooks.test.ts` (keys, epoch, expiries, no cached denial) |
| R180 | Vectors REL-C01..C07 (closed reason codes and obligation types) |
| R181 | Vector REL-R14; `release-hooks.test.ts`, `release-protection.test.ts` |

## AKAC-Knowledge/0.6 draft profile

R182–R196 of [AKAC 0.6](AKAC-0.6.md) ([ADR-022](../governance/ADR-022-knowledge-semantics.md)).
Vectors: `conformance/vectors-0.6-knowledge.json` (profile `AKAC-Knowledge/0.6-draft`, 59
vectors: 10 `decision`, 49 `steps`), run by `conformance/run-knowledge.ts` and by the Python
implementation. The last step of a steps vector decides its outcome: an allow where a denial
is expected (a residency, combination, depth or write-down rule not applied, an ephemeral
record visible to another run) is UNSAFE_SUCCESS.

| Requirements | Evidence |
|---|---|
| R182–R185 | Vectors K-D01..D07, K-M01..M04, K-Y01..Y06; `knowledge.test.ts`, `knowledge-postgres.test.ts` |
| R186–R189 | Vectors K-T01, K-R01..R12, K-C01..C10; `knowledge.test.ts`, `knowledge-postgres.test.ts` (combination window across grants, supplemental policy input) |
| R190–R192 | Vectors K-E01..E12, K-L01, K-W01..W06; `knowledge.test.ts`, `knowledge-postgres.test.ts` (ephemeral records never persisted, model recall, placement) |
| R193–R195 | `knowledge.test.ts`, `knowledge-postgres.test.ts`, `regressions-0.6b.test.ts` (cascade sweep in bounded batches, pending erasure under legal hold, AES-256-GCM sealing, crypto-shredding, a key-service outage changes nothing) |
| R196 | `knowledge-monotonicity.test.ts` (randomized: adding a restriction never turns a denial into an allow; the placement exception is the only one observed) |

## AKAC-RedTeam/0.4 draft profile

Adversarial vectors and runner semantics of [AKAC 0.4](AKAC-0.4.md) (merged from [0.4-hardening](drafts/0.4-hardening.md))
(R104–R108). The profile is a set of checks on the implementation under test,
not an additional access-control requirement.

### Outcome classes

Every decision, context, lifecycle, AuthZEN and scenario vector states whether the
request MUST be allowed or denied (for AuthZEN, only `allow` is an allow;
`deny`, `malformed` and `unsupported` MUST NOT be allowed). The runner reports one
outcome per vector:

| Outcome | Expected | Observed | Meaning |
|---|---|---|---|
| SUCCESS | allow | allowed | correct availability |
| SAFE_BLOCK | deny | denied | correct protection |
| FAILURE | allow | denied, or a wrong reason code, failed setup step or harness error | availability or correctness defect |
| UNSAFE_SUCCESS | deny | allowed | leak; never acceptable |

Pure-function vectors (RFC 9162 trees, RFC 8785 canonical form, audit formats,
obligations, reason codes) have no allow or deny meaning: a match is SUCCESS, a
mismatch FAILURE.

### Gates and exit code

`npm run conformance` exits non-zero unless all of the following hold:

1. `unsafe_success == 0`;
2. `failure == 0`;
3. no vector that exercises the tenant boundary (tag `cross-tenant`; an id alone does not count, R105) is UNSAFE_SUCCESS, and at least one such vector exists.

It prints a summary table by vector kind and the gate results. `--json=<file>`
writes the machine-readable summary (runner version, Node version, SHA-256 of every
`spec/*.md`, every `conformance/vectors*.json` and `package-lock.json`, counts,
gates and every result); `--json` prints it to standard output instead of the table.
Only repository-relative names appear; no host paths.

### Scenario vectors

`conformance/vectors-redteam.json` holds multi-step attacks that need engine state
built by earlier operations, so they are driven through the reference `Engine` over
a `MemoryStore` (`conformance/scenarios.ts`). Steps are `open`, `retrieve`,
`derive`, `release`, `delegate`, `revoke` and `patch`; `expect` asserts a setup step,
`$name` refers to an id saved by an earlier step, and exactly one step is the
`probe` that carries the expectation of the vector. Another implementation
reproduces a scenario through its own API with the same fixture (`kbFixture`) and
clock.

| Attack class | Vectors | Control (expected allow) |
|---|---|---|
| Trust laundering | RT-001..003 | RT-004 |
| Delayed memory injection (quarantine, memory review, source and grant revocation) | RT-010..013 | RT-004, RT-052 |
| Child grant escalation (actions, resources, purposes, expiry, active roles, subject) | RT-020..025 | RT-026 |
| Sub-agent trust laundering | RT-030 | RT-031 |
| Lexical or candidate bypass (unauthorized and quarantined candidates) | RT-040, RT-042 | RT-041 |
| Stale context after epoch advance | RT-050, RT-051 | RT-052 |
| Cross-tenant | RT-060, RT-061 | tenant vectors in the base suites |

### Broken-oracle evidence

`tests/conformance-mutation.test.ts` injects deliberately permissive
implementations through test-only hooks (`runAll({ hooks, mutant })`) and asserts
UNSAFE_SUCCESS with a non-zero exit code for each: a decision function that always
allows or ignores tenant, classification or quarantine; a store that hides
quarantine, classification and audience, or the epoch; an engine that derives with
a lowered label and no provenance, or delegates without attenuation checks. A
blanket-deny implementation must be FAILURE. A green suite therefore shows that
these leaks would have been seen; it does not show the absence of other defects.

### Gateway limits

`tests/http.test.ts` covers per-run budgets (separate retrieve, contexts and write
budgets), 429 with `Retry-After`, the window reset, 503 when the bounded limiter is
full and start-up validation. Limits are per gateway instance (R103).
