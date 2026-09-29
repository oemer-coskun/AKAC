# Conformance profiles

All names below are draft project profiles, not external certifications.

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

Sections R72–R78 (token binding, optional) and R91–R99 (cache isolation, operator obligations) of [AKAC 0.4](AKAC-0.4.md) are not separate profiles. The token binding requirements apply to a listener that enables DPoP and are covered by `tests/dpop.test.ts`; the cache isolation requirements are deployment obligations that the reference cannot enforce and no vector covers. The bonus modules under [bonus/](../bonus/README.md) are not part of any profile.

No profile claim implies automatic SSO, network sandboxing or provider-side deletion. This repository MUST NOT be described as a full production-conformant deployment without verifying the integration prerequisites.

## Running

`npm run conformance` emits JSON containing each portable vector and the actual/expected result. The fixture is defined in `examples/fixture.ts`; clock and mutations are in `conformance/vectors.json`. Other implementations can reproduce this fixture without using the reference engine. Follow with `npm test` for behavioral and transport checks.

Since 0.4 the runner covers every vector file (`vectors.json`, `vectors-0.3.json`,
`vectors-0.4.json`, `vectors-authzen.json`, `vectors-destinations.json`, the scenario vectors
`vectors-redteam.json` and, for 0.5, `vectors-runtime.json`), classifies each vector with one of the four outcome classes SUCCESS,
SAFE_BLOCK, FAILURE and UNSAFE_SUCCESS, and applies the same hard gates to all profiles:
no UNSAFE_SUCCESS, no FAILURE, and no UNSAFE_SUCCESS among (at least one) tenant-boundary vectors
([R104–R108](AKAC-0.4.md), details in the AKAC-RedTeam/0.4 section below). A non-zero exit code
means a gate failed.

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
| R70 | Enforcement boundary: integration contract ([INTEGRATIONS.md](../docs/INTEGRATIONS.md)); no vector |
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
| R109–R111 | Vectors RTC-P01..P19, RTC-E01..E13 (E09..E13: unknown destination merged over the run's classes, `internal-user` for users); `runtime-containment.test.ts` (supplemental policy conflicts, obligation merge, share/export without destination) |
| R112, R113 | Vectors RTC-R01..R12 (R08: provider-gate precedence; R10: same-tier conflict; R11, R12: revision drift, failed lease release); `runtime-containment.test.ts` (apply order, exact profiles, enforcer timeout, serialized sandbox-wide executions, per-execution revision check) |
| R114, R115 | `runtime-containment.test.ts` (security-admin only, validation, epoch advance, bound, admin routes), `runtime-postgres.test.ts` (checks, forced RLS) |
| R117 | `runtime-containment.test.ts` (execution header, audit members, hash coverage, schemas, policy digest over the active set), `authzen.test.ts` (AuthZEN execution header), `runtime-postgres.test.ts` |
| R119 | `runtime-containment.test.ts` (a policy change ends open contexts) |
| R120 | `runtime-containment.test.ts` (AuthZEN `context.obligations`) |
| R116, R118 | Operator obligations; the checklist in [RUNTIME-CONTAINMENT.md](../docs/RUNTIME-CONTAINMENT.md); no vector can show them |

Broken-oracle evidence: `runtime-containment.test.ts` injects a derivation that drops
every profile, one that lowers the output label, and a runtime that calls the provider
without its enforcer, and asserts UNSAFE_SUCCESS and a non-zero exit code; a blanket-deny
derivation is FAILURE.

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
3. no vector that exercises the tenant boundary (tag `cross-tenant`, or an id naming the tenant) is UNSAFE_SUCCESS, and at least one such vector exists.

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
