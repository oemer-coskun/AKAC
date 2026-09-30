# Verification record

## Reference 0.6.0 — hosted CI

Merged to `main` as `2d86a6a` (PR #17). Runs on the final PR head:

- Verification (CI): https://github.com/oemer-coskun/AKAC/actions/runs/36637735989 — strict type check and the Node suite including PostgreSQL 17 with pgvector and a real OPA server: 577 tests, 577 passed, 0 failed, 0 skipped. Conformance (629 vectors, hard gates unsafe_success == 0, failure == 0, cross-tenant leaks == 0 with 19 tagged vectors), coverage matrix gate, specification lint, Python implementation, backup/restore drill, reproducible image build (identical digests), container end-to-end and secret scan: passed.
- Formal model: https://github.com/oemer-coskun/AKAC/actions/runs/36637735899 — TLC faithful configurations hold; every broken-model configuration is detected.
- CodeQL, CycloneDX SBOM and Trivy image scan: passed.

Not covered: an external security review or penetration test, an independent implementation, load testing on production hardware and live KMS/HSM providers.

## Reference 0.6.0 — local evidence (not hosted CI)

Local runs on 2026-09-29 on a shared, heavily loaded Windows 11 developer workstation, Node.js 24, working tree of branch
`feat/akac-0.6` before the release commit (no code revision to cite). These are single observations on one host; the hosted
record above supersedes them.

| Check | Observed result |
|---|---|
| `npx tsc --noEmit` | clean |
| Node suite (`node --test --test-concurrency=2 tests/*.test.ts`, real OPA binary, no `AKAC_TEST_DATABASE_URL`) | 577 tests: 531 passed, 0 failed, 46 skipped. The skipped tests are the PostgreSQL integration tests, which need a database URL; they run in hosted CI |
| `npm run conformance` | 629 portable vectors: 232 SUCCESS, 397 SAFE_BLOCK, 0 FAILURE, 0 UNSAFE_SUCCESS; gates unsafe_success == 0, failure == 0 and cross-tenant leaks == 0 (19 tagged cross-tenant vectors) passed. 0.6 vector files: identity 38, crypto agility 110, release 49, knowledge 59 |
| Python implementation (`implementations/python`, Python 3.12) | `python -m unittest discover -s tests`: 17 tests passed. `python -m akac conformance` (every vector file, without the TypeScript harness): 629 vectors, 214 SUCCESS, 362 SAFE_BLOCK, 0 FAILURE, 0 UNSAFE_SUCCESS, 53 NOT_APPLICABLE (13 runtime-enforcer vectors, 34 release vectors for hooks, hints, budgets and the cache that the Python engine does not implement, 6 SLH-DSA vectors that the installed `cryptography` cannot verify), gates passed. Same-project implementation, not independent |
| `npm run coverage:matrix` | 196 requirements (R01-R196), 189 at MUST level; every MUST-level requirement has evidence: 92 with a vector, 179 with a test, 4 with a checked artifact (the TLA+ model), 12 with an operator procedure (4 with an operator procedure only: R92, R94, R98, R118); 0 uncovered; 35 vectors not mapped to a requirement (informational) |
| `npm run lint:spec` | 6 published specification files, 196 requirements without gaps, 0 errors, 4 warnings (R54, R61, R82, R95 state no RFC 2119 keyword; unchanged since 0.4) |
| Mutation testing (StrykerJS 10.0.0, full suite) of `reference/policy.ts`, `containment.ts`, `decision.ts`, `lifecycle.ts` | 94.76% (2116 of 2233 valid mutants killed or timed out; 99.95% excluding 116 documented equivalent mutants); details and the vectors-only score in [CONFORMANCE-COVERAGE.md](CONFORMANCE-COVERAGE.md#result-2026-09-29) |
| TLA+ model (TLC 2.19, tla2tools v1.7.4, [FORMAL-MODEL.md](FORMAL-MODEL.md#results)) | `MC.cfg`: no violation, 132,200 distinct states, depth 7; `MC_admin.cfg`: no violation, 245,340 distinct states, depth 8; each of the 8 broken configurations reports its property violated; each of the 5 witness configurations reaches its behaviour. Bounded model checking, not a proof |

Not covered locally: PostgreSQL integration (hosted CI), the container end-to-end job, a real KMS, HSM or Vault (the Vault Transit signer is tested against
a mock endpoint), TEE hardware, load testing, and any external security review, audit or certification.

## Reference 0.5.0 — hosted CI

Merged to `main` as `d6be41f` (PR #13). GitHub Actions run: https://github.com/oemer-coskun/AKAC/actions/runs/36561243505

- `npm run check` (strict type check and the Node suite, including PostgreSQL 17 with pgvector and a real OPA 1.9 server): 380 tests, 380 passed, 0 failed, 0 skipped.
- `npm run conformance`: all profiles PASS, including the runtime containment vectors; hard gates unsafe_success == 0, failure == 0 and cross-tenant leaks == 0 (11 tagged cross-tenant vectors) passed.
- Container end-to-end, secret scan (gitleaks), CodeQL, CycloneDX SBOM and Trivy image scan: passed.

Not covered: an external security review, load testing and multi-process enforcer serialization.

## Reference 0.4.0 — hosted CI

Code revision: squashed branch commit `b01a9b8`, merged to `main` as `944d7a6` (PR #8).
GitHub Actions run: https://github.com/oemer-coskun/AKAC/actions/runs/36528129751

- `npm run check` (strict type check and the Node suite, including PostgreSQL 17 with pgvector and a real OPA 1.9 server): 359 tests, 359 passed, 0 failed, 0 skipped.
- `npm run conformance`: all profiles PASS; hard gates unsafe_success == 0, failure == 0 and cross-tenant leaks == 0 (10 tagged cross-tenant vectors) passed.
- Container end-to-end job (Compose, migrations as schema owner, non-owner RLS-bound runtime role, vector ingest and retrieval, denied cases): passed.
- Secret scan (gitleaks, full history), CodeQL, CycloneDX SBOM and Trivy image scan: passed.

Not covered: an independent external security review or audit, load or performance testing, live embedding providers, and multi-instance DPoP replay under a shared database beyond the integration tests. Local runs on a heavily loaded Windows host showed PostgreSQL statement timeouts; the hosted run above is the authoritative 0.4.0 record.

## Reference 0.4.0 (in progress) local evidence: evidence routes and AuthZEN facade

Work-in-progress record for the integration of decisions, audit evidence and the optional AuthZEN facade; it is not a release record and is superseded when the 0.4.0 record is written. Local Windows 11 host, Node.js 24, PostgreSQL 17 with pgvector 0.8 in Docker, OPA 1.9, the branch working tree before commit (no code revision to cite). Tests run with `--test-concurrency=1`.

| Check | Observed result |
|---|---|
| Strict TypeScript check | clean |
| Node suite including PostgreSQL integration (`tests/*.test.ts`) | one full run: 297 of 301 passed; the 4 failures (real OPA server start-up in `tests/decisions.test.ts` and `tests/opa.test.ts`, migration 004 upgrade in `tests/evidence-postgres.test.ts`, which failed its file) coincided with a heavily loaded host and other concurrent runs; those files were re-run alone and passed (`tests/opa.test.ts` 2/2, `tests/decisions.test.ts` and `tests/evidence-postgres.test.ts` 11/11). A clean full run has not been recorded. |
| Portable conformance vectors (`npm run conformance`), including `AKAC-AuthZEN/0.4-draft` | no failing vector |
| New tests | `tests/admin-evidence.test.ts` (checkpoint, inclusion and consistency proofs verified with the independent RFC 9162 verifiers, strict queries, trace ids), `tests/authzen.test.ts` (mapping, tenant pinning, reasons, batch, authentication separation, parity with `decide()` over 400 generated requests and with `Engine.openContext` obligations), `tests/config-authzen.test.ts`, `tests/conformance-authzen.test.ts` |

Not verified: interoperability with any third-party AuthZEN enforcement point; file-permission enforcement of the checkpoint key on POSIX (the check is skipped on Windows, where the tests for it do not run); OPA and PostgreSQL behaviour under load; no independent review, penetration test or certification.

## Reference 0.3.0 local evidence — 2026-09-28

Branch `feat/akac-0.3`, code revision `daebb3b` (documentation-only changes follow). Node.js 24, TypeScript 5.9.3, Python 3, PostgreSQL 17 with pgvector 0.8 and OPA 1.9.

| Check | Observed result |
|---|---|
| Strict TypeScript check and Node suite (`npm run check`), including PostgreSQL and pgvector integration tests | **209 passed, 0 failed** (209/209) |
| Portable conformance vectors (`npm run conformance`) | **48/48** |
| Rego policy tests and real OPA server | Passed with OPA 1.9 |
| TypeScript/Python decision comparisons | Passed: 1,000 0.2 cases, 1,500 hierarchy/SoD/container cases and every portable vector |
| Docker Compose end-to-end (build, migrate, seed, gateway with pgvector retrieval, admin ingestion, reconcile, allowed and denied requests) | Passed locally |
| PostgreSQL evidence | Row-level security for a non-bypass role, tenant-scoped keys, migrations 001-003 with checksum refusal, non-truncating loads, start-up refusal of a bypassing role, pgvector pre-filter parity with the in-memory reference, recall under a selective filter on synthetic data |

Findings from an internal adversarial review of the 0.3 reference were fixed with regression tests before this record (see the changelog). That review was performed inside this project and is not an independent audit.

PostgreSQL evidence requires `AKAC_TEST_DATABASE_URL`; without it those tests are reported as skipped, and a run without it is not evidence for R30.

### Hosted CI for 0.3.0

A hosted GitHub Actions run on the `feat/akac-0.3` branch exists or will exist for the code revision above. Its result will be recorded here after merge, with the run URL and exact commit. Until then the hosted status of 0.3.0 is not claimed, and the 0.2.0 hosted evidence below must not be read as covering 0.3.0.

### Limits of this evidence

Tests are author-supplied engineering evidence. Vector recall and latency were measured on synthetic data only; no load or scale benchmark has been run; the HTTP embedder was tested against a local stub server, not a live provider; SCIM was tested against the repository's own client, not a specific identity provider. No independent security review, penetration test, legal review or certification has taken place.

## Reference 0.2.0 local evidence — 2026-09-28

Node.js 24.19.0, TypeScript 5.9.3, Python 3 and OPA 1.9.0.
Strict type checking passed. Node suite: **79 passed, 0 failed, 1 skipped**
(PostgreSQL is deferred to hosted CI). Includes 1,001 TypeScript/Python
differential cases, 500 generated clearance properties, signed-token attacks,
checkpoint tampering, bounded graph traversal and provider revocation tests.
Portable vectors: **15/15**. Rego tests: **4/4**. Runtime dependency audit:
**0 reported vulnerabilities** at execution time.

## Completed hosted evidence for 0.2.0

Code commit: `02b9eaa0e9630b60052193976b5783c8551340a5`.
GitHub Actions: https://github.com/oemer-coskun/AKAC/actions/runs/36419879307
Both `verify` and `containers` jobs completed successfully.
Hosted environment: Node.js 24.21.0, Python 3.12.3, PostgreSQL 17, OPA 1.9.0.

| Check | Observed result |
|---|---|
| Strict TypeScript and Node suite | **80 passed, 0 failed, 0 skipped** |
| PostgreSQL persistence, rollback, concurrency and revocation | Passed |
| TypeScript/Python decision comparisons | 1,001 cases passed |
| Generated clearance properties | 500 cases passed |
| JWT validation, key rotation and authenticated HTTP | Passed with synthetic keys |
| Provider input/output and mid-generation revocation | Passed with synthetic providers |
| Signed audit checkpoint tampering/rollback tests | Passed |
| Portable decision vectors | 15/15 passed |
| Rego and real OPA server | 4/4 policy tests; integration passed |
| Runtime dependency audit | 0 reported vulnerabilities at execution time |
| Docker Compose build, seed and service startup | Passed |
| Health, authenticated readiness and allowed/denied HTTP requests | Passed |

The final documentation commit records this tested code revision. No claim is
made about an external audit, live-provider isolation or production scale.

## Historical 0.1 evidence

Reference release: 0.1.0. Date: 2026-09-28.

Local environment: Node.js 24.19.0, TypeScript 5.9.3, Linux; OPA 1.9.0 static binary.

## Locally executed

- Strict TypeScript checking.
- Node test suite, including actual HTTP gateway/SDK requests and SQLite restarts.
- OPA adapter against malformed/error responses and a real OPA server.
- Four Rego policy tests.
- Portable decision conformance vectors.
- Synthetic company demonstration.

Local result: **53 passed, 0 failed, 1 skipped** (the PostgreSQL integration test).
All 15 portable decision vectors passed; Rego policy tests: **4/4 passed**.

## Completed hosted evidence

Code commit: `e473209a4ff9ae88fa678bd4c0243b31c9016b82`.
GitHub Actions run: https://github.com/oemer-coskun/AKAC/actions/runs/36362738113

| Check | Observed result |
|---|---|
| Strict TypeScript check | Passed |
| Node test suite on Node.js 24.21.0 | **54 passed, 0 failed, 0 skipped** |
| PostgreSQL 17 integration | Passed: persistence, rollback, concurrent connections, revocation and audit verification |
| Portable decision vectors | All 15 passed |
| Rego policy tests | 4/4 passed |
| Real OPA server integration | Passed |
| Runtime dependency audit | 0 reported vulnerabilities at execution time |
| Docker Compose configuration and image build | Passed |
| PostgreSQL/OPA/gateway stack startup | Passed |
| Loopback health endpoint | Passed |
| Allowed handbook and denied executive-document HTTP requests | Passed |

The first hosted run revealed a concurrent PostgreSQL schema-initialization race
and a missing ingress network for the published loopback port. Both were fixed,
and the unchanged integration tests passed in the linked run. This record describes
actual execution, not just the presence of workflow configuration.

## Hosted checks

`.github/workflows/ci.yml` runs the tests against a real PostgreSQL 17 service,
checks OPA, performs a dependency audit, builds Docker images, boots the Compose
stack and exercises allowed and denied HTTP requests. A workflow file is not proof
that the workflow ran; consult the GitHub Actions result for the exact commit.

The local environment has no Docker daemon or PostgreSQL server. Attempts to
install the latter were blocked by container privilege restrictions. Those checks
are therefore assigned to the hosted job rather than labeled as locally verified.

## Assurance limits

Tests are author-supplied engineering evidence, not an independent security audit.
No real-company deployment, performance certification, legal review, complete
runtime-isolation validation or independent standards adoption has occurred.
