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
