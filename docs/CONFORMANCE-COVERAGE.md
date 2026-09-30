# Conformance coverage: the rule matrix and mutation testing

Two instruments answer "does the evidence cover the rules?" and "would the evidence
notice a wrong rule?". Neither is a certification, an external review or a claim that
the reference is correct; both find gaps in the repository's own evidence. Decision:
[ADR-014](../governance/ADR-014-conformance-independence.md).

## Rule coverage matrix

`conformance/coverage/matrix.json` maps every normative requirement to its evidence:

- R01 to R196 of `spec/AKAC-0.1.md` to `spec/AKAC-0.6.md` (the 0.4, 0.5 and 0.6 drafts are merged
  into the numbered requirements; each merged draft starts with a "Merged into" note and is not read
  again, and its identifiers resolve through the mapping table of the specification it was merged
  into), and
- the requirements (`R-<TOPIC>-n`) of any `spec/drafts/0.6-*.md` draft not yet merged.

An entry lists any of:

| Member | Meaning |
|---|---|
| `vectors` | ids of conformance vectors in `conformance/vectors*.json` (`*` matches a prefix, for example `RT-020*`) |
| `tests` | `{file, name}`: a `node:test` file and the exact title of a `test()` |
| `artifacts` | repository files that are the evidence where no vector or test can be: the TLA+ model, its checker configurations and the workflow that runs them (R132–R135, requirements about the specification's own evidence) |
| `operator` | `{procedure, reason}`: the obligation is the operator's; `procedure` is a heading or `<a id>` anchor below that states how to test it |
| `note` | free text, for example that PostgreSQL tests only run where `AKAC_TEST_DATABASE_URL` is set |

`scripts/coverage-matrix.ts` (`npm run coverage:matrix`) parses the requirement ids and
their RFC 2119 level out of the specification files and fails (exit 1) when

- a requirement has no entry, or an entry names a requirement no specification defines;
- a requirement has no vector, no test, no artifact and no operator procedure (the roadmap
  rule: no normative MUST without evidence; a requirement with only `operator` evidence is
  counted separately in the report);
- a vector id, a test file, a test title or an artifact does not exist, or a vector id is duplicated;
- an operator procedure does not resolve to a heading or anchor in the named document.

`tests/coverage-matrix.test.ts` runs the same check and its negative controls. The CI job
`verify` runs `npm run coverage:matrix` after `npm run conformance`. A draft added under
`spec/drafts/` needs matrix entries in the same change, and so does its merge (the entries are
renamed from the draft identifiers to the R numbers); that is deliberate.

Mapping is a claim by a maintainer that a vector or test exercises the rule; the script
proves that the referenced evidence exists, not that it is sufficient. Mutation testing
(below) is the check on sufficiency for the decision core.

### Result (regenerate with `npm run coverage:matrix`)

| Specification | Requirements | MUST-level | With a vector | With a test | With an artifact | With an operator procedure | Uncovered |
|---|---|---|---|---|---|---|---|
| `AKAC-0.1.md` | 16 | 16 | 16 | 16 | 0 | 1 | 0 |
| `AKAC-0.2.md` | 5 | 5 | 3 | 5 | 0 | 0 | 0 |
| `AKAC-0.3.md` | 10 | 10 | 8 | 10 | 0 | 0 | 0 |
| `AKAC-0.4.md` | 77 | 72 | 31 | 72 | 0 | 11 | 0 |
| `AKAC-0.5.md` | 12 | 12 | 6 | 11 | 0 | 2 | 0 |
| `AKAC-0.6.md` | 76 | 74 | 32 | 70 | 4 | 0 | 0 |
| **Total** | 196 | 189 | 96 | 184 | 4 | 14 | 0 |

Of the 189 MUST-level requirements, 92 have at least one conformance vector, 179 at least one test, 4 are evidenced by checked artifacts (the TLA+ model and its checker configurations) and 12 carry an operator procedure; 4 rest on an operator procedure alone (R92, R94, R98, R118) because the object under test is the deployment. The 7 requirements without an uppercase MUST keyword (R54, R61, R82, R95, R99, R129, R188) are mapped as well. Counts as of 2026-09-29.

### Gaps that were closed rather than marked operator

The first pass of the matrix found requirements with no vector or test. They were closed
with evidence, not reclassified:

| Requirement | Gap | Evidence added |
|---|---|---|
| R20 | No portable vector for `accessExpiresAt` (only a unit test and the generated differential worlds) | Vectors `AKAC-015-access-expired`, `AKAC-016-access-not-yet-expired` (control), `AKAC-017-source-access-expired-transitive` |
| R90 | AuthZEN per-PEP budget (each batch item counts), 429 before engine work, 503 when the limiter store fails: untested | `tests/coverage-gaps.test.ts` |
| R12 | "MUST publish the revocation linearization point and any stale-access bound": not checked | `tests/coverage-gaps.test.ts` compares the documented bound with the engine |
| R17 | "MUST publish resource budgets": edges and grants budgets were nowhere published | Table below, checked against `LIMITS` by `tests/coverage-gaps.test.ts` |
| R17 | "MUST deny when it cannot establish authorization within the budgets": no portable vector at any bound | Boundary pairs `AKAC-055/056` (32 and 33 grants), `AKAC-070/071` (128 and 129 derivation records), `AKAC-072/073` (shared source at depth 128 and 129), `KB-034/035` (64 and 65 roles), `KB-036/037` (16 and 17 role levels), `KB-051/052` (32 and 33 containers) |
| R05, R13, R22-R25 | Delegation attenuation clauses, malformed authority data (roles, groups, constraints, containers, purposes, actions) and identity checks were only reached by unit tests and generated worlds | Vectors `AKAC-018` to `AKAC-081`, `KB-034` to `KB-062`; the mutation analysis below is what found them |
| R33, R36, R37 | Obligation validation and merging (bounds, duplicates, conflicts, ordering) and reason-code syntax: a handful of vectors | `E52` to `E85` |
| R109, R110, R114 | Runtime profile tier selection and malformed stored policies | `RTC-P22` to `RTC-P31` |
| R103 | Per-instance scope of limiter state: documentation only | `tests/coverage-gaps.test.ts` |
| R131 | Provenance statement of the implementations table | `tests/coverage-gaps.test.ts` |

## Operator procedures

These obligations cannot be shown by a vector or a unit test because the object under
test is the deployment (a cache, a network, a sandbox), not the decision function. Each
has a written procedure; a procedure that cannot be run is a finding, not a pass. Where
the reference covers part of the obligation, the matrix also lists those tests.

Common form: record the deployment version and date, run every step against the deployed
system with synthetic data (a canary string that is not a real secret), and keep the
evidence with the release. Pass means the prohibited effect did not occur, checked at
the destination (the other tenant's response, the file, the socket), not that a component
reported success.

<a id="op-isolation"></a>
### R16: no reuse of state or credentials from a more privileged run

1. Run agent A under a high-clearance grant. Place a canary in its scratch space, its environment, its model session and any cache it fills.
2. Start agent B (lower clearance, another grant) on the same host, sandbox pool or model runtime.
3. From B, try to read A's files, process memory, environment, credentials, model session or KV state, and to obtain A's contexts by id.
4. Confirm the sandbox is reset (fresh filesystem, no shared memory, new credentials) between the runs.

Pass: B never observes the canary and holds no credential of A. The reference part (contexts and grants are bound to one run; a sub-agent cannot read the parent's derived artifact) is `RT-030`, `RT-031` and `tests/core.test.ts`.

<a id="op-egress"></a>
### R70: bytes stay with the destination named by `destination_restricted`

1. Obtain an allowed release to a destination profile and to the implicit `internal-user` class under a restricted run.
2. Through every egress path of the integration (egress proxy, tool call, gateway), attempt to send the released content to a host that is not the named destination.
3. Repeat with a decision that carries a `destination_restricted` obligation the enforcement point does not understand.

Pass: no byte arrives at the other host (check on the receiving side), and the second case is treated as a deny by the enforcement point (R38).

<a id="op-cache-partitioning"></a>
### R91, R92: caches of protected context are partitioned

1. List every cache that holds protected content or derived model state: prompt, prefix, KV, response, embedding, retrieval-result, session and tool-output caches, and any CDN or proxy in front of them.
2. For each, show from configuration that the partition key includes the tenant and the classification, and the principal set unless every principal who could read the entry may reuse it.
3. Across tenants: send an identical prompt with a canary from tenant 1 and from tenant 2; the second must show no hit (cache counters, cached-token usage fields, latency).
4. Within a tenant: principal A (may read the source) fills the cache; principal B (may not) sends the same request; B must receive no cached content and no hit signal.

Pass: no cross-tenant or cross-principal hit.

<a id="op-cache-invalidation"></a>
### R93, R97: invalidation on epoch advance, revocation and expiry

1. Fill each cache with entries derived from a test source and grant.
2. Revoke the source (or the grant, or expire it), or advance the tenant epoch, and record the time.
3. Request the same content again and inspect each cache (hit counters, store contents).

Pass: the entries are gone, or unusable, within the documented bound. The reference part (epoch advance, index removal on revocation) is in the matrix entries.

<a id="op-cache-keys"></a>
### R94: cache keys are not computable from protected content alone

1. Document how each cache key is derived. A key that is an unkeyed hash of the plaintext, of retrieval results or of model output fails.
2. Compute the unkeyed hash of a known protected document and look for it in the cache namespace (key listing, side channels, error messages).

Pass: the key includes a secret or a tenant-scoped component the observer cannot reproduce, and the known-plaintext probe finds nothing.

<a id="op-cache-derivatives"></a>
### R95, R96: quantized, compressed and cached derivatives keep the classification

1. Enumerate persistent derivatives (embedding cache, quantized or compressed vectors, cached query results, activations, summaries).
2. For each, show the classification and audience metadata that is carried and enforced at read.
3. Retrieve the derivative of a restricted document as a principal without clearance, through every path that reads it.

Pass: no path yields the derivative or a hit signal; deleting or quarantining the source removes it. The reference index applies this to its own chunk tables (compartments, reconcile).

<a id="op-cache-readiness"></a>
### R98, R99: operator verification, logging and the residual timing risk

1. Keep the inventory of R91 to R97 as a production readiness checklist, signed and dated with the release.
2. Inspect logs and metrics for cache keys or content of protected material.
3. Record the acknowledged residual risk of cache-hit timing (R99) in the risk register.

Pass: the checklist exists for the deployed version, the log inspection finds no protected content, and the residual risk is recorded.

<a id="op-shared-limits"></a>
### R103: a global request bound across N instances

1. With `AKAC_SHARED_STATE=postgres`, run two gateway instances and send a run's budget plus one across both.
2. Without it, verify that the shared layer in front (ingress or API gateway) enforces the global bound.

Pass: the request over the total budget is refused with 429 regardless of instance; the deployed choice is documented. The shared store itself is covered by `tests/ha-postgres.test.ts` (hosted CI).

<a id="op-runtime-enforcer"></a>
### R116: the runtime enforcer is outside the agent's control

1. From inside the agent sandbox try to change or disable the applied profile: edit the profile or its template, call the enforcer's control interface, signal or kill the enforcer, alter the revision it reports.
2. After each attempt read the revision the enforcer reports and the audit trail.

Pass: every attempt fails, the reported revision is unchanged, and a revision that is no longer the one in force denies the answer (`RTC-R11`, `RTC-R13`). The reference only refuses a revision it cannot confirm; where the enforcer runs is the operator's.

<a id="op-non-bypass"></a>
### R118: every protected action traverses a non-bypassable enforcement point

1. Run the twelve scenarios of the [bypass test checklist](RUNTIME-CONTAINMENT.md#bypass-test-checklist) against the production topology.
2. From the agent sandbox connect to each vector index, object store, database, model provider endpoint and credential store by name, by IP literal and on alternate ports.

Pass: every direct path fails, and the only successful path is through the enforcement point. Repeat after every change to the runtime, its templates or the network.

## Published resource budgets (R17)

Budgets of the decision core (`LIMITS` in `reference/policy.ts`); exceeding one denies (`INVALID_CONTEXT` or `KNOWLEDGE_BOUNDARY`, see [PERFORMANCE.md](PERFORMANCE.md) for the measured cost at each bound). `tests/coverage-gaps.test.ts` fails when this table and the code differ.

| Budget | Value | Meaning |
|---|---|---|
| `roles` | 64 | distinct roles in one principal's closure |
| `roleDepth` | 16 | longest path in the role hierarchy |
| `containerDepth` | 32 | container chain length |
| `nodes` | 1024 | nodes of one derivation graph |
| `edges` | 4096 | source edges of one derivation graph |
| `path` | 128 | derivation path length (depth of the source chain) |
| `grants` | 32 | grants in one delegation ancestry |

Other published limits: request limits of the listeners (the operations guide, `AUTHZEN_LIMITS`, `ADMIN_LIMITS`), 64 sources per request, 128 direct sources per run, five-minute context lifetime (`docs/ARCHITECTURE.md`).

## Mutation testing of the decision core

Line coverage says a line ran; it does not say a wrong line would be noticed. Mutation testing changes the
reference one operator, literal or condition at a time (a "mutant") and reruns the suite: a mutant that no test
or vector fails ("survives") is a behaviour the evidence does not pin down. For `reference/policy.ts` every
survivor is treated as a missing vector: it is either killed by a new vector or test, or documented as
equivalent (no observable change) with the reason.

### Scope, tool and how to run

- Tool: [StrykerJS](https://stryker-mutator.io/) 10.0.0 (`@stryker-mutator/core`, exact version pinned in `package.json`), command test runner, no coverage analysis (`node:test` offers Stryker no per-test coverage hook, so every mutant reruns the suite).
- Mutated files: `reference/policy.ts` (the pure decision function and its helpers), `reference/containment.ts` (runtime profile derivation), `reference/decision.ts` (obligations, reason codes, identifiers) and `reference/lifecycle.ts` (lineage, retention, tombstones). `reference/control.ts` (720 lines, database-shaped control plane) is out of scope for this run: its behaviour is exercised through stores and HTTP, which the command runner cannot bound in reasonable time; it is a candidate for a scheduled run of its own.
- Suite, cheapest stage first, joined by `&&` so a mutant is killed by the first stage that fails: (1) the portable vectors (`node conformance/run.ts`), (2) the fast unit, property and differential files (`stryker.config.json` lists them), (3) the slower property, lifecycle and differential-fuzz files, run only for mutants that survived both.
- Two configurations: `stryker.config.json` (the full suite above; `npm run test:mutation`) and `stryker.vectors.config.json` (vectors only: `npx stryker run stryker.vectors.config.json`). The second answers "which behaviour do the portable vectors alone not distinguish?", which is what an independent implementation can rely on.
- Reports: `reports/mutation/index.html` and `mutation.json` (ignored by git). `node scripts/mutation-summary.ts [report.json]` prints the score per file and the survivors; the weekly workflow [`.github/workflows/mutation.yml`](../.github/workflows/mutation.yml) publishes both reports as an artifact and the table in the job summary.
- Score: killed plus timed out, over all valid mutants (survived plus uncovered plus killed plus timed out); mutants that do not compile or throw at start-up are not counted. The break threshold in `stryker.config.json` is 90 percent overall, the score achieved minus a margin for run-to-run noise (timeouts) and for code that other work adds to these files before its own tests land.

### Result: 2026-09-29

| File | Valid mutants | Killed or timed out | Survived | Documented equivalent | Mutation score | Score excluding documented equivalents |
|---|---|---|---|---|---|---|
| `reference/containment.ts` | 228 | 220 | 8 | 8 | 96.49% | 100.00% |
| `reference/decision.ts` | 393 | 378 | 15 | 15 | 96.18% | 100.00% |
| `reference/lifecycle.ts` | 221 | 210 | 11 | 11 | 95.02% | 100.00% |
| `reference/policy.ts` | 1391 | 1308 | 83 | 82 | 94.03% | 99.92% |
| **Total** | 2233 | 2116 | 117 | 116 | **94.76%** | 99.95% |

Measured on the working tree of branch `feat/akac-0.6` (files containment.ts 4ea356a4f9, decision.ts 5d177e29f2, lifecycle.ts 785dee14b8, policy.ts 5f7bbdea42) on 2026-09-29, with 2233 valid mutants, in about 67 minutes on a shared developer machine. One undocumented survivor of this run (the `unreadable` clause of `lineageLive()`) was pinned by a test added afterwards and is not re-measured in these numbers. It is a measurement of these files with these tests, not a proof of correctness: it cannot see a rule that is missing from the code, or a mutant class that Stryker's operators do not produce.

Score of the portable vectors alone (`stryker.vectors.config.json`, before and after the vectors added for this analysis, same operators): 55.85% over 1871 mutants before the vectors were added (containment.ts 72.81%, decision.ts 63.43%, lifecycle.ts 0.00%, policy.ts 61.37%); 68.74% over 2233 mutants after (containment.ts 78.07%, decision.ts 81.93%, lifecycle.ts 0.00%, policy.ts 74.41%). The rest of the difference to the full-suite score is behaviour that only unit and property tests pin: the helpers that the decision function does not call (`effectiveLabel`, `transitiveClassification`, `principalTokens`, `countSodHolders`, `lineageLive`, everything in `lifecycle.ts`) and exact values of malformed-input handling.

### What the survivors of the first run were, and what was done

The first run against the vectors alone left more than 800 survivors. They fell into four groups:

1. Decision behaviour no vector distinguished (about 60 clusters in `policy.ts`): each clause of the grant validity check, the delegation attenuation rules (actions, resources, purposes, time, session roles, destinations, result limit), the derivation, container, role and delegation budgets at their exact boundary, malformed roles, groups, constraints and containers, the identity checks, purpose length, the `declassify` action. These became 137 new vectors: 64 decision vectors in `vectors.json` (`AKAC-018` to `AKAC-081`), 29 decision and context vectors in `vectors-0.3.json` (`KB-034` to `KB-062`), 34 obligation and reason-code vectors in `vectors-0.4.json` (`E52` to `E85`) and 10 runtime profile vectors (`RTC-P22` to `RTC-P31`); the TypeScript and Python implementations agree on all of them (`tests/differential-vectors.test.ts`). The budget boundaries (32 and 33 grants, 128 and 129 derivation records, 32 and 33 containers, 16 and 17 role levels, 64 and 65 roles) are also the portable statement of R17 (bounded evaluation). The node and edge budgets (1024 nodes, 4096 edges) are not vectors: a vector file with that many records is not a useful conformance artifact; `tests/mutation-core.test.ts` pins them.
2. Pure helpers that the decision function does not call (`effectiveLabel`, `transitiveClassification`, `principalTokens`, `countSodHolders`, `lineageLive`, `destinationGate` verdicts, most of `lifecycle.ts`): these are reachable only through stores, indexes and the control plane, so a decision vector cannot express them. They got exact-value unit tests (`tests/mutation-core.test.ts`, `tests/mutation-core-2.test.ts`).
3. Code added to the same files by other 0.6 work after the first run (risk caps, heartbeat-bound and break-glass grants, session-scoped and unreadable records): boundary tests in `tests/mutation-core-2.test.ts`.
4. Equivalent mutants, below.

### Surviving mutants that are documented, not killed

The mutants below survive the whole suite and are reported separately (`conformance/coverage/equivalent-mutants.json`, matched by operator and source text, so a rule keeps applying when lines move). The raw score above, which is what the break threshold uses, counts them as survivors.

| Rule | Files | Operators | Mutants | Why they cannot change an observable result |
|---|---|---|---|---|
| E1 | `all four` | StringLiteral | 10 | The message of an internal exception. Every such exception is caught by the enclosing try/catch and mapped to a fixed decision; the text is never observed. |
| E2 | `policy.ts` | CallExpression, ConditionalExpression | 10 | Memoization and cycle bookkeeping. Without the memo the traversal recomputes the same value; without the in-progress marker a cycle recurses until the stack overflows, which the enclosing try/catch turns into the same fail-closed result (null or false) as the explicit cycle check. |
| E3 | `policy.ts` | EqualityOperator, ArithmeticOperator, ConditionalExpression, LogicalOperator, BooleanLiteral | 10 | Redundant depth accounting in visible(). The height of the whole graph is computed bottom-up and compared at the root (depth 0 + height <= LIMITS.path), so the entry check, the memoized-path check and the per-node check only end the traversal earlier; a cycle yields an undefined height (NaN) that fails the comparison at the root. |
| E4 | `policy.ts` | ConditionalExpression, LogicalOperator | 5 | canDelegate() repeats conditions that grantValid(next, child) checks again through the child's own chain (tenant, subject, agent liveness and tenant; a grant that is its own parent is a cycle). |
| E5 | `policy.ts` | ConditionalExpression, LogicalOperator, EqualityOperator, UpdateOperator, OptionalChaining | 6 | In lineageLive() every edge leads to a visit that increments the node count first, so the 1024-node budget is exhausted before the 4096-edge budget can be; a null reference throws and is caught as false, like an invalid id (see the findings). |
| E6 | `policy.ts` | OptionalChaining | 1 | A null source reference throws inside a try/catch that returns the same fail-closed value as the identifier check. |
| E7 | `policy.ts` | ArithmeticOperator, BooleanLiteral | 4 | A default that the callers always override, or an upper bound that the clearance index or the first cap of the loop already lowers. |
| E8 | `policy.ts` | ConditionalExpression, LogicalOperator, EqualityOperator, ArrowFunction, MethodExpression | 8 | grantValid() and sessionRoles() both reject an activation that is not a list of held role names, and held.has() is false for anything that is not a string; the second check is the one that decides. |
| E9 | `policy.ts` | ConditionalExpression, LogicalOperator, EqualityOperator | 3 | An undefined child value compared with a number is NaN and fails the comparison anyway; the tenant of a parent is checked again through the parent's own subject. |
| E10 | `policy.ts` | ConditionalExpression, LogicalOperator, EqualityOperator, BooleanLiteral, ArithmeticOperator | 10 | risky only selects the reason (RISK_CAP or KNOWLEDGE_BOUNDARY) of a denial that visible() already decided, and a principal whose cap is below public is denied with RISK_CAP by the fallback path as well; neither changes an effect. |
| E11 | `policy.ts` | ConditionalExpression, LogicalOperator | 3 | A missing destination record throws on the next property access and is caught as a denial; a non-string id never names a record (Object.hasOwn coerces it to a key that no record has). |
| E12 | `decision.ts` | ConditionalExpression, MethodExpression, LogicalOperator, EqualityOperator, BooleanLiteral | 15 | Type tests that the following conjunct already implies (a primitive has no `type`; a missing required member fails the value check; the prior obligation was looked up by its own type); equal levels assign the same value; identifier and trace-id tests fail for non-strings through the regular expression. |
| E13 | `all four` | EqualityOperator, ConditionalExpression | 15 | Comparator boundary for equal ids (ids are unique, so equality never occurs) and the second ternary of a sort comparator, which only tells 0 from 1: the engine's sort acts on negative results only. The first ternary is pinned by tests with unsorted input. |
| E14 | `lifecycle.ts` | ConditionalExpression | 1 | The outer loop only skips the remaining work after a bound was already reported; the returned records and the flag are unchanged. |
| E15 | `containment.ts` | ConditionalExpression | 2 | Entries of other obligation types are keyed by an undefined domain and never read back; the merged map only holds runtime_profile entries. |
| E16 | `policy.ts` | ArrayDeclaration | 1 | When the chain is null the function returns null on the next line whatever the levels are. |
| E17 | `policy.ts` | ConditionalExpression, StringLiteral | 2 | LEVELS.indexOf('deny') is -1 as well: the cap denies either way. |
| E18 | `policy.ts` | ConditionalExpression, LogicalOperator, ArrowFunction | 7 | Conditions that a second check subsumes: a break-glass grant with a parent is rejected by breakGlassShape() and by the delegation clause alike; sources that are not a list throw in the loop and are caught; a container cycle also hits the depth bound; missing roles throw in audience() and are caught. |
| E19 | `policy.ts` | OptionalChaining, ConditionalExpression | 2 | The subject of a grant in a chain is the evaluated user, whose existence, activity and tenant decide() has checked; a missing agent would throw and be caught, and the vectors pin the unknown-agent case as INVALID_DELEGATION. |
| E20 | `containment.ts` | ConditionalExpression | 1 | A primitive record has no tenant and is filtered out by the tenant comparison anyway. |

### Findings from the analysis

- `lineageLive()` counts a node on every visit, including a revisit of a shared source, before its memo check, while `visible()` and `transitiveClassification()` count each node once. A record with many references to few shared sources can therefore be visible to `visible()` and still be reported not live by `lineageLive()` at 1024 references, and the 4096-edge budget of `lineageLive()` can never bind (rule E5). Fail-closed, so not a security defect; the three traversals should share one budget definition. Not changed here: a behaviour change needs the specification and an ADR (GOVERNANCE.md).
- `lineage()` reports `truncated` for a chain of exactly `LIMITS.path` (128) descendants: the depth counter is compared before the empty frontier is noticed, so the bound is one level early. Conservative; pinned by `tests/mutation-core.test.ts`.
- The portable decision vectors compare effect and reason code but not the decision category (`deny` or `defer`, R29); only unit tests and the differential comparison see it. A `category` member in decision vectors would make R29 portable.
- Cycle safety in `visible()`, `transitiveClassification()` and the role closure does not depend on the in-progress marker alone: without it the recursion ends in a stack overflow that the enclosing `try` turns into the same denial (rule E2). The explicit marker is the intended defence and is what makes the failure cheap; the mutation run shows that the backstop exists.
- `control.ts` (720 lines) was not mutated: it is a database-shaped control plane exercised through stores and HTTP, and one full run of the command runner over it would take hours. It is the natural next scope for the weekly workflow once a per-file coverage hook exists.

