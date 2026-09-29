# Implementations and shared conformance results

AKAC's conformance material is language-neutral (ADR-014, [AKAC 0.6](../spec/AKAC-0.6.md)):
the synthetic company is a JSON document ([examples/fixture.json](../examples/fixture.json),
schema [schemas/fixture.json](../schemas/fixture.json)), every vector file is JSON, and a
runner contract (below) lets any implementation be compared with the reference case by case.

## Implementations

| Implementation | Language | Written by | Scope | How to run the shared vectors |
|---|---|---|---|---|
| Reference (`reference/`) | TypeScript, Node 24 | AKAC project | Complete: decisions, gateway, storage, HTTP, AuthZEN PDP, runtime containment | `npm run conformance` |
| `implementations/python` (`akac` package) | Python 3.10+, no required dependency | AKAC project | Decisions, gateway decisions with obligations, destination gate, runtime containment derivation, AuthZEN mapping, JCS, RFC 9162 proofs, audit hashes, Ed25519 checkpoint verification (optional `cryptography`) | `cd implementations/python && python -m akac conformance` |

Both implementations are written by the same project. The Python implementation
follows the specification and the reference behaviour rule by rule and shares no
code with it at run time; the agreement below is same-project differential
evidence. It detects a divergence between the two; it cannot detect an error
that both share. No implementation by an independent party exists yet, and
nothing here is a certification.

## Results per vector file

Four-way outcomes as defined in [spec/CONFORMANCE.md](../spec/CONFORMANCE.md) for
the vector set of this revision (regenerate with the commands above; the numbers
move when vectors are added). "Differential" is the number of runner-contract
cases of that file on which both implementations returned identical results
(`tests/differential-vectors.test.ts`; decision vectors are compared both as
`decide` and as `evaluate`, destination vectors also as open-and-release sequences).

| Vector file | Vectors | TypeScript reference | Python | Differential (identical / compared) |
|---|---|---|---|---|
| `vectors.json` | 82 | 16 SUCCESS, 66 SAFE_BLOCK | 16 SUCCESS, 66 SAFE_BLOCK | 164 / 164 |
| `vectors-0.3.json` | 62 | 15 SUCCESS, 47 SAFE_BLOCK | 15 SUCCESS, 47 SAFE_BLOCK | 116 / 116 |
| `vectors-0.4.json` (evidence, lifecycle) | 93 | 74 SUCCESS, 19 SAFE_BLOCK | 74 SUCCESS, 19 SAFE_BLOCK | 101 / 101 |
| `vectors-authzen.json` | 23 | 6 SUCCESS, 17 SAFE_BLOCK | 6 SUCCESS, 17 SAFE_BLOCK | 23 / 23 |
| `vectors-destinations.json` | 29 | 11 SUCCESS, 18 SAFE_BLOCK | 11 SUCCESS, 18 SAFE_BLOCK | 68 / 68 |
| `vectors-runtime.json` | 59 | 30 SUCCESS, 29 SAFE_BLOCK | 26 SUCCESS, 20 SAFE_BLOCK, 13 not applicable | 46 / 46 |
| `vectors-redteam.json` (scenarios) | 25 | 5 SUCCESS, 20 SAFE_BLOCK | 5 SUCCESS, 20 SAFE_BLOCK | 25 / 25 (every step's effect and code) |

FAILURE and UNSAFE_SUCCESS are 0 for both implementations; all gates pass. Not
applicable in Python: the 13 `runtime-enforcer` vectors, which test the
`ProtectedRuntime` protocol with a scripted enforcer (apply, revision checks,
lease release) rather than a decision. Without the optional `cryptography`
package the 6 `checkpoint-v2` vectors are also reported as not applicable (never
as passes).

Generated comparison (`tests/differential-fuzz.test.ts`): 2,000 random worlds
per CI run (fixed seed; 6,000 cases: `decide`, `evaluate` and an operation
sequence per world), with random tenants, role hierarchies (including cycles),
groups, SoD constraints, container chains (including cycles and broken parents),
derivation DAGs with stale and forward references, delegation chains that widen
or narrow scope, time, session roles, destinations and result limits, lifecycle
states, access expiry, destination profiles, runtime profile policies and
malformed members. The run fails on the first disagreement and prints the
minimized case; it also fails when allows or any major reason code or obligation
type never occur. Local campaigns of 3 x 10,000 worlds (seeds 1-3) and 6,000
worlds with malformed members in every world found no disagreement.

## Running the shared vectors in another language

1. **Load the fixture.** Parse `examples/fixture.json`. For fixture `F`, follow
   `fixtures[F].extends` to the base; start from an empty state
   (`{schema, policyVersion, epochs: {}, actors: {}, grants: {}, knowledge: {},
   contexts: {}, roles: {}, groups: {}, containers: {}, constraints: {},
   destinations: {}, runtimeProfiles: {}, audits: []}`), merge the base records,
   then the extension's; add the vector's clock to every `[collection, field]` in
   `clockRelative`. `bindings` names the credential bindings vectors refer to.
2. **Apply patches.** `[collection, id, field, value]` sets a member (an existing
   one or one of the optional members listed in `conformance/patch.ts`);
   `[collection, id, record]` inserts or replaces a record.
3. **Read JSON like the reference** (R128): integral numbers are integers
   (`1.0` is `1`), absent differs from `null`, malformed members deny with the
   code the reference gives.
4. **Evaluate** each vector kind as described in `spec/CONFORMANCE.md` and the
   header comment of its runner in `conformance/`, and report the four-way
   outcome per file (R130), naming any vector you do not cover.

To compare an implementation with the reference case by case, implement the
runner contract and run it against `tests/differential-harness.ts`
(`evaluateTs` computes the reference result of any case).

## Runner contract

Batch: `{"cases": [case, ...]}` on stdin, a JSON array of results on stdout
(`python -m akac eval`). Line mode: one case per line in, one result per line out
(`python -m akac serve`). Every case carries its complete `state`; an
implementation keeps nothing between cases. An unexpected failure is the result
`{"thrown": true}` and is compared like any other value. Results compare by JSON
value (member order is irrelevant; array order is significant).

| `op` | Input members | Result |
|---|---|---|
| `decide` (default) | `state`, `request` `{binding, action, resource, purpose, now}` | `{effect, code, category?}` (category `deny` or `defer` on a denial) |
| `evaluate` | `state`, `request`, `destination?` | `{effect, code, obligations, audited, category?}`: the read-only gateway decision with obligations (R121: share/export must name a destination) |
| `steps` | `state`, `now`, `steps`, `memoryReview?`, `candidates?`, `unenforceable?` | one result per step `{effect, code, obligations, audited, category?, documents?, record?, quarantined?, destination?}`, stopping after `{thrown: true}` |
| `gate` | `state`, `binding`, `recipient` (id or `null`), `sources`, `purpose` | `{ok, restrict?}` |
| `containment` | `state`, `tenant`, `sources` or `level`, `destinationClass?` or `classes?` | `{ok: true, obligations}` or `{ok: false, reason}` |
| `fresh` | `state`, `context`, `now`, `revision` | `true` / `false` |
| `classification` | `state`, `id` | highest transitive classification or `null` |
| `authzen` | `state`, `tenant`, `request`, `now` | `{mapped: "malformed" \| "unsupported"}` or `{mapped: "ok", binding, decision, evaluate}` |
| `scenario` | `scenario` (a `vectors-redteam.json` case; the fixture is loaded by the implementation) | `{outcome, steps: [{op, allowed, code}]}` |
| `jcs`, `merkleRoot`, `inclusionProof`, `consistencyProof`, `verifyInclusion`, `verifyConsistency`, `auditHash`, `auditLeaf`, `auditChain`, `obligations`, `reason`, `checkpointV2` | the members of the corresponding `vectors-0.4.json` kind | the value that kind's `expected` holds |

Step operations (`steps`): `open {binding, resources, purpose}`, `retrieve
{binding, query, purpose, limit?}`, `derive {binding, context, content, kind}`,
`release {binding, context, recipient, content, action}`, `delegate {binding,
child}`, `revoke {tenant, admin, type, id}`; a step with `save: name` stores the
context id (`open`, `retrieve`) or record id (`derive`), and a later string
`$name` is replaced by it. Each operation consumes one generated id for its
decision before any context or record id, and generated ids are
`00000000-0000-4000-8000-` followed by a 12-digit counter starting at 1, so both
sides order generated ids identically. `code` of an allow is its allow code
(`AUTHORIZED`, `PROTECTED_DERIVATION`, `AUTHORIZED_RECIPIENT`, `ATTENUATED`);
`audited` is false for requests refused before any tenant transaction (code
`NOT_AUTHORIZED`). A `record` is the derived record's `classification`,
`projects`, `readerRoles`, `readers`, `sources` and, when present, `retainUntil`,
`lifecycle`, `quarantineReason`.
