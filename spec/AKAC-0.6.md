# AKAC 0.6

Status: project specification, not a ratified external standard. Reference: 0.6.0.
This revision incorporates R01–R16 of [AKAC 0.1](AKAC-0.1.md), R17–R21 of
[AKAC 0.2](AKAC-0.2.md), R22–R31 of [AKAC 0.3](AKAC-0.3.md), R32–R108 of
[AKAC 0.4](AKAC-0.4.md) and R109–R120 of [AKAC 0.5](AKAC-0.5.md) by reference and
without weakening any of them: a requirement below only adds conditions,
obligations or evidence, and an implementation of 0.6 MUST still satisfy R01–R120.
Where a requirement below refines an earlier one (for example R121 refines R67 and
R109), the earlier requirement keeps every condition it stated and the refinement
adds one more; the single place where 0.6 makes an allow reachable that 0.5 did not
have is the break-glass read of R149, which is bounded by R149 and reachable only
after the multi-person approval of R150 and R153. MUST, MUST NOT, SHOULD, SHOULD NOT
and MAY are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when,
and only when, they appear in all capitals.

No external review, legal review, independent interoperability test or certification
has taken place. The second implementation in `implementations/python/` was written
by the authors of this specification and is same-project evidence (R131). Algorithms
standardised in FIPS 204 and FIPS 205 are used; no cryptographic module is claimed to
be FIPS-validated.

Numbering continues from 0.5. The drafts in [drafts/](drafts/) named `0.6-*.md` were
merged here; the table at the end maps every draft identifier (`R-<TOPIC>-n`) to its
R number, so references to a draft identifier stay resolvable. The R numbers are
stable: they are not reused or reordered in later revisions.

| Section | Requirements | Conformance profile |
|---|---|---|
| [Fixes from the review of 0.5.0](#fixes-from-the-review-of-050-r121r126) | R121–R126 | refines AKAC-Destinations/0.4, AKAC-AuthZEN/0.4, AKAC-RuntimeContainment/0.5, AKAC-Lifecycle/0.4 |
| [Conformance independent of the reference](#conformance-independent-of-the-reference-r127r131) | R127–R131 | runner contract; no decision |
| [Formal model](#formal-model-r132r135) | R132–R135 | evidence of the specification; no decision |
| [Operations at production shape](#operations-at-production-shape-r136r142) | R136–R142 | AKAC-Operations/0.6 |
| [Identity and authority](#identity-and-authority-r143r158) | R143–R158 | AKAC-Identity/0.6 |
| [Crypto agility and post-quantum checkpoints](#crypto-agility-and-post-quantum-checkpoints-r159r166) | R159–R166 | AKAC-CryptoAgility/0.6 |
| [Release and retrieval protection](#release-and-retrieval-protection-r167r181) | R167–R181 | AKAC-Release/0.6 |
| [Knowledge semantics and content encryption](#knowledge-semantics-and-content-encryption-r182r196) | R182–R196 | AKAC-Knowledge/0.6 |

Profiles, outcome classes and gates: [CONFORMANCE.md](CONFORMANCE.md). Rule coverage:
`conformance/coverage/matrix.json`, checked by `npm run coverage:matrix`
([CONFORMANCE-COVERAGE.md](../docs/CONFORMANCE-COVERAGE.md)). Migration:
[MIGRATION-0.6.md](../docs/MIGRATION-0.6.md). Editions and extension points:
[ADR-023](../governance/ADR-023-editions-and-extension-points.md).

## Extension points only narrow

Several requirements below define hooks an operator or an extension can fill: release
filters and derive sanitizers (R167–R170), an external risk provider (R152), an
external approval gate (R155), external checkpoint signers (R140, R164), content key
providers (R195) and the supplemental policy (R189). Whatever fills them, R181 applies:
a hook can only add a restriction, a failure of a hook denies, and no hook can turn a
denial into an allow. An implementation that ships no implementation of a hook still
conforms when it applies the default that the requirement states.

## Fixes from the review of 0.5.0 (R121–R126)

Merged from [0.6-findings](drafts/0.6-findings.md). Every requirement only adds conditions: nothing that 0.5 denied becomes an allow.
Decision: [ADR-013](../governance/ADR-013-findings-and-semantics-fixes.md).

**R121 — A read-only share/export evaluation names its destination.**
(Refines R67 and the "evaluation that names no Destination" case of R109.) A
read-only evaluation (Engine.evaluate, AuthZEN) of `share` or `export` that does
not name a Destination (`context.destination`) MUST be denied with `RECIPIENT`,
under an unrestricted run as well as under a run restricted to destinations. A
release checks that its recipient may see every source; an evaluation has no
recipient, so without a named Destination nothing bounds where the content goes.
The 0.4 behaviour (allowed, with `destination_restricted` listing a restricted
run's destinations, and without any condition under an unrestricted run) is
withdrawn. Reads and derivations are unchanged.

**R122 — No reachable destination class denies.** (Refines R109.) Where the
runtime obligations of a share or export are derived over the destination
classes a run allows (a release to a principal without a Destination profile),
and none is reachable (for example every Destination id of the run resolves to
no active profile of the tenant), the decision MUST be denied with `RECIPIENT`.
It MUST NOT fall back to a derivation without a destination class.

**R123 — Enforcement points that cannot apply runtime profiles.**
(Applies R38 and R113 to the agent HTTP listener.) An enforcement point that
returns content to a caller without applying the `runtime_profile` obligations
of the decision MUST treat such a decision as a deny, unless its operator has
declared that every caller runs inside a runtime enforcer that applies them
(R112). The reference agent listener has a setting for this
(`AKAC_RUNTIME_OBLIGATIONS`, `deny` by default, or `trusted-enforcer`); in `deny`
mode the operation MUST be denied with `UNSUPPORTED_OBLIGATION`, MUST leave no
state behind (no context, no derived record) and the denial MUST be audited with
the request's correlation ids. The declaration is not verifiable by AKAC and MUST
NOT be the default.

**R124 — The revision is confirmed after the final release.** (Refines
R112.) An enforcement point that releases a result produced under applied
runtime profiles MUST confirm, after the final release decision and before
returning the result, that the runtime still reports the applied revision for
that execution. If it does not, the result MUST be withheld and the withholding
audited as a denial (`UNSUPPORTED_OBLIGATION`) of the same operation, with the
execution id and the applied revision. The allow entry of the final release stays
in the audit stream; the denial that follows it records that nothing was
returned.

**R125 — A tombstone names no audience.** (Refines R53.) Erasure MUST also
clear the record's reader roles, so that the tombstone names no one who could
read it even for an evaluator that ignored `lifecycle`. The record's projects
MUST be kept: they are a conjunctive restriction, and removing them would widen
the label. Re-erasing a tombstone written before 0.6 MUST clear its reader roles
without changing its erasure time; erasure stays idempotent otherwise.

**R126 — Label widening is a declassification.** (Refines R15, the separately
authorized declassification process, and R31.) A new version of an existing
document whose label grants more than the current version (a lower own
classification; a reader or reader role added; a project removed; another
container; an access expiry removed or extended; a source dropped) is a
declassification. It MUST be accepted only from an administrator holding
`security-admin`; a `kb-admin` without that role MUST be refused with `CONFLICT`
and nothing stored. An administrator holding `security-admin` without `kb-admin`
MAY publish only such a label-widening version of an existing document with
unchanged content; any other document change by that administrator MUST be
refused (`NOT_AUTHORIZED`, audited as `NOT_ADMIN`). Model output and agents never
reach either path (R06, R31).


### Evidence

- `conformance/vectors-authzen.json`: Z21 (export without a destination, now
  deny `RECIPIENT`), Z22 (share without a destination, unrestricted run, deny
  `RECIPIENT`), Z23 (share naming a destination passes the rule). The runner
  applies R121 (`evaluationTargetNamed`) after `decide()`.
- `conformance/vectors-runtime.json`: RTC-E09 to RTC-E11 (evaluations without a
  destination deny `RECIPIENT`), RTC-E14 (the narrowed profile applies when the
  destination is named), RTC-E15 (inactive named destination denies), RTC-P20 and
  RTC-P21 (`containmentAcross` with no and with one reachable class), RTC-R13
  (revision changes after the final release: denied).
- Tests: `tests/authzen.test.ts` (R121 over HTTP), `tests/destinations.test.ts`,
  `tests/runtime-containment.test.ts` (R121 to R124), `tests/config.test.ts`
  (R123 setting), `tests/lifecycle.test.ts` (R125),
  `tests/regressions-0.6.test.ts` (R126).

## Conformance independent of the reference (R127–R131)

Merged from [0.6-conformance](drafts/0.6-conformance.md). These requirements govern the conformance material and how results are reported; they change no decision.
Decision: [ADR-014](../governance/ADR-014-conformance-independence.md).
Implementer guide: [docs/IMPLEMENTATIONS.md](../docs/IMPLEMENTATIONS.md).

**R127 — The fixture is data.** The synthetic world every vector file refers
to MUST be published as a JSON document (`examples/fixture.json`) that validates
against `schemas/fixture.json`. A fixture is loaded by starting from an empty
state, merging the records of every fixture in its `extends` chain (base first,
a later record replacing an earlier one with the same id), and then adding the
vector clock to every member named in `clockRelative`. Vector patches apply after
that. No conformance vector MAY depend on fixture data defined only in code; the
reference implementation MUST load its fixture from the same document.

**R128 — JSON value semantics.** An implementation MUST read vectors, the
fixture and records with JSON's single number type: a number with an integral
value is an integer however it is written (`1`, `1.0`, `1e0`, and `-0` as `0`);
a non-integral number is not an integer; `NaN` and `Infinity` are not JSON and
MUST be rejected. A missing member MUST be distinguished from a member whose
value is `null` wherever a rule depends on presence (for example `lifecycle`,
`activeRoles`, `destinations`, `maxResults`, `parent`, `container`). A record
whose members have unexpected types MUST fail closed with the same code as the
reference: the rule that could not be evaluated is not established.

**R129 — Runner contract.** An implementation that claims results for a
vector file SHOULD expose the language-neutral runner contract of
[docs/IMPLEMENTATIONS.md](../docs/IMPLEMENTATIONS.md): one JSON case in, one
JSON result out, over the case's complete state. The contract covers the pure
decision (`decide`), the gateway decisions (`evaluate`, and `steps` over `open`,
`retrieve`, `derive`, `release`, `delegate`, `revoke`), the destination gate, the
runtime containment derivation, context freshness, the AuthZEN mapping,
red-team scenarios and the evidence functions (JCS, RFC 9162, audit hashes,
obligations, reason codes, checkpoints). A result compares by value: effect,
reason code, category, obligations in their canonical order, and for operations
the disclosed ids, the derived label and the destination.

**R130 — Differential evidence.** A second implementation's results MUST be
stated per vector file as the number of vectors run and the four-way outcome
counts (SUCCESS, SAFE_BLOCK, FAILURE, UNSAFE_SUCCESS). A vector that the
implementation does not cover MUST be reported as not applicable with the reason;
it MUST NOT be counted as a pass. Where two implementations are compared on the
same cases, every disagreement in effect, code, category or obligations MUST fail
the comparison, and a generated-case comparison MUST report the minimized
disagreeing case. A comparison MUST include positive controls (allows) and report
how many decisions of each effect it compared: agreement on denials alone is not
evidence.

**R131 — Honest provenance.** A results table MUST state who wrote each
implementation. An implementation written by the authors of the specification is
same-project evidence and MUST NOT be described as independent; no result implies
certification.

### Relation to earlier text

Up to 0.5, [CONFORMANCE.md](CONFORMANCE.md) stated that the fixture "is defined in
`examples/fixture.ts`". From 0.6 it is defined in `examples/fixture.json`;
`examples/fixture.ts` only loads it (erratum E-0005). The four-way outcome model,
the gates and the cross-tenant tag rule (R105) are unchanged.

### Evidence

- `examples/fixture.json`, `schemas/fixture.json`; `examples/fixture.ts` loads the JSON
  (identical records and member order to the 0.5 code fixture).
- `implementations/python/`: `python -m akac conformance` runs every vector file
  without the TypeScript harness; `python -m akac eval` / `serve` implement the runner contract.
- `tests/differential-vectors.test.ts`: every vector file through both implementations,
  identical results required; integral-float reading (R128).
- `tests/differential-fuzz.test.ts`: 2,000 generated worlds (6,000 cases) per CI run with a fixed seed
  (`AKAC_FUZZ_RUNS`, `AKAC_FUZZ_SEED` to widen), minimized counterexample on disagreement.
- `tests/interop.test.ts`: the 0.2/0.3 generated comparisons, now through the runner contract.

## Formal model (R132–R135)

Merged from [0.6-formal](drafts/0.6-formal.md). These requirements concern the evidence of the specification, not the behaviour of an implementation: nothing that 0.5 allowed or denied changes.
Decision: [ADR-015](../governance/ADR-015-formal-model.md). Guide:
[docs/FORMAL-MODEL.md](../docs/FORMAL-MODEL.md).

**R132 — Informative model.** The specification is accompanied by a TLA+
model of its core authorization semantics (`formal/AKAC.tla`): principals, roles,
groups and SoD constraints (R22–R24), grants and delegation with attenuation of
actions, resources, purposes, destinations, result limit, expiry and session roles
(R04, R05, R24, R63, R65, R68, R69), knowledge with classification, containers and
provenance (R08, R09, R25), lifecycle and tenant epochs (R12, R28, R45–R49, R53,
R54), release to recipients and destinations (R10, R61–R63) and label widening
(R15, R31, R126). The model is informative. Where it and normative text
differ, the normative text applies and the model MUST be corrected.

**R133 — Checked properties.** The model states the following properties
and they MUST hold for every configuration of the faithful model published with
the specification:
1. *NoEscalationThroughDelegation*: an allowed decision under a grant is allowed
   by every grant of its delegation chain (action, resource, purpose, liveness,
   expiry, session roles); a release's destination class and a disclosure's
   document count are admitted by every grant of the chain.
2. *NoDeclassificationThroughDerivation*: a derived record whose provenance
   resolves is classified at least as high as the effective classification of
   every record of its lineage and keeps every project; it admits no principal
   that some record of its lineage does not admit.
3. *RevokedOrQuarantinedSourceNoDisclosure*: no read, derivation or release is
   allowed for a record whose lineage contains an inactive (revoked), quarantined
   or erased record, and no context is fresh while any source lineage contains one.
4. *TenantIsolation*: no allowed decision, context, derivation or release involves
   principals, grants or records of another tenant.
5. *SeparationOfDuty*: no allowed decision for a user or agent whose effective
   roles meet a static constraint or whose session roles meet a dynamic one, and
   no release to a recipient whose effective roles meet a static constraint.
6. *ReleaseRecipientCheck*: a release is allowed only if the recipient is of the
   run's tenant and admitted by every record of every released lineage and its
   containers, its destination profile admits the highest effective
   classification and the purpose, and every grant of the chain admits its
   destination class.
7. *LabelWideningRequiresSecurityAdmin*: every accepted document version whose
   label admits some conceivable principal the previous label did not was
   written by an administrator holding `security-admin`.

**R134 — Properties bite.** For each property of R133 the model MUST
ship at least one broken configuration that changes one rule, and the model
checker MUST report that property violated for it. The model MUST also ship
non-vacuity configurations showing that allowed releases, allowed decisions under
a delegated grant, derivation from derived knowledge and security-admin widening
are reachable.

**R135 — Stated bounds.** The published results MUST state the finite
universe, the depth bounds, the model checker version, the numbers of states
explored and what is not modelled. A result is a bounded model-checking result;
it MUST NOT be presented as a proof for unbounded systems or as verification of
an implementation.

### Evidence

- `formal/AKAC.tla`, `formal/MC.cfg`, `formal/MC_admin.cfg`, `formal/broken/*.cfg`,
  `formal/witness/*.cfg`, `formal/check.sh`; workflow `.github/workflows/formal.yml`.
- Results, bounds, limits and the traceability table (property to requirement to
  conformance vectors and tests): [docs/FORMAL-MODEL.md](../docs/FORMAL-MODEL.md).

## Operations at production shape (R136–R142)

Merged from [0.6-operations](drafts/0.6-operations.md). These requirements concern deployments with more than one gateway instance, checkpoint key custody and audit verification. They change no authorization decision: nothing that 0.5 denied becomes an allow, and no allow depends on the new state.
Decision: [ADR-016](../governance/ADR-016-ha-and-operations.md). Operator
guidance: the high-availability guide, the key custody guide,
the operations guide.

**R136 — Shared rate windows.** (Refines R103.) A gateway MAY keep its request
budgets (R100) in a store shared by every instance of the deployment. When it does,
every instance MUST count into the same window for the same key, the window MUST be
derived from one clock (the shared store's), and a request over budget on any instance
MUST be refused as R101 requires. Without a shared store R103 applies unchanged.

**R137 — Shared state is tenant-confined and fails closed.** Shared operational
state (rate windows, idempotency records) MUST be keyed by tenant and confined to it
with the same isolation as tenant records (R30: forced row-level security for a
PostgreSQL store; the runtime role never bypasses it). Keys MUST be digests of the
authenticated identity, never tokens. When the shared store cannot decide (unreachable,
timeout, error) the request MUST be refused with 503; it MUST NOT be admitted unmetered
and MUST NOT fall back silently to per-instance state.

**R138 — Idempotency across instances.** (Refines the admin Idempotency-Key
behaviour of 0.3.) When idempotency records are shared, a request whose key is already
recorded MUST be answered from the record on every instance, re-authorized and audited
exactly as on a single instance (`IDEMPOTENT_REPLAY`, `DENIED:IDEMPOTENCY_KEY_REUSED`).
Of two concurrent requests with the same new key, exactly one MUST execute; the other
MUST be refused (409 `CONFLICT`, audited as `DENIED:CONFLICT`) or answered from the
completed record. An in-flight claim MUST lapse after a bounded lease so that a crashed
instance cannot block a key indefinitely. Records MUST expire.

**R139 — Serialized maintenance jobs.** Retention (R56, R57) and index reconciliation
MUST NOT run concurrently for the same tenant, whichever instance, scheduler or
administrator starts them. A run that finds another in progress MUST NOT queue behind
it; a script run is skipped, and an administrative request is refused with 409 and
audited as `DENIED:CONFLICT` after the caller's standing role is checked. The lock MUST
be released when its holder ends, including abnormal termination.

**R140 — External checkpoint signers.** A checkpoint (format 2) MAY be signed by a
key held outside the gateway (KMS, HSM). The signer MUST be pinned to one key version,
the checkpoint `keyId` MUST identify that version, and the signature MUST be verified
against the pinned public key before the checkpoint is returned or stored. Only the
signing input (the JCS form of the checkpoint members) is sent to the signer, never
audit entries or content.

**R141 — Verification across key rotation.** A verifier MUST retain every key that
signed a checkpoint it relies on, with its status and validity window. It MUST reject a
checkpoint whose key is unknown or revoked, and a checkpoint issued outside the
validity window of a retired key. A consistency proof between two checkpoints does not
depend on their keys; history MUST remain verifiable across a rotation.

**R142 — Audit verification job.** A deployment SHOULD verify every tenant stream on
a schedule: the hash chain from sequence 1, the RFC 9162 root recomputed from the
entries, the stored tree head, and every anchored checkpoint as a prefix of the stream
(its first `treeSize` entries have its `rootHash`). Any failure MUST be treated as a
possible integrity incident, and a stream shorter than an anchored checkpoint is a
rollback, not a pass.

### Evidence

These requirements concern deployment state, not `decide()`, so they are covered by
tests rather than portable vectors: `tests/ha.test.ts` (R136..R139, memory seams, 409
and 503 paths), `tests/ha-postgres.test.ts` (two gateway instances on one database:
shared windows, one concurrent winner, lease lapse, TTL sweep, forced RLS, job locks and
a crashed holder), `tests/custody.test.ts` (R140..R142 with a mocked Vault Transit
endpoint, key rotation and tamper detection) and the CI backup/restore drill
(`scripts/backup-drill.ts`, R142 after restore).

## Identity and authority (R143–R158)

Merged from [0.6-identity](drafts/0.6-identity.md). Every requirement only adds conditions: nothing that 0.5 denied becomes an allow, except the break-glass read of R149, which is itself an allow only after the multi-person approval of R150.
Decision: [ADR-019](../governance/ADR-019-identity-and-authority.md).

References: RFC 8693 (OAuth 2.0 Token Exchange, Standards Track, January 2020),
sections 4.1 (`act`) and 4.4 (`may_act`); OpenID Shared Signals Framework 1.0,
OpenID CAEP 1.0 and OpenID RISC Profile 1.0 (Final Specifications, 2025);
RFC 8417 (Security Event Token).

### Delegated identities (RFC 8693)

**R143 — The current actor is the mapped agent.** An agent credential that
carries an `act` claim is a delegation token: its top-level `sub` is the party on
whose behalf the agent acts, the outermost `act` names the current actor and nested
`act` claims name prior actors (RFC 8693 section 4.1). An implementation MUST
authenticate such a token only when a trusted, operator-provisioned mapping binds
the token subject to one binding (tenant, user, agent, grant) AND names the expected
current actor (`sub`, and `iss` when the mapping sets one); the outermost `act` MUST
match it exactly. A prior actor MUST NOT satisfy the mapping. Any other delegation
token MUST be refused (unauthenticated).

**R144 — Impersonation and may_act.** A token subject whose mapping requires
delegation MUST NOT authenticate with a token without `act`. A token without `act`
MUST authenticate only through a mapping that does not require delegation (the 0.5
mapping, in which the operator's provisioning states that the token subject is the
run's delegating credential). A token that carries `act` for a subject whose mapping
does not require delegation MUST be refused. When `may_act` (section 4.4) is
present, it MUST name the mapped current actor (and its `iss`, when present, MUST
equal the actor's); `may_act` in a token without `act` MUST be refused.

**R145 — The chain is evidence.** The verified actor chain, the current actor
first, MUST be recorded with every audited decision taken with that credential
(`actorChain`, audit format 2). It MUST have 1 to 5 entries of 1 to 256 printable
ASCII characters; a token whose chain is deeper or malformed MUST be refused. Only
identity members of `act` are read; non-identity claims inside `act` carry no
meaning (section 4.1). The chain MUST NOT be accepted from request data.

**R146 — Delegation only narrows.** Roles, scopes, agent ids and any other claim of
a delegation token MUST be ignored for authorization: the mapped binding and its grant
decide, so a token exchange can only select a pre-provisioned run. Administrative and
policy-enforcement-point credentials MUST NOT be delegation tokens: a token with
`act` or `may_act` MUST be refused on those listeners.

### Heartbeat-bound grants

**R147 — A run lives only while its runtime reports.** A grant MAY carry
`heartbeatTtlMs` (1 000 to 86 400 000 ms). Such a grant MUST be treated as invalid
(`INVALID_DELEGATION`) unless its `lastHeartbeatAt` is a safe integer, not later
than the decision time, and less than `heartbeatTtlMs` before it. A child of a
heartbeat-bound grant MUST carry a TTL no longer than its parent's; since every
decision validates the whole delegation chain, a lapsed ancestor invalidates every
descendant, whatever their own heartbeats. `lastHeartbeatAt` MUST be set only by the
control plane (issuance: the issue time; delegation: the delegation time;
heartbeat): a value supplied by a caller MUST NOT be kept. A lapse is final: a
heartbeat for a grant whose chain is no longer valid MUST be refused (`CONFLICT`).
An in-process decision cache MUST NOT keep an allow past a heartbeat deadline.

**R148 — Heartbeats come from a trusted runtime.** Heartbeats MUST be accepted only
on the administrative listener (`POST /admin/v1/grants/{id}/heartbeat`) from a
principal holding the `runtime` role that is bound to the grant's agent
(`runtimeFor`, a list of agent ids on the runtime principal, managed by a
`security-admin`; a new binding passes the approval gate as a role widening); any other
grant MUST be refused (`NOT_AUTHORIZED`, audited `NOT_ADMIN`), whether it exists or
not. Heartbeats MUST be audited. The `runtime` and
`risk-ingest` roles are the only roles a `service` principal MAY exercise on the
control plane; every other administrative role MUST be held by an active `user`.

### Break-glass

**R149 — What a break-glass grant can do.** A grant with `breakGlass: true` MUST
be a root grant, allow exactly `read`, name 1 to 64 resources explicitly (never
`*`), and span at most two hours; otherwise it is invalid (`INVALID_DELEGATION`). A
grant whose parent carries `breakGlass` is invalid (never delegable). A valid
break-glass grant lifts, for its named resources and their sources, only the
audience clauses (readers, reader roles, projects of records and containers). It
MUST NOT lift the tenant boundary, activity, lifecycle states (quarantine, erasure),
access expiry, clearance or risk caps, and MUST NOT change any record, so legal
holds and erasure are untouched.

**R150 — Issuing break-glass.** A break-glass grant MUST be issued only by the
control plane after its approval quorum (R153), which MUST NOT be lower than 2.
Every audit entry of its request, approvals and issuance, and of every decision
taken under it, MUST carry `breakGlass: true`. Implementations SHOULD count
issuances and decisions in a metric suitable for alerting.

### Risk

**R151 — Risk caps lower clearance.** A risk signal names a principal, a level
(`none`, `low`, `medium`, `high`, `critical`) and an expiry. For a decision, the
highest unexpired level of each of the user's and the agent's same-tenant signals
MUST cap that principal's clearance: the cap of a level is the lowest cap configured
for it or any lower level, so a higher level never allows more; `critical` MUST deny
every decision (`RISK_CAP`). The default caps are none and low: no cap; medium:
`confidential`; high: `internal`. A decision denied only because of a cap MUST carry
`RISK_CAP`; a malformed signal of a principal or a malformed cap configuration MUST
defer (`INVALID_CONTEXT`). Recipients of share and export are capped the same way.

**R152 — Risk sources.** Risk signals MUST be ingested only by a principal holding
`security-admin` or `risk-ingest`; the source of a signal MUST be the authenticated
caller, never a request field, so a source can only replace its own signals. A
signal that raises the caller's previous level for the principal MUST advance the
tenant epoch. An external risk provider consulted by the engine MUST only be able to
add restrictions (its level is combined as one more signal); a failure, timeout or
unknown level MUST deny. SSF/CAEP receivers are connectors outside the core: a
CAEP `risk-level-change` maps LOW, MEDIUM and HIGH to `low`, `medium` and `high`.

### Approval quorum

**R153 — Sensitive operations need a quorum.** These operations MUST pass the
approval gate: issuing a break-glass grant; a label-widening document version
(R126); a role change that can widen its closure (inherits added, reactivation,
or a new role that inherits others); relaxing a SoD constraint (static to dynamic, a
role removed, a higher cardinality); changing an existing runtime profile policy;
widening a destination profile (a new active profile, reactivation, a higher
classification, a purpose added, another class); relaxing tenant settings. A quorum
of N MUST mean N distinct standing `security-admin` users: the requester and N-1
approvers who are not the requester. The default quorum is 1 (the requester alone,
0.5 behaviour) for every class except break-glass (2). While the quorum is not met
the operation MUST NOT take effect; the request is stored as a pending approval and
answered `APPROVAL_REQUIRED` (audited as a denial of the operation).

**R154 — Approvals.** An approval MUST be refused (`CONFLICT`, audited) from the
requester, from an approver who already approved, for an unknown, another tenant's,
decided or expired request. Approvals expire (default 24 hours, 5 minutes to 7
days). At execution the operation MUST run as the requester, who MUST still hold the
operation's role, with exactly the stored arguments (bound by their JCS SHA-256
digest), and MUST re-validate every rule of the operation against the current state;
only approvers who still hold `security-admin` count, and the quorum is the higher of
the recorded and the current one. An approval MUST execute at most once. Any
`security-admin` MAY reject a pending request (the requester withdraws it).

**R155 — External approval workflows only add requirements.** An external
approval gate MAY raise the quorum of a request and MAY require an external
workflow; it MUST NOT lower the tenant quorum and MUST NOT execute an operation on
its own. A request that requires the external workflow MUST execute only when the
internal quorum is met AND the gate confirms the workflow. A gate error or timeout
MUST fail closed (the external workflow is then required and unconfirmed).

**R156 — Settings.** Tightening tenant settings (a higher quorum, a shorter
approval lifetime, a lower risk cap) MAY take effect at once. Any relaxation MUST
need the highest quorum configured for any class. The break-glass quorum MUST NOT
be configured below 2, and a cap for `critical` MUST NOT be configurable.

**R157 — Storage.** Risk signals, tenant settings and approvals are tenant
records: a store MUST keep them in the tenant's partition (PostgreSQL: forced
row-level security, migration 010) and MUST load them within published bounds
(BudgetExceeded above them, never a silently truncated set).

**R158 — Elevation to an approver role.** The roles whose holders count towards a
quorum are the *approver roles*; in this profile only `security-admin`. Any change
that makes a principal newly hold an approver role in its standing roles MUST pass the
approval gate with the highest quorum configured for any class (as R156, so never
below the break-glass quorum): a role assignment, creating or changing a principal
(including reactivating a deactivated administrator), creating or changing a group
(members or roles), a role whose closure newly grants an approver role (inheritance
added, a role record activated or created), and every SCIM operation that maps to
these. The principals an elevation names MUST NOT count towards, and MUST NOT be
allowed to cast, an approval of their own elevation. Rationale: otherwise one
`security-admin` could make a second principal an approver and reach any quorum of 2
alone. Consequence: a tenant with a single `security-admin` cannot create a second one
through the control plane; the first administrators are provisioned out of band
(seed, migration or the identity provider's bootstrap).

*Limitation.* Quorums count distinct principal ids, not distinct persons. Two accounts
of one person satisfy a quorum of 2. Deployments that rely on four eyes MUST ensure
one account per person for approver roles (SCIM provisioning from an identity provider
that enforces person uniqueness, periodic access review); AKAC cannot verify it.

### Evidence

- `conformance/vectors-0.6-identity.json` (profile `AKAC-Identity/0.6-draft`):
  ID-H01..ID-H10 (R147), ID-B00..ID-B13 (R149), ID-R01..ID-R14 (R151); run by
  `conformance/run-identity.ts` and by the Python implementation.
- Tests: `tests/identity.test.ts` (every requirement), `tests/identity-postgres.test.ts`
  (R157, migration 010, forced RLS), `tests/regressions-0.6b.test.ts` (R147 runtime
  binding, R158 elevation).

## Crypto agility and post-quantum checkpoints (R159–R166)

Merged from [0.6-crypto](drafts/0.6-crypto.md). These requirements concern the signature algorithm of audit checkpoints. They change no authorization decision and no audit entry: nothing that 0.5 denied becomes an allow, and no allow depends on the new state. Format 1 and format 2 checkpoints stay valid and verifiable.
Decision: [ADR-021](../governance/ADR-021-crypto-agility-and-pq.md). Operator
guidance and the inventory of every cryptographic use:
[CRYPTO-AGILITY.md](../docs/CRYPTO-AGILITY.md); key handling:
the key custody guide.

Sources for the algorithms: NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA), both
published as final standards on 13 August 2024; RFC 8032 (Ed25519); RFC 8785 (JCS);
RFC 9162 (Merkle trees). Nothing here claims FIPS validation of any module: using an
algorithm standardised in a FIPS publication is not a validated cryptographic module.

**R159 — Closed algorithm registry.** A checkpoint signature algorithm MUST be
one of the registered identifiers: `ed25519`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`,
`slh-dsa-sha2-128s`, `slh-dsa-sha2-256s`, `ed25519+ml-dsa-65`. An implementation MUST
refuse any other identifier, including `none`, in every role (signing, verification,
configuration, keyring). An identifier in a document never selects an algorithm the
verifier has not registered.

**R160 — Checkpoint format 3.** A format 3 checkpoint
(`akac-audit-checkpoint/3`) carries the members of format 2 and `alg`. Its signature
MUST cover the RFC 8785 (JCS) form of every member except `signature`, that is
`{format, alg, stream, treeSize, rootHash, issuedAt, keyId}`, so that the algorithm
cannot be changed without invalidating the signature and a format 3 signature is never
valid as a format 2 one. `keyId` MUST be `<alg>:<label>` with the checkpoint's own `alg`.
`signature` MUST be the canonical unpadded base64url of the component signatures in
registry order and MUST have exactly the length of the algorithm; a verifier MUST refuse
any other length or encoding. Format 1 and format 2 checkpoints MUST remain verifiable
unchanged. A verifier MUST refuse a checkpoint with an unknown member.

**R161 — Hybrid signatures.** A checkpoint with `alg` `ed25519+ml-dsa-65` MUST
carry an Ed25519 signature followed by an ML-DSA-65 signature over the same bytes and is
valid only if both verify under the two public keys of the key id. A verifier MUST refuse
it when either component is missing, malformed, or invalid, when the components come from
different messages, and when the key material is not exactly an Ed25519 key followed by
an ML-DSA-65 key.

**R162 — Verifier policy.** A verifier MUST decide which registered algorithms it
accepts by its own policy (an allowlist); the checkpoint MUST NOT influence that decision.
A checkpoint whose `alg` the policy excludes MUST be refused even if its signature is
valid. Without a policy a verifier MAY accept every registered algorithm it can execute.

**R163 — No downgrade.** For one stream, once a checkpoint with a post-quantum
component (`ml-dsa-*`, `slh-dsa-*`, hybrid) has verified, a verifier MUST refuse a
classical-only checkpoint of that stream that is issued at or after, or is larger than,
the earliest such checkpoint, unless its policy explicitly permits classical checkpoints
after post-quantum ones. A checkpoint issued earlier and not larger MAY still verify; it
remains bound by append-only history (RFC 9162 consistency, R44). Only
signature-verified checkpoints MAY raise this floor. A set of checkpoints in which any
member fails MUST fail as a whole. Moving from a hybrid to a post-quantum-only algorithm is
not a downgrade (a post-quantum component remains) and MUST be accepted under the policy.
The issue time of a checkpoint is asserted by its signer: a holder of a classical key can
present a *backdated* classical checkpoint that passes this rule when its tree is not larger
than the earliest post-quantum checkpoint's. Such a checkpoint can only attest a prefix that
the post-quantum checkpoints also cover and stays bound by RFC 9162 consistency; verifiers
that are required to exclude classical signatures altogether after a migration MUST remove classical
algorithms from their policy.

**R164 — Algorithm selection by configuration.** The signing algorithm MUST be
selected by operator configuration and defaults to `ed25519`, which writes format 2
(readable by every 0.4 and later verifier). Any other algorithm writes format 3. A
signer MUST verify its own signature under its public key before returning a
checkpoint and MUST fail closed on a key that does not match the configured algorithm
or on a key id without the `<alg>:` prefix. A signer that cannot produce a
post-quantum signature (for example a key service without one) MUST NOT be configured
for one.

**R165 — Key material handling.** Private key material MUST NOT be written to
logs, error messages, JSON serialisations or metrics. An implementation SHOULD read key
files as byte buffers and overwrite them after parsing, and SHOULD NOT retain key
material as a string. An implementation MUST NOT claim that keys held in a
garbage-collected runtime's key objects are erased.

**R166 — Unavailable algorithms are not passes.** An implementation that cannot
execute a registered algorithm (missing library support) MUST report verification as
unavailable, not applicable, or failed, and MUST NOT accept the checkpoint or count the
vector as passed.

### Evidence

`conformance/vectors-0.6-crypto.json` holds verification-only known answers: public keys
and signatures, generated once from ephemeral keys that were discarded. ML-DSA and
SLH-DSA signing is randomised (FIPS 204, FIPS 205), so a signature cannot be regenerated;
Ed25519 is deterministic (RFC 8032). Kinds: `checkpoint-v3` (accept or reject one
checkpoint under an optional policy and minimum size) and `checkpoint-history` (accept or
reject a set of checkpoints of one stream, R163). A second implementation reports a
vector of an algorithm it lacks as NOT_APPLICABLE.

## Release and retrieval protection (R167–R181)

Merged from [0.6-release](drafts/0.6-release.md). Every requirement only adds conditions: nothing that 0.5 denied becomes an allow, and no hook, budget, hint or cache described here can turn a denial into an allow.
Decision: [ADR-020](../governance/ADR-020-release-and-retrieval-protection.md).
Guide: [RELEASE-PROTECTION.md](../docs/RELEASE-PROTECTION.md).
Vectors: `conformance/vectors-0.6-release.json` (profile `AKAC-Release/0.6-draft`).

**R167 — Release filters.** A release filter has a stable identifier (a valid
identifier, at most 16 configured filters) and one operation that receives the
tenant, the content about to be released, its highest transitive classification,
the recipient and the purpose, and returns exactly one of `pass`, `redact` (with
the replacement content) or `deny` (with a reason). Configured filters MUST run
in order for every `share` and `export` release, after the operation was
authorized (decide(), the supplemental policy, the recipient checks and the
destination gate) and before the content is returned, and each filter MUST see
the output of the previous one. A filter MUST NOT be able to allow an operation
that was denied, and MUST NOT be able to widen the content: a redaction is
non-empty, at most 100000 characters and at most twice the length of its input
plus 256 characters; any other result is malformed (R168).

**R168 — Hooks fail closed.** A release filter or derive sanitizer that
throws, does not answer within its deadline (default 2000 ms, at most 10000 ms)
or returns a malformed result MUST cause the operation to be denied: releases
with `RELEASE_FILTER`, derivations with `SANITIZER`, and nothing MUST be
released or stored. An implementation MAY offer an explicit operator setting
under which a broken hook is ignored; the default MUST be to deny, and such a
setting MUST NOT apply to a release filter that R169 requires.

**R169 — The `release_filter` obligation.** The obligation
`{"type": "release_filter", "value": [id, ...]}` (one to 16 distinct identifiers)
names filters a release MUST pass. Obligations of this type merge as the sorted
union of their ids; a union of more than 16 ids is unsatisfiable. A release whose
required filters (from the obligations of the decision, from an operator
configuration per tenant and highest classification, or from the caller through
`Call.requireFilters`) are not all configured MUST be denied with `RELEASE_FILTER`
before any filter runs. A release that passes every required filter has
satisfied the obligation: the engine MUST NOT hand a satisfied `release_filter`
to the caller, and MUST record it in the audit entry. An enforcement point that
performs the release itself and cannot run the listed filters MUST treat an allow
carrying `release_filter` as a deny (R38).

**R170 — Derive sanitizers.** A derive sanitizer has a stable identifier and
one operation that receives the tenant, the content about to be stored and its
kind (`memory` or `artifact`), and returns `pass`, `clean` (with the cleaned
content and findings) or `deny` (with findings). Configured sanitizers MUST run
in order over the content of every derivation after the derivation was
authorized and before anything is stored; a denial or a failure (R168)
MUST store nothing and be audited as `SANITIZER`. The same bounds on content as in
R167 apply to cleaned content. A sanitizer MUST NOT change the classification,
sources, readers or any other attribute of the derived record.

**R171 — Findings in audit are closed.** The audit entry of an operation in
which a hook or a budget acted MAY carry `findings`: one to 32 strings of the
characters `A-Z a-z 0-9 . _ : -`, each at most 128 characters. Findings MUST NOT
carry content, resource identifiers, queries or free text. The reference names
them `<filter>:redact`, `<filter>:deny`, `reason:<code>`, `<hook>:error`,
`<hook>:timeout`, `<hook>:invalid`, `<sanitizer>:clean`, `finding:<code>`,
`required:<filter>:missing` and `volume:<classification>`. A verifier MUST reject
an audit entry whose `findings` do not match this shape.

**R172 — Response-time equalisation.** An implementation SHOULD offer a
response-time floor (0 to 5000 ms) with jitter (0 to 1000 ms) for retrieval, context and
policy-decision endpoints. When configured, every response of such an endpoint
after authentication (a match, a denial, a no-match, a malformed request, an unknown
route, a refused rate or size limit and an internal error) MUST NOT be sent before the floor plus a fresh random jitter has elapsed since the
request was received. A denial and a no-match MUST have the same status and the
same members (the reference: HTTP 403, `ok`, `code` `NOT_AUTHORIZED`,
`decisionId`). The floor hides differences below it only; an operator MUST set it
above the 99th-percentile latency of the endpoint, and MUST size the listener's
concurrency for held connections.

**R173 — Denial hints.** Denial hints are OFF by default. When enabled, a
denial MAY carry one member `hint` with one of `GRANT_EXPIRED`,
`PURPOSE_NOT_GRANTED`, `ACTION_NOT_GRANTED`, `RATE_LIMITED`, `APPROVAL_REQUIRED`,
`RUNTIME_ENFORCER_REQUIRED`; otherwise the denial is unchanged (`code`
`NOT_AUTHORIZED`). A hint MUST be computed only from the caller's own grant (and
its ancestors), the requested action and purpose, the caller's own rate and volume
state and the state of the listener and the tenant configuration. It MUST NOT
depend on whether a resource exists, its labels, its ACL, its lifecycle or any
other attribute of a resource: for the same caller state and request parameters,
the hint of a denial MUST be the same for an existing and a missing resource.
`GRANT_EXPIRED`, `PURPOSE_NOT_GRANTED` and `ACTION_NOT_GRANTED` MUST be emitted
only when the fact denies the request for every resource. `RUNTIME_ENFORCER_REQUIRED`
is emitted when the listener has no runtime enforcer (R123) and the tenant has
an active runtime profile policy; it does not say that a particular resource is
protected. A volume hint MUST NOT be emitted for the operation that itself
consumed the budget. A denial hint never carries a resource identifier, a reason
code beyond this set or a value.

**R174 — Volume budgets.** An implementation SHOULD offer volume budgets:
per (tenant, user, agent) and classification, a maximum number of bytes and
documents released in a window. What a read projection returns and what a share or
export outputs count, at the highest transitive classification of each returned
document (of the sources, for a release). The disclosure that would exceed a budget
MUST NOT be made: it is denied with `VOLUME_EXCEEDED`, or, where the operator
configured approval mode, with `APPROVAL_REQUIRED` (a deferral), and the audit entry
carries the finding `volume:<classification>`. A failure of the budget store MUST
deny (fail closed, `STORE_ERROR`). A refused charge still counts within the window.
The reference uses fixed windows (a principal can spend up to twice a budget across
a window boundary) in the shared rate-limit store when one is configured.
Statistical scoring of behaviour over time is outside this requirement.

**R175 — The `approval_required` obligation.** The obligation
`{"type": "approval_required", "value": id}` states that an approval is needed
before the content is used. No approval workflow is part of this specification: an
enforcement point that cannot obtain one MUST treat an allow carrying it as a deny
(R38). The reference agent listener and ProtectedRuntime do so. Two obligations of
this type merge into one.

**R176 — Progressive backoff.** An implementation SHOULD offer backoff:
after a configured number of consecutive denials of one (tenant, user, agent) within a
reset period, each further denial doubles the time (from a base, up to a cap) for which the
principal's requests to the same endpoints are refused with HTTP 429 and `Retry-After`; a
success resets the streak. A no-match and a denial MUST count alike. The backoff MUST NOT
depend on resources beyond that.

**R177 — Embedding anchors.** An implementation that offers vector retrieval SHOULD
offer embedding anchors: operator-chosen anchor texts are embedded at start-up and
periodically and compared with a baseline. When the cosine similarity of any anchor to its
baseline falls below the configured threshold (default 0.98), or the model, the dimension
count or the anchor set differs from the baseline, vector retrieval MUST be disabled: a
retrieval MUST be deferred with `RETRIEVAL_DISABLED` before any index is queried, and the
audit entry records it. Retrieval MUST stay disabled until an administrator re-baselines; a
later check that finds the vectors matching MUST NOT re-enable it. Until a baseline has been
established retrieval MUST be disabled. The baseline MUST be persistent (it survives a
restart), and an implementation MUST NOT establish a baseline implicitly: a missing or
unreadable baseline at start-up or at a later check leaves retrieval disabled until an
administrator re-baselines explicitly, except for an explicit one-time operator bootstrap
that creates the baseline only when none exists and never replaces an existing or
unreadable one. Otherwise a restart that lost the baseline, or an embedder replaced while
the gateway was down, would be adopted silently as the reference. Failing to reach the
embedder is not drift. The baseline stores digests of the anchor texts, not the texts.

**R178 — Pre-filter by both audiences.** (Refines the permission-aware retrieval of ADR-004.) A
vector candidate source MUST pre-filter chunks by the audience of the user and of the agent:
a chunk is a candidate only when the user's tokens and projects admit it and the agent's
tokens and projects admit it (document, every ancestor container, required projects). The
authoritative decision of every candidate (decide()) MUST be kept. An index that ignores the
agent's audience stays correct but loses recall.

**R179 — Decision cache.** An implementation MAY cache allow verdicts of a read-only
evaluation in process. It MUST be off unless configured. A cached verdict MUST be keyed at
least by tenant, tenant epoch, policy digest, subject, agent, grant, resource, action, purpose,
destination and the audited operation (so two listeners never share entries) and, when an
external risk provider is configured, the levels it reports now for the user and the agent
(an unanswered provider bypasses the cache). It MUST NOT outlive the configured TTL (at most
300000 ms, the context lifetime), the earliest expiry of any grant, heartbeat deadline, access
window or session-scoped record it read, the close of a session of its run, or a change of the
tenant epoch, and MUST be read in the same transaction that reads the epoch. Every change that
can withdraw access MUST advance the epoch or be part of the key: role, group, actor,
constraint, destination, runtime profile, combination rule and settings changes, a raised
risk signal, quarantine, revocation and erasure advance the epoch; a heartbeat lapse and
expiries bound the entry; provider risk levels are in the key. A denial MUST NOT
be cached. A cached verdict MUST still be audited as a decision of its own. A supplemental
policy whose answers change without a new revision is bounded by the TTL only.

**R180 — Closed sets.** The reason codes `RELEASE_FILTER`, `SANITIZER`,
`VOLUME_EXCEEDED`, `APPROVAL_REQUIRED` (deferral) and `RETRIEVAL_DISABLED` (deferral) and the
obligation types `release_filter` and `approval_required` extend the closed sets of
the decision requirements (ADR-006). Implementations that verify audit entries or parse obligations MUST know them.

**R181 — Extensions only narrow.** Any component added behind these extension points
(filters, sanitizers, scoring, adaptive throttling) MUST only add restrictions: it can
redact, clean, deny or slow a request down, and it can never authorize, widen a projection,
raise a clearance or lower a classification. An implementation MUST validate what such a
component returns and treat what it cannot validate as a denial.

## Knowledge semantics and content encryption (R182–R196)

Merged from [0.6-knowledge](drafts/0.6-knowledge.md). Every requirement only adds conditions or computes attributes: nothing that 0.5 denied becomes an allow (R196).
Decision: [ADR-022](../governance/ADR-022-knowledge-semantics.md).
Vectors: `conformance/vectors-0.6-knowledge.json` (profile `AKAC-Knowledge/0.6-draft`).

References: ISO 3166-1 (country codes, alpha-2); Regulation (EU) 2016/679 (GDPR),
Article 17 (right to erasure) and its paragraph 3 exemptions, point (e) (legal
claims); NIST SP 800-38D (GCM); D. E. Bell and L. J. LaPadula, *Secure Computer
Systems: Unified Exposition and Multics Interpretation* (MITRE, 1976); K. J. Biba,
*Integrity Considerations for Secure Computer Systems* (MITRE, 1977); D. F. C. Brewer
and M. J. Nash, *The Chinese Wall Security Policy* (IEEE Symposium on Security and
Privacy, 1989). The references explain the models; AKAC claims no formal equivalence.

### Terms

The *closure* of a record is the record, its container chain (R27) and, transitively,
every source it references (R25) with their container chains, bounded as in R25
(nodes, edges, path; a cycle cannot be established). The *generation* of a record is
0 when it has no sources, else 1 plus the highest generation of its sources. A *run*
is one grant (binding); its *accumulated sources* are the sources of every context
of the run.

### Lineage

**R182 — Derivation depth.** A tenant MAY set `lineageDepth` (1 to 127, default
16) in its settings. A derivation whose result would have a generation above the
limit MUST be denied (`LINEAGE_DEPTH`). A malformed limit MUST deny (deferred). The
limit never exceeds the traversal bound of R25 (128 nodes). Raising the limit is a
relaxation and passes the approval gate of the tenant settings (R156).

**R183 — Modality is descriptive.** A record MAY carry `modality` (`text`,
`image`, `audio`, `video`, `table`, `code`, `other`). Modality MUST NOT influence any
decision. A derivation MUST inherit classification, projects, audience, tags,
residency and retention of its closure whatever the modality of its sources and of
its result: an image derived from restricted text is restricted, and text derived
from a restricted image is restricted. A caller MAY state the modality of what it
derives; an unknown modality is refused (`INVALID_REQUEST`).

**R184 — Consolidation.** The only way to start a new lineage from derived
knowledge is an administrative document: a `kb-admin` ingests a `human` or `system`
document (R50 scanning applies) whose label the administrator sets. A document
with sources continues their generation and MUST carry at least their transitive
classification (R25). Model output never becomes a root by itself.

**R185 — Cycles.** A record whose closure contains a provenance cycle (including
a self-reference) MUST be invisible to every gate, and so MUST every record derived
from it; a derivation over it cannot be established (deferred denial). Bounded
traversal (R25) is the evaluation budget: a cycle is detected, never followed.

### Attributes

**R186 — Tags.** Records and containers MAY carry `tags` (at most 32 distinct
identifiers). The *effective tags* of a record are the union over its closure. Tags
MUST NOT grant anything; they are read by combination rules (R188) and passed to
the supplemental policy (R189). A derived record MUST store the effective tags
of its sources (more than 32: deferred `BUDGET_EXCEEDED`). Removing a tag from a
document version is a label widening (R15, R126). A malformed tag list anywhere
in a closure MUST make that closure unestablished (deny).

**R187 — Residency.** Records and containers MAY carry `residency`: 0 to 32
residency codes (ISO 3166-1 alpha-2 or operator-defined region codes of the form
`[A-Z][A-Z0-9-]{1,15}`, compared exactly; AKAC does not expand regions). Destination
profiles MAY carry one `region`. The *effective residency* of a record is the
intersection of every residency set in its closure; it is *unset* when no member of
the closure sets one (0.5 behaviour). A share or export (release, the provider gate of
a protected runtime, and the read-only evaluation of a share/export) of content whose
combined effective residency is set MUST be denied (`RESIDENCY`) unless its recipient
is governed by an active Destination profile of the tenant whose `region` is in that
set: an implicit user, a principal without a profile, a profile without a region and
an empty set receive nothing. The check follows the destination gate (R62–R66),
so `RECIPIENT` keeps precedence. A derived record MUST store the effective residency
of its sources. Dropping or widening the residency of a document version, and adding
or changing the region of a destination, are widenings that need the approval of
R153. Reads and derivations are processing inside the gateway and are not
residency-checked; the location of the gateway itself is an operator obligation.

**R188 — Combination rules.** A tenant MAY hold up to 256 combination rules
`{id, tagsA, tagsB, effect, upliftTo?, active}` (Brewer-Nash style separation and
aggregation). A rule *matches* a set of tags when the set contains a tag of `tagsA`
and a tag of `tagsB`. Over the effective tags of a run's accumulated sources plus the
records of the operation:

- an active `deny` rule that matches MUST deny opening the context and deriving
  (`COMBINATION`); a read-only evaluation of a single record whose closure matches is
  denied likewise;
- an active `uplift` rule that matches MUST raise the classification of what the run
  derives to at least `upliftTo`, or one level above the classification it would
  otherwise have (never above `restricted`). It never lowers.

A disclosure (opening a context, retrieval) MUST also count every record the same user
and agent read under any other grant in contexts alive during the combination window
(default and minimum: the maximum context lifetime, 300 000 ms; operator-configurable up
to 30 days), so that a forbidden combination split across grants or credentials of the
same pair is still refused. A context that expired more than one window ago no longer
counts; records that no longer exist do not count. The read-only evaluation (AuthZEN)
checks the single record only. Two different agents of one user are two pairs: rules
spanning agents belong in the supplemental policy.

A malformed rule of the tenant, or more than 256, MUST deny (deferred). Rules are
loaded with every decision closure; a rule change advances the tenant epoch; relaxing
a rule (deactivation, a tag removed, deny to uplift, a lower uplift) passes the approval
gate. Policy packs that need more (conflict classes, history across runs) belong in
the supplemental policy (R189), which can only narrow.

**R189 — Attributes for the supplemental policy.** The input of the
supplemental policy MUST carry, besides action, tenant, classification and purpose,
the effective `tags` of the resource, its effective `residency` when set, and
`sources`: the ids of every record the operation of the run reads. A policy
implementation MUST NOT treat an absent attribute as a permission; existing policies
that ignore them keep their meaning.

### Derivation and placement

**R190 — Session-scoped knowledge.** A derivation MAY request a session
(`session: {id, ttlMs?}`, 1 s to 24 h, default 1 h). Its result is *ephemeral*:
`{sessionId, run, expiresAt}` with `run` the grant and `expiresAt` the earliest of the
requested lifetime, the run's expiry and the expiry of every ephemeral record in its
closure. A derivation whose closure contains an ephemeral record MUST itself be
ephemeral in the same session; two sessions in one derivation, or an ephemeral record
of another run, MUST be refused (`OUT_OF_SCOPE`). An ephemeral record:

- MUST be visible only to decisions of its own run and only before `expiresAt` (a
  malformed scope hides it); records derived from it are hidden with it;
- MUST NOT be written to a persistent store or a vector index: implementations keep it
  in process memory, so it is gone after a restart, and a store MUST refuse to persist
  one;
- MUST be removed when the run closes its session (`DELETE /v1/sessions/{id}`, the
  credential's own run only, audited `session_close`) and at its expiry. A decision
  cache MUST NOT serve an allow past the expiry of any ephemeral record the verdict
  read, and closing a session MUST evict the run's cached allows (R179).

An implementation with several gateway instances does not share ephemeral records: a
session lives on the instance that holds it. Bounds: 1 000 records per session and
10 000 per tenant (deferred `BUDGET_EXCEEDED` beyond).

**R191 — Model lineage.** A derived record MAY carry `model {id, version}`. It MUST
come only from a trusted path (operator configuration of the gateway, or an
in-process trusted runtime), never from agent request data. A security-admin MUST be
able to quarantine every record of a model within an inclusive version range (reason
`model_recall`, numeric-aware version order), in bounded audited batches, followed by
the sweep of their lineage (R193).

**R192 — No write-down on placement.** A derivation MAY place its result into a
container (`container`). The run MUST name the container in its grant resources (or
`*`), every container of its chain MUST be active (`OUT_OF_SCOPE` otherwise), and the
placement MUST be denied (`WRITE_DOWN`) unless the *static* label of the placed record
admits no principal that the static label of a source does not admit. Precisely: for
every source S and every audience clause c of S's effective label (its own reader list
and reader roles, and each of its ancestor containers'), the placed record MUST have a
clause d (its own inherited ACL or one of the target chain's) whose readers and reader
roles are subsets of c's, and its classification and projects MUST be at least S's.
This keeps a placement correct even for an evaluator that reads labels without
traversing provenance. Integrity (Biba): derived content is always `origin: model` and
never becomes human or system content (R184), so a derivation never raises
integrity; a quarantined source hides it (R46).

### Lifecycle

**R193 — Cascade sweep.** Denial of descendants stays lazy and authoritative
(R46). An implementation SHOULD sweep the lineage of a record that was revoked,
erased, quarantined or relabelled upward: descendants not yet in a lifecycle state are
quarantined (`poisoned` below a record quarantined as poisoned or suspected poisoned,
otherwise `ancestor_revoked`); after an upward relabel, descendants whose stored
classification is below their transitive classification are raised to it; affected
documents are removed from or re-checked against the vector index. The sweep MUST run
in bounded batches (at most 100 records per audited transaction, at most 8 192
descendants listed), resume by id, advance the epoch when it changed anything, and run
under a job lock shared by every instance. A quarantine set by the sweep is lifted
only by a security-admin release of that record.

**R194 — Erasure under legal hold.** An erasure request (with cascade) blocked by a
legal hold on the record or its lineage MUST NOT erase anything and MUST be stored as
pending (`erasureRequestedAt`, audited) and answered `CONFLICT` with `pending: true`
(HTTP 409) and the number of held records. A pending erasure MUST run automatically
(audited `pending_erase`) once no hold blocks it (the pending-erasure job, triggered
by lifting a hold, by the administrative endpoint or on a schedule). The pending marker
survives new versions and is cleared by the erasure. Rationale: Article 17(3)(e) GDPR
exempts processing necessary for the establishment, exercise or defence of legal
claims from the right to erasure; whether an exemption applies is a legal
determination outside AKAC, which only records the hold and the request.

**R195 — Content encryption and crypto-shredding.** A deployment MAY seal every
stored record content with AES-256-GCM under a fresh 256-bit content key per record
version, wrapped by a key provider under key material that belongs to that record
only; the associated data MUST bind tenant, record id and version. Erasing a record
MUST then destroy that key material after the erasure committed, so that copies of the
ciphertext (backups) become unreadable; a failed destruction MUST be retried and
reported. Content whose key the provider reports as destroyed MUST be treated as erased
by every gate. Content that cannot be opened for any other reason (the key service is
unavailable, the envelope is malformed or tampered) is *unreadable*: every gate MUST hide
the record and everything derived from it (a decision on it defers, `STORE_ERROR`), and
the implementation MUST NOT tombstone, shred, overwrite or otherwise write such a record:
an operation that would change it MUST fail as a deferred store error and change nothing.
Rationale: an outage is never to be mistaken for an erasure (a legal hold would be lost
and the key destroyed). The unreadable marker is internal and never persisted. The
community edition ships a local development provider only; production deployments
use a KMS or HSM provider (an extension). Labels, audience and provenance stay in the
clear. Chunk text is never stored; embeddings of restricted content are protected
data and their storage MUST be encrypted at rest by the operator (volume or database
encryption and encrypted backups). Off by default.

### Monotonicity

**R196 — Restrictions only restrict.** Adding a tag to a record or container,
setting or narrowing a residency, adding or activating a combination rule, narrowing a
container audience, lowering the depth limit or adding a risk cap MUST NOT turn any
denied decision or operation into an allow, with one intended exception: narrowing the
audience of the *target* container of a placement can make that placement admissible
under R192, because the placed record then admits fewer principals; no principal
gains access to anything. The property is tested by randomized property tests
(`tests/knowledge-monotonicity.test.ts`, which checks the exception is the only one
observed) and holds structurally: every rule above is an additional condition
evaluated after the 0.5 gates allowed.

### Not covered

Region hierarchies (a region code that implies others), jurisdiction-aware routing,
history-based Chinese walls across runs, conflict-of-interest classes, exposure
reports built from audit, and KMS/HSM key providers are left to extensions (policy
packs, providers) that can only narrow. Deterministic or searchable encryption of
metadata is not provided (equality leakage).

## Errata and closing notes

Corrections of published text made together with this revision (no change in meaning)
are logged in [ERRATA.md](ERRATA.md) as E-0001 to E-0005. New reason codes of this
revision: `RELEASE_FILTER`, `SANITIZER`, `VOLUME_EXCEEDED`, `APPROVAL_REQUIRED`
(deferral), `RETRIEVAL_DISABLED` (deferral), `RISK_CAP`, `LINEAGE_DEPTH`,
`RESIDENCY`, `COMBINATION`, `WRITE_DOWN`; new obligation types:
`release_filter`, `approval_required` (R180). Public responses stay
non-distinguishing (R35).

See the [migration notes](../docs/MIGRATION-0.6.md), [conformance](CONFORMANCE.md) and
the [changelog](../CHANGELOG.md).

## Draft identifier mapping

| Draft id | Requirement | Draft file |
|---|---|---|
| R-FIND-1 | R121 | [0.6-findings](drafts/0.6-findings.md) |
| R-FIND-2 | R122 | [0.6-findings](drafts/0.6-findings.md) |
| R-FIND-3 | R123 | [0.6-findings](drafts/0.6-findings.md) |
| R-FIND-4 | R124 | [0.6-findings](drafts/0.6-findings.md) |
| R-FIND-5 | R125 | [0.6-findings](drafts/0.6-findings.md) |
| R-FIND-6 | R126 | [0.6-findings](drafts/0.6-findings.md) |
| R-CONF-1 | R127 | [0.6-conformance](drafts/0.6-conformance.md) |
| R-CONF-2 | R128 | [0.6-conformance](drafts/0.6-conformance.md) |
| R-CONF-3 | R129 | [0.6-conformance](drafts/0.6-conformance.md) |
| R-CONF-4 | R130 | [0.6-conformance](drafts/0.6-conformance.md) |
| R-CONF-5 | R131 | [0.6-conformance](drafts/0.6-conformance.md) |
| R-FORMAL-1 | R132 | [0.6-formal](drafts/0.6-formal.md) |
| R-FORMAL-2 | R133 | [0.6-formal](drafts/0.6-formal.md) |
| R-FORMAL-3 | R134 | [0.6-formal](drafts/0.6-formal.md) |
| R-FORMAL-4 | R135 | [0.6-formal](drafts/0.6-formal.md) |
| R-OPS-1 | R136 | [0.6-operations](drafts/0.6-operations.md) |
| R-OPS-2 | R137 | [0.6-operations](drafts/0.6-operations.md) |
| R-OPS-3 | R138 | [0.6-operations](drafts/0.6-operations.md) |
| R-OPS-4 | R139 | [0.6-operations](drafts/0.6-operations.md) |
| R-OPS-5 | R140 | [0.6-operations](drafts/0.6-operations.md) |
| R-OPS-6 | R141 | [0.6-operations](drafts/0.6-operations.md) |
| R-OPS-7 | R142 | [0.6-operations](drafts/0.6-operations.md) |
| R-ID-1 | R143 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-2 | R144 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-3 | R145 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-4 | R146 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-5 | R147 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-6 | R148 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-7 | R149 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-8 | R150 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-9 | R151 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-10 | R152 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-11 | R153 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-12 | R154 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-13 | R155 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-14 | R156 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-15 | R157 | [0.6-identity](drafts/0.6-identity.md) |
| R-ID-16 | R158 | [0.6-identity](drafts/0.6-identity.md) |
| R-CRYPTO-1 | R159 | [0.6-crypto](drafts/0.6-crypto.md) |
| R-CRYPTO-2 | R160 | [0.6-crypto](drafts/0.6-crypto.md) |
| R-CRYPTO-3 | R161 | [0.6-crypto](drafts/0.6-crypto.md) |
| R-CRYPTO-4 | R162 | [0.6-crypto](drafts/0.6-crypto.md) |
| R-CRYPTO-5 | R163 | [0.6-crypto](drafts/0.6-crypto.md) |
| R-CRYPTO-6 | R164 | [0.6-crypto](drafts/0.6-crypto.md) |
| R-CRYPTO-7 | R165 | [0.6-crypto](drafts/0.6-crypto.md) |
| R-CRYPTO-8 | R166 | [0.6-crypto](drafts/0.6-crypto.md) |
| R-REL-1 | R167 | [0.6-release](drafts/0.6-release.md) |
| R-REL-2 | R168 | [0.6-release](drafts/0.6-release.md) |
| R-REL-3 | R169 | [0.6-release](drafts/0.6-release.md) |
| R-REL-4 | R170 | [0.6-release](drafts/0.6-release.md) |
| R-REL-5 | R171 | [0.6-release](drafts/0.6-release.md) |
| R-REL-6 | R172 | [0.6-release](drafts/0.6-release.md) |
| R-REL-7 | R173 | [0.6-release](drafts/0.6-release.md) |
| R-REL-8 | R174 | [0.6-release](drafts/0.6-release.md) |
| R-REL-9 | R175 | [0.6-release](drafts/0.6-release.md) |
| R-REL-10 | R176 | [0.6-release](drafts/0.6-release.md) |
| R-REL-11 | R177 | [0.6-release](drafts/0.6-release.md) |
| R-REL-12 | R178 | [0.6-release](drafts/0.6-release.md) |
| R-REL-13 | R179 | [0.6-release](drafts/0.6-release.md) |
| R-REL-14 | R180 | [0.6-release](drafts/0.6-release.md) |
| R-REL-15 | R181 | [0.6-release](drafts/0.6-release.md) |
| R-KNOW-1 | R182 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-2 | R183 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-3 | R184 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-14 | R185 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-4 | R186 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-5 | R187 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-6 | R188 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-12 | R189 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-7 | R190 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-8 | R191 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-9 | R192 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-10 | R193 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-11 | R194 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-13 | R195 | [0.6-knowledge](drafts/0.6-knowledge.md) |
| R-KNOW-15 | R196 | [0.6-knowledge](drafts/0.6-knowledge.md) |
