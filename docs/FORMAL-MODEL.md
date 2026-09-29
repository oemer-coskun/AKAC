# Formal model (TLA+)

A bounded TLA+ model of AKAC's core authorization semantics, checked with the TLC model
checker. Decision: [ADR-015](../governance/ADR-015-formal-model.md). Draft requirements:
[AKAC 0.6](../spec/AKAC-0.6.md). Files: [formal/](../formal/).

What this is: exhaustive exploration of every behaviour of a small, finite AKAC world,
checking seven safety properties in every reachable state. What it is not: a proof for
unbounded systems, and not verification of the TypeScript reference. The model is written
from `reference/policy.ts`, `engine.ts`, `control.ts` and `lifecycle.ts` and the
specification; that it matches them is argued by review and exercised by the conformance
vectors and tests in the [traceability table](#traceability), not proven.

## Running it

Requirements: Java 11 or later and `tla2tools.jar` v1.7.4
(`https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar`, SHA-256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`; the release publishes no
digest, this one was computed from the release download and is the pin CI verifies).

```sh
export TLA2TOOLS=/path/to/tla2tools.jar
bash formal/check.sh                 # every configuration
bash formal/check.sh MC.cfg          # one configuration (paths relative to formal/)
TLC_WORKERS=4 bash formal/check.sh   # worker threads (default: auto)
```

`check.sh` exits non-zero when a faithful configuration reports any violation or error, or
when a broken or witness configuration does not report the violation it names. CI runs it in
`.github/workflows/formal.yml` (three parallel jobs).

## Model

One module, [formal/AKAC.tla](../formal/AKAC.tla), in two parts.

**Operational part** (mirrors the reference):

| Model operator / action | Reference |
|---|---|
| `EffRoles`, `CloseRoles`, `Session`, `SessionValid`, `Violates` | `effectiveRoles`, `closeRoles`, `sessionRoles`, `sodViolated` |
| `GrantValid`, `Attenuates` | `grantValid` (liveness, expiry, attenuation of actions, resources, purposes, expiry, activeRoles, destinations, maxResults, recursively) |
| `Visible`, `Audience`, `EffCls`, `TransCls` | `visible` (record, container, every transitive source at its bound version), `audience`, `effectiveLabel`, `transitiveClassification` |
| `Decide` = `Scope` ∧ `Core` | `decide` / `evaluate` (allow/deny only; reason codes are not modelled) |
| `OpenContext`, `Usable`, `Fresh` | `openContext` / `projection`, `contextSources`, `contextFresh` (epoch, expiry, source versions, same-binding contexts) |
| `Derive`, `DerivedRecord` | `derive` (highest transitive classification, union of projects and local ACLs, provenance = every source of the run) |
| `ReleaseOK`, `DestGate` | `release` (re-authorize share, recipient `visible` with standing roles, `destinationGate`) |
| `Delegate` | `engine.delegate` / `canDelegate` |
| `RevokeGrant`, `RevokeKnowledge`, `Quarantine`, `Unquarantine`, `Erase` | `ControlPlane.revoke`, `quarantine`, `release`, `erase` (cascade, tombstone per R125); each advances the tenant epoch |
| `Relabel`, `SynWidens` | `upsertKnowledge` of an existing document with unchanged content, `widensLabel` (R15, R126) |

**Declarative part**: the seven properties, each quantified over every request of the finite
universe in every reachable state. They use their own closures (grant chain, lineage and role
closure computed as fixpoints over the whole state), raw tenant equality instead of the
operational `SameTenant`, and a semantic definition of label widening (some conceivable
principal of `HypPrincipals` is admitted by the new label and not by the old one) instead of
`widensLabel`.

| # | Property | Kind | Statement (informal) |
|---|---|---|---|
| 1 | `NoEscalationThroughDelegation` | invariant | Every allowed (action, resource, purpose) under a grant is allowed by every grant of its chain, which is also live, unexpired and of the same subject; activated session roles stay within every activated ancestor; a release's destination class and a disclosure's document count are admitted by every grant of the chain. |
| 2 | `NoDeclassificationThroughDerivation` | invariant | A derived record with resolving provenance is classified at least as high as the effective classification of every lineage record and keeps their projects; any principal it admits is admitted by every lineage record and its container. |
| 3 | `RevokedOrQuarantinedSourceNoDisclosure` | invariant | No allowed decision (read, derive, share) and no release for a record whose lineage holds an inactive, quarantined or erased record; no context is fresh while a source lineage holds one (contexts opened earlier included, through the epoch). |
| 4 | `TenantIsolation` | invariant | Allowed decisions, contexts, derived provenance and releases never involve another tenant. |
| 5 | `SeparationOfDuty` | invariant | No allowed decision for a user or agent whose effective roles meet a static constraint, or whose session roles meet a dynamic one; session roles are held roles; no release to a recipient that meets a static constraint. |
| 6 | `ReleaseRecipientCheck` | invariant | A release is allowed only to a same-tenant recipient admitted by every record of every released lineage and its container, whose destination profile admits the highest effective classification and the purpose, and whose destination class every restricting grant of the chain admits. |
| 7 | `LabelWideningRequiresSecurityAdmin` | action property | Every accepted document version that semantically widens the label was written by an administrator holding `security-admin`. |

## Bounds

The universe (constants in the module):

| Element | Bound |
|---|---|
| Tenants | t1 (all activity), t2 (one user `v1`, one document `k3` whose ACL names t1 principals) |
| Principals | users `u1` (grant subject), `u2` (external Destination profile: max internal, purpose p1), `v1` (t2); agent `a1`; administrators `sec` (security-admin) and `kb` (kb-admin) |
| Classification | 3 levels (public, internal, confidential); the reference has 4 |
| Roles | `lead` (inherits `staff`), `staff`, `audit`; static SoD {lead, audit}, dynamic SoD {staff, audit}, both cardinality 2; one group granting `audit` |
| Initial worlds | u1 holds `staff` or `lead`, with or without the group; root grant A (read/derive/share, all resources, p1, unrestricted) or B (read/derive, k1 and k2, p1 and p2, restricted to internal-user, activated `staff`, maxResults 1, earlier expiry): 8 initial states |
| Knowledge | documents k1 (in container c1: floor internal, ACL u1 and a1), k2, k3; derived slots d1, d2 |
| Purposes, actions | p1, p2; read, derive, share (export behaves as share) |
| Delegation | a chain g1 ← g2 ← g3; each child is the parent with one field replaced (actions, resources, purposes, destinations, activeRoles, maxResults, expiry) from a small domain |
| Contexts | up to 2, each requesting 1 or 2 records |
| Time | one tick (0 → 1); grants expire at 1 or 2 |
| Administration | revoke grant, revoke / quarantine / release / erase a document, relabel k1 or k2 (one field: classification ±1, reader u2, role audit, project pa) by either administrator; each advances the epoch, at most `MaxEpoch` times |

Configurations of the faithful model (`Mutation = "none"`); both MUST hold:

| Config | Delegations | Admin changes | Contexts | Derived | Purpose |
|---|---|---|---|---|---|
| `MC.cfg` | 2 (depth-2 chain) | 1 | 1 | 1 | delegation with release, derivation and one revocation, quarantine, erasure or relabel |
| `MC_admin.cfg` | 0 | 2 | 2 | 2 | derivation chains (derived from derived), two administrative changes, stale contexts |

## Results

Local run, 2026-09-29, TLC 2.19 (tla2tools v1.7.4), Temurin JDK 21, 4 worker threads on a
shared, heavily loaded Windows workstation (times are indicative; hosted runners differ):

| Config | Result | Distinct states | States generated | Search depth | Wall time |
|---|---|---|---|---|---|
| `MC.cfg` | no violation | 132,200 | 247,846 | 7 | 3 min 45 s |
| `MC_admin.cfg` | no violation | 245,340 | 459,516 | 8 | 4 min 25 s |
| 8 broken configs | each reports its property violated | from the initial states (NoTenantCheck, DynSoDOnlyActivated) up to 1,403 | | | 2 to 4 s each |
| 5 witness configs | each reports its predicate violated | up to 419 | | | 2 to 5 s each |

Hosted CI results are recorded in [VERIFICATION.md](VERIFICATION.md) once the workflow has run.

### Broken models

Each configuration in `formal/broken/` switches in one mutated rule and lists only the
property it must break; TLC MUST report that property violated.

| Config (`Mutation`) | Mutated rule | Property that must fail |
|---|---|---|
| `NoPurposeAttenuation` | `grantValid` no longer requires child purposes ⊆ parent purposes | NoEscalationThroughDelegation |
| `DeriveOwnMinLabel` | `derive` labels with the lowest own source classification (no container floor, no transitive sources) | NoDeclassificationThroughDerivation |
| `LifecycleNotTransitive` | `visible` checks the lifecycle of the requested record only | RevokedOrQuarantinedSourceNoDisclosure |
| `QuarantineNoEpoch` | quarantine does not advance the tenant epoch | RevokedOrQuarantinedSourceNoDisclosure |
| `NoTenantCheck` | every tenant comparison of the decision path is dropped | TenantIsolation |
| `DynSoDOnlyActivated` | dynamic SoD is checked only for grants with explicit `activeRoles` | SeparationOfDuty |
| `ReleaseShallowRecipient` | `release` checks the recipient against the direct sources' own labels only (no container, no transitive sources) | ReleaseRecipientCheck |
| `KbAdminMayWiden` | a kb-admin may publish a label-widening version (the 0.5 behaviour) | LabelWideningRequiresSecurityAdmin |

### Non-vacuity witnesses

An invariant over allowed decisions holds trivially if nothing is ever allowed. Each
configuration in `formal/witness/` asserts that something never happens; TLC MUST find a
behaviour where it does: a release to the external colleague `u2`, an allow under the depth-2
grant `g3`, a derived record whose source is derived, a read of a derived record, and a
security-admin widening.

## What the results do and do not show

They show: in every state reachable within the bounds above, for every request over the finite
universe, the seven properties hold for the faithful model, and each property detects at least
one realistic defect in the rule it protects.

They do not show:

- **Anything beyond the bounds.** More principals, levels, roles, grants, derivation depth or
  administrative changes are not explored; the configurations do not combine two delegations
  with two administrative changes.
- **Anything about the code.** The model is hand-written. A defect in `reference/*.ts` that the
  model does not share is not found by TLC; the conformance vectors, tests, property tests and
  differential fuzzing remain the evidence for the implementation.
- **Unmodelled features**: supplemental policy (OPA) and obligations (they can only narrow an
  allow, R36/R37), runtime containment (R109–R119), retrieval and indexing (they re-authorize
  through the same decision, R26), the AuthZEN facade and read-only `evaluate` (R121),
  `write_memory` and memory review (R51), `declassify` (always denied), destination ids (only
  classes; one profile), inactive or unknown profiles, access expiry (R20), retention and legal
  hold (R55–R57), `reinstate`, `revokeLineage`, `removeKnowledge`, actor revocation, changes to
  roles, groups, constraints or containers during a behaviour, label widening through container
  change, access-expiry extension or dropped sources, malformed input and the traversal and
  budget bounds (their fail-closed branches), audit and evidence, storage, concurrency beyond
  interleaving (each action is atomic, as a tenant transaction is), and the other tenant's
  epoch (t2 has no administrative activity).
- **Reason codes.** The model decides allow or deny only; `Decide` orders its conjuncts for
  checking speed, which would change only the reported reason.

## Traceability

Requirement ids are those of the numbered specifications (R-LIFE-n and R-DEST-n of the 0.4
drafts are R45–R59 and R60–R71). Vectors are in `conformance/`; tests in `tests/`.

| Property | Requirements | Conformance vectors | Tests | Broken config |
|---|---|---|---|---|
| NoEscalationThroughDelegation | R04, R05, R24 (activation narrowing), R63, R65, R68, R69 | AKAC-006-expiry, AKAC-007-purpose, KB-015-child-widens-activation, KB-016-child-narrows-activation, DST-D02 to DST-D07, DST-D11, RT-020, RT-021, RT-022, RT-024 | `core.test.ts` "delegation attenuates and respects parent revocation", "delegation cannot extend lifetime"; `destinations.test.ts` "child grants can only narrow destinations and the result limit" | NoPurposeAttenuation |
| NoDeclassificationThroughDerivation | R08, R09, R25 | AKAC-017-source-access-expired-transitive, KB-027-source-container-applies, DST-G17, RT-001 to RT-004, RT-030 | `core.test.ts` "mixed-source memory inherits restrictions and transitively blocks intern" | DeriveOwnMinLabel |
| RevokedOrQuarantinedSourceNoDisclosure | R11, R12, R28, R45, R46, R47, R49, R53, R54, R125 | AKAC-008-source-revoked, AKAC-009-source-stale, KB-030-context-current-epoch, KB-032-own-tenant-revocation, L02 to L06, L08, RT-012, RT-013, RT-050, RT-052 | `core.test.ts` "revocation invalidates contexts and derived knowledge", "changed source version invalidates a previous context"; `lifecycle.test.ts` "quarantined ancestor denies every descendant ...", "erase cascades to every descendant ...", "property: after erase(id), no gate discloses content of id or any descendant" | LifecycleNotTransitive, QuarantineNoEpoch |
| TenantIsolation | R03, R28, R60 | every vector tagged `cross-tenant` (hard gate 3 of spec/CONFORMANCE.md), among them AKAC-004-tenant, KB-004, KB-007, KB-023, KB-031, DST-G07, RT-060, RT-061, Z05, Z06, RTC-P19 | `core.test.ts` "recipient check blocks cross-agent and cross-tenant laundering" | NoTenantCheck |
| SeparationOfDuty | R22, R23, R24 | KB-008-ssd-direct, KB-009-ssd-via-group, KB-010-ssd-via-hierarchy, KB-011-dsd-all-roles-active, KB-012-dsd-activated-subset, KB-013-active-role-not-held, KB-014-active-role-excludes-needed | conformance runner over `vectors-0.3.json` | DynSoDOnlyActivated |
| ReleaseRecipientCheck | R10, R24 (recipient), R61, R62, R63 | DST-G01 to DST-G06, DST-G09 to DST-G13, RT-061 | `core.test.ts` "recipient check blocks cross-agent and cross-tenant laundering"; `destinations.test.ts` "a run restricted to internal-user cannot release to a provider, a tool or a service without a profile", "property: a destination restriction or profile never turns a deny into an allow" | ReleaseShallowRecipient |
| LabelWideningRequiresSecurityAdmin | R15, R31, R126 | none (control-plane behaviour; no portable vector) | `regressions-0.6.test.ts` "a kb-admin cannot widen a document label through a new version", "narrowing versions stay kb-admin work; a security-admin alone may only relabel with unchanged content" | KbAdminMayWiden |

## Maintaining the model

A semantic change to a rule listed in the operational table (AGENTS.md: specification,
conformance evidence and an ADR) also updates the model: change the operator, keep or add a
broken configuration that shows the affected property still bites, and run `bash formal/check.sh`.
If a bound has to grow, record the new state counts and times here.
