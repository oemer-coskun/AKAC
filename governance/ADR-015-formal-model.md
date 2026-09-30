# ADR 015: bounded formal model of the core authorization semantics

Status: proposed for AKAC 0.6 (draft). No external review has taken place. Model:
[formal/AKAC.tla](../formal/AKAC.tla). Guide and results:
[docs/FORMAL-MODEL.md](../docs/FORMAL-MODEL.md). Draft requirements:
[AKAC 0.6](../spec/AKAC-0.6.md). Workflow:
`.github/workflows/formal.yml`.

## Context

AKAC's safety arguments (delegation only narrows, derivation never lowers a label, a
revoked or quarantined source discloses nothing downstream, tenants never mix, SoD holds,
a release reaches only an admitted recipient, label widening is a declassification) were
supported by example-based tests, conformance vectors, property tests over generated
inputs and differential fuzzing. None of these explores every interleaving of delegation,
context capture, derivation and administrative change. The roadmap asked for a model of
`decide()`, delegation narrowing, derivation label inheritance, revocation epochs and the
release gate, with the three central invariants checked.

## Decision

1. **TLA+ and TLC.** A TLA+ specification checked by the explicit-state model checker TLC
   (tla2tools v1.7.4, the latest non-prerelease `tlaplus/tlaplus` release, pinned by a
   SHA-256 computed from the release download because the release publishes no digest).
   TLA+ was chosen over Alloy because the properties are about reachable states of an
   interleaved system (contexts opened before an epoch advance, derivations after a
   delegation), which TLC explores exhaustively within bounds.
2. **Operational and declarative parts in one module.** The operational part mirrors
   `reference/policy.ts`, `engine.ts` and `control.ts`. Each property is stated
   declaratively, with its own closures (grant chains, lineages, role closures computed
   as fixpoints over the state) and raw tenant equality, and quantifies over every request
   of the finite universe in every reachable state, so it is not a restatement of the
   operator it checks.
3. **Seven properties.** NoEscalationThroughDelegation, NoDeclassificationThroughDerivation,
   RevokedOrQuarantinedSourceNoDisclosure, TenantIsolation, SeparationOfDuty,
   ReleaseRecipientCheck (state invariants) and LabelWideningRequiresSecurityAdmin (an
   action property, using a semantic definition of widening: some conceivable principal
   is admitted by the new label and not by the old).
4. **The properties must bite.** Each property has at least one broken-model configuration
   (`formal/broken/`) that switches in one mutated rule; CI fails unless TLC reports that
   specific property violated. Non-vacuity configurations (`formal/witness/`) require TLC
   to reach an external release, an allow through a depth-2 delegation, derivation from
   derived knowledge, a read of derived knowledge and a security-admin widening.
5. **Two faithful bounds.** `MC.cfg` (a depth-2 delegation chain, one administrative
   change, one context, one derived record) and `MC_admin.cfg` (no delegation, two
   administrative changes, two contexts, two derived records). Both MUST hold. Splitting
   keeps each run within minutes on a hosted runner; interleavings of delegation with two
   administrative changes, or with derivation from derived knowledge, are not checked.
6. **Model is not code.** Agreement between the model and the TypeScript reference is
   argued by review and exercised by the conformance vectors and tests listed in the
   traceability table of docs/FORMAL-MODEL.md; it is not proven. The model is informative:
   where it and the normative specification differ, the specification wins and the model
   is corrected.

## Consequences

- A semantic change ([GOVERNANCE.md](../GOVERNANCE.md)) now also reviews the model: when a rule of `decide()`,
  delegation, derivation, lifecycle, release or relabelling changes, the model and, where
  needed, a broken configuration change with it, and the workflow must pass.
- Results are bounded model checking. They show that no counterexample exists within the
  stated universe and depth; they do not show absence of counterexamples for larger
  universes, for the unmodelled features listed in docs/FORMAL-MODEL.md, or for the
  implementation.
- The TLC run adds a separate workflow (`contents: read`, actions pinned by SHA, JDK from
  `actions/setup-java`, the jar verified by SHA-256 before use). It runs on changes under
  `formal/` and on demand, not on every code change, because the model does not read code.
- While building the model, TLC's action-level evaluation treated disjunctions inside
  guards as branches and produced many identical successor states; guards are wrapped in
  `Holds(P) == P = TRUE`. This is a performance measure of the checker and changes no
  result.

## Alternatives considered

- **Alloy.** Good for relational structure (grant trees, lineages) but bounded traces of
  interleaved operations are more natural in TLA+.
- **Proof (TLAPS, Coq, Lean).** Unbounded results, but a large effort for a draft
  specification that still changes; may follow once the semantics stabilise.
- **Model extracted from the code.** Would narrow the model-code gap but tie the model to
  implementation details; the declarative properties are meant to hold for any conforming
  implementation.
