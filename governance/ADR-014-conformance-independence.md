# ADR 014: conformance independent of the reference implementation

Status: proposed for AKAC 0.6 (draft); internal review only, no external review.
Requirements: [AKAC 0.6](../spec/AKAC-0.6.md) R127 to
R131. Implementer guide: [docs/IMPLEMENTATIONS.md](../docs/IMPLEMENTATIONS.md).

## Context

The review of 0.5.0 found that the Python decision evaluator had fallen behind
the specification: it ignored `lifecycle` (a quarantined record was allowed in
Python and denied in TypeScript), did not narrow `destinations` and `maxResults`
on delegation (R68), and rejected JSON `1.0` where the reference accepted it. The
TypeScript/Python comparison ran only `vectors.json` and `vectors-0.3.json`, so
none of this was caught. Every other vector file (evidence, lifecycle, AuthZEN,
destinations, runtime containment, red-team scenarios) needed the TypeScript
engine to set up its fixture, because the synthetic company existed only as code
in `examples/fixture.ts`.

A conformance suite that only the reference can run proves that the reference
agrees with itself.

## Decision

1. **The fixture is data** (R127). `examples/fixture.json`, validated by
   `schemas/fixture.json`, holds the synthetic company: base records, the
   knowledge-base extension (`extends`), and the grant times as clock offsets
   (`clockRelative`). `examples/fixture.ts` keeps its exports (`fixture`,
   `kbFixture`, `bindings`) and loads the JSON; the loaded states are identical to
   the 0.5 code fixture, including member order.
2. **A runner contract** (R129): one JSON case in, one JSON result out, over
   the complete state of the case. It covers the decision, the gateway operations
   with their obligations, the destination gate, runtime containment, AuthZEN
   mapping, red-team scenarios and the evidence functions, so every vector file
   has a language-neutral form.
3. **A second implementation at 0.5 parity.** `implementations/python/` is now a
   package (`akac`) with the decision function, the gateway decisions and
   obligations, the destination gate, runtime containment, the AuthZEN mapping,
   JCS, RFC 9162 proofs, audit hashes, and Ed25519 checkpoint verification behind
   an optional dependency. It reads JSON with the reference's value semantics
   (R128). It runs all vector files on its own
   (`python -m akac conformance`). The runtime enforcer protocol (13 vectors) is
   not a decision and is reported as not applicable.
4. **Differential testing on everything** (R130). Every vector file runs
   through both implementations and must give identical effect, code, category
   and obligations; a property-based comparison generates random worlds (tenants,
   role graphs, groups, SoD, container chains, derivation DAGs, delegation chains,
   lifecycle states, destinations, runtime policies and malformed members) and
   fails with the minimized case. It asserts that allows and every major reason
   code and obligation type occur, so agreement on denials alone cannot pass.

## Consequences

- A third party can run the shared vectors without Node.js: load the JSON fixture,
  apply patches, implement the runner contract (docs/IMPLEMENTATIONS.md).
- A semantic change now has to be made in both implementations, or the
  differential tests fail. That is the intended cost: the second implementation is
  an executable reading of the specification, and a disagreement is either a
  defect in one of them or an ambiguity in the text.
- CI needs Python 3.10+ (present on the hosted runners); the Python checks skip
  with a stated reason when no interpreter is found (`AKAC_PYTHON` selects one).
  The generated comparison adds about ten seconds.
- Both implementations are written by this project. The evidence is same-project
  differential evidence (R131); an implementation by an independent party is
  still outstanding and is the next step toward the roadmap's exit criterion.

## Alternatives considered

- **Keep the fixture in code and port it to each language.** Rejected: every
  port is a new place for the fixture to drift, which is how the Python evaluator
  fell behind.
- **Generate the second implementation from the reference (transpilation).**
  Rejected: it would share every reference defect by construction. The Python
  implementation is written by hand, but by the same project and against the
  reference behaviour, so it can still share a misreading of the text; only an
  independent implementation removes that.
- **Compare only vector outcomes (allow/deny).** Rejected: a wrong reason code or
  a missing obligation is a real divergence (an enforcement point acts on both).
