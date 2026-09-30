# ADR 010: optional modules and the core boundary

Status: proposed for reference 0.4.0. No external review yet.

## Context

Useful extensions exist that the AKAC specification does not require and that build
on standards or methods of very different maturity: rank fusion for retrieval, policy
engines, provenance for images, human approval workflows, transparency exports, replay
of audited decisions. Some follow working-group drafts that may change. If they lived
in the core, every conformance claim would silently depend on them, their dependencies
and their changing upstream status, and a defect in an optional module could weaken an
invariant of the specification.

## Decision

1. **Optional modules are separate from the core.** They are self-contained and are not
   part of this repository; they are part of the full package ([EDITIONS.md](../docs/EDITIONS.md)).
2. **Not part of conformance.** No AKAC profile, requirement number or portable
   vector covers an optional module, and no conformance claim may mention one. The
   specification (`spec/`) does not reference them as requirements.
3. **One-way dependency.** Optional modules may import the public exports of
   `reference/` and `adapters/`. Core code (`reference/`, `adapters/`, `scripts/`)
   MUST NOT import from them, statically, dynamically or through `require`.
   `tests/boundary.test.ts` scans those directories and fails on any offending specifier.
4. **No authority.** An optional module cannot change identities, grants, labels or
   policy. Retrieval helpers only produce candidate hints that `decide()` re-checks;
   policy adapters can only narrow a decision; approval workflows and exports sit
   outside the decision function.

## Alternatives considered

- *Everything in core behind flags*: rejected; it enlarges the trusted computing base
  and the dependency set for users who need none of it.
- *Documenting extensions only*: rejected; unexecuted examples drift.

## Consequences

- A deployment can be conformant without any optional module.
- The boundary rule is enforced mechanically, but only for import specifiers; it does
  not sandbox anything at run time. A module that a deployer enables runs with the
  deployer's privileges and must be reviewed like any other dependency.
