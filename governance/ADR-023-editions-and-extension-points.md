# ADR 023: editions and the extension-point contract

Status: proposed for AKAC 0.6 (draft). No external review has taken place.
Related: [AKAC 0.6](../spec/AKAC-0.6.md) (R181 and the section "Extension points only
narrow"), [EDITIONS.md](../docs/EDITIONS.md), the public security-class matrix,
[ADR-010](ADR-010-optional-module-boundary.md) (the same boundary rule for optional modules).

## Context

0.6 adds several places where behaviour can be supplied from outside the core: release
filters and derive sanitizers (R167–R171), an external risk provider (R151, R152), an
external approval gate (R153–R155), checkpoint signers backed by a key service (R140,
R164), content key providers for crypto-shredding (R195) and the supplemental policy
(R189, and R13 since 0.1). Some implementations of these hooks are substantial pieces of
work in their own right (key-service providers, detection heuristics, connectors to
identity and security tooling) and may be offered separately from this repository.

AKAC is a security standard with a reference implementation. Its value to an auditor, an
implementer of a second implementation or a buyer depends on one property: everything
that determines whether a request is allowed can be read, tested and reimplemented from
public material. If a separately offered component could change decision semantics, a
conformance result obtained with the public vectors would say nothing about a deployment
that uses it, and the specification would no longer describe the product.

## Decision

1. **Two editions, one semantics.** The *community edition* is this repository, under
   MIT-0: the specification, the schemas and OpenAPI documents, the portable conformance
   vectors, the reference gateway with every decision rule, the second implementation,
   the formal model, every extension point as a typed interface with a documented
   default, and development providers for them (for example a local content key
   provider and a Vault Transit checkpoint signer example). Separately offered
   implementation packages can fill the public extension points and provide adoption
   services. Their inventory, implementation details and delivery terms are not
   published here. They have no decision semantics of their own.
2. **Hooks can only narrow.** An extension point MAY deny, redact, clean, add an
   obligation, raise a label, lower a clearance, slow a caller down or require an extra
   approval. It MUST NOT allow what the core denies, widen a projection, relabel
   downward, extend a grant or change an identity (R181). What an implementation returns
   is validated by the core; what cannot be validated, an error, a timeout or an absent
   implementation that the configuration requires, denies (R168). The default of every
   hook is the secure behaviour of the community edition: no filter configured means
   nothing is filtered but nothing is widened either; a required filter that is not
   configured denies (R169); the default approval quorum is one standing
   `security-admin` and two for break-glass (R153).
3. **The core never imports an enterprise component.** Dependencies point one way:
   enterprise code depends on the public core interfaces, never the reverse. No core
   module, script or package dependency names an enterprise module; nothing in this
   repository requires a licence key or a call to a vendor service. `tests/boundary.test.ts`
   checks the module specifiers of the core sources and the dependencies of
   `package.json`, as it does for optional modules (ADR-010).
4. **Semantics first, in public.** A behaviour that changes whether a request is
   allowed is specified, implemented and tested in the community edition first, with an
   ADR and conformance vectors, under [CHANGE-CONTROL.md](../spec/CHANGE-CONTROL.md). An
   extension point is added the same way: its contract, its fail-closed default and its
   validation are part of the specification.
5. **Same vectors.** A build that includes enterprise components MUST pass the same
   public vectors with the same results. No conformance claim rests on private vectors.
6. **Every security class is reachable in the community edition.** The mechanisms that
   the security classes of [SECURITY-CLASSES.md](../docs/profiles/SECURITY-CLASSES.md)
   require exist in the community edition as semantics or as hooks with a documented
   contract. Where a class needs a production implementation of a hook (for example an
   HSM signer for the hybrid post-quantum checkpoints of SK-4), an operator can write it
   against the public contract; without it the deployment fails closed at start-up
   instead of running weaker.

## Rationale

Auditability of a security standard. A reviewer has to be able to answer "can this
component make the system allow more than the specification says?" without access to
the component. Under this contract the answer is structural: no, because the core
evaluates every rule first, validates every hook result and denies on anything it cannot
validate, and because nothing outside the public code can reach the decision path except
through those hooks. Separating semantics (open) from implementations of narrowing hooks
(which may be offered separately) keeps the conformance vectors, the formal model and the
second implementation meaningful for every deployment.

## Consequences

- The community edition carries more interface and default code than a closed product
  would, and every new hook needs specification text, vectors and a fail-closed default
  before it ships.
- An enterprise component cannot fix a semantic gap; a gap is fixed in the public core.
- Operators can replace any enterprise component with their own implementation of the
  same hook, with the same guarantees.
- The boundary is checked by a test only for the import direction; the narrowing
  property is checked by the conformance vectors, the hook tests (`release-hooks.test.ts`,
  `identity.test.ts`, `crypto-agility.test.ts`, `knowledge.test.ts`) and the
  monotonicity property tests.

## Alternatives considered

- *Everything in one open repository, including detection heuristics and connectors.*
  Rejected for the scope of this repository: heuristics and connectors change often,
  depend on third-party products and would make the conformance surface depend on them.
  They do not affect decision semantics, so keeping them outside costs no auditability.
- *Enterprise components allowed to extend semantics behind a feature flag.* Rejected:
  the public vectors would no longer describe the deployment, and a flag is not an
  audit boundary.
