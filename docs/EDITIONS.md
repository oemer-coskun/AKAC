# Editions

**Community edition (this repository, MIT-0).** Decision semantics, the reference gateway, the conformance suite and the
extension points. Anything that determines a security decision stays open and auditable here.

The extension points are hooks. A hook can only narrow a decision, never widen it, and a missing or failing hook denies
(fail closed). Implemented Community mechanisms are testable in this repository; operator controls and production hook
implementations require deployment-specific evidence. Planned class requirements remain blockers. Decision record:
[ADR-023](../governance/ADR-023-editions-and-extension-points.md).

**Separately scoped packages and services.** May provide deployment-specific implementations and adoption assistance.
Availability, licensing, supported versions and deliverables are agreed directly. No private implementation inventory,
internal repository identifiers or proprietary operating recipes are published here. A separate component cannot widen
a core denial; its integration must respect the public extension contract. These offers do not change the MIT-0 rights
to material already released in this repository.

**Public scope.** Specifications, reference code, schemas, public hook contracts, synthetic examples, tests and evidence
remain available so the Community edition can be used, reviewed and independently implemented. Required integration
controls and known security limitations are not withheld. Publication rules:
[PUBLICATION-BOUNDARY.md](process/PUBLICATION-BOUNDARY.md).

Inquiries: [CONTACT.md](../CONTACT.md).
