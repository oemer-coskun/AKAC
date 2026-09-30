# Editions

**Community edition (this repository, MIT-0).** Decision semantics, the reference gateway, the conformance suite and the
extension points. Anything that determines a security decision stays open and auditable here.

The extension points are hooks. A hook can only narrow a decision, never widen it, and a missing or failing hook denies
(fail closed). Every feature a security class requires is testable in this repository. Decision record:
[ADR-023](../governance/ADR-023-editions-and-extension-points.md).

**Full package.** Adds hook implementations and the items listed under "Full package" in the [README](../README.md#full-package).
It never changes decision semantics.

Inquiries: [CONTACT.md](../CONTACT.md).
