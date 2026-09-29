# ADR 011: optional AuthZEN policy decision point facade

Status: proposed for reference 0.4.0 (amended: the duplicate decision code was replaced by `Engine.evaluate`). No external review yet.

## Context

Gateways, API managers and agent frameworks increasingly ask an external policy
decision point (PDP) "may this subject perform this action on this resource?". The
OpenID AuthZEN Authorization API 1.0 (Final, 11 January 2026) standardises that
question and its answer. AKAC already computes such a decision (`decide()`, R29) and,
since ADR-006, returns it as a structured decision with an identifier and obligations
that is deliberately shaped like AuthZEN's decision entity.

## Decision

1. **A separate optional listener** (`AKAC_AUTHZEN_PORT`, off by default, loopback by
   default). AuthZEN callers are enforcement points (trusted services), a third
   population next to agents (untrusted-model-adjacent) and administrators. Mounting the
   PDP on the agent listener would let agent credentials ask policy questions about
   arbitrary bindings; mounting it on the admin listener would grant PEPs administrator
   reach. A listener with its own credentials, audience, port, rate limits and
   NetworkPolicy keeps the populations separate.
2. **Tenant from the credential only.** PEP credentials map to `{tenant, pep}` by
   operator configuration. Requests can carry no tenant. Unknown request members are
   ignored, as AuthZEN 1.0 section 10.1.1 requires, and are therefore never able to
   influence identity.
3. **A fixed mapping profile** (`docs/AUTHZEN.md`): subject `user` or `agent` with the
   run grant in `properties`, resource `knowledge`, five actions, purpose in `context`.
   Anything else is `decision: false`. The mapping is lossless for the AKAC binding
   `{tenant, user, agent, grant}` and is covered by portable vectors.
4. **The same decision function.** The facade calls `Engine.evaluate()`, a read-only,
   audited engine method that hydrates one tenant snapshot, runs `decide()` and applies
   the supplemental policy and obligation derivation exactly like `openContext()`. It
   cannot open a context or read content, and it duplicates none of the engine's policy
   code. Parity tests compare its decisions with `decide()` and its obligations with
   `openContext()`. `context.destination` (optional, ADR-008) is passed through to
   the engine's destination checks (R62, R63, R67).
5. **Audit every evaluation**, content-free, with `decisionId` returned as
   `context.id`. This makes PEP decisions reconstructible from the tenant audit stream
   and provable with the Merkle evidence of ADR-006.
6. **Reasons hidden by default.** A PDP that explains denials to every PEP lets a
   compromised PEP probe policy (AuthZEN 1.0 section 11.2 warns of exactly this). The
   closed reason code is returned only with `AKAC_AUTHZEN_REASONS=admin`.
7. **Obligations as an AKAC extension** in `context.obligations`. AuthZEN 1.0 has no
   obligation member and the working-group obligations work is a draft. A PEP that
   cannot enforce the obligations must deny; this is stated normatively (R-AZ-9).
8. **Spec fidelity over convenience.** Where the AKAC brief and AuthZEN 1.0 differ,
   the specification wins: unknown members are ignored (not rejected), batch
   semantics follow section 7.1.2.1 (remaining evaluations omitted), an unknown
   semantic value is refused because the specification does not define it, and
   `X-Request-ID` is echoed.

## Consequences

- An allow from the facade is advisory: the engine re-checks run contexts, freshness
  and the epoch at the time of use. Operators must not treat a PDP allow as a lease.
- A PEP that ignores `context.obligations` will over-disclose restricted material.
  This is the PEP's contract, documented and testable, but not enforceable by AKAC.
- Batch evaluations run one transaction per item: throughput is bounded by the
  per-tenant serialisation of the store. No benchmark is claimed.
- Not implemented: Search APIs, signed metadata, capability URNs. Interoperability
  with third-party PEPs has not been tested.
- The listener adds an attack surface: it needs its own NetworkPolicy and credential
  rotation (`docs/SECURITY-OPERATIONS.md`).
