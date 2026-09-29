# ADR 019: delegated identities, heartbeats, break-glass, approval quorum and risk

Status: proposed for AKAC 0.6 (draft). No external review has taken place.
Requirements: [AKAC 0.6](../spec/AKAC-0.6.md) (R143..R157).

## Context

0.5 authenticated an agent credential by mapping its verified `sub` to one run and
ignored every other claim. Deployments that use OAuth 2.0 Token Exchange (RFC 8693)
present tokens whose `act` claim names the agent acting for a user; such a token
could be mapped, but the actor was neither checked nor recorded. A grant stayed valid
until it expired or was revoked, even when the runtime that held it had died. Every
administrative change was authorized by one standing administrator, including
declassification, role widening and runtime policy changes, and there was no
emergency access path other than an ordinary grant. Nothing lowered a principal's
authority when an identity provider reported elevated risk.

## Decision

1. **RFC 8693 in the authenticator, not in the decision.** `adapters/jwt.ts` reads
   `act` (section 4.1) and `may_act` (section 4.4). A per-subject delegation mapping
   names the expected current actor (`sub`, optionally `iss`); the outermost `act` must
   match, prior actors never do, and `may_act` must name the same actor. Subjects with
   a delegation mapping authenticate only with delegation tokens; subjects without one
   only without `act` (the 0.5 mapping is the operator's statement that the token
   subject is the run's credential). Administrative and PEP credentials never carry
   `act`/`may_act`. The verified chain (at most 5 identifiers) is attached to the
   returned binding object in process (`reference/delegation.ts`, a WeakMap no request
   can reach) and recorded as `actorChain` in every audit entry of that binding.
   decide() is unchanged by delegation: the grant still governs, so an exchange only
   selects a provisioned run and can never widen it.
2. **Heartbeat-bound grants in decide().** `heartbeatTtlMs` and `lastHeartbeatAt` are
   grant fields checked in the delegation-chain validation, so a lapsed ancestor
   invalidates every descendant with no extra machinery, and a child can only
   shorten the TTL. The heartbeat time is written by the control plane only (issue,
   delegate, heartbeat); a lapse is final. Heartbeats arrive on the administrative
   listener from a new least-privilege role, `runtime`, which a `service` principal may
   hold; `service` principals can exercise only `runtime` and `risk-ingest`. No epoch
   change: the decision itself sees the deadline, and the in-process decision cache
   (ADR-020) bounds entries by it.
3. **Break-glass is a narrow grant, not a bypass.** A `breakGlass` grant is a root,
   read-only grant on at most 64 named resources for at most two hours. In decide() it
   lifts only the audience clauses (readers, reader roles, projects); tenant,
   lifecycle, activity, expiry, clearance and risk caps still apply, and it writes no
   record, so erasure and legal holds are untouched. It is issued only through the
   approval gate with a quorum of at least 2; every audit entry of the workflow and
   of its use carries `breakGlass: true`, and `akac_break_glass_*` metrics exist for
   alerting.
4. **Approval quorum in the control plane.** Sensitive operations (break-glass,
   label widening, role widening, SoD relaxation, runtime profile changes,
   destination widening, settings relaxation) call one gate. Quorum N means N distinct
   standing security-admin users including the requester; default 1 (0.5 behaviour)
   except break-glass (2). Below the quorum the request is stored (`akac_approvals`)
   and answered `APPROVAL_REQUIRED` (HTTP 202). Execution re-runs the original
   operation as the requester with the stored arguments (digest-bound), so every rule of
   the operation is re-validated against the current state; approvers who lost the
   role no longer count; approvals expire; relaxing settings needs the highest quorum
   of any class, and the break-glass quorum cannot go below 2. The `ApprovalGate`
   hook lets an external workflow (an enterprise edition, an IGA or ticketing system)
   raise the quorum or require its own confirmation; it can never approve alone and
   fails closed.
5. **Risk caps in decide().** Risk signals (`akac_risk_signals`, one per source and
   principal, source = the authenticated caller) cap the user's and the agent's
   clearance by their highest unexpired level; caps are monotone by construction, and
   `critical` always denies (`RISK_CAP`). Defaults: medium to confidential, high to
   internal. The `RiskProvider` hook adds a level per operation as one more signal, so
   it can only narrow; a failure denies. A raised signal advances the tenant epoch.
6. **Open core.** The public core holds the decision semantics, the storage, the
   routes and the hooks (`ApprovalGate`, `RiskProvider`) with secure defaults. SSF/CAEP
   receivers (RFC 8417 SET verification, stream management) and identity-provider
   connectors are connectors outside the core; `reference/risk.ts` documents the
   CAEP `risk-level-change` mapping they use.

## Consequences

- decide() changes (heartbeat, break-glass, risk): new conformance vectors
  (`vectors-0.6-identity.json`), a new reason code `RISK_CAP`, and the same rules in
  the Python implementation. Audit format 2 gains two optional members
  (`actorChain`, `breakGlass`); earlier entries hash and verify unchanged, and a
  verifier that predates them rejects entries that carry them (closed shape).
- Migration 010 adds three tenant tables with forced RLS and optional columns on
  `akac_grants` and `akac_audit`.
- A risk raise ends the open contexts of the tenant (epoch), like any other security
  change. Approval requests are bounded by the admin rate limit and their lifetime;
  a listing returns at most 256 pending requests.
- Heartbeats are audited, so short TTLs increase audit volume; operators choose TTLs
  of seconds to minutes accordingly.
- Not done: an SSF receiver, per-runtime binding of which runtime may heartbeat which
  grant (any `runtime` principal of the tenant may), and delegation of administrative
  authority. These are documented limits.

## Amendment (0.6b, second review round)

- **Elevation (R158).** Making a principal newly hold an approver role
  (`security-admin`) by assignment, principal create/update/reactivation, group
  change, role inheritance or activation, or SCIM, passes the approval gate at the
  highest quorum of any class; the elevated principals never count towards or cast
  their own approval. Without it one administrator could create the second approver of
  a break-glass request. Consequence: the first two administrators are provisioned out
  of band. Quorums count principal ids, not persons (documented limit; one account per
  person via the identity provider).
- **Runtime binding (R147, R148).** `Actor.runtimeFor` lists the agents whose runs a
  runtime principal may heartbeat (migration 010 column `akac_actors.runtime_for`);
  anything else is refused `NOT_AUTHORIZED`. This replaces the limit stated above
  ("any `runtime` principal of the tenant may"). A new binding is a role widening.
- New role and group records advance the epoch too (a new group can change session roles
  under dynamic SoD, which a cached allow would otherwise outlive).
