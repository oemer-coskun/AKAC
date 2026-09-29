# ADR 013: fixes and semantic changes from the review of 0.5.0

Status: proposed for AKAC 0.6 (draft); internal review only, no external review has
taken place. Requirements: [AKAC 0.6](../spec/AKAC-0.6.md)
(R121 to R126).

## Context

A read-only review of the 0.5.0 reference reported gaps where the core allowed
more than its own rules imply, plus documentation drift. Each item below was
reproduced against the current code before it was changed. Where there was a
choice, the more restrictive option was taken: every change only adds denials.

## Decisions

1. **Share/export evaluations must name a Destination (R121).** `release()`
   requires the recipient to see every source; `Engine.evaluate` and the AuthZEN
   facade had no recipient, and under an unrestricted run a `share` or `export`
   without `context.destination` was allowed with no recipient condition at all.
   Such evaluations are now denied (`RECIPIENT`) under every run. The 0.4 rule
   that allowed them under a restricted run with `destination_restricted` naming
   the run's destinations (R67, second sentence) is withdrawn as well: it relied
   on the enforcement point honouring an obligation that AuthZEN 1.0 does not
   define, and naming the destination costs the enforcement point nothing.
   Considered and rejected: a `context.recipient` principal (it would duplicate
   `release()` without a context) and documenting the gap only.
   Changed vectors: Z21 (was allow), RTC-E09 (reason code), RTC-E10 and RTC-E11
   (were allow; the narrowed-profile coverage moved to RTC-E14).
2. **No reachable destination class denies (R122).** `containmentAcross` with
   no class fell back to the derivation without a destination class, which could
   be weaker than any narrowed policy. It now denies (`RECIPIENT`). After
   decision 1 the path is not reachable from the engine; the rule is kept as
   defence in depth and pinned by RTC-P20.
3. **Agent HTTP listener and runtime obligations (R123).** The listener
   returned content with `runtime_profile` obligations to the agent credential,
   which cannot be assumed to be confined. New listener option
   `runtimeObligations: 'deny' | 'trusted-enforcer'` (environment
   `AKAC_RUNTIME_OBLIGATIONS`), default `deny`. The engine takes a per-call list
   of obligation types the caller cannot enforce (`Call.unenforceable`); an allow
   carrying one is turned into `UNSUPPORTED_OBLIGATION` by rolling the operation's
   transaction back and auditing the denial in a new transaction, so no context
   or derived record survives. A malformed list refuses every allow.
   `trusted-enforcer` is an operator declaration that AKAC cannot verify; it is
   documented as such and is never the default. Operational effect: deployments
   with active runtime profile policies that consumed content over the agent
   listener must either move to `ProtectedRuntime` or set `trusted-enforcer`.
4. **Re-verify after the final release (R124).** `ProtectedRuntime` checked
   the runtime revision before the final release decision only; a change between
   that check and the return went unnoticed. It now checks again after the
   release and before returning; on a change it withholds the answer and audits a
   denial through `Engine.withhold()` (an in-process, deny-only entry point, not
   exposed over HTTP). The allow entry of the release stays in the append-only
   audit stream; the denial after it records that nothing was returned. Covered
   by RTC-R13 and a unit test. A window between the second check and the caller's
   use of the answer remains inherent to any check-then-use design; the lease is
   still held during both checks.
5. **Tombstones name no audience (R125).** Erasure cleared `readers` but kept
   `readerRoles`, so a tombstone was readable by role for any evaluator that
   ignored `lifecycle`. `readerRoles` is now cleared too. `projects` is kept on
   purpose: it is a conjunctive restriction in `visible()`, so clearing it would
   widen the label (the review suggested clearing it; that was not adopted).
   Legacy tombstones are cleaned on a repeated erasure without changing their
   erasure time.
6. **Label widening is a declassification (R126, R15).** A kb-admin could
   lower a document's classification or widen its audience by publishing a new
   version: an audited but not separately authorized declassification. A new
   version that widens the label (lower classification, added reader or reader
   role, removed project, other container, removed or extended access expiry,
   dropped source) now needs `security-admin`; a kb-admin alone gets `CONFLICT`.
   A security-admin without kb-admin may publish only such a relabelling of an
   existing document with unchanged content (otherwise `NOT_AUTHORIZED`, audited
   `NOT_ADMIN`), so declassification and authoring stay separate duties. Dual
   control (two administrators) was considered; it needs a pending-change store
   and is left for a later version.

## Consequences

- AuthZEN enforcement points and egress proxies that evaluated `share`/`export`
  without `context.destination` now receive `decision:false` and must send the
  Destination id.
- The agent listener denies disclosures for tenants with active runtime profile
  policies unless configured `trusted-enforcer`.
- Ingestion pipelines that relabel documents downwards need a security-admin
  identity for those versions.
- The Python port is not changed by this ADR; the TS/Python differential tests do
  not cover these rules.
