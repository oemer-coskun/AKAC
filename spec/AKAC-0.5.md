# AKAC 0.5

Status: project specification, not a ratified external standard. Reference: 0.5.0.
This revision incorporates R01–R16 of [AKAC 0.1](AKAC-0.1.md), R17–R21 of
[AKAC 0.2](AKAC-0.2.md), R22–R31 of [AKAC 0.3](AKAC-0.3.md) and R32–R108 of
[AKAC 0.4](AKAC-0.4.md) by reference and without weakening any of them: a
requirement below only adds conditions, obligations or evidence, and an
implementation of 0.5 MUST still satisfy R01–R108. The following requirements apply
to the AKAC-RuntimeContainment 0.5 draft profile ([conformance](CONFORMANCE.md)).
MUST, SHOULD and MAY retain their RFC 2119/8174 meanings.

No external review, legal review or independent interoperability test has taken
place. The contract below is AKAC's own vendor-neutral proposal. No runtime vendor
defines an interface for an external policy decision point that it implements; in
particular it is not an interface of the NVIDIA Open Agent Safety Platform, and no
conformance to it is claimed (see [ADR-012](../governance/ADR-012-runtime-containment-contract.md)).
The OWASP Top 10 for LLM Applications 2025 and the OWASP agentic-application threat
list are risk catalogues, not conformance targets.

Numbering continues from 0.4. The draft in [drafts/](drafts/) was merged here; the
table at the end maps every draft identifier to its R number. The R numbers are
stable: they are not reused or reordered in later revisions.

Operator guide and bypass-test checklist: [docs/RUNTIME-CONTAINMENT.md](../docs/RUNTIME-CONTAINMENT.md).
Conformance evidence: `conformance/vectors-runtime.json` (run by
`conformance/run-runtime.ts`), `tests/runtime-containment.test.ts`,
`tests/runtime-postgres.test.ts`.

## Threats addressed

- Content that AKAC released is used by an agent runtime that can reach networks,
  files, tools or credentials the decision never considered (OWASP Top 10 for LLM
  Applications 2025, LLM02 and LLM06; the OWASP agentic threat list, ASI02 and ASI03).
- An obligation that exists in the decision but disappears when it is translated
  into runtime controls (a silent downgrade at the enforcement point).
- An agent that rewrites its own runtime policy, or that bypasses retrieval by
  reading a vector, object or database store directly.

## Model

A *runtime profile policy* is a tenant-scoped record `{id, tenant, classification,
destinationClass?, profiles, active}`. `profiles` maps one or more of the domains
`network`, `filesystem`, `tool`, `credential` to a *profile id*: an identifier of
an operator-reviewed runtime template. A *runtime enforcer* is the policy
enforcement point that applies profiles to the runtime that holds released content
and reports a *runtime revision* identifying what it applied.

Two obligations carry the contract on the wire:

```json
{"type": "runtime_profile", "domain": "network", "profile": "deny-all"}
{"type": "max_output_classification", "value": "restricted"}
```

## Runtime containment (R109–R120)

**R109 — Derivation.** When the tenant of a decision holds at least one active
runtime profile policy, every allowed read (openContext, retrieval, read-only
evaluation), derivation and release MUST carry the runtime obligations derived as
follows. Let *L* be the highest transitive effective classification (R25) of the
material, and *D* the destination class of the decision: the class of the
recipient's Destination for a release or an evaluation that names one;
`internal-user` for a release to a user without a Destination profile (the
implicit user destination of ADR-008); absent for a read, a retrieval, a
derivation and a read-only evaluation of those actions. A policy applies when it
is active, its `classification` is at most *L* and its `destinationClass` is
absent or equal to *D*. For each domain, among the applicable policies naming a
profile for it, the policy with the highest `classification` wins; at equal
`classification` a policy with `destinationClass` wins over one without. The
decision carries one `runtime_profile` per domain that has a winner, in the order
network, filesystem, tool, credential.

A share or export whose destination class is not known (an evaluation that names
no Destination, or a release to a non-user principal without a Destination
profile) MUST NOT receive a weaker derivation than a named destination would:
the derivation above is made once for every destination class the run allows (the
classes in the run's `destinations`, a Destination id by the class of its active
profile; every class for an unrestricted run), and the results are merged. Where
two of these name different profiles for one domain, R110 applies (deny); the
enforcement point can name the destination instead. (AKAC 0.6: an evaluation
that names no Destination is denied outright, and no reachable class denies;
[R121, R122](AKAC-0.6.md).)

**R110 — Conflicts deny.** If, for a domain, two winners of R109 (or two
destination classes of an unknown destination under R109) name different profiles, or the runtime obligations combined with any other obligation
of the operation (for example a supplemental policy's) name two profiles for one
domain, the decision MUST be a denial with `UNSUPPORTED_OBLIGATION` (category
`deny`). After merging, an obligation list carries at most one profile per domain.
A malformed stored policy of the tenant MUST defer (`INVALID_CONTEXT`).

**R111 — Output label.** Under R109 the decision MUST also carry
`max_output_classification` with the value *L*. Every output derived from the
released content MUST carry at least that classification outside AKAC. Merging
keeps the highest value. A tenant without an active policy receives neither
obligation: its decisions are unchanged from 0.4.

**R112 — No obligation disappears in translation.** A policy enforcement point
that turns decisions into runtime controls MUST apply every `runtime_profile` of
every decision governing the content it holds, exactly as named. It MUST NOT drop,
weaken, merge away or substitute a profile. Where two decisions governing the same
content name different profiles for one domain, it MUST deny, with one exception:
for the hop that sends content to a recipient (for example the provider gate of a
model call), the release decision for that recipient governs the hop and its
profile supersedes that of the earlier read for each domain it names, provided the
release is derived over at least the read's material within the same policy epoch
(so its R109 winner is never of a lower tier) and carries a
`max_output_classification` at least as high; a lower one MUST deny.

Enforcement is execution-scoped. The enforcement point MUST name the execution
it applies profiles for and MUST NOT let the profiles applied for one execution
govern another execution's content. A runtime whose policy is shared by
everything it holds (sandbox-wide, for example one sandbox policy) MUST be used by
one execution at a time: apply, the protected action, the check below, the
release of the result and the end of the execution's hold complete before another
execution applies profiles to it; otherwise one runtime per execution is
required. Before a result produced under applied profiles is released, the
enforcement point MUST confirm that the runtime still reports the applied revision
for that execution, and MUST deny if it does not, or if ending the execution's
hold fails. The reference `ProtectedRuntime` serializes executions through every
enforcer not declared `per-execution`.

**R113 — Unsupported means deny.** A policy enforcement point that has no
runtime enforcer, whose enforcer has no operator-reviewed template for a named
profile, cannot confirm the revision in force for an execution (R112), or whose
enforcer fails, times out or reports a malformed revision or lease, MUST
treat the decision as a deny, before protected content reaches a model provider,
tool or other destination. An obligation of an unknown type still denies (R38).

**R114 — Operator-reviewed templates, never model-generated policy.** A
profile id MUST reference a runtime template reviewed and approved by the
operator. AKAC MUST NOT accept, store or emit runtime policy text; policy records
and obligations carry identifiers only. A profile or policy proposed by a model,
an agent or request content MUST NOT become a runtime profile policy (R06, R31).

**R115 — Privileged changes.** Creating, changing or deactivating a runtime
profile policy MUST be a security-admin operation of the control plane, performed
by a human administrator or an authorized service principal under the operator's
approval process, and audited. The reference accepts human security-admin users
only. Every accepted change MUST advance the tenant epoch, so open contexts end and
re-establish authority under the new obligations (R28). A change that widens
runtime authority (deactivation, removing a domain, a lower tier, a different
profile) MUST NOT be reachable from agent credentials or model output. Changes to
the runtime templates themselves are an operator obligation under the same rule.

**R116 — Out-of-band enforcement.** The runtime enforcer MUST run outside the
control of the agent it confines: the agent MUST NOT be able to change, disable or
replace the applied profile, and the runtime revision it reports MUST identify the
policy revision actually applied (operator obligation; AKAC cannot observe it).

**R117 — Evidence correlation.** Engine and control-plane entry points MAY
accept an execution id (an AKAC identifier) naming the agent execution; a valid
one MUST be recorded in the audit entry as `executionId`, an invalid one MUST be
ignored. Over HTTP it is the `x-akac-execution-id` header; a malformed header is a
400. The runtime revision applied by a trusted runtime enforcer MUST be recorded
as `runtimeRevision` on the audit entry of the decision that releases the result
produced under it, and only after it was confirmed to be in force for that
execution (R112). The AuthZEN listener accepts the header on the same terms. A runtime revision MUST NOT be accepted from an agent over
HTTP, nor from the caller of a runtime that has its own enforcer. Both members are
optional members of audit format 2, covered by its hash; entries without them are
unchanged. Neither is authority. The `policyDigest` of an engine decision that
loaded the tenant's runtime profile policies also covers the tenant's active
policy set (SHA-256 over the JCS form of the valid active records sorted by id,
appended to the digest input); for a tenant without an active policy the digest
input is unchanged from 0.4.

**R118 — Non-bypassability.** Every protected action MUST traverse at least
one non-bypassable policy enforcement point. Direct paths from the agent sandbox to
vector indexes, object stores, databases, model provider endpoints and credential
stores MUST be unreachable (operator obligation; the reference cannot verify it).
Operators SHOULD run the bypass checklist of
[RUNTIME-CONTAINMENT.md](../docs/RUNTIME-CONTAINMENT.md) before production use
and after every runtime or template change.

**R119 — Staleness.** After an epoch advance a runtime SHOULD discard content
held under the ended context and MUST obtain a fresh decision (and apply its
profiles) before any further protected action.

**R120 — AuthZEN.** The AuthZEN facade (R79–R90) MUST return
`runtime_profile` and `max_output_classification` in `context.obligations` of an
allow exactly as the engine derives them.

Denials under R110 use the existing code `UNSUPPORTED_OBLIGATION`; public
responses stay non-distinguishing (R35).

See the [migration notes](../docs/MIGRATION-0.5.md), [conformance](CONFORMANCE.md) and
the [changelog](../CHANGELOG.md).

## Draft identifier mapping

| Draft id | Requirement | Draft file |
|---|---|---|
| R-RTC-1 | R109 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-2 | R110 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-3 | R111 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-4 | R112 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-5 | R113 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-6 | R114 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-7 | R115 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-8 | R116 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-9 | R117 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-10 | R118 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-11 | R119 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
| R-RTC-12 | R120 | [0.5-runtime-containment](drafts/0.5-runtime-containment.md) |
