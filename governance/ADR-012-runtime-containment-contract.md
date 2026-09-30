# ADR 012: vendor-neutral runtime containment contract

Status: proposed for AKAC 0.5 (draft); internal review only, external security
review outstanding. Requirements: [AKAC 0.5](../spec/AKAC-0.5.md) R109–R120 (merged from the
[0.5 runtime containment draft](../spec/drafts/0.5-runtime-containment.md)). Revised after an
internal adversarial review of 0.5 (decisions 3, 5, 7 and 9 to 11 below).
Operator guide: [RUNTIME-CONTAINMENT.md](../docs/RUNTIME-CONTAINMENT.md).

## Context

AKAC decides whether knowledge may be read, derived from or released, and states
what the enforcement point must do with it (obligations, ADR-006). What happens
to released content inside the agent's runtime (which networks it can reach,
which files it can write, which tools and credentials it can use) was outside the
contract: `destination_restricted` (ADR-008) governs a release, not the sandbox
that holds the content afterwards.

On 2026-09-28 NVIDIA published the Open Agent Safety Platform (OASP), a reference
design with an application, a runtime and an infrastructure layer (primary source:
<https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/>). Its runtime is
NVIDIA OpenShell (Apache-2.0, primary source: <https://github.com/NVIDIA/OpenShell>),
which sandboxes agents under operator-defined policies for file, network, tool and
credential access, enforced out of band; NVIDIA Sentry with BlueField-4/DOCA is an
optional hardware layer. OASP states five principles: policy is verifiable;
enforcement is out of band; the path to the model is the control point; agent
authority scales with the ability to inspect it; responsibility is shared.

OASP defines no interface for an external policy decision point. Anything AKAC
specifies here is therefore AKAC's own, vendor-neutral proposal. It is not an
NVIDIA or OASP interface, and no conformance to OASP is claimed.

## Decision

1. **Obligations name profiles, not policy.** Two obligations carry the contract:
   `{"type":"runtime_profile","domain":"network"|"filesystem"|"tool"|"credential","profile":"<id>"}`
   and `{"type":"max_output_classification","value":"<level>"}`. A profile id is
   an AKAC identifier that names an operator-reviewed runtime template. Mapping
   ids to a concrete runtime is an integration, kept outside the core (for
   example an optional module under ADR-010 for one runtime).
2. **Per-tenant policy records.** `RuntimeProfilePolicy {id, tenant,
   classification, destinationClass?, profiles, active}`, security-admin only,
   audited, stored like destinations (PostgreSQL migration 008, `(tenant, id)`
   key, forced row-level security; Memory and SQLite stores). At most 256 per
   tenant. Every accepted change, including creation, advances the tenant epoch:
   a new or stricter policy must reach running contexts, not only new ones.
3. **Deterministic derivation with an explicit order.** A policy applies when its
   classification is at most the decision's transitive classification (R25) and
   its destination class, if set, equals the decision's. Per domain the policy
   with the highest classification wins; at equal classification a
   destination-narrowed one wins over an unnarrowed one; two winners with
   different profiles deny with `UNSUPPORTED_OBLIGATION`, the same code and path
   as an empty `destination_restricted` intersection. We rejected a free `rank`
   integer: it adds a second ordering an operator must keep consistent with the
   classification tiers, and ties still need a rule. AKAC cannot compare opaque
   profile ids, so the rule assumes (and the guide requires) that a higher tier
   names a template at least as restrictive.
   The destination class of a release to a user without a Destination profile is
   `internal-user` (the implicit user destination of ADR-008), so policies
   narrowed to that class apply to it. A share or export whose destination class
   is unknown (an evaluation without a destination, a release to a non-user
   principal without a profile) is derived for every class the run allows and
   merged; a difference between classes denies. The first version derived it as
   "no destination", so an unnamed destination got the unnarrowed profile, weaker
   than the one a named external destination would get. We rejected picking the
   "most restrictive" of differing profiles: AKAC cannot order opaque ids.
4. **Opt-in per tenant, including `max_output_classification`.** A tenant without
   an active policy gets exactly the 0.4 obligations. We considered emitting
   `max_output_classification` on every allow; every existing 0.4 enforcement
   point that correctly denies unknown obligations (R38) would then deny every
   decision after an upgrade. Enabling it with the first policy makes the tenant's
   switch to 0.5-aware enforcement points an explicit operator act. No existing
   test expectation changed.
5. **Enforcement point contract, execution-scoped.** `ProtectedRuntime` accepts
   an optional `RuntimeEnforcer { isolation?; supports(domain, profile);
   apply(profiles, {executionId}) -> {runtimeRevision, release?}; current(executionId) }`.
   Before the provider is called it requires every governing profile of the
   provider hop to be supported, non-conflicting and applied for the execution;
   otherwise it denies. After the provider call it requires `current(executionId)`
   to still report the applied revision before it releases the answer, and a
   failed lease `release()` denies the answer. `RUNTIME_OBLIGATIONS` (the 0.4
   list) is unchanged, so other runtimes that reuse it deny the new obligations
   instead of ignoring them.

   The first version had `apply(profiles)` without an execution: concurrent
   answers shared one enforcer, so a later, weaker `apply()` could be in force
   while an earlier restricted request was at the provider, and the earlier
   answer's audit entry named a revision that no longer governed it. We now
   serialize, per enforcer object, every execution through an enforcer that does
   not declare `isolation: 'per-execution'` (apply, provider call, revision check,
   final release, lease release). Serialization is the safe default because a
   sandbox-wide runtime (for example one OpenShell sandbox policy) cannot hold two
   policies at once; concurrency needs one runtime per execution and is an
   explicit operator declaration. The cost is throughput per sandbox; operators
   scale with more sandboxes, not with overlap. We rejected merging concurrent
   executions' profiles (AKAC cannot compute a meet of opaque ids) and a
   check-only design without serialization (it would detect, and deny, most
   overlaps instead of preventing them). Serialization holds within one process;
   several processes driving one sandbox must use one sandbox per execution.

   Provider hop precedence: the provider gate is a release derived over at least
   the context's material (every context of the run) in the same epoch and over a
   superset of the applicable policies (unnarrowed plus those narrowed to the
   provider's class), so its winner per domain is never of a lower tier than the
   context's. Its profile therefore supersedes the context's for each domain it
   names, provided its output label is not lower. The first version treated them
   as a conflict, so any policy narrowed to `model-provider` made every answer
   deny. A genuine same-tier conflict (two narrowed policies with different
   profiles) still denies in the engine (R110).
6. **Evidence correlation in audit format 2.** `executionId` and
   `runtimeRevision` are added as optional members of format 2, like `runId` and
   `traceId` before them, rather than as a format 3. The hash is SHA-256 over the
   RFC 8785 form of whatever members are present, so an entry without them is
   byte-identical to a 0.4 entry and verifies unchanged; an entry with them binds
   them. The verifier's closed shape now admits them; a verifier that predates
   this change rejects such an entry, which fails closed. The Merkle leaf,
   checkpoint and proof semantics are unchanged. A format 3 would have added a
   second hash rule, a downgrade rule and schema branch for two optional strings.
7. **Runtime revision only from a trusted path.** `executionId` may come from
   any caller, including agents and AuthZEN enforcement points
   (`x-akac-execution-id` on the agent, admin and AuthZEN listeners; malformed is
   a 400), because it only correlates. `ProtectedRuntime` uses the caller's
   execution id, or a fresh one, for the enforcer and the audit entries. `runtimeRevision` asserts what containment was in force; an agent
   could claim any value, so the HTTP listeners never accept one, and
   `ProtectedRuntime` discards a caller-supplied value and records only its own
   enforcer's result on the answer's audit entry.
8. **AuthZEN.** The facade already returns engine obligations in
   `context.obligations`; the new types appear there unchanged.
9. **Policy digest covers the containment policy.** An engine decision that
   loaded the tenant's runtime profile policies appends a digest of the tenant's
   active set (JCS, sorted by id) to its `policyDigest` input. Tenants without an
   active policy keep the 0.4 digest, and the digest is independent of the store
   (the set is loaded in full, bounded at 256). Control-plane and AuthZEN refusal
   entries, which do not load the set, are unchanged.
10. **Integration templates must not widen each other.** A runtime
   adapter that renders all four domains into one sandbox policy must not let its tool and
   credential templates add `network_policies` entries to any network profile, or
   `network/deny-all` would not be deny-all. Templates
   declare the sections they write, and the network profile is authoritative
   for `network_policies`: `deny-all` admits no other domain's entry, the
   allowlist profiles admit only entries whose hosts are in their allowlist, and
   anything else makes `apply()` throw (the caller denies).
11. **Residual risk recorded, not solved.** `access: read-only` endpoints still
   permit GET requests, so data can leave in query strings to an allowed host.
   Path- or method-level rules are not used because their schema was not verified
   against a primary source; operators keep read-only allowlists to hosts they
   control or log.

## Alternatives considered

- **Emitting raw vendor policy from AKAC** (for example a sandbox policy document
  per decision). Rejected: it would bind the core to one runtime's schema and
  release cycle, make AKAC a generator of executable policy (a new injection
  surface, since decisions consider request content), and move the review of
  runtime policy from the operator to AKAC. Profile ids plus operator-reviewed
  templates keep the policy verifiable where it is enforced.
- **Profiles as a supplemental-policy (OPA) concern only.** Possible and still
  supported (a policy may add `runtime_profile`), but tenants then need a policy
  bundle for a basic control, and the conflict rule would differ per bundle.
- **A new reason code for profile conflicts.** Rejected: `UNSUPPORTED_OBLIGATION`
  already means "no enforcement point can satisfy this".

## Consequences

- A tenant opts in by creating its first policy; from then on every enforcement
  point for that tenant must understand both new obligations or deny.
- Runtime mapping, template review, out-of-band enforcement and the removal of
  direct store and network paths remain operator obligations; AKAC decides,
  states and records, and cannot observe the sandbox.
- One more tenant-scoped load per content decision (bounded at 256 rows).
- A sandbox-wide enforcer processes one answer at a time; per-execution
  runtimes are the operator's route to concurrency.
- Share/export evaluations without a destination deny when destination-narrowed
  policies differ between the classes the run allows; enforcement points name the
  destination (or restrict the run) instead.
- Migration 008 adds `akac_runtime_profiles` and two nullable audit columns;
  migrations 001–007 are unchanged.
