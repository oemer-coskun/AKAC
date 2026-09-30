# Runtime containment (0.5 draft)

**This is guidance, not a certification.** It describes AKAC's vendor-neutral
contract between authorization decisions and the runtime that holds released
content, and what an operator must build and test around it. Requirements:
[AKAC 0.5](../spec/AKAC-0.5.md) R109–R120.
Decision: [ADR-012](../governance/ADR-012-runtime-containment-contract.md).

AKAC decides and records. It does not sandbox anything, cannot see network or
file activity, and cannot verify that a runtime applied what it reported.

## The contract in one paragraph

A security administrator stores per-tenant *runtime profile policies*: for
material at or above a classification (optionally only when it goes to one
destination class), which operator-reviewed profile to apply per domain
(`network`, `filesystem`, `tool`, `credential`). Every allow over content then
carries one `runtime_profile` obligation per domain and a
`max_output_classification` obligation. The enforcement point must apply every
profile through a *runtime enforcer* before anything protected happens, or deny.
The enforcer reports the runtime policy revision it applied, which AKAC records
with the decision. A tenant without an active policy sees no change from 0.4.

```json
{"type": "runtime_profile", "domain": "network", "profile": "deny-all"}
{"type": "max_output_classification", "value": "restricted"}
```

Derivation (R-RTC-1, R-RTC-2): a policy applies when its classification is at most
the decision's transitive classification and its destination class, if set, is
the decision's. Per domain the highest classification wins; at equal
classification a destination-narrowed policy wins; different profiles from equal
winners deny with `UNSUPPORTED_OBLIGATION`. Configure higher tiers with templates
at least as restrictive as lower ones: AKAC cannot compare profile contents.

A destination-narrowed policy governs the decision that sends to that class (a
release or an evaluation naming a Destination), not the read before it. A release
to a user without a Destination profile has the class `internal-user`. For the
model call, the reference `ProtectedRuntime` applies the provider gate's profile
for each domain the gate names (it supersedes the context's: the gate is derived
over at least the same material and over more applicable policies), and the
context's profile for the other domains; a gate with a lower output label than
the context denies. A release to a service principal without a Destination
profile (its destination class is not known) is derived for every destination
class the run allows and merged; if narrowed policies make those classes differ,
the decision denies with `UNSUPPORTED_OBLIGATION`, and a run whose destinations
resolve to no class denies (R122). A share or export evaluation
(AuthZEN or `Engine.evaluate`) must name its `destination`: without one it is
denied (`RECIPIENT`, R121). Name the destination, or restrict the
run to the destinations it needs.

## The agent HTTP listener

The agent listener (`/v1/contexts`, `/v1/retrieve`, `/v1/derive`, `/v1/release`)
returns content to the agent credential. It cannot apply a runtime profile and
cannot tell whether its client runs inside a runtime enforcer. Its behaviour for
decisions carrying `runtime_profile` is therefore an explicit operator setting
(R123):

| `AKAC_RUNTIME_OBLIGATIONS` (`createGateway` option `runtimeObligations`) | Behaviour |
|---|---|
| `deny` (default) | An operation whose allow would carry a `runtime_profile` obligation is denied with `UNSUPPORTED_OBLIGATION` (R38, R113). Nothing of it persists (no context, no derived record); the denial is audited with the request's trace and execution ids. Tenants without an active runtime profile policy are unaffected. |
| `trusted-enforcer` | The obligations are returned with the content. Set it only when every client of the listener runs inside a runtime enforcer that applies them before the content is used (R112), for example an agent sandbox whose egress is the listener. This is a declaration by the operator; AKAC cannot verify it and does not record a runtime revision for HTTP requests. |

Any other value is a configuration error. For model calls prefer
`ProtectedRuntime`, which applies the profiles itself.

## Sandbox-wide and per-execution runtimes

The enforcer contract is execution-scoped (R112): `apply(profiles, {executionId})`
returns a lease `{runtimeRevision, release?}`, and `current(executionId)` reports
the revision in force for that execution. `ProtectedRuntime` checks `current()`
after the provider call and before it releases the answer, checks it again after
the final release and before it returns the answer (R124: a change
in between withholds the answer and audits the denial), and ends the lease
afterwards; a mismatch or a failed `release()` denies the answer.

- **Sandbox-wide** (default; `isolation` absent or `'sandbox-wide'`): one runtime
  policy governs everything the runtime holds, for example one sandbox
  policy. `ProtectedRuntime` serializes every execution through such an enforcer
  (apply, provider call, check, final release, lease release), also across
  `ProtectedRuntime` instances in one process that share the enforcer object.
  Several processes that drive one sandbox are not serialized by AKAC: give each
  execution its own sandbox, or serialize outside AKAC.
- **Per-execution** (`isolation: 'per-execution'`): one runtime per execution id
  (for example a fresh sandbox per job); executions run concurrently. Declare it
  only when the policy applied for one execution id can never govern another.

An enforcer that applies a later execution's policy to a shared sandbox must stop
reporting the earlier execution's revision from `current()`; the earlier answer is
then denied rather than recorded under a revision that was not in force.

## Responsibilities

| Concern | AKAC (reference) | Runtime and operator |
|---|---|---|
| Which profile a decision needs | Derives `runtime_profile` per domain from tenant policies, deterministic, conflicts deny | Keeps policies consistent (higher tier at least as strict) |
| What a profile means | Nothing: ids only, never policy text | Writes, reviews and versions the template behind each id |
| Applying profiles | `ProtectedRuntime` calls the enforcer before the provider, per execution, serialized for sandbox-wide enforcers, re-checks the revision before and after the final release, and denies on any gap; the agent HTTP listener denies runtime obligations unless declared `trusted-enforcer` | Implements the enforcer, out of band, not changeable by the agent; declares `per-execution` only for one runtime per execution |
| Unsupported or failed enforcement | Denies before the provider receives content | Monitors denials; never "falls back" to an unconfined runtime |
| Output labelling | States `max_output_classification` | Labels every derived output at least that high in downstream systems |
| Policy changes | security-admin only, human administrator, audited, epoch advance | Approval process for policy and template changes; restart or reconfine sandboxes after an epoch advance |
| Non-bypassability | Mediates reads, derivation and release | Removes direct paths from the sandbox to stores, providers and credentials |
| Evidence | Records `executionId`, `runtimeRevision`, decision id, trace id in the hash-chained audit | Keeps runtime logs with the same execution id and revision; retains them |
| Hardware isolation | None | Optional (for example DPU-based isolation); outside AKAC's scope |

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant Agent as Agent (in sandbox)
    participant PEP as PEP (ProtectedRuntime or gateway)
    participant AKAC as AKAC engine
    participant RT as Runtime enforcer (out of band)
    participant LLM as Model provider
    Agent->>PEP: task, resource ids, x-akac-execution-id
    PEP->>AKAC: openContext (decision 1)
    AKAC-->>PEP: allow + obligations (runtime_profile..., max_output_classification)
    PEP->>AKAC: release to provider principal (decision 2)
    AKAC-->>PEP: allow + obligations (destination class narrowing applies)
    alt any profile unsupported, conflicting, or no enforcer
        PEP-->>Agent: NOT_AUTHORIZED (provider never called)
    else every profile supported
        Note over PEP,RT: sandbox-wide enforcer: one execution at a time
        PEP->>RT: apply(profiles, executionId)
        RT-->>PEP: lease {runtimeRevision, release} (or failure/timeout: deny)
        PEP->>LLM: authorized payload only
        LLM-->>PEP: output
        PEP->>RT: current(executionId)
        RT-->>PEP: same runtimeRevision (else deny)
        PEP->>AKAC: release answer to subject (decision 3, records runtimeRevision)
        AKAC-->>PEP: allow + obligations
        PEP->>RT: current(executionId)
        RT-->>PEP: same runtimeRevision (else deny, audited)
        PEP->>RT: lease.release() (failure: deny)
        PEP-->>Agent: answer + obligations (label >= max_output_classification)
    end
```

## Bypass test checklist

This is the canonical list of twelve scenarios. Run each against the deployed system before production use
and after every change to the runtime, its templates or the network. **Pass = the
prohibited effect does not occur** (check the destination, file, store or memory
itself), not merely that the agent refuses. A test that cannot be run is a
finding, not a pass. "Enforced by" names who prevents the effect; for AKAC core
the last column points to the tests and conformance vectors that already cover it
(`conformance/vectors-runtime.json`, `conformance/vectors-redteam.json`,
`tests/runtime-containment.test.ts`). Rows enforced by the PEP or the runtime are
operator deployment tests; AKAC only supplies the decision and the evidence.

| # | Scenario | Enforced by | Pass (prohibited effect does not occur) | Covered in AKAC |
|---|---|---|---|---|
| 1 | Prompt injection requests secret exfiltration | Runtime (network and credential profiles) | No secret or restricted content reaches any outside host or store, including in the query string of a GET to a host a read-only profile allows | Injected text never changes grants or policy (R06); egress itself is the runtime's. |
| 2 | Agent calls the raw backend instead of the PEP | PEP and runtime | No connection to the vector index, object store, database or model provider except through the PEP | AKAC core only mediates what passes through it; `RTC-R01`, `RTC-R10` (deny before the provider) |
| 3 | Agent opens a prohibited file | Runtime (filesystem profile) | The read fails; nothing outside the allowed paths or of another tenant is exposed | Operator test. |
| 4 | Agent uses an alternate DNS or host path | Runtime (network profile) | Hostname, IP-literal and resolver variants of a blocked destination all fail | Operator test. |
| 5 | Agent attempts an unauthorized POST | Runtime (network and tool profiles) | No write reaches an endpoint granted read-only | Operator test. |
| 6 | Credential reuse against another host | Runtime (credential profile) | A credential is unusable for a host or binary it is not bound to | Operator test |
| 7 | Policy service unavailable | PEP (fail closed) and runtime | Actions are denied, not allowed unconfined; the provider is never called | `RTC-R01` to `RTC-R06`; slow-enforcer test; OPA error tests (R13) |
| 7a | Two agent executions share one sandbox; the second has a weaker profile | PEP (serialization, revision check) and runtime | Restricted content is never at the provider while a weaker profile is in force; no answer is recorded under a revision that was not in force | `RTC-R11`, `RTC-R12`; "regression: concurrent answers through one sandbox-wide enforcer" |
| 8 | Stale delegation or grant | AKAC core | An expired or revoked grant, an older epoch or an old `runtimeRevision` authorizes nothing | `RT-013`, `RT-020` to `RT-025`, `RT-050`, `RT-051`; "a runtime profile change ends open contexts"; `RTC-R09` |
| 9 | Malicious tool result | PEP and runtime | A tool output cannot change policy, profile, grant or label; only stored, reviewed ids are applied | `RTC-R09`, `RTC-P18` (free-text profile is malformed); model text never issues grants (R06) |
| 10 | Restricted source summarized into lower-class output | AKAC core | The derived output keeps the source classification and the label is at least `max_output_classification` | `RT-001`, `RT-002`, `RTC-P07`, `RTC-P08`, `RTC-E08` |
| 11 | Restricted result written to shared memory | AKAC core | A lower-cleared principal cannot read it; delayed use after quarantine or revocation fails | `RT-001`, `RT-003`, `RT-010` to `RT-013` |
| 12 | Subagent receives data without clearance | AKAC core | A subagent below the required clearance cannot open the parent's derived content | `RT-030`, `RT-031` (control), `RT-020` to `RT-024` (child grants cannot widen) |

## Release filters at the provider hop (0.6)

`ProtectedRuntime` treats the prompt it sends to the model provider as a release (`share`) and the
answer as a release to the subject. Release filters and the `release_filter` obligation (0.6,
[RELEASE-PROTECTION.md](RELEASE-PROTECTION.md), R167..R169) therefore apply to both hops: the release
filter ids that the context's decision names are required for the provider gate and the final release,
so a filter that is not deployed stops the answer before the provider receives anything, and a
redaction of the prompt reaches the provider instead of the original. `approval_required` is not
enforceable by the runtime and denies. Containment of the runtime itself is unchanged.

## Example runtime

Primary source for the reference design: NVIDIA, "NVIDIA Open Agent Safety Platform" blog post,
2026-09-28, <https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/>.
One runtime that can play the enforcer role is NVIDIA OpenShell (Apache-2.0,
<https://github.com/NVIDIA/OpenShell>), the runtime of the NVIDIA Open Agent Safety
Platform reference design, which sandboxes agents under operator-defined file,
network, tool and credential policies enforced out of band. A mapping from AKAC
profile ids to its policies is an integration outside the core (outside
the public repository), not part of any AKAC conformance profile. The optional NVIDIA Sentry and
BlueField-4/DOCA hardware layer is outside AKAC's scope. NVIDIA defines no
interface for an external policy decision point; this contract is AKAC's own
proposal, and no OASP conformance is claimed.

### Alignment with the published OASP principles (no conformance claim)

| OASP principle | Where AKAC contributes | What stays with the runtime or operator |
|---|---|---|
| "Policy needs to be verifiable" | Decisions, obligations and policy changes are hash-chained, provable audit evidence; profile ids name reviewed templates | Template review and versioning |
| "Enforcement must be out of band" | AKAC is a separate decision point; the agent cannot change decisions or policies | The enforcer runs outside the agent's control |
| "The path to the model (the brain) is the control point" | `ProtectedRuntime` authorizes the provider as a recipient and applies profiles before calling it | Network profile that makes every other path unreachable |
| "Scale agent authority with the ability to inspect its thinking" | Classification-tiered profiles and output labels; `executionId` and `runtimeRevision` tie runtime activity to decisions | Runtime logging and inspection |
| "Applying the shared responsibility model" | The responsibility table above | Everything in its right-hand column |
