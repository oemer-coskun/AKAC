# AKAC 0.3 draft

Status: project specification, not a ratified external standard. Reference: 0.3.0.
This revision incorporates R01–R16 of [AKAC 0.1](AKAC-0.1.md) and R17–R21 of
[AKAC 0.2](AKAC-0.2.md) without weakening them. The following requirements apply
to the AKAC-KB/0.3 draft profile. MUST and SHOULD retain their RFC 2119/8174 meanings.
R24–R26 and R29–R31 were amended after an internal adversarial review of the
reference implementation (see the changelog); no external review has taken place.

## Additional requirements

**R22 — Hierarchical roles.** A role MAY include junior roles (NIST hierarchical
RBAC). The effective roles of a principal are the closure, over active roles of
the principal's own tenant, of its directly assigned roles and the roles of active
groups (R23) it belongs to. An inactive role contributes neither itself nor its
juniors. Cycles, and closures above a published budget, MUST deny; the reference
budget is 64 effective roles and 16 roles on any inheritance path. For 0.2
compatibility, a role name with no role record in the principal's tenant is a
flat role without juniors; a record in another tenant never applies. Operators
SHOULD deactivate rather than delete role records, because deletion restores the
flat meaning of the name.

**R23 — Groups.** A group assigns roles to its listed members while the group is
active and in the member's tenant. Group membership MUST NOT be inferred from
token claims, model output or content.

**R24 — Separation of duty.** A static constraint over a role set with
cardinality *n* (≥ 2) makes any principal whose effective roles include *n* or
more of the set invalid for every decision, including as a release recipient. A
grant MAY carry `activeRoles`, a session activation which MUST be a subset of the
subject's effective roles and, for a delegated grant, of the parent grant's
activation; a child of an activated grant MUST itself be activated. When present,
only the activated roles and their juniors establish the subject's audience; when
absent, every effective role is active. A dynamic constraint denies when the
active set includes *n* or more of its roles. A malformed constraint MUST deny.
Administrative interfaces SHOULD reject a change that would put a currently valid
principal into a static violation: a role assignment, a group change, a change to
the role hierarchy or a new or tightened static constraint. Such a rejection
SHOULD report at most the number of affected principals, never their identities.
Deactivation and other pure reductions of authority (removing roles, group
members, group roles or projects, lowering clearance, deactivating a role or
group) MUST always succeed, including for a principal that is already in
violation, so that deprovisioning can never be blocked. Decisions MUST enforce
every stored constraint regardless.

**R25 — Containers.** Knowledge MAY name a container. A container is a
knowledge base (a root, without parent) or a folder (with a parent). Each has a
classification floor, an audience (readers, reader roles, projects) and a
lifecycle state. A principal MUST satisfy the audience of the object **and of
every ancestor container**, and its clearance MUST dominate the effective
classification: the highest of the object's and all ancestors' classifications.
The effective projects are the union. Missing, cyclic, cross-tenant or
malformed chains, and chains deeper than a published budget (reference: 32),
MUST deny; an inactive container denies every descendant. This applies
recursively to every source of a derived object. A derivation's classification
MUST be at least the effective classification of each source, taken over the
source's own transitive sources. A document ingested with sources MUST reference
sources that resolve in its tenant at the stated version, and its effective
classification MUST be at least the transitive effective classification of each
source; otherwise ingestion MUST be rejected. Supplemental policy (R29) MUST be
given the highest effective classification over the object's whole source graph,
not only its own container chain. Containers only restrict: placing an object in
a container MUST NOT allow a decision that denies without it.

**R26 — Retrieval pre-filters.** A retrieval index is an optimization, never an
authority ([ADR-004](../governance/ADR-004-knowledge-base-partitioning.md)).
Candidate generation MUST be restricted to the caller's tenant, and SHOULD be
physically partitioned by tenant and classification compartment so that no
compartment above `min(user clearance, agent clearance)` is queried. Principal
tokens (`user:`, `role:`, `project:`) MAY pre-filter candidates. Every candidate
MUST be re-authorized with the full decision (R04, R08, R25) before any content,
rank, score or count is observable; a candidate that fails MUST be dropped and
SHOULD be counted as a filter mismatch without recording content. Scoring MUST
use only authorized candidates. An unavailable candidate source MUST deny. A
fallback that scores the tenant corpus in process MUST bound both the number of
records and the total content it loads (reference: 1,000 records and 64 MiB of
UTF-8 content) and MUST deny with category `defer` above either bound. Index
maintenance SHOULD plan from metadata and load content only for the documents it
re-indexes, in bounded batches.
Embeddings and index metadata are protected derivatives of their source.
An index entry MUST derive its compartment, audiences and project requirements from
the document's effective label (R25), never from content or model output. When the
authoritative record and the index disagree, or an index update fails, the record
remains authoritative: the document MUST NOT become more readable, and the
implementation SHOULD reconcile the index (including removal of chunks of inactive
or expired documents). Index chunks SHOULD NOT contain plaintext beyond what the
embedding requires.

**R27 — Origin.** Every knowledge object carries `origin`, a closed enumeration
`human | system | model`. Memory and generated artifacts are always `model`.
A missing or unknown origin MUST deny. Origin is provenance evidence only: no
decision may grant, label or elevate anything based on content or origin, and
administrative ingestion MUST NOT accept `model` origin as a document.

**R28 — Tenant-scoped revocation.** Revocation epochs are per tenant. A context
binds to its tenant's epoch; revoking or changing security metadata advances only
that tenant's epoch and invalidates only that tenant's contexts. A context of a
revoked run cannot be revived; the run MUST be re-provisioned.

**R29 — Decision categories.** A deny decision carries a category: `deny` for a
definite policy denial, `defer` when authorization could not be established
(invalid input, missing records, malformed authority data, exhausted budgets or
an unavailable required service). Both are denials. Public responses MUST NOT
reveal the code or category; audit records SHOULD retain them.

| Code | Category | Meaning |
|---|---|---|
| `INVALID_REQUEST` | defer | Malformed decision input |
| `NOT_AUTHORIZED` | defer | Principal, grant or resource not found |
| `INVALID_CONTEXT` | defer | Malformed authority data: role cycle/budget, invalid origin or container chain |
| `IDENTITY_BOUNDARY` | deny | Kind, liveness or tenant mismatch |
| `INVALID_DELEGATION` | deny | Grant chain, lifetime, attenuation or role activation invalid |
| `OUT_OF_SCOPE` | deny | Action, resource or purpose outside the grant |
| `UNSUPPORTED_OBLIGATION` | deny | Declassification requested |
| `SOD_VIOLATION` | deny | Static or dynamic separation of duty |
| `KNOWLEDGE_BOUNDARY` | deny | Clearance, audience, project, container or source check failed |

Checks are evaluated in the table's order after request validation. Adapters MAY
add `POLICY_DENIED` (deny) and `POLICY_UNAVAILABLE` (defer) for supplemental policy.
Outside decide(), an operation MAY end with `BUDGET_EXCEEDED` (defer) when a
published load, hydration or retrieval budget is exhausted before a decision can
be made; the attempt MUST be audited and MUST deny. When a transaction fails for
another reason (for example a database error) the implementation SHOULD audit the
attempt as `STORE_ERROR` (defer) in a separate transaction, best effort, without
changing the failure the caller receives.

**R30 — Scalable storage.** A shared deployment MUST NOT require loading all
tenants' state to decide. Authority records SHOULD be stored per record type with
the tenant as an indexed column. Where the database supports it, row-level
security MUST restrict every tenant table to the transaction's tenant, MUST be
forced for the table owner, and the runtime role MUST be neither superuser nor
able to bypass row-level security. One tenant's authorize–act–audit transaction
MUST be linearizable; tenants SHOULD proceed in parallel. A decision over a
partial snapshot MUST first load the full closure it can reach (grant ancestry,
principals, group memberships, role hierarchy, sources, containers, run contexts,
constraints, epoch). A load MUST NOT be silently truncated: a store either returns
everything requested, including the closure it names, or aborts, and the caller
denies with category `defer`. Bounds MUST count requested names, including names
without a record, because a role name without a record reads as a flat role (R22)
and would otherwise hide an inactive role. Record keys MUST include the tenant:
the same identifier in two tenants denotes two unrelated records, a write MUST NOT
change a record's tenant, and an administrative request naming another tenant's
identifier MUST be indistinguishable from one naming an unused identifier.
Loads MUST filter by tenant in addition to row-level security. An implementation
MUST refuse to serve (at start-up and in readiness) when its runtime role is a
superuser or bypasses row-level security, unless an operator explicitly opts out
for local development. Each tenant has its own hash-chained audit stream. Readiness checks MUST
be bounded (for example, a tail window verified against a stored head).
Schema migrations MUST be versioned, serialized and checksum-verified.

**R31 — Administrative separation.** Identity, role, group, constraint, grant
and revocation changes require a `security-admin`; container and document
changes, including retiring a document, require a `kb-admin`; audit reads require
an `auditor`. Retiring a document MUST advance the tenant epoch like a
revocation. Administrators are active users of the same tenant whose standing
roles (R22, R24) include the role. Every administrative attempt MUST be audited,
including an attempt answered from an idempotency cache (whose caller MUST be
re-authorized before the stored response is replayed) and an attempt whose
transaction failed (R29). Administrative operations MUST NOT be reachable with
agent credentials or through model output.

## Compatibility and evidence

Wire routes remain `/v1` and response envelopes are unchanged. Storage moves to
`akac-state/0.3`; `akac-state/0.1` is upgraded on load (documents `system`,
memory and artifacts `model`, every tenant inheriting the former epoch; the old
global audit chain is retained verbatim and verified with its original rules).
Contexts created under 0.2 carry the old core revision and deny. See
[migration](../docs/MIGRATION-0.3.md) and [conformance](CONFORMANCE.md).
