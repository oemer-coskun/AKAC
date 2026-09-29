# AKAC 0.1 — Draft Specification

Status: draft. Normative language: English. Normative keyword interpretation: RFC 2119 and RFC 8174. Requirements apply within the declared deployment trust boundary; a conforming implementation MUST publish that boundary.

## 1. Scope

AKAC governs controlled knowledge access and information flow for delegated AI assistants. It standardizes authorization semantics and observable obligations, not a model, vector database or corporate hierarchy. Knowledge includes source documents, chunks, retrieved text, working context, episodic records, semantic memories, procedures and generated artifacts. A procedure can describe an action; it cannot authorize that action.

Confidentiality, epistemic confidence and execution authority are distinct attributes. A high-confidence or repeatedly recalled statement MUST NOT gain authority. Authorizing a knowledge read does not authorize a business transaction.

## 2. Actors and trust

An identity authority authenticates principals. A delegation authority grants bounded work. The policy decision point (PDP) evaluates authoritative attributes. Policy enforcement points (PEPs) mediate all entry and exit paths. The model is an untrusted proposer. Resource ingestion is a trusted administrative operation: labels and ACLs MUST originate from an authenticated authoritative source, not inferred model text.

Agent credentials MUST remain in the trusted runtime. Request bodies MUST NOT override tenant, subject, agent or grant bindings. An implementation MUST declare how it prevents direct storage, tool, network, cache and model-provider bypasses.

## 3. Required knowledge contract

Each knowledge object has a tenant, stable ID, version, kind, classification, audience policy, provenance references and lifecycle state. Versions MUST change whenever content or security-relevant metadata changes. References bind both ID and version. Cyclic, missing, inconsistent or unsupported provenance MUST NOT produce an allow decision.

The reference profile defines public < internal < confidential < restricted. These labels alone do not authorize access: audience rules and project membership also apply. Even public objects remain tenant-scoped in this profile. Implementations MAY define other lattices, but MUST identify them and provide comparison semantics.

## 4. Normative invariants

| ID | Requirement |
|---|---|
| R01 | Every controlled read and release MUST pass an enforcement point; absence of an explicit allow MUST deny. |
| R02 | Identity, tenant and grant bindings MUST be independently verified; model-supplied identity claims MUST NOT authorize. |
| R03 | Cross-tenant access MUST deny unless an explicitly supported federation profile authorizes it. |
| R04 | Effective authority MUST satisfy the user, agent, action, resource, purpose and delegation constraints simultaneously. |
| R05 | Delegation MUST NOT widen action, resource, purpose or time scope; invalid ancestry MUST deny. |
| R06 | Adaptive memory and generated text MUST NOT issue grants, policy exceptions or authoritative labels. |
| R07 | Unauthorized objects MUST be removed before content ranking, generation and observable result metadata. |
| R08 | A derivation MUST retain the restrictions of every protected input in its actual execution context. Model citations are insufficient evidence of complete provenance. |
| R09 | Source restrictions MUST combine by conjunction. Union of readers or use of the highest classification alone is insufficient. |
| R10 | The destination principal and environment MUST be authorized before disclosure. Reading does not imply sharing. |
| R11 | Authorization MUST bind relevant source, policy and delegation versions and MUST remain valid at its enforcement boundary. |
| R12 | Revocation MUST affect dependent artifacts and future accesses. A deployment MUST publish the revocation linearization point and any stale-access bound. |
| R13 | Unsupported obligations, malformed authority and unavailable required policy services MUST fail closed. |
| R14 | Security-relevant decisions MUST be auditable with versioned policy evidence; logs MUST NOT create an uncontrolled disclosure path. |
| R15 | Declassification MUST use a separately authorized, auditable process. The model MUST NOT self-declassify. |
| R16 | State and credentials from a more privileged run MUST NOT be reused in a less privileged run without an enforced reset or equivalent isolation. |

## 5. Authorization semantics

For a read, evaluate the authenticated binding, principal liveness, delegation chain, requested action, purpose, target, tenant, clearance, project membership and audience policy. Any explicit deny wins. Missing information is not an allow. A decision is usable only if all required obligations can be enforced.

The reference audience predicate requires every listed project plus at least one matching reader ID or reader role. It applies separately to the user and agent and recursively to source objects. Organizational seniority is not blanket access.

For a derivation from sources S, allowed recipients must satisfy the current policy of every source in S as well as the output's own policy. Restrictions cannot disappear through repeated summarization or storage. Outputs of a model which read multiple sources conservatively inherit all sources unless a separately verified isolation mechanism establishes a narrower dependency.

## 6. Context and lifecycle

Each run MUST maintain a trusted manifest of actual inputs. A context handle is not an independent permission token. Reusing an earlier handle MUST NOT omit subsequent reads in the same run. Source changes, expired grants and policy revisions require renewed authorization.

Revocation and deletion are distinct. Revocation makes future accesses unauthorized; deleting the original alone does not revoke copies or derivatives. Physical erasure, backups, retention and external recipients require additional lifecycle mechanisms. Revocation cannot undo a completed disclosure.

## 7. Protocol

Requests carry an action, resource or context reference, purpose and optional destination. Authenticated binding comes from the transport adapter. Responses distinguish authorized results from a generic denial; public error details MUST NOT reveal hidden resource existence. Internal decision codes MAY be more specific in an access-controlled audit.

JSON Schema documents define the reference wire representation. Unknown request fields MUST be rejected. API and schema versions MUST be identified. Unsupported major versions MUST deny, not silently downgrade. Extension semantics MUST be explicit; an unenforceable required extension denies.

## 8. Conformance and evidence

Conformance is profile- and version-specific. Implementations MUST publish supported obligations and deployment assumptions. Portable decision vectors test a subset of requirements; runtime isolation and lifecycle properties require integration evidence. Passing the suite does not establish freedom from vulnerabilities or independent certification.

## 9. Security considerations

Prompt injection cannot be allowed to alter authoritative attributes. Still, an authorized but malicious model can misuse already permitted information; access control alone does not ensure safe task behavior. Content detectors MAY tighten a decision, never provide missing authority. Timing, traffic analysis, colluding recipients, compromised administrators, dishonest ingestion and model pretraining leakage are outside the reference guarantee and MUST be documented.

## References

- NIST SP 800-162: https://csrc.nist.gov/pubs/sp/800/162/upd2/final
- RFC 2119: https://www.rfc-editor.org/rfc/rfc2119
- RFC 8174: https://www.rfc-editor.org/rfc/rfc8174
- OPA architecture: https://www.openpolicyagent.org/docs

Licensing: see the repository LICENSE. These sources establish prior art; AKAC does not claim their invention.
