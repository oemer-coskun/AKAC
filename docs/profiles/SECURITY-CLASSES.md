# Security classes (Schutzklassen)

Four classes group AKAC features by the assurance a deployment needs. A class is a **configuration and obligation
bundle**, not a certification: choosing SK-3 does not make a deployment compliant with any law, and no class has been
reviewed by an external party. Editions are described in
[EDITIONS.md](../EDITIONS.md). Items marked **implemented in 0.6** exist in the 0.6 reference (same-project tests only); items marked **planned** are not
implemented, and a deployment that needs them cannot claim the class until they ship.

| Class | Name | Typical use |
|---|---|---|
| SK-1 | Basis | Internal assistants over unregulated material; one team; low impact of disclosure |
| SK-2 | Enterprise | Multi-tenant SaaS or a company-wide deployment under ISO/IEC 27001 or SOC 2 style controls |
| SK-3 | Regulated | Finance, health, legal, insurance: regulated data, audits, incident reporting |
| SK-4 | High-Assurance | Classified or export-controlled material, critical infrastructure, defence, crown-jewel IP |

SK-1 is public and deploys with Docker Compose ([SK-1.md](../SK-1.md)). Presets and production deployment for SK-2 to SK-4, and industry profiles, are part of the full package (see [CONTACT.md](../../CONTACT.md)).

## Feature by class

R = required, Rec = recommended, O = optional, - = not needed. Status is that of the reference.

| Feature | Status | SK-1 | SK-2 | SK-3 | SK-4 |
|---|---|---|---|---|---|
| Core: `decide()` on every read, derive, release; tenant isolation; audit chain | Implemented | R | R | R | R |
| PostgreSQL with forced RLS, non-owner runtime role | Implemented | O (SQLite for one node) | R | R | R |
| Default-deny network policy, restricted workload security settings | Operator | Rec | R | R | R |
| Shared state over PostgreSQL, more than one replica | Implemented | - | R | R | R |
| Signed audit checkpoints | Implemented | O | R (server key) | R (KMS key: Vault Transit Ed25519, see note) | R (PQ-hybrid key in an HSM, extension signer, see note) |
| External anchoring of checkpoints, daily audit-verify job | Implemented (hook, job) | - | Rec | R | R (hourly verify) |
| DPoP sender-constrained tokens (JWT mode) | Implemented | - | Rec (admin listener) | R | R |
| Runtime containment obligations with a tested enforcer | Implemented (contract) | - | Rec | R | R |
| Destination profiles for every external provider | Implemented | - | R | R | R |
| Quarantine, retention, legal hold, cascade erasure | Implemented | O | R | R | R |
| No hash embedder; embeddings treated as classified data | Implemented (production refusal) | Rec | R | R | R |
| Dedicated database for the `restricted` compartment | Implemented | - | O | Rec | R |
| In-boundary embedding model (no external provider for restricted) | Operator | - | Rec | Rec | R |
| Crypto-erasure (content key per document) | implemented in 0.6 | - | O | R | R |
| Per-tenant keys (cryptographic tenant separation) | planned | - | O | Rec | R |
| Dual control (M-of-N) for label lowering, role widening, policy change | implemented in 0.6 | - | Rec | R | R |
| Break-glass with two distinct security-admins, read-only, at most 2 hours | implemented in 0.6 | - | O | O (if used, dual) | O (if used, dual) |
| Sovereignty gates: residency (jurisdiction attributes are planned) | implemented in 0.6 | - | O | R | R |
| PQ-hybrid checkpoint signatures | implemented in 0.6 | - | O | Rec | R |
| TEE attestation-gated key release | planned (interface) | - | - | O | R |
| HSM custody of signing and content keys | Operator (HSM); signer and key-provider hooks implemented in 0.6 | - | O | Rec | R |
| Timing equalisation, release filter and sanitizer hooks, volume budgets | implemented in 0.6 | - | Rec | R | R |
| Heartbeat-bound grants, RFC 8693 actor chains, risk-signal hook | implemented in 0.6 | - | Rec | Rec | R |
| Access attestation export for recertification | planned | - | R | R | R |
| Embedding anchors against drift | implemented in 0.6 | - | Rec | R | R |
| **Edition** | - | Community | Community; full package optional | Community carries every required feature; the full package typical | Community carries every required feature; the full package typical |

Note on checkpoint keys: at SK-3, key custody in a KMS takes precedence over a post-quantum signature. The SK-3 configuration signs
with a HashiCorp Vault Transit `ed25519` key at a pinned version (format 2); Vault Transit
signs Ed25519 only. Move SK-3 to the hybrid `ed25519+ml-dsa-65` once the KMS signs ML-DSA, through a signer that keeps the key in
the KMS. At SK-4 both are required: the configuration signs hybrid `ed25519+ml-dsa-65` checkpoints (format 3,
[CRYPTO-AGILITY.md](../CRYPTO-AGILITY.md)) with a signer supplied by an extension (`AKAC_CHECKPOINT_SIGNER=extension`,
[ADR-023](../../governance/ADR-023-editions-and-extension-points.md)), for example an enterprise HSM signer. The stock image has no
such signer and refuses to start with the SK-4 configuration; it never falls back to a file-held or classical key. A file-held hybrid key
(`AKAC_CHECKPOINT_ALG` with `AKAC_CHECKPOINT_KEY_FILE`) remains possible for either class as an explicit, recorded deviation.

The Community edition contains every mandatory security semantic for every class. Where a required item is a hook (for example an approval
gate that enforces two distinct approvers), the Community edition defines the contract and a default; a deployment can
satisfy the requirement with its own implementation. The full package adds hook implementations and deployment material.

## SK-1 Basis

**Typical use.** A team assistant over handbooks, wikis and notes that carry no regulated or personal data of
consequence.

**Threat assumptions.** Honest operators; curious insiders; accidental over-sharing by agents; prompt injection that
tries to widen retrieval. No sustained targeted attacker, no external audit.

**Required.** The core; tenant and compartment separation; `decide()` on every read and release; the audit chain.
**Recommended.** Default-deny network policy; a real embedding model
if vector retrieval is used (the hash embedder is not semantic).

**Operator obligations.** TLS and network segmentation between listeners; secrets outside values and prompts; backups
of the database; review of who holds admin credentials.

**Evidence auditors expect.** Configuration export, list of administrators, sample of audit entries. For SK-1 few
audits will ask.

**Deployment.** Public, Docker Compose: [SK-1.md](../SK-1.md). Deployments for SK-2 to SK-4 are part of the full package.


## SK-2 Enterprise

**Typical use.** A SaaS platform serving many tenants, or a company deployment with several projects, departments and
agents; controls mapped to ISO/IEC 27001 Annex A or SOC 2 Trust Services Criteria.

**Threat assumptions.** Malicious or careless tenants; a compromised agent credential; a curious internal
administrator; unreliable model providers. External attackers with network access to exposed listeners. No nation-state
adversary.

**Required.** SK-1 plus: PostgreSQL with forced row-level security and a non-owner runtime role; more than one replica
with shared state; signed checkpoints and the daily audit-verify job; retention and legal hold; destination profiles for
every external provider; no hash embedder; an access attestation export for recertification (planned).
**Recommended.** DPoP on the admin listener; runtime containment; dual control for sensitive admin operations (planned
in 0.6); external anchoring.

**Operator obligations.** Tenant onboarding and offboarding; SCIM provisioning; monitoring and alert routing
(alert rules are not validated on production traffic); backup and restore drills; egress control for destinations.

**Evidence auditors expect.** Policy and role exports, admin action audit, audit-verify job results, retention job
logs, restore drill record, checkpoint anchoring receipts, control mapping walkthrough.


## SK-3 Regulated

**Typical use.** Financial entities, healthcare providers and processors, law firms, insurers: personal data of special
categories, professional secrecy, regulated ICT risk management and incident reporting.

**Threat assumptions.** SK-2 plus: stolen bearer tokens; insider misuse by a privileged administrator; regulators and
auditors who will test erasure, access review and incident evidence; cross-border transfer constraints.

**Required.** SK-2 plus: DPoP on every listener that is not strictly internal; runtime containment with a tested
enforcer; crypto-erasure so that erasure also covers backups (implemented in 0.6; production needs an enterprise KMS or HSM key provider, the local provider is refused); dual control for label lowering, role
widening and policy changes (implemented in 0.6); the residency gate (implemented in 0.6; jurisdiction attributes are planned); checkpoint signing in a KMS
(Vault Transit Ed25519) with external anchoring; timing equalisation, release filter hooks and volume budgets (implemented in 0.6); embedding anchors
(implemented in 0.6).
**Recommended.** PQ-hybrid checkpoint signatures (implemented in 0.6; at SK-3 only once the KMS signs ML-DSA); dedicated database for the restricted compartment;
per-tenant keys; heartbeat-bound grants and risk signals (implemented in 0.6).

**Operator obligations.** Everything in SK-2, plus: legal basis, records of processing and impact assessments (AKAC
records decisions; it does not decide lawfulness); provider contracts and a register of ICT third parties; in-boundary
or approved embedding models; break-glass procedure and its review; backup encryption and restore drills with the
erasure path in mind; incident response that uses the audit export.

**Evidence auditors expect.** SK-2 evidence, plus: erasure and legal-hold records with crypto-erasure proof (since 0.6 the
erasure is audited and key destruction is reported as a metric event), dual-control approval records, break-glass audit events and reviews, anchored checkpoint chain with consistency
proofs, DPoP configuration proof, runtime enforcer test results, residency configuration.


## SK-4 High-Assurance

**Typical use.** Public-sector material with classification markings, operators of critical infrastructure, defence,
export-controlled research, crown-jewel design data. The responsible security authority, not this document, decides
whether a deployment may process such material; AKAC is not approved for any classification level.

**Threat assumptions.** SK-3 plus: a capable, targeted adversary; a compromised host or hypervisor; a malicious cloud
operator; long-term confidentiality (harvest now, decrypt later). Physical attacks on hardware are largely outside what
current confidential-computing products defend.

**Required.** SK-3 plus: TEE attestation-gated key release (planned, interface); a dedicated database for the
restricted tier with its own keys and network; break-glass only with two distinct approvers, if used at all;
external anchoring; HSM custody of signing and content keys; per-tenant keys (planned); PQ-hybrid checkpoint signatures from
the HSM (extension signer; the stock image refuses to start without one);
in-boundary embedding models; **no hash embedder**; hourly audit verification.
**Recommended.** Heartbeat-bound grants, risk signals, RFC 8693 actor chains.

**Operator obligations.** Hardware and firmware supply chain; measured boot and attestation policy; HSM lifecycle;
personnel and physical security; independent review before use; separate administrative domains for security-admin,
kb-admin and auditor.

**Evidence auditors expect.** SK-3 evidence, plus: attestation policy and key-release logs (planned), HSM
audit records, key ceremony records, network and enclave configuration, results of independent review and testing that
the operator commissioned.


## Choosing a class

Pick the class from the data and the adversary, not from the industry. A hospital's wiki can be SK-2; a bank's
public-facing FAQ agent can be SK-1; a manufacturer's turbine design repository can be SK-4. When in doubt, take the
higher class. A class applies to a deployment; an estate with mixed needs runs a stricter deployment (or a
dedicated restricted-tier database) for the material that needs it rather than hardening everything at once.
