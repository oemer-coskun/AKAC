# Supported behavior

Status column describes reference 0.6.0 (specification 0.6, a draft project specification). Rows first present in 0.4 are marked (0.4), rows first present in 0.6 are marked (0.6). "Tested" means exercised by the repository's own tests, not independently validated: no external review, penetration test, audit or certification of any part of AKAC has taken place.

| Capability | Status (0.6) |
|---|---|
| User/agent binding and role/attribute checks | Implemented |
| Hierarchical roles, groups, static and dynamic separation of duty, session role activation | Implemented (R22-R24); bounded closures, cycles deny |
| Knowledge bases and folders with inherited audience and classification floor | Implemented (R25); depth-bounded |
| Bounded delegation and ancestor validation | Implemented; issued through the audited admin API or the library |
| Source ACL intersection, provenance versions, transitive derivation labels | Implemented |
| Authorized-first bounded lexical retrieval | Implemented (default; 1,000 records, 64 MiB) |
| Permission-aware vector retrieval | Implemented (R26): per-compartment partitions, token pre-filter on the user and (0.6) the agent audience, authoritative re-check |
| Embeddings, chunking and vector index | Deterministic chunker; `HashEmbedder` (dev/test, lexical only); OpenAI-compatible `HttpEmbedder` (tested against a local stub server only); memory index partitioned per tenant and compartment |
| pgvector compartment tables | Implemented (`migrations/002`, `PgVectorIndex`): forced RLS, token pre-filter, HNSW with iterative scans; tested on PostgreSQL 17 with pgvector 0.8; recall tested on synthetic data only |
| Dedicated database for the `restricted` compartment | Implemented as `RoutedVectorIndex` and `AKAC_VECTOR_RESTRICTED_DATABASE_URL`; the separate instance, network and key custody are deployment responsibility |
| Vector reconciliation, relabel and revocation | Implemented (`Ingestor`): `INDEX_PENDING`, `reconcile`, `relabel`, removal of inactive or expired documents; bounded per call |
| Hybrid lexical/vector fusion, passage-level results | Outside the Community implementation; no claim of supported private implementation is made here |
| Indexing of derived memories | Not implemented |
| Memory derivation and recipient checks | Implemented |
| Memory and SQLite persistence | Implemented; partitioned per tenant, one coarse transaction, single node |
| PostgreSQL normalized storage with forced RLS, per-tenant locks, per-tenant audit streams | Implemented (R30); verified against PostgreSQL 17 in local runs; a hosted CI result for 0.4.0 is not recorded |
| Refusal of superuser or `BYPASSRLS` runtime role | Implemented at start-up and in readiness; local-development opt-out only |
| Checksum-verified serialized migrations, import of the 0.2 state | Implemented |
| Admin control plane (REST, port 8788) with role separation and audit of every attempt | Implemented (R31) |
| SCIM 2.0 subset (Users, Groups, discovery; deprovisioning under SoD) | Implemented subset; interoperability with specific identity providers not tested |
| Interactive SSO and external document connectors | Not implemented |
| Signed access-token verification | Implemented with issuer/audience/type/algorithm checks and trusted mappings, for agent and admin listeners |
| OPA policy enforcement | Implemented; policy and real-server tests passed |
| Metrics (Prometheus), structured logs, request and trace ids | Implemented; alert rules are suggestions, not validated on production traffic |
| Container deployment | Compose example (SK-1) tested locally and in hosted CI; no Kubernetes material in this repository |
| OpenAPI (agent and admin), schemas and portable vectors | Included |
| Provider isolation / outbound proxy | Deployment responsibility; not supplied. Destination profiles (0.4) let AKAC decide and audit release targets; a proxy or gateway must enforce them |
| Declassification / cross-tenant federation | Denied |
| Retention, legal holds and erasure of knowledge content (0.4) | Implemented as mechanisms (R53-R59): `retainUntil`, legal holds anywhere in the lineage, cascade erasure to tombstones, retention job; not legally reviewed |
| Erasure from backups, replica history and storage remnants | Not implemented; deployment responsibility |
| Signed audit checkpoints | Implemented and tested (format 1 and, in 0.4, format 2); 0.6: `CheckpointSigner` with a Vault Transit example adapter (tested against a mock only), keyring rotation, file anchoring hook and a verify job; network anchoring is not shipped; a server-held key attests only what that server saw |
| Shared rate limits, admin idempotency, job locks (0.6) | Implemented over PostgreSQL (migration 009, forced RLS) and tested with two gateway instances on one database; concurrency caps stay per instance; no availability or RTO figure is claimed |
| Logical source expiry | Implemented transitively; physical removal of content only through erasure (R53) |
| Provider input/output adapter | Implemented; synthetic-provider tests, no network sandbox |
| Python decision interoperability | Same-project generated comparisons for the 0.2 and 0.3 decision rules; not external certification. The Python evaluator does not implement the 0.4 lifecycle or destination decisions |
| Control mapping to external frameworks | Outside the Community scope; no certification or attestation |
| Structured decisions: decision id, closed reason codes, policy digest, obligations (0.4) | Implemented (R32-R39); obligation shape is draft-aligned with the AuthZEN working-group draft, not a conformance claim |
| Obligation enforcement | `ProtectedRuntime` enforces the four obligations; any other caller must enforce them or deny |
| Runtime obligations on the agent HTTP listener (0.6) | The listener cannot confine the runtime that receives content. By default (`AKAC_RUNTIME_OBLIGATIONS=deny`) a disclosure whose allow would carry `runtime_profile` is denied (`UNSUPPORTED_OBLIGATION`), rolled back and audited. `trusted-enforcer` returns the obligations and is an operator declaration that every client runs inside a runtime enforcer; AKAC cannot verify it ([RUNTIME-CONTAINMENT.md](RUNTIME-CONTAINMENT.md)) |
| Read-only share/export evaluation without a destination (0.6) | Denied (`RECIPIENT`) over `Engine.evaluate` and AuthZEN, for every run; the enforcement point must name the Destination ([AUTHZEN.md](AUTHZEN.md)) |
| Audit format 2 (RFC 8785), RFC 9162 Merkle tree, inclusion and consistency proofs (0.4) | Implemented (R40-R44); verified with independent verifiers written for the tests; not verified against third-party RFC 9162 implementations |
| Quarantine, blast radius, memory review, ingestion scanner hook (0.4) | Implemented (R45-R52); no scanner is supplied, only the hook |
| Destination profiles and run result limits (0.4) | Implemented (R60-R71) as decisions; egress enforcement is not supplied |
| DPoP sender-constrained tokens (0.4) | Implemented (R72-R78), optional per listener; no server nonces, no mutual-TLS binding; the in-memory replay store is per instance, PostgreSQL store shared; tested with the repository's own signer only |
| AuthZEN PDP facade (0.4) | Implemented (R79-R90), optional, off by default: Access Evaluation and Access Evaluations. Search APIs, signed metadata and capability URNs not implemented; not interoperability-tested with third-party enforcement points |
| Cache isolation (0.4) | Operator obligations (R91-R99); not enforceable by the reference |
| Adversarial conformance: outcome classes, hard gates, scenario vectors, broken-oracle tests (0.4) | Implemented (R100-R108); same-project evidence |
| Runtime obligations, share/export destinations, label widening, tombstones (0.6, R121..R126) | Implemented: destination-less share/export evaluations and unreachable destination classes deny (`RECIPIENT`); the HTTP listener denies `runtime_profile` obligations by default; the revision is re-confirmed after the final release; a label-widening version needs `security-admin`; a tombstone names no readers |
| Heartbeat-bound grants, RFC 8693 actor chains, break-glass, approval quorum, risk signals, tenant settings (0.6, R-ID) | Implemented (migration 010, ADR-019). Approvals need N distinct `security-admin` identities (quorum 1 by default, break-glass fixed at 2); `ApprovalGate` and `RiskProvider` are hooks with no implementation shipped: no workflow engine, no IdP or CAEP connector, no external identity-governance integration |
| Release filter and derive sanitizer hooks (0.6, R-REL) | Interfaces, ordering and fail-closed handling only. AKAC ships no PII redaction, sanitizer, canary or content classifier; an operator module (`AKAC_HOOKS_MODULE`) supplies them |
| Response-time floor, opt-in denial hints, volume budgets, progressive backoff, decision cache (0.6) | Implemented, off by default. Budgets are shared through PostgreSQL; backoff and the decision cache are per process; the floor hides neither network timing nor work done before AKAC ([RELEASE-PROTECTION.md](RELEASE-PROTECTION.md)) |
| Embedding anchors (0.6) | Implemented for vector retrieval: drift of a hosted embedder on fixed probe texts disables retrieval until re-baselined (`POST /admin/v1/index/anchors/rebaseline`); does not prove the embedder honest and does not re-embed the corpus |
| Lineage depth, modality, tags, residency, combination rules, write-down rule, model lineage, ephemeral session knowledge, cascade sweeper, pending erasure under legal hold (0.6, R-KNOW; migration 011) | Implemented as decisions and mechanisms. Residency is checked at release against destination regions; jurisdiction attributes, region hierarchies and policy packs are not implemented |
| Content encryption at rest and crypto-shredding (0.6, R195) | Per-record content keys behind a `KeyProvider` interface; only a development provider ships and it is refused when `NODE_ENV=production`; no KMS or HSM provider is included, so a production deployment needs one from an extension. Labels, ACLs, provenance and audit metadata stay in the clear; embeddings of restricted content are not encrypted by AKAC. Erasure reaches backups only if the key material is not in the same backup |
| Crypto agility (0.6, R-CRYPTO; ADR-021) | Algorithm registry with Ed25519, ML-DSA-44/65/87, SLH-DSA-SHA2-128s/256s and the Ed25519 + ML-DSA-65 hybrid on `node:crypto` (Node 24); checkpoint format 3; format 2 Ed25519 stays the default and needs no change. Tested with the repository's own vectors, not against independent implementations; the Vault Transit signer signs Ed25519 only |
| Conformance coverage matrix, mutation testing, formal model, Python parity (0.6) | Same-project evidence. The coverage matrix and mutation runs find gaps in the repository's own tests; the bounded TLA+ model checks seven safety properties of a small finite world with TLC and is not a proof for unbounded systems or of the TypeScript code; the Python evaluator covers the decision rules listed in its README |
| Scheduled jobs (0.6): retention, cascade sweep, audit verification | Scripts, serialized per tenant by the PostgreSQL job lock; not exercised against production traffic |
| Upgrade 0.5 to 0.6 and rollback | Forward path in [MIGRATION-0.6.md](MIGRATION-0.6.md), not rehearsed by the project on a real deployment; there are no down migrations and rollback is untested, so unsupported |
| Complete scalable multi-tenant production platform | Not claimed |

The agent API has no endpoint for changing identities, ACLs, grants or policies. Administration is a separate listener with separate credentials and audited standing roles. The seed, revoke and reconcile scripts illustrate the boundary using synthetic identities.
