# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Upgrade steps for each release are in the
`docs/MIGRATION-*.md` files. No external security review, audit or certification has taken place for any release.

## 0.6.0 - 2026-09-30

- Identity and authority: delegation chains, break-glass grants, approval quorum, heartbeat-bound grants.
- Post-quantum-ready checkpoint signatures with crypto agility.
- Release protection and knowledge semantics: derived-knowledge classification inheritance, write-down rule, cascade erasure.
- Security classes SK-1 to SK-4; formal model and conformance independent of the reference implementation.

## 0.5.0 - 2026-09-29

- Runtime containment contract: AKAC decides, the runtime enforces.
- Runtime profile obligations and an enforcer seam with execution-level evidence.
- Conformance profile for runtime containment.

## 0.4.0 - 2026-09-29

- Structured decisions with reason codes and obligations.
- Verifiable Merkle audit with inclusion and consistency proofs and signed checkpoints.
- Knowledge lifecycle: quarantine, retention, legal hold, lineage revocation.
- Destination profiles, AuthZEN interface and DPoP sender-constrained tokens; MIT-0 licensing.

## 0.3.0 - 2026-09-29

- Hierarchical roles, groups, separation of duty, knowledge bases and folders.
- Permission-aware vector retrieval with PostgreSQL row-level security.
- Admin control plane with SCIM subset and audit export.

## 0.2.0 - 2026-09-28

- Signed access-token verification and protected model-provider boundary.
- Signed audit checkpoints and a Python decision evaluator with differential tests.

## 0.1.0 - 2026-09-28

- First draft specification and reference gateway: role and attribute checks, bounded delegation, authorized-first retrieval, protected memory, audit chain.
- Portable conformance vectors.
