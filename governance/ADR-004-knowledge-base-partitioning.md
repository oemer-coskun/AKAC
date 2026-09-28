# ADR 004: knowledge bases, classification compartments and vector partitioning

Status: accepted for reference 0.3.0; external security review outstanding.

## Context

Enterprise deployments organize knowledge into knowledge bases and folders, and
retrieve it through embedding indexes. Three layouts are common:

1. **One shared index with metadata filtering.** Cheap and flexible, but a single
   filter defect or a post-filtering retriever discloses everything. Unfiltered
   similarity scores, index statistics and approximate-nearest-neighbour recall
   also leak across permission boundaries (OWASP LLM08).
2. **One index per permission set.** Strong isolation, but the number of distinct
   ACLs grows combinatorially with roles, users and projects. Every ACL change
   moves or re-embeds content, which makes revocation slow and error prone.
3. **One folder or storage prefix per security level.** Easy to explain, but a
   folder alone is not an access decision: it does not model roles, projects,
   derivation or delegation, and misfiled documents inherit the wrong boundary.

## Decision

Use a layered design. Partition physically only along **stable, low-cardinality**
dimensions; express fine-grained permissions as **pre-filters**; and keep the
AKAC decision function the only authority.

| Layer | Boundary | Mechanism | Purpose |
|---|---|---|---|
| L1 | Tenant | Separate PostgreSQL row-level-security scope and a separate vector namespace | No cross-tenant candidate can be scored |
| L2 | Classification compartment | One vector collection per `(tenant, classification)`; one object-storage prefix and data key per compartment | Callers never query compartments above `min(user clearance, agent clearance)`; a filter bug cannot reach higher tiers |
| L3 | Knowledge base and folder | Hierarchical containers; a folder sets a classification floor and an ACL that every descendant must also satisfy | Familiar "folder per security level" administration, without making folders the authority |
| L4 | Document and chunk ACL | Principal tokens (`role:`, `user:`, `project:`) stored on every chunk and applied as a pre-filter inside the index query | Unauthorized chunks never enter similarity ranking |
| L5 | Authoritative re-check | `decide()` on every candidate, with transitive source checks, before any content leaves the gateway | Index metadata can be stale; the gateway cannot be |

Chunks inherit the effective label of their document: the highest classification
among the document and its ancestor folders, the intersection of all ancestor
ACLs and the union of project requirements. Moving a document between
compartments re-indexes it; any other ACL change updates chunk metadata and
advances the tenant epoch.

Dedicated databases per compartment remain an operator option for the
`restricted` tier (separate instance, network segment and key custody). The
`VectorIndex` adapter contract makes this a deployment choice, not a code fork.

## Consequences

- An index query can never return a chunk above the caller's compartment, even if
  metadata filtering fails.
- Index metadata is an optimization. A chunk that passes the index filter but
  fails `decide()` is dropped, counted in metrics and audited as a filter mismatch.
- Relevance scores are computed only over authorized candidates. Empty results do
  not distinguish "no match" from "no authority".
- Embeddings are treated as protected derivatives of their source and carry the
  same label; they are never exported through the agent API.
- Re-labelling a document into a different compartment costs a re-index. That is
  accepted: classification changes are rare, security-relevant events.
- Partitioning per individual permission set is rejected as a default.
