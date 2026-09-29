# ADR 007: knowledge lifecycle — quarantine, blast radius, retention, legal hold, erasure

Status: proposed for reference 0.4.0; internal review only, external security and
legal review outstanding. Requirements: [0.4 knowledge lifecycle draft](../spec/drafts/0.4-knowledge-lifecycle.md).
Operator guide: [RETENTION.md](../docs/RETENTION.md).

## Context

Through 0.3 a record was either active or not. That was enough to retire a
document, but not to respond to poisoning (OWASP LLM04; OWASP Agentic ASI06
memory and context poisoning): an operator who learns that a document was
poisoned needs to stop its use and the use of everything derived from it now,
find the derived records, and later either clear or destroy them. Nor could a
deployment remove content on request (GDPR Art. 17), keep it while a legal hold
applies, or expire it on a retention schedule.

decide() already walks the provenance DAG (`visible()` checks every transitive
source), so the cheapest sound design is to make lifecycle part of what that walk
checks.

## Decision

1. **One optional `lifecycle` field, orthogonal to `active`.** Values
   `quarantined` (reversible) and `erased` (terminal). Absent is normal, so 0.3
   records and stores keep their meaning. `visible()` rejects any node whose
   `lifecycle` is present, so decide() stays a single check with no new code
   path, and an unknown value fails closed. We rejected a single status enum
   replacing `active` (would change the meaning of every stored row and every
   existing vector) and separate booleans (more combinations to reason about).
2. **Lazy transitive denial plus explicit cascades.** Quarantine rewrites one row
   and hides the whole lineage through the existing traversal: it is O(1) and
   works for lineages of any size. Lineage revocation and erasure additionally
   rewrite every descendant, because derived content may contain the data being
   removed; they are bounded (1000 records) and change nothing when the bound is
   exceeded (deferred denial). Operators quarantine first when a lineage is large.
3. **Roles.** Quarantine: kb-admin or security-admin (fast containment by the
   people who curate content). Release, erasure, lineage revocation, legal hold,
   retention: security-admin only (separation of duty between containing and
   clearing). Blast-radius reads: auditor or security-admin.
4. **Reverse provenance without an edge table.** PostgreSQL traverses
   descendants with a recursive CTE over `sources @> '[{"id": …}]'`, served by a
   GIN `jsonb_path_ops` index (migration 005). We considered a separate edge table
   `akac_knowledge_sources`; it would be a second copy of the provenance that the
   adapter (and every future writer, including legacy import) must keep in sync,
   and a missed edge would silently shrink an erasure cascade. With the index,
   `sources` remains the single source of truth and no backfill is needed; the
   table keeps its forced RLS from migration 001. Traversal is bounded (depth
   128, 8192 visited edges) and reports truncation.
5. **Tombstones, not deletes.** Erasure keeps id, tenant, version, kind, origin,
   classification and source ids (pseudonymous), empties the content and the
   reader list, and marks the row inactive and `erased`. Keeping the row keeps
   descendants denied, keeps the id burned (a new document version with that id
   is refused), and keeps audit entries interpretable. A database CHECK requires
   empty content on erased rows.
6. **Retention and legal hold are record attributes.** `retainUntil` is set by the
   kb-admin at ingestion (and inherited by derived records as the earliest of
   their sources); it does not end access, which remains `accessExpiresAt`.
   `legalHolds` is a list of hold ids so independent matters can hold the same
   record; a hold anywhere in the lineage blocks erasure, and the refusal reports
   only a count. The retention job is resumable by id cursor and audits every
   erasure separately.
7. **Scanner and memory review fail toward quarantine.** An ingestion scanner's
   error, timeout or unknown verdict quarantines (or rejects, by configuration);
   it never indexes. Model-origin memory review is an engine option
   (`memoryReview`, global or per tenant function) rather than tenant state: the
   state schema has no tenant settings collection, and adding one only for this
   would need its own administrative surface. A failing per-tenant selector
   quarantines. Default is no review, keeping 0.3 behavior.
8. **Security revocation and legal hold survive new versions.** A document
   version replaces the stored record, so a version must not become a way around
   a security decision. `revoke` (knowledge) and `revokeLineage` set a durable
   `revokedAt` marker (a nullable column added to migration 005, which is not yet
   released); `upsertKnowledge` carries it over and refuses a version with
   `active: true` (CONFLICT). Only a security-admin `reinstate` clears it, for that
   record only (descendants stay revoked until reinstated individually), and
   advances the epoch. We considered silently forcing such versions inactive; a
   refusal is explicit and audited. A kb-admin removal sets no marker, so the
   kb-admin can still reverse its own retirements. Likewise a legal hold keeps the
   held record's `content` and `sources`: a version that changes either is
   refused with CONFLICT and a `held` count; metadata-only versions (labels,
   readers, activity, retention) remain possible. A hold on a descendant does not
   freeze the ancestor's content (derived records are never rewritten by a
   version of their source, and their own content stays held).
9. **No new reason codes.** Lifecycle denials are `KNOWLEDGE_BOUNDARY`; a legal
   hold refusal is `CONFLICT`; a scanner rejection is audited as
   `ingest_rejected` with `DENIED:INVALID_REQUEST`. Denials stay
   non-distinguishing and the audit and decision schemas are unchanged.

## Consequences

- Quarantine is immediate and complete for every gate, including retrieval
  (every candidate is re-checked); stale vector chunks can cost recall, never
  disclose content. The ingestor drops lineage chunks eagerly and reconcile
  re-checks the ancestry of every indexed document that has sources.
- Erasure removes content from the authoritative rows and the vector index. It
  does not reach backups, WAL history, dead tuples before VACUUM, logs of
  integrations, or copies outside AKAC; RETENTION.md states the operator's
  obligations. Crypto-shredding is not implemented.
- Lineage bounds mean very large lineages cannot be erased in one operation by the
  reference implementation; they can always be quarantined.
- Audit entries are never rewritten; their retention is a separate policy.

## Evidence

`tests/lifecycle.test.ts` (memory and SQLite stores, including a fast-check
property that no gate discloses an erased lineage), `tests/lifecycle-postgres.test.ts`
(RLS-bound runtime role, migration from a database at 004 and 007),
`conformance/vectors-0.4.json` cases L01–L08.
