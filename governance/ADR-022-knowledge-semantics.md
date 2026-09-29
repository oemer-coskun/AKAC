# ADR 022: knowledge semantics and content encryption

Status: proposed for AKAC 0.6 (draft). No external review has taken place.
Requirements: [AKAC 0.6](../spec/AKAC-0.6.md) (R182..R196).

## Context

0.5 bounded provenance traversal and denied cycles, but put no limit on how many
model generations could be stacked on each other. Labels carried classification,
projects and audiences only: there was no way to express where content may be
processed, which sources must not be combined in one run, or which model produced a
derivation. Revocation and quarantine denied descendants lazily, which is correct but
left stale index entries and no explicit marking. An erasure blocked by a legal hold
was refused and forgotten. Derived memory was always persistent. Content sat in the
database in the clear, so erasure could not reach backups.

## Decision

1. **Pure semantics, engine enforcement.** `reference/knowledge.ts` holds pure,
   bounded functions over one tenant snapshot (closure facts: level, tags, residency,
   generation, session scopes; combination verdicts; residency admission; the
   placement rule). decide() gains only the session-scope check (R190), because a
   session-scoped record must be invisible to every other run like any label. All
   other rules are operation-level conditions in the engine, applied after the 0.5
   gates allowed, so each can only add a denial or raise a label (R196).
2. **Depth per tenant setting.** `lineageDepth` (default 16, at most 127 under the
   128-node traversal bound) lives in the tenant settings so that raising it is an
   approval-gated relaxation (ADR-019). Consolidation is an administrative document,
   never model output (R184).
3. **Attributes are inherited, not trusted.** Tags (union) and residency
   (intersection) are computed over the closure at every use and also stored on
   derived records, like classification. Removing a tag or widening residency on a
   document version is a label widening. Residency is enforced only at egress
   (share/export and the provider gate) against a Destination `region`; a recipient
   without a region receives nothing (fail closed). Region codes are opaque: no
   hierarchy is expanded in the core.
4. **Minimal combination rules in the core.** Tenant rules with two tag sets and a
   `deny` or `uplift` effect cover separation (Brewer-Nash style) and aggregation
   without history outside the run. Richer policy packs (conflict classes, cross-run
   walls, sovereignty) are extensions; to let them narrow, the supplemental policy
   input now carries effective tags, residency and the run's source set (the OPA
   adapter forwards the input unchanged, so existing bundles keep working).
5. **Placement rule instead of a new label model.** Writing derived content into a
   container is allowed only when the placed record's static label is at least as
   narrow as every source's static label, clause by clause. This catches a placement
   that would only be safe because of provenance traversal. Integrity stays with the
   origin rule: model output is never human or system content.
6. **Ephemeral records live in the engine.** `reference/ephemeral.ts` wraps the store
   of an engine: session-scoped records are injected into snapshots and taken out
   before the store commits; they enter the in-memory partition only after the commit.
   Stores refuse to persist one (defence in depth). There is no cross-instance
   sharing and no persistence by design; restart ends every session.
7. **Model lineage from trusted paths only.** The engine takes the model identity from
   its configuration (`AKAC_MODEL_ID`, `AKAC_MODEL_VERSION`) or from an in-process
   trusted caller; the agent API never accepts it. A model recall quarantines by id and
   version range and sweeps the lineage.
8. **Sweeper as hygiene, not authority.** `reference/sweeper.ts` drives bounded,
   audited, resumable control-plane batches under a job lock (`sweep`, `erasure`)
   shared across instances (ADR-016). It quarantines descendants
   (`ancestor_revoked`, `poisoned`) or raises stale stored classifications and keeps
   the index in step. The admin listener runs it in the background after lifecycle
   changes when configured; lazy denial stays authoritative when it does not run.
9. **Pending erasure.** An erasure blocked by a hold is stored (`erasureRequestedAt`)
   and runs once no hold blocks it (pending-erasure job, triggered by lifting a hold,
   by the endpoint or on a schedule). The response is 409 with `pending: true`.
10. **Content encryption as a store wrapper.** `reference/content-crypto.ts` seals
    content with AES-256-GCM under a fresh key per record version, wrapped by a
    `KeyProvider` under per-record key material; erasure destroys that material after
    commit (crypto-shredding). Unchanged records are written back byte-identical, so
    reads never rewrite rows. The community edition ships only a local development
    provider (a 0600 key file, refused in production); KMS and HSM providers are
    extensions implementing the same interface. Off by default.
11. **Migration 011.** New nullable columns (knowledge, containers, destinations,
    settings), the widened quarantine reason check, indexes for model recall and
    pending erasures, and `akac_combination_rules` keyed by (tenant, id) with forced
    row-level security.

## Consequences

- New closed reason codes: `LINEAGE_DEPTH`, `RESIDENCY`, `COMBINATION`, `WRITE_DOWN`.
  New quarantine reasons: `poisoned`, `ancestor_revoked`, `model_recall`.
- Every decision closure loads the tenant's combination rules (bounded, 256).
- Residency-bound content cannot be shared with principals that lack a Destination
  profile with a region: operators must provision profiles before setting residency.
- Ephemeral sessions are instance-local; load balancers need session affinity for
  them, and a restart loses them (by design).
- A local key file in the same backup as the database defeats crypto-shredding; the
  key material belongs in a separate trust domain (KMS/HSM, not included).
- The Python implementation ports the decision semantics (depth, combination,
  residency, placement, modality inheritance, session scope) and runs the same vectors;
  the sweeper, content encryption and pending-erasure job are TypeScript only.

## Alternatives considered

- Enforcing combination rules in decide(): rejected, a single-resource decision cannot
  see the run's accumulated sources; the operation level can.
- Residency checks on reads: rejected for the core, reads happen inside the gateway
  whose location the operator controls; an extension can narrow further.
- Intersection of source ACLs as the derived ACL: rejected, it would change 0.5
  derivation semantics; the placement rule targets the actual risk.
- Encrypting in the control plane and engine: rejected, a store wrapper covers every
  write path (admin, derive, lifecycle) with one implementation.

## Amendment (0.6b, second review round)

- **Unreadable is not erased (R195).** Only a `KeyDestroyed` rejection of the key
  provider makes a record read as erased. Any other failure marks the record with an
  internal, never persisted `unreadable` flag: gates hide it (decisions on it defer with
  `STORE_ERROR`), and the encrypting store refuses to commit any transaction that changes
  it, so a key service outage can no longer tombstone a held record and shred its key.
  decide() treats the flag like a lifecycle state (Python implementation and differential
  generators updated).
- **Combination window (R188).** Disclosures check combination rules over what the
  same (tenant, user, agent) read under any grant in contexts alive during the window
  (default 300 s, configurable up to 30 days), loaded by a bounded per-pair query; this
  narrows the "history across runs" gap listed under Not covered for the same pair.
