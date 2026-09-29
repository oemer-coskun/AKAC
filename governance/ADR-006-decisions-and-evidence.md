# ADR 006: structured decisions and verifiable audit evidence

Status: proposed for reference 0.4.0; internal review only, external security
review outstanding. Requirements: [0.4 decisions and evidence draft](../spec/drafts/0.4-decisions-evidence.md).

## Context

Through 0.3 a decision left two artefacts: an opaque `NOT_AUTHORIZED` or a result
for the caller, and a hash-chained audit entry whose reason was a free-form
string. Nothing linked the two, callers had no machine-readable way to learn the
conditions attached to an allow, and an auditor could verify a chain only by
holding all of it. A signed checkpoint (format 1) signed the last entry hash:
enough to detect a rewrite of a held stream, not to prove to a third party that
one entry is part of a history or that a later history extends an earlier one.

## Decision

1. **Decision records.** Every engine and control-plane decision gets a UUIDv4
   `decisionId`, a closed reason code with the existing R29 category, the policy
   revision and a `policyDigest` (SHA-256 over the RFC 8785 form of the revision
   components, so `a|b`+`c` and `a`+`b|c` differ). The id is returned; the code is
   recorded in audit only, keeping denials non-distinguishing.
2. **Obligations, draft-aligned.** Allows carry a closed obligation set. The
   shape follows the AuthZEN Authorization API 1.0 (Final) plus its obligations
   working-group draft; because the latter is a draft AKAC says "draft-aligned".
   Unknown obligations deny (`UNSUPPORTED_OBLIGATION`); a PEP that cannot enforce
   one denies. The reference runtime is such a PEP. The OPA adapter accepts an
   optional `obligations` array next to the unchanged `{allow, revision}`.
3. **Result shape.** `Result` gains `decisionId` (both branches) and
   `obligations` (allow) as top-level members rather than inside `value`, so
   existing consumers of `value` are unaffected and the HTTP body (which is the
   Result) stays a closed, non-distinguishing envelope.
4. **Audit format 2 with RFC 8785.** New entries add `formatVersion`,
   `decisionId`, `reasonCode`, `policyDigest`, `obligations`, `runId`, `traceId`
   and are hashed over their JCS form. A small canonicalizer covers exactly the
   JSON subset evidence uses and rejects everything else. The chain continues
   across the format change; verifiers select the rule per entry and reject
   downgrades.
5. **RFC 9162 Merkle tree per tenant stream.** Leaf `sequence - 1` is
   `H(0x00 || JCS(entry))`. PostgreSQL stores every complete perfect subtree in
   `akac_audit_node` (append-only, forced RLS): an append adds the leaf and the
   subtrees it completes, computed from the frontier loaded with the audit head
   (O(log n) rows, one extra indexed read per transaction). Proofs need O(log² n)
   nodes in one query and never read entry content. The memory and SQLite
   developer stores recompute from the stream (O(n)). Migration 004 backfills the
   nodes of existing format 1 entries in SQL; a test proves byte equality with the
   TypeScript leaves, including strings that need escaping.
6. **Checkpoint format 2.** Ed25519 over the JCS form of `{format, stream,
   treeSize, rootHash, issuedAt, keyId}`. `scripts/checkpoint.ts` recomputes the
   root from the entries (not from stored nodes) and cross-checks the store.
   Two checkpoints are linked by a consistency proof, which detects forks,
   truncation and rollback without the entries. Format 1 stays verifiable.
7. **Auditor library functions.** `ControlPlane.auditProof`, `auditConsistency`
   and `latestCheckpoint` (auditor role, each audited). A server-held signing key
   is optional and documented as weaker than an offline key.

## Alternatives considered

- *Reason codes in HTTP bodies*: rejected; it would make hidden and absent
  objects distinguishable (R29).
- *Recomputing proofs from entries*: O(n) per proof; rejected for PostgreSQL.
- *Storing only the frontier*: O(log n) per append but O(n) per historical
  proof; rejected in favour of storing all perfect subtrees (about 2n rows).
- *Re-hashing format 1 entries with JCS*: would break every existing chain and
  checkpoint; rejected in favour of per-entry format selection.

## Consequences

Callers must handle `obligations` (or deny). Clients comparing whole results must
ignore the random `decisionId`. The node table roughly doubles audit row count.
A checkpoint key held by the gateway is convenient but not independent evidence;
operators should sign with `scripts/checkpoint.ts` and anchor externally.
`destination_restricted` is issued by the destination profiles of ADR-008 and
enforced by the reference runtime; a caller that cannot enforce it must deny.
