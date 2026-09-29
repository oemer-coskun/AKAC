# ADR 021: crypto agility and post-quantum checkpoint signatures

Status: proposed for AKAC 0.6 (draft). No external review has taken place.
Requirements: [AKAC 0.6](../spec/AKAC-0.6.md) (R159..R166).
Guides: [CRYPTO-AGILITY.md](../docs/CRYPTO-AGILITY.md), [KEY-CUSTODY.md](../docs/KEY-CUSTODY.md),
[CONFIDENTIAL-COMPUTING.md](../docs/CONFIDENTIAL-COMPUTING.md).

## Context

Audit checkpoints (format 2) are Ed25519 signatures over an RFC 9162 tree head. An
adversary with a cryptographically relevant quantum computer (Shor's algorithm) could
forge Ed25519 signatures; a checkpoint is evidence that must stay trustworthy for as long
as the audit history is kept, which can be longer than the expected life of classical
signatures. NIST published FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) as
final standards on 13 August 2024, and Node 24 with OpenSSL 3.5 provides ML-DSA, SLH-DSA
and ML-KEM natively through `node:crypto`, so no new dependency is needed. The
inventory of other cryptographic uses (JWT and DPoP algorithms, hashing, TLS, content
encryption) is in CRYPTO-AGILITY.md; only the checkpoint signature is a signature the
gateway itself produces and long-lived evidence depends on.

## Decision

1. **A closed registry, not free strings.** `reference/crypto/algorithms.ts` registers
   `ed25519`, `ml-dsa-44/65/87`, `slh-dsa-sha2-128s` and `-256s`, and the hybrid
   `ed25519+ml-dsa-65`, each with key types, exact signature lengths and standard. Every
   role refuses an unregistered identifier. SHA2-128s and SHA2-256s cover the small and the
   conservative SLH-DSA choices; the `s` (small signature) sets were chosen over `f` because
   checkpoints are signed rarely and stored for years.
2. **Checkpoint format 3.** Same content as format 2 plus `alg`, signed over the JCS form,
   so the algorithm is authenticated and a signature is not transferable between formats.
   Key ids are `<alg>:<label>`. Format 1 and 2 verify unchanged.
3. **Hybrid means both.** `ed25519+ml-dsa-65` concatenates an Ed25519 and an ML-DSA-65
   signature over identical bytes; both must verify. It is an AKAC composition, not an
   IETF or NIST hybrid signature standard, and it is registered as such (the registry says
   so in its `standard` field). Its purpose is to remain unforgeable if either primitive
   is broken.
4. **The verifier owns the policy.** `VerifierPolicy` is an allowlist chosen by the
   verifier. Default: every registered algorithm (all are standardised primitives).
5. **No downgrade.** `AlgorithmFloor` records, per stream, the earliest signature-verified
   checkpoint with a post-quantum component; a classical-only checkpoint that is newer or
   larger is refused unless the policy sets `allowClassicalAfterPq`. Rationale: an
   attacker who can forge only Ed25519 (quantum adversary, stolen classical key) must not
   be able to present a fresh classical checkpoint for a migrated stream. A backdated
   classical forgery still has to be a prefix of the later stream. The floor is verifier
   state (persistable); `verifyAuditStream` derives it from the verified checkpoints it is
   given and needs a keyring, because an unauthenticated `alg` proves nothing.
6. **Configuration selects the signer.** `AKAC_CHECKPOINT_ALG` (default `ed25519`, format 2)
   selects the algorithm for the file signer; other values write format 3. The signer
   verifies its own signature before returning it. `scripts/checkpoint.ts keygen` creates
   keys; the offline form detects the algorithm from the key.
7. **Key material.** File keys are read as Buffers, erased after parsing, and held as
   `KeyObject`s; signers redact themselves from JSON and `util.inspect`. Erasure of
   `KeyObject` material is not possible in Node and is not claimed.
8. **Vault Transit stays Ed25519.** The shipped `VaultTransitSigner` signs Ed25519 only.
   HashiCorp announced experimental ML-DSA sign and verify in Transit for Vault
   Enterprise 1.19; AKAC has not adapted or tested against it, and configuring Vault with
   another algorithm is refused. A KMS or HSM with post-quantum signatures implements
   `CheckpointSigner` with `alg` set.
9. **Python verifies what `cryptography` provides.** Ed25519 always; ML-DSA and the hybrid
   with a `cryptography` release that ships `mldsa` (present in 50.0.1, absent in 46.0.5,
   the two versions inspected); never SLH-DSA. Unavailable algorithms are NOT_APPLICABLE
   in the second implementation's runner and never count as passes.
10. **Not in this change.** JOSE and DPoP post-quantum algorithms (IETF drafts; the DPoP
    algorithm list stays configurable), TLS key exchange (operator), content encryption
    (ADR-022), FN-DSA, and stateful hash-based signatures.

## Alternatives considered

- *Replace Ed25519 with ML-DSA outright*: rejected; format 2 verifiers exist and hybrid
  covers the risk that a young lattice scheme is weakened.
- *A composite-signature standard*: the IETF work on composite ML-DSA is not final at the
  time of writing; the AKAC hybrid is a plain concatenation and is named as AKAC-specific so
  it can be replaced by a standardised composition in a new registry entry.
- *A pure-JavaScript or WASM PQ library*: rejected; a new dependency and a second
  implementation of a security-critical primitive, while `node:crypto` offers it natively.
- *`alg` outside the signed content*: rejected; it would allow relabelling and make the
  no-downgrade rule unenforceable.
- *Time-based downgrade rule only*: rejected as sole rule because `issuedAt` is chosen by
  the signer; the size condition ties the classical checkpoint to append-only history.
- *Signing with the FIPS 204 context string*: not used; the algorithm and format are in the
  signed content already, and Python's verification API for context handling was not
  relied on. Can be added with a new registry entry.

## Consequences

- Format 3 signatures are large (ML-DSA-65 3309 bytes, SLH-DSA-SHA2-256s 29792 bytes);
  checkpoints, anchors and API responses grow accordingly. Signing SLH-DSA-256s is slow;
  measure before choosing it for a hot path (checkpoints are on demand).
- A verifier older than 0.6 cannot verify format 3 and must fail closed; keep signing
  format 2 (the default) until every verifier is updated, or publish both.
- A deployment on a Node without OpenSSL 3.5 cannot use the new algorithms; `keygen` and
  the configuration check fail with a clear message.
- Quantum-safe checkpoints do not protect the transport, JWT or DPoP signatures, or
  data at rest; CRYPTO-AGILITY.md lists each with its risk.
- No claim of FIPS validation, external cryptographic review, or a standardised hybrid
  is made.
