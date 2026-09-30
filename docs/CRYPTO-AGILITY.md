# Cryptographic agility and post-quantum readiness (0.6)

Status: AKAC 0.6 ([R159–R166](../spec/AKAC-0.6.md)). Decision record: [ADR-021](../governance/ADR-021-crypto-agility-and-pq.md).
Requirements: [AKAC 0.6](../spec/AKAC-0.6.md) (R159..R166). No external
cryptographic review has taken place, no module is FIPS-validated, and nothing here is
a compliance claim. Standards and product statuses below were checked on 29 September
2026; they move, so re-check before you rely on them.

## What AKAC signs, and what changed

AKAC's own long-lived signature is the **audit checkpoint**: a signature over the RFC 9162
Merkle root of a tenant's audit stream. It is evidence that must stay trustworthy as long
as the history is kept. In 0.6 the checkpoint signature algorithm is agile:

| `alg` | Kind | Standard | Signature | Notes |
|---|---|---|---|---|
| `ed25519` | classical | RFC 8032 | 64 B | default; written as format 2 |
| `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` | post-quantum | NIST FIPS 204 | 2420 / 3309 / 4627 B | lattice-based |
| `slh-dsa-sha2-128s`, `slh-dsa-sha2-256s` | post-quantum | NIST FIPS 205 | 7856 / 29792 B | hash-based; conservative assumptions, large and slow to sign |
| `ed25519+ml-dsa-65` | hybrid | RFC 8032 + FIPS 204 | 3373 B | AKAC-specific composition: both signatures over the same bytes, both must verify |

NIST published FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) as final
standards on 13 August 2024. The hybrid is not an IETF or NIST hybrid-signature standard;
it is a plain concatenation registered as AKAC-specific so it can be replaced by a
standardised composition later. Publishing an algorithm in a FIPS document does not make
Node's or OpenSSL's implementation a validated module.

Runtime: Node 24 with OpenSSL 3.5 provides ML-DSA, SLH-DSA and ML-KEM through
`node:crypto` (verified on Node 24.13, OpenSSL 3.5.4). No dependency was added. On an older
build the algorithms are unavailable and configuration or `keygen` fails with a message.

### Checkpoint format 3

`akac-audit-checkpoint/3` signs the JCS (RFC 8785) form of
`{format, alg, stream, treeSize, rootHash, issuedAt, keyId}`: the format 2 content plus
`alg`. Because `alg` is inside the signed bytes it cannot be swapped or stripped, and a
format 3 signature is never valid as format 2. `keyId` is `<alg>:<label>`, for example
`ml-dsa-65:prod-2026`. `signature` is the canonical base64url of the component signatures
(hybrid: Ed25519 then ML-DSA-65) with the exact length of the algorithm. Format 1 and 2
checkpoints still verify unchanged (schema: `schemas/checkpoint.json`).

### Choosing the signing algorithm (configuration)

| Variable | Meaning |
|---|---|
| `AKAC_CHECKPOINT_ALG` | one of the registered ids; default `ed25519` (format 2) |
| `AKAC_CHECKPOINT_KEY_FILE` | PKCS#8 PEM private key of that algorithm; for the hybrid an Ed25519 block followed by an ML-DSA-65 block |
| `AKAC_CHECKPOINT_KEY_ID` | `<alg>:<label>` (for `ed25519` any legacy id) |

```sh
node scripts/checkpoint.ts keygen --alg ed25519+ml-dsa-65 --out-private cp.key --out-public cp.pub
AKAC_CHECKPOINT_ALG=ed25519+ml-dsa-65 AKAC_CHECKPOINT_KEY_FILE=cp.key \
  AKAC_CHECKPOINT_KEY_ID=ed25519+ml-dsa-65:prod-2026 node scripts/checkpoint.ts sign --tenant acme --out cp.json
```

The signer verifies its own signature under its public key before returning a checkpoint,
and configuration fails closed on a mismatched key, an unknown algorithm, or a key id
without the `<alg>:` prefix. The offline form
`node scripts/checkpoint.ts PRIVATE_KEY_FILE TENANT KEY_ID OUTPUT` detects the algorithm from
the key. `AKAC_CHECKPOINT_SIGNER=vault-transit` signs Ed25519 only and refuses another
algorithm (see Vault below).

### Verifying: policy, keyring and no downgrade

`scripts/checkpoint.ts verify` and `verifyAuditStream` take a **verifier policy**, decided by
the verifier and never by the document: `--allow-alg ALG` (repeatable) or `--policy FILE`
(`{"algorithms": [...], "allowClassicalAfterPq": false}`); default: every registered
algorithm. A checkpoint whose algorithm is not allowed fails even with a valid signature.

**No downgrade.** For one stream, once a checkpoint with a post-quantum component (pq or
hybrid) has verified under the keyring, a classical-only checkpoint that is issued at or
after it, or covers a larger tree, is refused (`downgrade`) unless the policy sets
`allowClassicalAfterPq` (`--allow-classical-after-pq`). Older, not-larger classical
checkpoints still verify: they are what the stream signed before the migration, and they
remain bound by append-only consistency proofs. The reasoning: an attacker who can forge
only Ed25519 (a quantum adversary, or a stolen classical key) must not be able to present a
fresh classical checkpoint for a stream that migrated. The rule needs the keyring, since an
unauthenticated `alg` proves nothing; a long-running verifier persists the floor
(`AlgorithmFloor.snapshot()`), as it persists the latest trusted checkpoint.

### Migration path

1. Update every verifier (0.6 or later) and load a keyring; verifiers older than 0.6 refuse
   format 3.
2. Generate the new key (`keygen`); add it to the keyring as `active` with `notBefore`
   (keyring entries follow the key custody guide; the key id names the algorithm and the key
   material must match it).
3. Sign and anchor a last checkpoint with the classical key; switch `AKAC_CHECKPOINT_ALG`,
   key file and key id; mark the classical key `retired`.
4. Sign and anchor a checkpoint with the new key; check it extends the last classical one
   (`verifyCheckpointExtension`). From here classical-only checkpoints of that stream are a
   downgrade.
5. Consider signing with the hybrid first: it stays unforgeable if either primitive is broken.

Cost: ML-DSA-65 signatures are 3309 bytes; SLH-DSA-SHA2-256s signatures are 29792 bytes and
slower to sign. Checkpoints are produced on demand, not per decision; measure before
choosing SLH-DSA for a busy tenant.

### Key material hygiene, and its limits

* Key files are read as byte buffers and overwritten (`fill(0)`) as soon as the key is parsed;
  the key then lives in `node:crypto` `KeyObject`s. **`KeyObject` material cannot be zeroed
  from JavaScript**; it is released by the garbage collector and OpenSSL when the object is
  freed. AKAC does not claim erasure of it. JavaScript strings (PEM text, JWK) are immutable
  and cannot be erased at all: `signCheckpointV3(entries, alg, pem, ...)` and the legacy
  Ed25519 helpers take PEM strings and are for tests and offline signing; the server path
  holds keys in signer objects, never as strings, for the post-quantum algorithms.
* Signers redact themselves: `JSON.stringify` and `util.inspect` of a signer show key id and
  algorithm only. Error messages never contain keys, signing input, or remote response bodies.
* What remains is the runtime's limit: heap snapshots, core dumps, swap and debugger attach can
  expose memory in a garbage-collected runtime. The defence is process and hardware isolation,
  short key lifetimes, rotation, and keeping the private key out of the process (KMS/HSM):
  see the confidential-computing guide ("Memory hygiene in
  garbage-collected runtimes").

### Vault Transit and other key services

`VaultTransitSigner` (the key custody guide) is Ed25519 only and configuring it with another
`AKAC_CHECKPOINT_ALG` is refused. HashiCorp's Transit API documentation lists `ml-dsa`,
`slh-dsa` and `hybrid` key types as Vault Enterprise features (announced experimental with
Vault Enterprise 1.19). AKAC has not adapted or tested a signer for them; treat Vault-held
keys as classical (format 2) until a `CheckpointSigner` with `alg` set is written and tested
against a real service. Any KMS or HSM whose product provides one of the registered
algorithms fits the `CheckpointSigner` interface (`alg`, `keyId`, `publicPem`, `sign`).

### Second implementation (Python)

`implementations/python/akac/checkpoint.py` verifies format 3 with the optional
`cryptography` package: Ed25519 always; ML-DSA-44/65/87 and the hybrid only with a release
that ships `cryptography.hazmat.primitives.asymmetric.mldsa` (present in 50.0.1, absent in
46.0.5, the two versions inspected); **SLH-DSA is not provided by `cryptography`** and is
never verified in Python. A vector whose algorithm the installation lacks is reported
NOT_APPLICABLE with the reason, never as a pass (`python -m akac conformance`), and a
verifier that cannot check a signature never accepts it (R166).

### Vectors

`conformance/vectors-0.6-crypto.json` (profile `AKAC-CryptoAgility/0.6-draft`): verification-only
known answers, public keys and signatures only; the ephemeral private keys were discarded.
ML-DSA and SLH-DSA signing is randomised (FIPS 204, FIPS 205), so signatures cannot be
regenerated; Ed25519 is deterministic. The vectors cover every algorithm, tampering,
relabelling, truncation, wrong keys, policy exclusion, rollback, hybrid partial failure
(one half bad, one half missing, mixed components, wrong key blocks) and downgrade
histories.

## Inventory of cryptographic uses in AKAC

Quantum risk: **Shor** breaks RSA, ECDSA/ECDH and EdDSA (public-key signatures and key
exchange); **Grover** gives at most a quadratic speedup against symmetric keys and hashes, so
a 256-bit key or a SHA-256 preimage search keeps about 128-bit quantum security, and no known
quantum algorithm weakens SHA-256 collision resistance meaningfully. Harvest-now-decrypt-later matters for confidentiality (transport, encrypted
data), not for signatures that are verified at a time of use.

| Use | Where | Primitive | Quantum risk | Status and path |
|---|---|---|---|---|
| Agent and admin access tokens (JWT, JWS) | `adapters/jwt.ts`, verified with `jose` 6.2.12 | RS256, ES256, EdDSA (allowlist; keys and algorithms from operator configuration, never the token) | Shor: forgeable by a quantum adversary once one exists; short-lived tokens limit the window | The IdP signs them. ML-DSA in JOSE is RFC 9964 (Standards Track, May 2026; `alg` ML-DSA-44/65/87, `kty` AKP) and `jose` 6.2.12 lists those algorithms, but AKAC's allowlist does not include them and no test covers them: enabling needs an IdP that issues them, tests and an ADR. Watch item. |
| DPoP proofs (RFC 9449) | `adapters/dpop.ts` | ES256, EdDSA, PS256 (`AKAC_DPOP_ALGS` selects a subset) | Shor: as above; proofs live seconds | List stays configurable; extending it to ML-DSA is the same watch item as JWT. |
| Static bearer credentials (digest lookup) | `reference/http.ts`, `reference/config.ts` | SHA-256 digest of the presented token | Grover: preimage search on a 256-bit digest stays infeasible | none needed; use high-entropy tokens |
| Audit entry hash chain | `reference/audit.ts` | SHA-256 over JCS | Grover: no practical effect | none needed; format 2 entries are JCS-hashed |
| Merkle tree | `reference/merkle.ts` | RFC 9162 (SHA-256, 0x00/0x01 domain separation) | none practical | none needed |
| **Checkpoint signatures** | `reference/checkpoint.ts`, `reference/crypto/` | Ed25519 (format 2); registry above (format 3) | Shor: Ed25519 forgeable; long-lived evidence | **agile in 0.6**: ML-DSA, SLH-DSA, hybrid; no-downgrade |
| Content encryption at rest | planned, ADR-022 (AES-256-GCM per document) | AES-256-GCM | Grover: 256-bit keys keep about 128-bit security | not present in this tree at the time of writing; the recommendation is AES-256 for anything encrypted at rest (below) |
| Key wrapping for content keys | planned, KMS provider interface (enterprise) | KMS-defined | provider-defined | operator/provider choice; ask the provider for its post-quantum roadmap |
| TLS between clients, gateway, database, OPA, embeddings, Vault | operator (reverse proxy, service mesh, PostgreSQL, HTTP clients) | TLS 1.3 | Shor breaks classical key exchange; harvest-now-decrypt-later applies | see transport guidance |
| Identifiers and nonces | `randomUUID`, `randomBytes` | CSPRNG | none | none |

## Transport: TLS 1.3 hybrid key exchange (operator obligation)

AKAC does not terminate TLS itself; the reverse proxy, mesh, database and egress paths
do. Harvest-now-decrypt-later means recorded traffic can be decrypted later, so key exchange
is the part of transport that a post-quantum-capable deployment should upgrade first.

* Group `X25519MLKEM768` (ML-KEM-768, FIPS 203, combined with X25519) is defined by
  **RFC 10024**, "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS
  1.3", Standards Track, published August 2026, together with `SecP256r1MLKEM768` and
  `SecP384r1MLKEM1024`. The rfc-editor.org page lists these; the group codepoint is 4588
  (0x11EC).
* OpenSSL 3.5 (LTS, released 8 April 2025) supports ML-KEM, ML-DSA and SLH-DSA and offers
  `X25519MLKEM768` by default in the TLS 1.3 key share, so a client and server both on
  OpenSSL 3.5 negotiate it without configuration; other stacks and proxies vary, so verify by
  handshake capture rather than by version number.
* Obligations: run the edge and internal hops on a TLS stack that offers the hybrid group,
  keep classical groups as fallback only where peers cannot yet negotiate it, terminate TLS
  inside the trust boundary (the confidential-computing guide), and record the negotiated group in
  your own evidence. TLS certificates are still classical signatures; post-quantum
  certificate chains are a separate, later step outside AKAC's control.

## JOSE post-quantum algorithms: status

RFC 9964 (May 2026, Standards Track) registers ML-DSA-44/65/87 for JOSE and COSE with the new
`AKP` key type. This is the signature side only; JWE key agreement with ML-KEM and hybrid or
composite JOSE algorithms are separate IETF work whose status you should re-check. AKAC
consumes JWTs and DPoP proofs, it does not issue them, so adoption depends on your identity
provider and on `AKAC_DPOP_ALGS` and the JWT algorithm configuration; both remain configuration,
not code. Until an IdP issues and a test covers ML-DSA tokens, keep the allowlists as
configured and treat this as a watch item.

## AES-256 at rest

Use AES-256 (for example AES-256-GCM, or the storage layer's AES-256 modes) for everything
encrypted at rest, whether by AKAC's content encryption (ADR-022) or by disk, database and
backup encryption you operate. Grover's algorithm halves the effective key length at most,
so 256-bit keys keep about 128-bit security against a quantum adversary; 128-bit keys
would drop to about 64-bit and should not be chosen for data with a long confidentiality
life. Key management, not the cipher, is the weak point: keep keys in a KMS or HSM, rotate
them, and separate them from the data and from the gateway host.

## Operator checklist

* Decide whether checkpoints need post-quantum protection now (long-retention evidence: yes,
  consider the hybrid) and plan the migration above.
* Give every verifier a keyring and a policy; persist the downgrade floor for long-running
  verifiers.
* Enforce TLS 1.3 with a hybrid group at the edge and on internal hops where your stack allows.
* Use AES-256 at rest with keys outside the gateway host.
* Watch: composite signature standards, JWT/DPoP post-quantum issuance by your IdP, Vault or
  KMS post-quantum signing (then write and test a `CheckpointSigner`), and FIPS validation
  status of the crypto modules you rely on.
