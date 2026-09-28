# AKAC 0.2 draft

Status: project specification, not a ratified external standard. Reference: 0.2.0.
This revision incorporates all requirements R01–R16 of [AKAC 0.1](AKAC-0.1.md)
without weakening them. The following additional requirements apply to the
AKAC-Hardened/0.2 draft profile. MUST and SHOULD retain their RFC 2119/8174 meanings.

## Additional requirements

**R17 — Bounded evaluation.** An implementation MUST publish resource budgets and
deny when it cannot establish authorization within them. Cycles, missing sources
and stale source versions MUST deny. Shared ancestry MUST NOT remove a source ACL
or bypass the depth limit. The reference allows at most 1,024 distinct nodes,
4,096 edges and 128 nodes on a path for each visibility evaluation; delegation
remains limited to 32 grants. Retrieval denies above 1,000 tenant candidates and
has a five-second scanning budget. These are reference limits, not universal
interoperability constants. They do not guarantee constant-time evaluation.

**R18 — Policy freshness.** Contexts MUST bind to the active core and supplemental
policy revisions. A revision mismatch MUST invalidate the context. Supplemental
policy MAY narrow a core allow but MUST NOT widen a core deny. The reference OPA
contract is an exact object `{allow: boolean, revision: string}` under `result`;
missing, oversized, malformed, unreachable or unexpected-revision results deny.
Operators MUST change the revision whenever company-policy semantics change.

**R19 — Trusted identity mapping.** Signed-token deployments MUST validate the
signature with operator-selected keys and algorithms, issuer, audience, token
type and validity period before mapping the verified subject to a bounded run.
Roles, grants, agent IDs and tenant claims supplied by a caller MUST NOT override
server authority. Reference access tokens require `typ=at+jwt`, `sub`, `iat`,
`exp`, and `jti`; default maximum lifetime is 300 seconds, configurable up to 900.
A `jti` alone is not replay prevention. Bearer-token replay protection requires
additional deployment controls. Opaque service credentials remain supported as
an alternative authentication mode; modes MUST NOT silently fall back.

**R20 — Logical access expiry.** Where a source has `accessExpiresAt` (Unix
milliseconds), access at or after that time MUST deny, including transitive reads,
derivation and release. Absence means no object-level time bound; grants and
contexts still expire. Expiry MUST NOT be represented as physical deletion,
backup erasure or model unlearning.

**R21 — Model boundary.** A model-provider integration MUST authorize the
configured provider recipient before disclosing protected input, and MUST check
the final recipient again after generation. Failure, expiry or revocation MUST
prevent the final release. R16 still requires isolation, complete mediation and
capturing every prior read in the run. Already delivered provider input cannot be
recalled. The supplied library adapter is not an egress firewall or provider sandbox.

## Optional audit checkpoint format

`akac-audit-checkpoint/1` signs the UTF-8 JSON array
`[format,stream,sequence,hash,issuedAt,keyId]` with Ed25519. `sequence` is the count
of audit entries and `hash` is the hash of that prefix's final entry (64 zeroes for
an empty prefix). `signature` is unpadded base64url; see the checkpoint schema.
Verification MUST check a trusted stream, key identity, externally retained
minimum sequence and the local hash chain. Public keys, checkpoints and rollback
floors MUST be anchored independently of the mutable application database.
A signature made by a compromised signer cannot establish trustworthy history.

## Compatibility and evidence

Wire routes remain `/v1`; this is an experimental API major identifier, not a
claim of standards maturity. Core storage format remains `akac-state/0.1`.
Old contexts and the former bare-boolean OPA response are intentionally rejected;
follow [migration](../docs/MIGRATION-0.2.md). See [conformance](CONFORMANCE.md) for
evidence and declared deployment obligations.
