# ADR 009: optional DPoP sender-constrained access tokens

Status: proposed for reference 0.4.0. No external review yet.

## Context

R19 accepts short-lived `at+jwt` access tokens and states that bearer replay needs deployment controls. The
administrative listener in particular is a high-value target: a stolen operator token is a stolen administrator.
RFC 9449 (DPoP) constrains a token to a key without mutual TLS, which suits deployments behind a terminating proxy.

## Decision

1. **Per-listener, opt-in.** `AKAC_DPOP` and `AKAC_ADMIN_DPOP` take `off` (default), `optional`, `required`. Required is
   recommended for production, not forced: token issuers must support `cnf.jkt` first.
2. **Verification lives in the gateway, binding in the authenticator.** `adapters/dpop.ts` validates the proof; the JWT
   authenticator compares `cnf.jkt` with the proof key thumbprint. A token with `cnf` never works as Bearer, in any
   mode, so a downgrade attempt cannot succeed even when DPoP is off.
3. **Configured public URL.** `htu` is checked against `AKAC_PUBLIC_URL` / `AKAC_ADMIN_PUBLIC_URL` because the `Host`
   header is attacker-controlled behind a proxy.
4. **Algorithms.** ES256, EdDSA and PS256 only, restricted further by `AKAC_DPOP_ALGS`. The proof key must be a public
   JWK of a matching type; RSA needs 2048 to 4096 bits.
5. **Replay store is an interface.** Default: in-memory, per instance, bounded (100000 entries), refusing rather than
   evicting when full. With `DATABASE_URL`: `akac_dpop_replay (jti, jkt, expires_at)` from migration 007, shared by all
   instances, selected by default and overridable with `AKAC_DPOP_REPLAY=memory`. The replay entry is written only
   after the token authenticated and matched the proof key, so unauthenticated callers cannot fill the store.
6. **Opaque credentials are excluded.** They have no `cnf`; enabling DPoP with them is a start-up error.
7. **Not included.** Server nonces (`DPoP-Nonce`), mTLS binding (RFC 8705), token issuance, and body signing.

## Consequences

- Stolen tokens alone stop working on DPoP-enforced listeners; a stolen token and its key still work until expiry or
  revocation.
- With the in-memory store, a second replica does not see proofs used on the first; use the PostgreSQL store for HA.
- The runtime role needs DML on `akac_dpop_replay`. In the reference deployment `deploy/postgres/init.sql` sets default
  privileges for tables that `akac_owner` creates, so migration 007 needs no operator grant; a deployment with its own
  role setup must grant SELECT, INSERT, UPDATE, DELETE itself. The table has forced row-level security with an
  unconditional policy so the runtime-role posture check still holds; it has no tenant data.
- Clients need a signer (`DpopSigner` in the TypeScript SDK) and fresh proofs per request.
