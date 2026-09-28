# ADR 003: identity, bounded work and model boundaries

Status: accepted for reference 0.2.0; external security review outstanding.

## Context

A knowledge boundary also needs authenticated callers, bounded graph traversal,
policy freshness and a trustworthy path from captured context to model output.
A locally consistent audit chain alone cannot detect wholesale history rollback.

## Decision

Use the maintained jose verifier for signed access tokens, with explicit
algorithm/issuer/audience/type validation and server-managed subject-to-run
mapping. Do not infer privileges from token claims. Keep opaque service tokens as
an explicit alternative for local deployments. Enforce graph budgets with
memoized ancestry validation, and bind contexts to the OPA revision. Add logical
source expiry, an input/output provider adapter and optional Ed25519 checkpoints.

Implement a second decision algorithm in Python and compare generated states
against TypeScript. This checks semantic agreement, not independent authorship
or security certification. Preserve portable deterministic vectors as the base.

## Consequences

Deployments must provision run identities, rotate signing keys and revisions,
anchor audit checkpoints externally and enforce network/provider isolation.
The reference database still serializes the entire state and is not a scalable
production architecture. Limits intentionally trade availability for fail-closed
behavior. Policy changes require new grants/contexts; the migration guide documents
this compatibility break. The custom project license remains unchanged.
