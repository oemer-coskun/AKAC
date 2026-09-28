# ADR-002: Serialized state and conservative revocation

Status: accepted for reference 0.1.

All authoritative state changes use one transaction. PostgreSQL locks one state
row; SQLite locks the write transaction. This avoids an authorization-to-use race
inside the state boundary and makes persisted audit and access changes atomic.
Source dependencies are evaluated lazily against current state and pinned versions.

Revocation advances a global epoch and invalidates all contexts. It may interrupt
unrelated work, but never silently preserves a stale privilege. Future tenant-local
epochs and normalized tables need equivalent concurrency proofs and tests.

Already released bytes and external model caches remain outside the transaction.
No claim of instant global recall is made.
