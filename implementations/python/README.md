# AKAC in Python

A second implementation of the AKAC 0.6 decision rules and evidence
verification, in Python 3.10+ with no required dependency. It follows the
specification and the reference behaviour rule by rule and shares no code with the
TypeScript reference at run time. It is produced by the same project: this is
same-project differential evidence, **not** an independently authored external
implementation, not a gateway, and not certified. A comparison of the two detects
divergence; it cannot detect an error both share.

## What it implements

| Area | Module | Rules |
|---|---|---|
| `decide()`: identity, delegation chains (time, scope, session roles, destinations and result limits narrowing, R68), roles and groups (R22-R24), separation of duty (R26), containers (R27), origins, lifecycle (R45/R46, R-LIFE-1), transitive visibility and classification (R25, R28) | `akac/policy.py` | closed reason codes and deny/defer categories |
| Gateway decisions: evaluate, open, retrieve, derive, release, delegate, revoke over one snapshot, with core obligations (`audit_level`, `no_persist`, `max_context_ttl_ms`), `destination_restricted`, the destination gate (R-DEST-3..7), runtime containment (`runtime_profile`, `max_output_classification`, R106-R112) and the 0.6 fixes R121..R123 | `akac/engine.py`, `akac/containment.py`, `akac/decision.py` | no transport, persistence, audit writer or supplemental policy hook |
| AuthZEN 1.0 request mapping of the AKAC profile | `akac/authzen.py` | |
| RFC 8785 (JCS) subset, RFC 9162 Merkle roots and inclusion/consistency proofs and their verification, audit format 1/2 hashes and chains | `akac/jcs.py`, `akac/merkle.py`, `akac/audit.py` | |
| Format 2 checkpoint verification (Ed25519) | `akac/checkpoint.py` | needs the optional `cryptography` package |
| Knowledge semantics (0.6, ADR-022): derivation depth, combination rules (deny, uplift), inherited tags and residency, the residency gate of release and evaluation, placement without write-down, modality inheritance, session-scoped visibility and session close, trusted model lineage | `akac/knowledge.py`, `akac/policy.py`, `akac/engine.py` | session-scoped records stay in the snapshot (no in-memory partition); no cascade sweeper, pending-erasure job or content encryption (TypeScript reference only) |
| Format 3 checkpoint verification (0.6): Ed25519, ML-DSA-44/65/87, hybrid `ed25519+ml-dsa-65`; verifier policy and no-downgrade history | `akac/checkpoint.py` | ML-DSA needs a `cryptography` release that ships `asymmetric.mldsa` (present in 50.0.1, absent in 46.0.5); **SLH-DSA is not verified** (not provided by `cryptography`). Vectors of an unavailable algorithm are NOT_APPLICABLE, never a pass |
| Fixture loader (`examples/fixture.json`) and vector patches | `akac/fixture.py` | |

JSON is read with the value semantics the rules are stated in (`akac/js.py`): an
integral number is an integer whatever its spelling (`1`, `1.0`, `1e0`), a missing
member differs from `null`, and malformed members fail exactly as they do in the
reference, so both implementations deny the same malformed records.

Not implemented: the runtime enforcer protocol of `ProtectedRuntime` (the 13
`runtime-enforcer` vectors), HTTP, OAuth/DPoP, storage and the control plane beyond
`revoke`. Lexical retrieval orders equal-score matches with an approximation of the
reference's locale collation for ids; the disclosed set can differ from the
reference only when more equal-score matches than the limit exist.

## Use

```sh
cd implementations/python
python -m akac conformance            # every shared vector, this implementation only
python -m akac conformance --json     # machine-readable report
python -m akac eval < cases.json      # runner contract: {"cases": [...]} -> JSON array
python -m akac serve                  # one JSON case per line -> one result per line
python -m unittest discover -s tests  # unit tests (checkpoint test skipped without cryptography)
```

`pip install ".[crypto]"` installs it with the optional dependency (local use only;
the package is marked not for upload). When installed outside this repository, pass
`--vectors DIR --fixture FILE` to `conformance`.

The runner contract (the `op` of each case and its result) is documented in
[docs/IMPLEMENTATIONS.md](../../docs/IMPLEMENTATIONS.md). The TypeScript tests
`tests/differential-*.test.ts` and `tests/interop.test.ts` compare this
implementation with the reference on every vector file and on generated worlds.
