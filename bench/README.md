# AKAC benchmarks

Latency and throughput of the reference engine on synthetic data, and the cost of
the documented bounds. No dependencies beyond the repository's own (`pg` for the
PostgreSQL backend); the load generator is built in (`bench/stats.ts`).
Retrieval quality with a real embedding model lives in `bench/quality/`.

| File | Purpose |
| --- | --- |
| `data.ts` | Seeded synthetic data set (`SCALES`), vector chunks, authorized-draw sampling |
| `stats.ts` | Seeded PRNG, closed-loop load generator, percentiles, machine description |
| `curves.ts` | Cost curves of `LIMITS` (role depth and closure, container depth, derivation path and DAG size) |
| `pg.ts` | Throwaway schema, migrations and a non-bypass runtime role for PostgreSQL runs |
| `run.ts` | CLI: runs everything, writes JSON and Markdown |
| `render.ts` | JSON results to Markdown tables |

## Run

```sh
# MemoryStore only, small scale (1k documents, 1k grants, 10 tenants)
node bench/run.ts --scale small

# Also PostgreSQL + pgvector: an owner connection that may create schemas and roles.
# Use a password-less URL (trust or ~/.pgpass) or a throwaway local database.
AKAC_BENCH_DATABASE_URL=postgresql://owner@127.0.0.1:5432/akac_bench \
  node bench/run.ts --scale medium --backend memory,postgres --concurrency 1,8,32 \
  --out bench-results/medium.json --markdown bench-results/medium.md

# Re-render a results file
node bench/render.ts bench-results/medium.json
```

Options: `--scale tiny|small|medium|large` (or `AKAC_BENCH_SCALE`), `--backend
memory|postgres|memory,postgres`, `--concurrency 1,8` (in-process callers),
`--iterations N` (calls per workload and caller count; derivation-depth and lexical
workloads use a fifth), `--seed N`, `--no-curves`, `--out`, `--markdown`.
`AKAC_TEST_DATABASE_URL` is used when `AKAC_BENCH_DATABASE_URL` is unset.

| Scale | Tenants | Documents | Grants | Roles per tenant (chain depth) | Container depth | Derivation depth |
| --- | --- | --- | --- | --- | --- | --- |
| tiny (tests) | 2 + 1 | 120 + 60 | 40 + 20 | 40 (8) | 8 | 16 |
| small | 10 + 1 | 1,000 + 1,000 | 1,000 + 100 | 200 (8) | 8 | 16 |
| medium | 10 + 1 | 10,000 + 1,000 | 10,000 + 100 | 200 (8) | 8 | 16 |
| large | 10 + 1 | 100,000 + 1,000 | 10,000 + 100 | 200 (8) | 8 | 16 |

The "+ 1" tenant (`tlex`) holds exactly the lexical corpus bound (1,000 documents)
for the bounded lexical retrieval workload; the lexical path refuses larger tenants
(`DEFERRED:BUDGET_EXCEEDED`), so it is not measured on them.

## What is measured

- `evaluate read`: `Engine.evaluate` (the AuthZEN decision path), one audited decision.
- `openContext`: one or eight documents, audited, context persisted.
- `retrieve, vector`: `VectorCandidateSource` over `MemoryVectorIndex` or
  `PgVectorIndex` with the HashEmbedder (256 dimensions), then the engine's
  authoritative re-check. Embedding cost of a real model is not included; see
  `bench/quality/` for recall with one.
- `retrieve, lexical`: the bounded fallback over the 1,000-document tenant.
- `evaluate derived artifact, derivation depth d`: a model-derived artifact whose
  source path is d records long (end-to-end, including hydration on PostgreSQL).
- Cost curves: the pure `decide()` / `transitiveClassification()` over a
  hand-built snapshot, one step past each bound to show the fail-closed point.

"authorized" workloads draw a (binding, document) pair checked beforehand with the
pure `decide()`; "mixed" workloads draw both at random and are mostly denials
(about 9% of random pairs are allowed in this data set: five departmental
knowledge bases, clearance and project gates). The outcome counts are reported
next to every latency row, so a denial-dominated row cannot pass for an allow path.

The PostgreSQL backend connects as a freshly created role without superuser or
BYPASSRLS (`requireRls: true`), so forced row-level security is in effect. Setup
(import and chunk load) is not measured; the chunk rows are bulk-inserted by the
owner with the same columns `PgVectorIndex.upsert` writes.

## Limits of these numbers

In-process callers: no HTTP, TLS, JSON parsing or token verification. MemoryStore
serializes every transaction and copies the tenant snapshot, so its numbers grow
with tenant size and fall with concurrency; it is not a production store. The
PostgreSQL service in CI is a default-configured container on the same runner. The
published figures and the machine they ran on are in `docs/PERFORMANCE.md`.
