# Performance

What the reference implementation costs per decision and per retrieval, at stated
data sizes, on a named machine, and what the documented bounds (`LIMITS` in
`reference/policy.ts`, `HYDRATION` in `reference/hydrate.ts`, `RETRIEVAL` in
`reference/engine.ts`) cost as they are approached. These are measurements of the
reference code, not service-level commitments; SLO targets are operator choices
(the operations guide).

## Method

- Harness: `bench/` (see `bench/README.md`). Seeded synthetic data, a built-in
  closed-loop load generator, per-call latency with `performance.now()`, warm-up
  excluded, nearest-rank p50/p95/p99. No third-party load tool.
- Data set per tenant: 200 roles in chains of depth 8 (effective closures stay
  below `LIMITS.roles` = 64), 5 knowledge bases with folder chains of depth 8,
  documents spread over all folder levels with a weighted classification mix
  (public 20%, internal 50%, confidential 20%, restricted 10%) and 10% project
  restrictions, one agent and one grant per user, groups, one static
  separation-of-duty constraint, model-derived artifacts in derivation chains of
  depth 16. About 9% of random (binding, document) pairs are allowed.
- Scales: `small` 10 tenants / 1,000 documents / 1,000 grants; `medium` 10 / 10,000
  / 10,000; `large` 10 / 100,000 / 10,000; plus a tenant holding exactly the
  lexical corpus bound (1,000 documents) for the lexical workload.
- Backends: MemoryStore + MemoryVectorIndex, and PostgreSQL + pgvector through the
  production adapters, connected as a runtime role without BYPASSRLS (forced
  row-level security in effect), HNSW with iterative scans.
- Every measured call is a complete audited operation: hydration, `decide()`, one
  hash-chained audit entry and its Merkle nodes, commit. Callers are in-process: no
  HTTP, TLS, JSON or token verification cost, which a deployment adds on top.
- Workloads report their outcome counts; "authorized" rows are allows by
  construction, "mixed" rows are mostly denials.

## Published figures

The published figures come from `.github/workflows/bench.yml` (manual and weekly)
on the GitHub-hosted `ubuntu-latest` runner, scales `medium` and `large`, callers
1, 8 and 32, MemoryStore and PostgreSQL 17 + pgvector (service container pinned by
digest). Each run uploads `akac-bench-<scale>` (JSON and Markdown, including the
runner's CPU model, core count, memory, OS image, Node.js, PostgreSQL and pgvector
versions and the commit) and writes the tables into the run summary.

<!-- published-figures: replace this block with the tables of a bench.yml run, its date, commit and run link -->
**Not yet published.** No `bench.yml` run has been recorded in this document yet;
until one is, this repository makes no claim about latency on the hosted runner.

## Local development run (not the published figures)

A short `small`-scale run on a developer workstation that was heavily loaded by
other work at the time (other databases, builds and test suites running
concurrently; PostgreSQL in a Docker container on Windows). It validates the
harness; do not read it as achievable latency.

<!-- local-run: bench/run.ts --scale small --backend memory,postgres --concurrency 1,8 --iterations 200 -->
Run 2026-09-29, commit `f21d5af95db5`, seed 1: AMD Ryzen 7 5700X 8-Core Processor (16 logical cores), 31.9 GiB, Windows_NT, Node.js v24.13.0, PostgreSQL 17.11 with pgvector 0.8.6 (Docker). 200 calls per row (40 for the lexical and derivation rows).

**memory**

| Workload | Callers | p50 ms | p95 ms | p99 ms | Calls/s | Outcomes |
| --- | --- | --- | --- | --- | --- | --- |
| evaluate read, authorized document | 1 | 1.8 | 3.5 | 4.6 | 477 | allow 200 |
| evaluate read, authorized document | 8 | 26.0 | 40.2 | 42.6 | 307 | allow 200 |
| evaluate read, random document (mixed) | 1 | 2.3 | 4.1 | 4.9 | 391 | KNOWLEDGE_BOUNDARY 181, allow 19 |
| evaluate read, random document (mixed) | 8 | 21.2 | 29.3 | 39.6 | 355 | KNOWLEDGE_BOUNDARY 181, allow 19 |
| openContext, 1 authorized document | 1 | 4.8 | 8.9 | 15.9 | 182 | allow 200 |
| openContext, 1 authorized document | 8 | 47.2 | 81.9 | 91.0 | 156 | allow 200 |
| openContext, 8 authorized documents | 1 | 6.3 | 14.5 | 22.1 | 131 | allow 200 |
| openContext, 8 authorized documents | 8 | 62.3 | 84.1 | 96.5 | 126 | allow 200 |
| openContext, 1 random document (mixed) | 1 | 5.6 | 11.0 | 16.6 | 160 | deny 181, allow 19 |
| openContext, 1 random document (mixed) | 8 | 41.2 | 59.2 | 73.7 | 190 | deny 181, allow 19 |
| retrieve, vector (HashEmbedder, k=5) | 1 | 11.3 | 15.8 | 20.6 | 86 | allow 200 |
| retrieve, vector (HashEmbedder, k=5) | 8 | 99.8 | 139.4 | 162.7 | 76 | allow 200 |
| retrieve, lexical (1000 documents in tenant) | 1 | 30.4 | 40.1 | 43.1 | 33 | allow 39, deny-or-no-match 1 |
| retrieve, lexical (1000 documents in tenant) | 8 | 179.3 | 203.7 | 213.1 | 43 | allow 39, deny-or-no-match 1 |
| evaluate derived artifact, derivation depth 1 | 1 | 5.7 | 8.2 | 9.8 | 168 | allow 40 |
| evaluate derived artifact, derivation depth 2 | 1 | 6.9 | 11.4 | 12.3 | 134 | allow 40 |
| evaluate derived artifact, derivation depth 4 | 1 | 6.2 | 8.1 | 9.9 | 157 | allow 40 |
| evaluate derived artifact, derivation depth 8 | 1 | 4.8 | 6.7 | 9.9 | 194 | allow 40 |
| evaluate derived artifact, derivation depth 12 | 1 | 5.2 | 7.5 | 8.4 | 187 | allow 40 |
| evaluate derived artifact, derivation depth 16 | 1 | 5.0 | 7.3 | 7.9 | 191 | allow 40 |

**postgres+pgvector**

| Workload | Callers | p50 ms | p95 ms | p99 ms | Calls/s | Outcomes |
| --- | --- | --- | --- | --- | --- | --- |
| evaluate read, authorized document | 1 | 22.3 | 37.7 | 55.1 | 42 | allow 200 |
| evaluate read, authorized document | 8 | 32.3 | 95.2 | 112.7 | 185 | allow 200 |
| evaluate read, random document (mixed) | 1 | 22.5 | 48.8 | 62.4 | 39 | KNOWLEDGE_BOUNDARY 181, allow 19 |
| evaluate read, random document (mixed) | 8 | 37.4 | 84.2 | 146.4 | 174 | KNOWLEDGE_BOUNDARY 181, allow 19 |
| openContext, 1 authorized document | 1 | 27.2 | 118.5 | 701.9 | 18 | allow 200 |
| openContext, 1 authorized document | 8 | 51.9 | 328.5 | 625.8 | 81 | allow 200 |
| openContext, 8 authorized documents | 1 | 36.3 | 178.3 | 283.4 | 16 | allow 200 |
| openContext, 8 authorized documents | 8 | 65.3 | 254.6 | 378.4 | 89 | allow 200 |
| openContext, 1 random document (mixed) | 1 | 25.0 | 39.3 | 51.3 | 37 | deny 181, allow 19 |
| openContext, 1 random document (mixed) | 8 | 42.9 | 118.6 | 225.7 | 143 | deny 181, allow 19 |
| retrieve, vector (HashEmbedder, k=5) | 1 | 48.6 | 83.7 | 109.3 | 19 | allow 200 |
| retrieve, vector (HashEmbedder, k=5) | 8 | 183.9 | 401.7 | 477.4 | 38 | allow 200 |
| retrieve, lexical (1000 documents in tenant) | 1 | 152.1 | 321.4 | 602.1 | 6 | allow 39, deny-or-no-match 1 |
| retrieve, lexical (1000 documents in tenant) | 8 | 1699.4 | 4463.0 | 4977.3 | 4 | allow 39, deny-or-no-match 1 |
| evaluate derived artifact, derivation depth 1 | 1 | 22.0 | 32.1 | 38.4 | 42 | allow 40 |
| evaluate derived artifact, derivation depth 2 | 1 | 22.9 | 27.2 | 30.8 | 44 | allow 40 |
| evaluate derived artifact, derivation depth 4 | 1 | 25.0 | 53.8 | 66.5 | 35 | allow 40 |
| evaluate derived artifact, derivation depth 8 | 1 | 22.8 | 35.7 | 59.1 | 39 | allow 40 |
| evaluate derived artifact, derivation depth 12 | 1 | 31.5 | 81.8 | 438.0 | 20 | allow 40 |
| evaluate derived artifact, derivation depth 16 | 1 | 26.4 | 43.4 | 61.1 | 35 | allow 40 |

Filter mismatches: 0 in every row.

## Cost of the documented bounds

Pure `decide()` (and `transitiveClassification()`) over an in-memory snapshot, one
step past each bound. Past the bound the result is always a denial (a deferred
`INVALID_CONTEXT` for role and container limits, `KNOWLEDGE_BOUNDARY` for
derivation graphs whose visibility cannot be established), never an allow over
partial data. Figures from the same local run (microseconds, p50):

| Bound | Parameter | p50 us | Effect | Code |
| --- | --- | --- | --- | --- |
| LIMITS.roleDepth = 16 (role hierarchy depth) | 1 | 3.7 | allow | AUTHORIZED |
| LIMITS.roleDepth = 16 (role hierarchy depth) | 8 | 5.5 | allow | AUTHORIZED |
| LIMITS.roleDepth = 16 (role hierarchy depth) | 16 | 6.7 | allow | AUTHORIZED |
| LIMITS.roleDepth = 16 (role hierarchy depth) | 17 (bound + 1) | 31 | deny | INVALID_CONTEXT |
| LIMITS.roles = 64 (role closure size) | 1 | 6.2 | allow | AUTHORIZED |
| LIMITS.roles = 64 (role closure size) | 32 | 8.7 | allow | AUTHORIZED |
| LIMITS.roles = 64 (role closure size) | 64 | 16.1 | allow | AUTHORIZED |
| LIMITS.roles = 64 (role closure size) | 65 (bound + 1) | 47.8 | deny | INVALID_CONTEXT (closure not established) |
| LIMITS.containerDepth = 32 (container chain depth) | 1 | 8.2 | allow | AUTHORIZED |
| LIMITS.containerDepth = 32 (container chain depth) | 16 | 15.3 | allow | AUTHORIZED |
| LIMITS.containerDepth = 32 (container chain depth) | 32 | 18.7 | allow | AUTHORIZED |
| LIMITS.containerDepth = 32 (container chain depth) | 33 (bound + 1) | 6 | deny | INVALID_CONTEXT |
| LIMITS.path = 128 (derivation path length) | 1 | 3.4 | allow | AUTHORIZED |
| LIMITS.path = 128 (derivation path length) | 64 | 37.4 | allow | AUTHORIZED |
| LIMITS.path = 128 (derivation path length) | 128 | 75.5 | allow | AUTHORIZED |
| LIMITS.path = 128 (derivation path length) | 129 (bound + 1) | 48.4 | deny | KNOWLEDGE_BOUNDARY |
| LIMITS.nodes = 1024 (derivation dag size) | 1 | 5.6 | allow | AUTHORIZED |
| LIMITS.nodes = 1024 (derivation dag size) | 512 | 251.1 | allow | AUTHORIZED |
| LIMITS.nodes = 1024 (derivation dag size) | 1024 | 551.6 | allow | AUTHORIZED |
| LIMITS.nodes = 1024 (derivation dag size) | 1025 (bound + 1) | 348.8 | deny | KNOWLEDGE_BOUNDARY |

Reading the curves: role closure, container chain and derivation path cost grow
roughly linearly with the parameter and stay well below a millisecond at their
bounds; the derivation DAG size bound (1,024 records) is the most expensive one
to approach. On PostgreSQL the load side is bounded separately by `HYDRATION`
(16 rounds, 8,192 records): a graph that needs more rounds or records than that is
a `DEFERRED:BUDGET_EXCEEDED` denial before `decide()` runs. The derivation-depth
rows of the backend tables measure that end-to-end path up to depth 16.

## Observations

- MemoryStore serializes every transaction and copies the tenant snapshot, so its
  latency grows with tenant size and its throughput does not rise with callers.
  It is the test and single-process store.
- PostgreSQL linearizes one tenant's decisions with a per-tenant advisory lock;
  throughput scales with callers across tenants, not within one tenant. The
  lexical rows run on a single tenant, so their 8-caller latency is mostly queueing
  on that lock.
- Lexical retrieval authorizes every record of the tenant before scoring and is
  bounded at 1,000 records; above that it refuses. Use vector retrieval for larger
  tenants.
- The vector pre-filter uses the user's principal tokens. An agent that holds fewer
  roles than its user (for example, not a member of the user's groups) makes the
  engine drop candidates the agent may not read; they are counted as filter
  mismatches (`akac_filter_mismatch_total`) and never disclosed. The synthetic data
  keeps agent and user roles equal, and the harness reports zero mismatches.

## Reproduce

```sh
npm ci
node bench/run.ts --scale small                          # MemoryStore
AKAC_BENCH_DATABASE_URL=postgresql://owner@127.0.0.1:5432/akac_bench \
  node bench/run.ts --scale medium --backend memory,postgres --concurrency 1,8,32
```

Or run the `AKAC benchmarks` workflow (`workflow_dispatch`) and download its
artifacts.

## Retrieval quality

<!-- retrieval-quality: maintained by bench/quality -->
Does permission-aware retrieval lose relevant results compared with an unfiltered
exact search over what the caller may read, and how good are the results with a real
embedding model compared with the hash embedder? Harness: `bench/quality/`
(`bash bench/quality/ci.sh`; the `quality` job of `bench.yml`).

**Model.** `Xenova/all-MiniLM-L6-v2`, the ONNX export of
`sentence-transformers/all-MiniLM-L6-v2` (Apache-2.0, 384 dimensions, mean pooling,
L2-normalized), pinned to Hugging Face commit
`751bff37182d3f1213fa05d7196b954e230abad9`. `bench/quality/model.lock` records the
sha256 of every file. The files are downloaded at that commit and checked before
use, and remote model loading is turned off. It runs locally through
`@huggingface/transformers` 4.3.0 on onnxruntime-node (CPU). That dependency has its
own lockfile in `bench/quality/` and is not part of the gateway's dependency tree.

**Corpus and permissions.** The corpus is synthetic and seeded. It has 30 topics
across HR, finance, engineering, legal and product, and documents are built from
templates with slot values, filler text and neighbouring-topic sentences. There are
120 queries: 90 are paraphrased questions that avoid the documents' wording, and 30
are title-keyword queries. The classification mix is 20/40/30/10 %
(public/internal/confidential/restricted). Each domain has one knowledge base with a
folder per classification and its own role audience, on an 11-role hierarchy. About
15 % of non-public documents carry a project restriction and about 5 % name
individual readers. About 5 % are model-derived artifacts of one or two sources whose
audience can be narrower than the artifact's own. A second tenant holds 10 % more
documents. The six principals are: an intern; an engineer; a controller; an HR lead;
an executive whose agent is capped at confidential; and a legal counsel whose agent
holds only `employee`.

**Metrics.** Each (principal, query) pair runs through `Engine.retrieve` with
`VectorCandidateSource` over the index built by the real `Ingestor`. The run records
the following:
- *Recall@k vs exact*: the overlap with an exact brute-force cosine top-k over the
  documents `decide()` authorizes for that principal. It uses the same chunk vectors
  and the same score floor, with no index, pre-filter or candidate caps.
- *Relevance@k*: capped recall of the query's topic among authorized documents, i.e.
  hits / min(k, |relevant|), for both AKAC and the exact baseline.
- *Filter mismatches*: candidates the index returned that `decide()` rejected.
- *Unauthorized* and *cross-tenant* results: any non-zero value fails the run.

**Local development run (not the published figures).** Recorded on 2026-09-29 on a
Windows workstation (AMD Ryzen 7 5700X, 16 threads, 32 GiB, Node 24.13) that other
work was loading heavily at the time. The CI job on `ubuntu-latest` produces the
published numbers. The memory-index run used 1,500 documents (+150 in the second
tenant). The pgvector run used 600 (+60) documents on PostgreSQL 17 + pgvector with
HNSW (m 16, ef_construction 64, ef_search 100, iterative scans), with the embedding
column widened to `vector(384)` in a throwaway schema by the procedure described in
migration 002.

| Embedder | Index | Queries | Recall@10 vs exact | Relevance@5 AKAC | Relevance@10 AKAC | Relevance@10 exact |
|---|---|---|---|---|---|---|
| hash (256d) | memory, 1,500 docs | paraphrase | 0.998 | 0.074 | 0.069 | 0.069 |
| hash (256d) | memory, 1,500 docs | keyword | 0.999 | 0.841 | 0.821 | 0.821 |
| MiniLM-L6-v2 (384d) | memory, 1,500 docs | paraphrase | 1.000 | 0.783 | 0.765 | 0.765 |
| MiniLM-L6-v2 (384d) | memory, 1,500 docs | keyword | 1.000 | 1.000 | 1.000 | 1.000 |
| hash (256d) | pgvector HNSW, 600 docs | paraphrase | 0.998 | 0.074 | 0.072 | 0.072 |
| hash (256d) | pgvector HNSW, 600 docs | keyword | 1.000 | 0.791 | 0.748 | 0.748 |
| MiniLM-L6-v2 (384d) | pgvector HNSW, 600 docs | paraphrase | 1.000 | 0.745 | 0.685 | 0.685 |
| MiniLM-L6-v2 (384d) | pgvector HNSW, 600 docs | keyword | 1.000 | 0.992 | 0.986 | 0.986 |

Across all four runs (2,880 retrievals in total) there were no unauthorized results
and no cross-tenant results. Filter mismatches were 0.63–0.80 % of candidates
(memory: hash 190/28,800, MiniLM 182/28,800; pgvector: hash 210/28,800, MiniLM
231/28,800). About 95 % of them came from the counsel principal, whose agent holds
fewer roles than its user: the index pre-filter uses the user's tokens, and
`decide()` also checks the agent. The rest came from derived artifacts whose sources
have a narrower audience than the artifact's own label.

Reading the results:
- Enforcing permissions costs no recall here. Across both indexes, AKAC's results
  match the exact top-k over the authorized set (recall@10 vs exact 0.998–1.000). The
  hash embedder falls below 1.000 only by a few tie-order differences between
  equal-scored documents.
- The embedder decides quality, not the permission layer. On paraphrased questions
  the hash embedder is close to chance (relevance@10 about 0.07, where 1/30 of topics
  would be 0.03). MiniLM reaches 0.69–0.77. On keyword queries both do well.
- At this corpus size HNSW with iterative scans lost nothing against exact search.
  Larger corpora, more selective filters or a lower `ef_search` can change that. The
  CI job runs 3,000 documents on both indexes.
- Mismatches above zero are expected whenever agents hold narrower roles than their
  users, or derived records have narrower sources. The engine never discloses them,
  but they use up candidate slots, and `akac_filter_mismatch_total` shows how often.

Limits: the corpus is synthetic and templated. Real documents are longer, chunk into
several pieces and overlap in vocabulary less cleanly. Relevance is judged by topic
labels, not by human assessors. The model is a small English model. None of this is
a claim about any real data set.
