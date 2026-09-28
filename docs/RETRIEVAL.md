# Permission-aware vector retrieval

Reference 0.3 ships an optional vector retrieval path that implements
[ADR-004](../governance/ADR-004-knowledge-base-partitioning.md). It is a
`CandidateSource` for the engine: it narrows what is searched, and the engine's
`decide()` still authorizes every candidate before any content leaves the gateway.
The default remains bounded lexical retrieval; nothing here changes the HTTP contract.

## How a query is protected

1. **Tenant.** Every chunk row carries its tenant. Queries name one tenant, and on
   PostgreSQL forced row-level security on `akac.tenant` applies in addition.
2. **Compartment.** Chunks live in one physical partition per classification
   (`akac_chunks_public|internal|confidential|restricted`; one `Map` per tenant and
   level in `MemoryVectorIndex`). `VectorCandidateSource` queries only the levels up to
   `min(user clearance, agent clearance)`. A caller below `restricted` never touches the
   restricted table, even if every other filter were broken.
3. **Pre-filter.** Inside the same statement as the nearest-neighbour search a chunk
   must pass: document ACL any-of (`user:`/`role:` tokens), every ancestor container
   ACL any-of (one list per level), and all required projects held by the caller.
   Empty ACL lists match nobody. Scores are computed only for chunks that pass, so
   unauthorized documents leave no trace in ranking.
4. **Authoritative re-check.** The engine runs `decide()` on each returned document id
   (grant, purpose, audience of user and agent, containers, sources, expiry, policy). A
   failure is dropped, counted as `filter_mismatch` and audited; the response cannot be
   told apart from "no match". An unavailable embedder or index denies.

Chunk metadata is derived by the `Ingestor` from `effectiveLabel()` (highest
classification of the document and its folders, own audience plus every ancestor
audience, union of projects) and never from document text or model output. Chunk text is
not stored in the index; vectors are protected derivatives of their source.

Tokens come from the user, while the agent must also satisfy each audience. The
pre-filter can therefore admit a chunk that the agent alone would be denied. Such
candidates are dropped by step 4 and counted as mismatches; they can reduce the results
of a narrowly scoped agent.

## Choosing an embedder

| Embedder | Use |
|---|---|
| `HashEmbedder(dims)` | Tests, air-gapped development. Lexical feature hashing, no semantics. Default 256 dims. |
| `HttpEmbedder` | OpenAI-compatible `POST {baseUrl}/v1/embeddings`. HTTPS required unless loopback, 10 s timeout, redirects refused, response shape and dimensions validated, errors carry no text. |
| Your own | Implement `Embedder { model, dimensions, embed(texts, signal?) }`. |

An embedder sees document and query text, so it belongs inside the trust boundary of
the most sensitive compartment it serves. Use a local model for `restricted` content
unless the provider is approved for it, and keep API keys in operator configuration.

## PostgreSQL and pgvector

Migration `002_vector_compartments.sql` (same runner, checksums and advisory lock as
`001`) installs the `vector` extension if absent and creates the four chunk tables with
GIN indexes on the token arrays, an HNSW index (`vector_cosine_ops`) and forced RLS.
Because it is part of the migration set, every PostgreSQL deployment needs pgvector
available (the compose file and CI use the `pgvector/pgvector` image). Requirements:
pgvector 0.8 or later is recommended (iterative scans); the runtime role needs `USAGE`
on the extension's schema and must not own tables or bypass RLS.

```ts
const store = new PostgresStore(process.env.DATABASE_URL!, { migrate: process.env.AKAC_MIGRATION_DATABASE_URL, requireRls: true });
const index = new PgVectorIndex(process.env.DATABASE_URL!, { efSearch: 100 });
const embedder = new HttpEmbedder({ baseUrl, model, dimensions: 256, apiKey });
const ingestor = new Ingestor({ control: new ControlPlane(store), store, index, embedder });
const engine = new Engine(store, { candidates: new VectorCandidateSource({ index, embedder }) });
```

**Vector dimension.** The column is `vector(256)`. A typed column lets HNSW be built and
makes the database reject mismatching writes; `PgVectorIndex` also verifies the column at
first use and refuses every operation on a mismatch. To change the dimension, ship a new
migration that truncates the four tables, alters `embedding` to `vector(N)` (N at most 2000)
and recreates the HNSW indexes, then set `dimensions` and run `reconcile()` (below).

**Tuning.** Filtered approximate search can under-return when a filter is selective.
`PgVectorIndex` sets `hnsw.iterative_scan = relaxed_order` (pgvector 0.8 or later) and
`hnsw.ef_search` (option `efSearch`, default 100; raise for recall, lower for latency), and
ranks exactly in the client because relaxed scans are only approximately ordered.
`maxScanTuples` caps the scan (default 20000). For very selective ACLs the planner may use
the GIN indexes and an exact sort instead, which is always correct. Watch p95 latency per
compartment and measure recall against an exact query on a sample before raising limits.
One HNSW graph per compartment serves all tenants; at large tenant counts partition the
chunk tables by tenant hash or move large tenants to their own database.

**Dedicated database for the restricted tier.** `RoutedVectorIndex({ default, restricted })`
sends compartments to different backends, for example a second `PgVectorIndex` on a separate
instance, network segment and key custody. Low-clearance queries then never open a
connection to the restricted backend. Keep the embedder for that tier local.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AKAC_RETRIEVAL` | `lexical` | `lexical` (bounded keyword retrieval) or `vector`. The vector settings below are refused unless this is `vector`. |
| `AKAC_VECTOR_BACKEND` | `pgvector` | `pgvector` (needs `DATABASE_URL`) or `memory` (process-local, development only; refused when `NODE_ENV=production`; lost on restart until `reconcile`). |
| `AKAC_VECTOR_DATABASE_URL` | `DATABASE_URL` | Optional override for the default vector database. Must be a non-owner, non-BYPASSRLS role. Password: `AKAC_VECTOR_DATABASE_PASSWORD_FILE`. |
| `AKAC_VECTOR_RESTRICTED_DATABASE_URL` | unset | Routes the `restricted` compartment to a dedicated database through `RoutedVectorIndex`. Must differ from the default. Password: `AKAC_VECTOR_RESTRICTED_DATABASE_PASSWORD_FILE`. |
| `AKAC_EMBEDDINGS_URL` | unset | OpenAI-compatible provider base URL (`HttpEmbedder`); https unless loopback. Takes precedence over `AKAC_EMBEDDINGS`. |
| `AKAC_EMBEDDINGS_MODEL` | unset | Model name; required with `AKAC_EMBEDDINGS_URL`. |
| `AKAC_EMBEDDINGS_DIMENSIONS` | `256` | Integer 1-2000. Must equal the `vector(N)` column; `PgVectorIndex` also verifies it at first use and refuses every operation on a mismatch. |
| `AKAC_EMBEDDINGS_API_KEY_FILE` | unset | File holding the provider key (single line). The key is never read from an environment value; `AKAC_EMBEDDINGS_API_KEY` is rejected. |
| `AKAC_EMBEDDINGS` | unset | `hash` selects `HashEmbedder` (used when no URL is set). Lexical, not semantic. |
| `AKAC_ALLOW_HASH_EMBEDDER` | `false` | Required (`true`) to use `hash` when `NODE_ENV=production`. The compose demo sets it for synthetic data only. |
| `AKAC_RETRIEVAL_MIN_SCORE` | `0` | Optional cosine floor, -1 to 1. |

All values are validated at start-up and every problem is reported at once (exit code 2).
The gateway also exposes `POST /admin/v1/index/reconcile` (kb-admin, audited as
`index_reconcile`) on the admin listener, and `node scripts/reconcile.ts <tenant> <admin-actor>`
does the same from a job or a shell (same variables as the gateway, owner rights not needed).
Ingest results with `INDEX_PENDING` are returned as HTTP 202 by the admin API.

## Operations: indexing, repair and revocation

* `ingestor.ingest(tenant, adminId, document)` performs the authorized upsert (kb-admin,
  audited), then chunks (about 1200 characters, 150 overlap, at most 2000 chunks; more fails
  rather than truncating), embeds and replaces the document's chunks atomically. A version
  lower than the indexed one is ignored.
* If embedding or indexing fails afterwards the document stays authoritative but unindexed:
  the result is `{ ok: false, code: 'INDEX_PENDING', id, version }` and an `index_pending`
  event is emitted (no ids or text). Run `ingestor.reconcile(tenant)` on a schedule, at
  start-up and after incidents.
* `reconcile(tenant)` compares the authoritative store with the index (version, label digest,
  embedding model) and re-indexes differences; it removes chunks of documents that are
  inactive, expired, unlabelable or gone. It scans up to 5000 documents per tenant and does
  not remove unseen chunks when the scan is truncated. It plans from document metadata
  (no content) and loads content only for documents it re-indexes, 32 per transaction. Index state is derived from the chunk
  tables, so there is no separate outbox that can fall out of sync.
* Changing a container's classification or audience changes descendants' labels: call
  `reconcile(tenant)` (or `relabel(tenant, docId)` for one document). Moving a document
  between compartments deletes the old chunks in the same transaction that writes the new ones.
* `ingestor.remove(tenant, adminId, docId)` retires the document (`ControlPlane.removeKnowledge`:
  kb-admin, audited, advances the tenant epoch) and deletes its chunks. Even if deletion is delayed, the engine denies an
  inactive document, so stale chunks can cost recall but never disclose content.
* Changing the embedding model or dimension requires re-embedding: `reconcile()` detects the
  model change and re-embeds every document.

## Limitations

Only administrator-ingested `document` records are indexed; derived memories and artifacts are
reachable through explicit context capture. There is no hybrid lexical fusion and no
passage-level projection: the engine still returns whole documents. Without a candidate
source the lexical fallback loads at most 1,000 records and 64 MiB of content
(`RETRIEVAL.contentBytes`, overridable with the `contentBytes` engine option) and denies
above either bound. Reconcile is bounded
(5000 documents per tenant per call). Index metadata is a pre-filter and is not itself
certified; correctness rests on the authoritative re-check.
