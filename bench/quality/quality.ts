import { Engine } from '../../reference/engine.ts';
import type { CandidateSource, EngineEvent } from '../../reference/engine.ts';
import { ControlPlane } from '../../reference/control.ts';
import { MemoryStore } from '../../reference/store.ts';
import { Ingestor } from '../../reference/ingest.ts';
import { VectorCandidateSource } from '../../reference/retrieval.ts';
import { MemoryVectorIndex } from '../../reference/vector.ts';
import type { IndexedChunk, IndexedDocument, VectorHit, VectorIndex, VectorQuery } from '../../reference/vector.ts';
import { decide } from '../../reference/policy.ts';
import type { Embedder } from '../../reference/embedding.ts';
import type { State } from '../../reference/types.ts';
import { PRINCIPALS } from './corpus.ts';
import type { Corpus } from './corpus.ts';

/** Captures the chunk vectors written by the Ingestor, so the exact baseline ranks the very same vectors. */
export class RecordingIndex implements VectorIndex {
  readonly chunks = new Map<string, { tenant: string; vectors: Float32Array[] }>();
  private inner: VectorIndex;
  constructor(inner: VectorIndex) { this.inner = inner; }
  async upsert(chunks: IndexedChunk[]): Promise<void> {
    await this.inner.upsert(chunks);
    const byDoc = new Map<string, IndexedChunk[]>();
    for (const c of chunks) byDoc.set(c.docId, [...byDoc.get(c.docId) ?? [], c]);
    for (const [doc, list] of byDoc) this.chunks.set(doc, { tenant: list[0]!.tenant, vectors: list.map(c => Float32Array.from(c.vector)) });
  }
  async removeDocument(tenant: string, docId: string) { await this.inner.removeDocument(tenant, docId); this.chunks.delete(docId); }
  query(q: VectorQuery): Promise<VectorHit[]> { return this.inner.query(q); }
  state(tenant: string): Promise<Map<string, IndexedDocument>> { return this.inner.state(tenant); }
}

const dot = (a: Float32Array, b: Float32Array) => { let n = 0; for (let i = 0; i < a.length; i++) n += a[i]! * b[i]!; return n; };
/**
 * Exact baseline: every authorized document scored by its best chunk (cosine; vectors
 * are L2-normalized), the same score floor as VectorCandidateSource (> minScore), ties
 * by id. No index, no pre-filter, no candidate caps.
 */
export function exactTopK(query: Float32Array, docs: Iterable<string>, chunks: ReadonlyMap<string, { vectors: Float32Array[] }>, k: number, minScore = 0): string[] {
  const scored: [string, number][] = [];
  for (const id of docs) {
    const c = chunks.get(id);
    if (!c) continue;
    let best = -Infinity;
    for (const v of c.vectors) best = Math.max(best, dot(query, v));
    if (best > minScore) scored.push([id, best]);
  }
  return scored.sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, k).map(([id]) => id);
}
/** |got ∩ want| / |want| over the first k of `got` (want is already a top-k list); undefined when want is empty. */
export function overlapRecall(got: readonly string[], want: readonly string[], k: number): number | undefined {
  const w = want.slice(0, k);
  if (!w.length) return undefined;
  const g = new Set(got.slice(0, k));
  return w.filter(x => g.has(x)).length / w.length;
}
/** Capped relevance recall@k: relevant hits in the top k / min(k, |relevant|); undefined without relevant documents. */
export function cappedRecall(got: readonly string[], relevant: ReadonlySet<string>, k: number): number | undefined {
  if (!relevant.size) return undefined;
  return got.slice(0, k).filter(x => relevant.has(x)).length / Math.min(k, relevant.size);
}
type Row = { kind: string } & Record<string, number | undefined | string>;
const scores = (rows: Row[], ks: number[]): Scores => {
  const m = (key: string) => mean(rows.map(r => r[key] as number | undefined));
  return { recallVsExact: Object.fromEntries(ks.map(k => [`@${k}`, m(`rec@${k}`)])), relevanceAkac: Object.fromEntries(ks.map(k => [`@${k}`, m(`relA@${k}`)])),
    relevanceExact: Object.fromEntries(ks.map(k => [`@${k}`, m(`relE@${k}`)])) };
};
const mean = (xs: (number | undefined)[]) => { const v = xs.filter((x): x is number => x !== undefined); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : NaN; };

type Scores = { recallVsExact: Record<string, number>; relevanceAkac: Record<string, number>; relevanceExact: Record<string, number> };
export type PrincipalResult = Scores & {
  principal: string; authorized: number; queries: number;
  candidates: number; filterMismatches: number; returned: number; disclosures: number; emptyResults: number;
};
export type QualityResult = {
  embedder: string; dimensions: number; backend: string; documents: number; chunks: number; queries: number; k: number[];
  indexSeconds: number; queryMsP50: number; queryMsP95: number;
  principals: PrincipalResult[];
  /** Mean over every (principal, query) pair of the given query kind; `all` covers both kinds. */
  byKind: Record<'all' | 'paraphrase' | 'keyword', Scores>;
  overall: { filterMismatchRate: number; filterMismatches: number; candidates: number; disclosures: number; crossTenant: number };
};
const pct = (xs: number[], p: number) => { const s = [...xs].sort((a, b) => a - b); return s.length ? s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)]! : NaN; };

/**
 * Indexes the corpus with the real Ingestor (reconcile) and runs every query for
 * every principal through Engine.retrieve (VectorCandidateSource over `index`),
 * comparing with the exact baseline over the documents decide() authorizes.
 */
export async function evaluateQuality(corpus: Corpus, embedder: Embedder, options: { index?: VectorIndex; backend?: string; k?: number[]; limit?: number; minScore?: number; log?: (m: string) => void } = {}): Promise<QualityResult> {
  const ks = options.k ?? [5, 10], limit = options.limit ?? Math.max(...ks), minScore = options.minScore ?? 0, log = options.log ?? (() => {});
  const store = new MemoryStore(corpus.state), clock = () => corpus.now;
  const index = new RecordingIndex(options.index ?? new MemoryVectorIndex());
  const control = new ControlPlane(store, { clock });
  const ingestor = new Ingestor({ control, store, index, embedder, clock });
  const started = performance.now();
  for (const tenant of ['acme', 'globex']) {
    const r = await ingestor.reconcile(tenant);
    if (r.failed || r.truncated) throw new Error(`reconcile ${tenant}: ${JSON.stringify(r)}`);
  }
  const indexSeconds = (performance.now() - started) / 1000;
  log(`${embedder.model}: indexed ${index.chunks.size} documents in ${indexSeconds.toFixed(1)} s`);
  const inner = new VectorCandidateSource({ index, embedder, minScore });
  let candidates = 0;
  const source: CandidateSource = { candidates: async input => { const ids = await inner.candidates(input); candidates += ids.length; return ids; } };
  let mismatches = 0;
  const onEvent = (e: EngineEvent) => { if (e.type === 'filter_mismatch') mismatches++; };
  const engine = new Engine(store, { clock, candidates: source, onEvent });
  const snapshot: State = await store.transaction('acme', async tx => structuredClone(tx.state));
  const topicOf = new Map(corpus.docs.map(d => [d.id, d.topic]));
  const allAcme = [...topicOf.keys()];
  const [vectors] = [await embedder.embed(corpus.queries.map(q => q.text))];
  const principals: PrincipalResult[] = [], latencies: number[] = [], rows: Row[] = [];
  let crossTenant = 0;
  for (const pr of PRINCIPALS) {
    // The authorized set is decided by the reference decision function itself, per document.
    const probe = corpus.binding(pr.name, corpus.queries[0]!.id);
    const authorized = new Set(allAcme.filter(id => decide(snapshot, { binding: probe, resource: id, action: 'read', purpose: 'work', now: corpus.now }).effect === 'allow'));
    const mine: Row[] = [];
    const c0 = candidates, m0 = mismatches;
    let returned = 0, disclosures = 0, empty = 0;
    for (const [i, q] of corpus.queries.entries()) {
      const t0 = performance.now();
      const r = await engine.retrieve(corpus.binding(pr.name, q.id), q.text, 'work', limit);
      latencies.push(performance.now() - t0);
      const got = r.ok ? r.value.documents.map(d => d.id) : [];
      if (!got.length) empty++;
      returned += got.length;
      for (const id of got) { if (!authorized.has(id)) disclosures++; if (!topicOf.has(id)) crossTenant++; }
      const exact = exactTopK(vectors![i]!, authorized, index.chunks, limit, minScore);
      const relevant = new Set([...authorized].filter(id => topicOf.get(id) === q.topic));
      mine.push({ kind: q.kind, ...Object.fromEntries(ks.flatMap(k => [[`rec@${k}`, overlapRecall(got, exact, k)], [`relA@${k}`, cappedRecall(got, relevant, k)], [`relE@${k}`, cappedRecall(exact, relevant, k)]])) });
    }
    rows.push(...mine);
    principals.push({ principal: pr.name, authorized: authorized.size, queries: corpus.queries.length, ...scores(mine, ks),
      candidates: candidates - c0, filterMismatches: mismatches - m0, returned, disclosures, emptyResults: empty });
    log(`${embedder.model} ${pr.name}: authorized ${authorized.size}, recall@${ks.at(-1)} vs exact ${principals.at(-1)!.recallVsExact[`@${ks.at(-1)}`]!.toFixed(3)}`);
  }
  return { embedder: embedder.model, dimensions: embedder.dimensions, backend: options.backend ?? 'memory', documents: index.chunks.size,
    chunks: [...index.chunks.values()].reduce((n, c) => n + c.vectors.length, 0), queries: corpus.queries.length, k: ks, indexSeconds,
    queryMsP50: pct(latencies, 0.5), queryMsP95: pct(latencies, 0.95), principals,
    byKind: { all: scores(rows, ks), paraphrase: scores(rows.filter(r => r.kind === 'paraphrase'), ks), keyword: scores(rows.filter(r => r.kind === 'keyword'), ks) },
    overall: { filterMismatches: mismatches, candidates, filterMismatchRate: candidates ? mismatches / candidates : 0,
      disclosures: principals.reduce((n, p) => n + p.disclosures, 0), crossTenant } };
}

const f3 = (x: number) => Number.isFinite(x) ? x.toFixed(3) : 'n/a';
/** Markdown report of one or more runs. */
export function markdown(results: QualityResult[], meta: Record<string, string>): string {
  const ks = results[0]?.k ?? [];
  const lines = ['### Retrieval quality', '', ...Object.entries(meta).map(([k, v]) => `- ${k}: ${v}`), '',
    `| Embedder | Backend | Queries | ${ks.map(k => `Recall@${k} vs exact`).join(' | ')} | ${ks.map(k => `Relevance@${k} AKAC`).join(' | ')} | ${ks.map(k => `Relevance@${k} exact`).join(' | ')} |`,
    `|---|---|---|${ks.map(() => '---').join('|')}|${ks.map(() => '---').join('|')}|${ks.map(() => '---').join('|')}|`];
  for (const r of results) for (const kind of ['all', 'paraphrase', 'keyword'] as const) {
    const o = r.byKind[kind];
    lines.push(`| ${r.embedder} (${r.dimensions}d) | ${r.backend} | ${kind} | ${ks.map(k => f3(o.recallVsExact[`@${k}`]!)).join(' | ')} | ${ks.map(k => f3(o.relevanceAkac[`@${k}`]!)).join(' | ')} | ${ks.map(k => f3(o.relevanceExact[`@${k}`]!)).join(' | ')} |`);
  }
  lines.push('', '| Embedder | Backend | Docs / chunks | Index s | Filter mismatches / candidates | Unauthorized results | Cross-tenant results | Query p50 / p95 ms |', '|---|---|---|---|---|---|---|---|');
  for (const r of results) {
    const o = r.overall;
    lines.push(`| ${r.embedder} | ${r.backend} | ${r.documents} / ${r.chunks} | ${r.indexSeconds.toFixed(1)} | ${o.filterMismatches} / ${o.candidates} (${(100 * o.filterMismatchRate).toFixed(2)} %) | ${o.disclosures} | ${o.crossTenant} | ${r.queryMsP50.toFixed(1)} / ${r.queryMsP95.toFixed(1)} |`);
  }
  const top = `@${ks.at(-1)}`;
  lines.push('', `Per principal, all queries (recall${top} vs exact / relevance${top} AKAC / filter mismatches of candidates):`, '',
    `| Principal | ${results.map(r => `${r.embedder} ${r.backend}`).join(' | ')} |`, `|---|${results.map(() => '---').join('|')}|`);
  for (const p of results[0]?.principals ?? []) {
    lines.push(`| ${p.principal} (${p.authorized} authorized) | ${results.map(r => { const x = r.principals.find(y => y.principal === p.principal)!;
      return `${f3(x.recallVsExact[top]!)} / ${f3(x.relevanceAkac[top]!)} / ${x.filterMismatches}/${x.candidates}`; }).join(' | ')} |`);
  }
  return lines.join('\n') + '\n';
}
