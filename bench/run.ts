import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { Engine } from '../reference/engine.ts';
import type { EngineEvent } from '../reference/engine.ts';
import { MemoryStore, importState } from '../reference/store.ts';
import { HashEmbedder } from '../reference/embedding.ts';
import { MemoryVectorIndex } from '../reference/vector.ts';
import type { VectorIndex } from '../reference/vector.ts';
import { VectorCandidateSource } from '../reference/retrieval.ts';
import type { Store } from '../reference/types.ts';
import { authorize, chunks, generate, query, SCALES } from './data.ts';
import type { DataSet, Scale } from './data.ts';
import { curves } from './curves.ts';
import type { Curve } from './curves.ts';
import { load, machine, prng } from './stats.ts';
import type { Machine, Summary } from './stats.ts';
import { openBenchDb } from './pg.ts';
import { toMarkdown } from './render.ts';

export type Row = Summary & { backend: string; workload: string; filterMismatches: number };
export type BackendResult = { name: string; setupSeconds: number; rows: Row[] };
export type Results = {
  format: 'akac-bench/1'; startedAt: string; seed: number; scale: Scale; dataset: Record<string, number>;
  machine: Machine; backends: BackendResult[]; curves: Curve[]; notes: string[];
};
export type BenchOptions = { scale: Scale; backends: ('memory' | 'postgres')[]; concurrency: number[]; iterations?: number; seed?: number;
  curves?: boolean; databaseUrl?: string; log?: (line: string) => void };

async function workloads(data: DataSet, store: Store, index: VectorIndex, o: { iterations: number; concurrency: number[]; seed: number; backend: string; log: (l: string) => void }): Promise<Row[]> {
  let mismatches = 0;
  const onEvent = (e: EngineEvent) => { if (e.type === 'filter_mismatch') mismatches++; };
  const plain = new Engine(store, { onEvent });
  const vector = new Engine(store, { onEvent, candidates: new VectorCandidateSource({ index, embedder: new HashEmbedder(256) }) });
  const pickIn = (i: number) => {
    const r = prng(o.seed * 7919 + i + 1_000_000), t = r.pick(data.tenants);
    return { r, t, b: r.pick(t.bindings) };
  };
  const rows: Row[] = [];
  const measure = async (workload: string, fn: (i: number) => Promise<string>, iterations = o.iterations, concurrency = o.concurrency) => {
    for (const c of concurrency) {
      const before = mismatches;
      const s = await load(fn, { iterations, concurrency: c, warmup: Math.min(20, Math.ceil(iterations / 10)) });
      rows.push({ backend: o.backend, workload, ...s, filterMismatches: mismatches - before });
      o.log(`${o.backend} ${workload} c=${c}: p50 ${s.p50} ms, p95 ${s.p95} ms, p99 ${s.p99} ms, ${s.throughput}/s ${JSON.stringify(s.outcomes)}`);
    }
  };
  // Authorized draws: a sampled binding and documents it may read (bench/data.ts authorize()).
  const tenantsWithAllows = data.tenants.filter(t => t.authorized?.length);
  const pickAllowed = (i: number) => {
    const r = prng(o.seed * 104729 + i + 1), t = r.pick(tenantsWithAllows), a = r.pick(t.authorized!);
    return { r, b: a.binding, docs: a.docs };
  };
  await measure('evaluate read, authorized document', async i => {
    const { r, b, docs } = pickAllowed(i);
    const v = await plain.evaluate(b, r.pick(docs), 'read', 'work');
    return v.decision ? 'allow' : v.code;
  });
  await measure('evaluate read, random document (mixed)', async i => {
    const { r, t, b } = pickIn(i);
    const v = await plain.evaluate(b, r.pick(t.docs), 'read', 'work');
    return v.decision ? 'allow' : v.code;
  });
  await measure('openContext, 1 authorized document', async i => {
    const { r, b, docs } = pickAllowed(i);
    return (await plain.openContext(b, [r.pick(docs)], 'work')).ok ? 'allow' : 'deny';
  });
  await measure('openContext, 8 authorized documents', async i => {
    const { r, b, docs } = pickAllowed(i);
    return (await plain.openContext(b, Array.from({ length: 8 }, () => r.pick(docs)), 'work')).ok ? 'allow' : 'deny';
  });
  await measure('openContext, 1 random document (mixed)', async i => {
    const { r, t, b } = pickIn(i);
    return (await plain.openContext(b, [r.pick(t.docs)], 'work')).ok ? 'allow' : 'deny';
  });
  await measure('retrieve, vector (HashEmbedder, k=5)', async i => {
    const { b } = pickIn(i);
    const res = await vector.retrieve(b, query(data, i), 'work', 5);
    return res.ok ? (res.value.documents.length ? 'allow' : 'allow-empty') : 'deny-or-no-match';
  });
  await measure(`retrieve, lexical (${data.lexical.docs.length} documents in tenant)`, async i => {
    const r = prng(o.seed + i), b = r.pick(data.lexical.bindings);
    const res = await plain.retrieve(b, query(data, i), 'work', 5);
    return res.ok ? (res.value.documents.length ? 'allow' : 'allow-empty') : 'deny-or-no-match';
  }, Math.max(10, Math.floor(o.iterations / 5)));
  // End-to-end derivation depth: node d-1 of a readable chain has a source path of d records.
  const chains = data.tenants.flatMap(t => t.readableChains ?? []);
  for (const d of [1, 2, 4, 8, 12, 16].filter(d => d <= data.scale.dagDepth)) {
    await measure(`evaluate derived artifact, derivation depth ${d}`, async i => {
      if (!chains.length) return 'no-readable-chain';
      const c = prng(o.seed + 31 * i).pick(chains);
      const v = await plain.evaluate(c.binding, c.chain[d - 1]!, 'read', 'work');
      return v.decision ? 'allow' : v.code;
    }, Math.max(10, Math.floor(o.iterations / 5)), [1]);
  }
  return rows;
}

export async function runBench(o: BenchOptions): Promise<Results> {
  const log = o.log ?? (() => {});
  const seed = o.seed ?? 1, iterations = o.iterations ?? o.scale.iterations;
  const started = new Date().toISOString();
  let t = performance.now();
  const data = generate(o.scale, seed);
  const embedder = new HashEmbedder(256);
  authorize(data);
  const all = await chunks(data, embedder);
  log(`generated ${JSON.stringify(data.counts)} and ${all.length} chunks in ${Math.round(performance.now() - t)} ms`);
  const results: Results = { format: 'akac-bench/1', startedAt: started, seed, scale: o.scale, dataset: { ...data.counts, chunks: all.length }, machine: machine(), backends: [], curves: [],
    notes: [
      'Closed-loop load: each of `concurrency` in-process callers issues the next call when its previous one returns; latency is per call (performance.now), warm-up calls excluded.',
      'Callers run in the same Node.js process as the engine (no HTTP, TLS or authentication cost). Every call is a full audited decision: a store transaction that appends one hash-chained audit entry.',
      '"authorized" workloads draw a sampled binding and a document it may read (checked beforehand with the pure decide()); "mixed" workloads draw binding and document at random and are mostly denials. The outcomes column shows what the engine returned.',
      'MemoryStore serializes all transactions and copies the tenant snapshot per transaction; it is the test/single-process store, not a production backend.',
      'PostgreSQL: runtime role without BYPASSRLS (forced row-level security on), per-tenant advisory lock per transaction, so callers of one tenant are serialized while tenants run in parallel.'
    ] };
  if (o.curves !== false) { t = performance.now(); results.curves = curves(); log(`cost curves in ${Math.round(performance.now() - t)} ms`); }
  for (const backend of o.backends) {
    t = performance.now();
    if (backend === 'memory') {
      const store = new MemoryStore(), index = new MemoryVectorIndex();
      for (const state of data.states.values()) await importState(store, state);
      await index.upsert(all);
      const setupSeconds = Math.round(performance.now() - t) / 1000;
      log(`memory setup ${setupSeconds} s`);
      results.backends.push({ name: 'memory', setupSeconds, rows: await workloads(data, store, index, { iterations, concurrency: o.concurrency, seed, backend: 'memory', log }) });
      await store.close();
    } else {
      if (!o.databaseUrl) throw new Error('postgres backend needs AKAC_BENCH_DATABASE_URL (or AKAC_TEST_DATABASE_URL)');
      const db = await openBenchDb(o.databaseUrl, { max: Math.max(16, ...o.concurrency) + 4 });
      try {
        results.machine.postgres = db.version; results.machine.pgvector = db.pgvector;
        for (const state of data.states.values()) await importState(db.store, state);
        await db.loadChunks(all); await db.analyze();
        const setupSeconds = Math.round(performance.now() - t) / 1000;
        log(`postgres setup ${setupSeconds} s (schema ${db.schema})`);
        results.backends.push({ name: 'postgres+pgvector', setupSeconds, rows: await workloads(data, db.store, db.index, { iterations, concurrency: o.concurrency, seed, backend: 'postgres+pgvector', log }) });
      } finally { await db.close(); }
    }
  }
  return results;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const { values } = parseArgs({ options: {
    scale: { type: 'string', default: process.env.AKAC_BENCH_SCALE ?? 'small' },
    backend: { type: 'string', default: process.env.AKAC_BENCH_BACKENDS ?? 'memory' },
    concurrency: { type: 'string', default: '1,8' },
    iterations: { type: 'string' }, seed: { type: 'string', default: '1' },
    'no-curves': { type: 'boolean', default: false },
    out: { type: 'string', default: 'bench-results/results.json' }, markdown: { type: 'string' }
  } });
  const scale = SCALES[values.scale!];
  if (!scale) { console.error(`unknown scale ${values.scale}; one of ${Object.keys(SCALES).join(', ')}`); process.exit(2); }
  const backends = values.backend!.split(',').map(b => b.trim()) as ('memory' | 'postgres')[];
  if (backends.some(b => b !== 'memory' && b !== 'postgres')) { console.error('backend: memory, postgres or memory,postgres'); process.exit(2); }
  const concurrency = values.concurrency!.split(',').map(Number);
  if (concurrency.some(c => !Number.isInteger(c) || c < 1 || c > 256)) { console.error('concurrency: comma-separated integers 1-256'); process.exit(2); }
  const results = await runBench({ scale, backends, concurrency, seed: Number(values.seed), curves: !values['no-curves'],
    ...(values.iterations ? { iterations: Number(values.iterations) } : {}),
    ...(process.env.AKAC_BENCH_DATABASE_URL || process.env.AKAC_TEST_DATABASE_URL ? { databaseUrl: process.env.AKAC_BENCH_DATABASE_URL || process.env.AKAC_TEST_DATABASE_URL } : {}),
    log: line => console.error(line) });
  mkdirSync(dirname(values.out!), { recursive: true });
  writeFileSync(values.out!, JSON.stringify(results, null, 2) + '\n');
  const md = toMarkdown(results);
  if (values.markdown) { mkdirSync(dirname(values.markdown), { recursive: true }); writeFileSync(values.markdown, md); }
  console.log(md);
}
