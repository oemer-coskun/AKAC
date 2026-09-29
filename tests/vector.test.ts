import { bare } from './bare.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Engine } from '../reference/engine.ts';
import type { EngineEvent } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { MemoryStore } from '../reference/store.ts';
import { HashEmbedder, HttpEmbedder } from '../reference/embedding.ts';
import type { Embedder } from '../reference/embedding.ts';
import { chunkText } from '../reference/chunking.ts';
import { MemoryVectorIndex, RoutedVectorIndex, labelDigest } from '../reference/vector.ts';
import type { IndexedChunk, VectorIndex, VectorQuery } from '../reference/vector.ts';
import { VectorCandidateSource } from '../reference/retrieval.ts';
import { Ingestor } from '../reference/ingest.ts';
import type { IngestEvent } from '../reference/ingest.ts';
import { kbFixture, bindings } from '../examples/fixture.ts';
import { LEVELS } from '../reference/types.ts';
import type { Binding, Knowledge, State } from '../reference/types.ts';

const now = 1800000000000;
const other: Binding = { tenant: 'other', subject: 'o-user', agent: 'o-agent', grant: 'o-run' };
const hash = new HashEmbedder(4096);
function world(): State {
  const s = kbFixture(now);
  s.actors.admin!.roles = ['security-admin', 'kb-admin', 'auditor'];
  s.actors['o-user'] = { id: 'o-user', tenant: 'other', kind: 'user', roles: ['staff'], projects: [], clearance: 'restricted', active: true };
  s.actors['o-agent'] = { ...s.actors['o-user']!, id: 'o-agent', kind: 'agent' };
  s.actors['o-admin'] = { ...s.actors.admin!, id: 'o-admin', tenant: 'other' };
  s.grants['o-run'] = { ...s.grants['chief-run']!, id: 'o-run', tenant: 'other', subject: 'o-user', agent: 'o-agent' };
  s.knowledge['o-doc'] = { ...s.knowledge.handbook!, id: 'o-doc', tenant: 'other', content: 'Other tenant product notes.' };
  return s;
}
/** Records which compartments each query touched. */
class SpyIndex extends MemoryVectorIndex {
  queries: VectorQuery[] = [];
  override async query(q: VectorQuery) { this.queries.push(q); return super.query(q); }
}
async function rig(options: { embedder?: Embedder; index?: VectorIndex; minScore?: number } = {}) {
  const store = new MemoryStore(world());
  const index = options.index ?? new SpyIndex(), embedder = options.embedder ?? hash;
  const engineEvents: EngineEvent[] = [], ingestEvents: IngestEvent[] = [];
  const control = new ControlPlane(store, { clock: () => now });
  const ingestor = new Ingestor({ control, store, index, embedder, clock: () => now, onEvent: e => ingestEvents.push(e) });
  const engine = new Engine(store, { clock: () => now, onEvent: e => engineEvents.push(e),
    candidates: new VectorCandidateSource({ index, embedder, minScore: options.minScore ?? 0.3 }) });
  stores.set(engine, store);
  for (const tenant of ['acme', 'other']) await ingestor.reconcile(tenant);
  return { store, index, embedder, control, ingestor, engine, engineEvents, ingestEvents };
}
const doc = (id: string, content: string, extra: Partial<Knowledge> = {}): Knowledge => ({ id, tenant: 'acme', version: 1, kind: 'document', origin: 'human',
  content, classification: 'internal', projects: [], readerRoles: ['staff'], readers: [], sources: [], active: true, ...extra });
const stores = new WeakMap<Engine, MemoryStore>();
let runs = 0;
/** Each call uses a fresh run grant: an epoch bump (any administrative change) invalidates earlier runs by design. */
const ids = async (engine: Engine, b: Binding, query: string) => {
  const store = stores.get(engine)!, grant = `${b.grant}-${++runs}`;
  await store.transaction(b.tenant, async tx => { tx.state.grants[grant] = { ...structuredClone(tx.state.grants[b.grant]!), id: grant }; });
  const r = await engine.retrieve({ ...b, grant }, query, 'work', 10);
  return r.ok ? r.value.documents.map(d => d.id).sort() : null;
};
const STRATEGY = 'acquisition strategy confidential purchase budget';
const tokensOf = (...t: string[]) => t;

test('HashEmbedder is deterministic, normalized and lexical', async () => {
  const [a, b, c] = await hash.embed(['The synthetic reserve figure', 'the SYNTHETIC reserve   figure!', 'entirely unrelated words'])
  assert.deepEqual(a, b); assert.equal(a!.length, 4096);
  assert.ok(Math.abs(a!.reduce((n, x) => n + x * x, 0) - 1) < 1e-5);
  assert.equal(a!.reduce((n, x, i) => n + x * c![i]!, 0), 0, 'no shared features, no similarity');
  assert.deepEqual((await hash.embed(['   ']))[0], new Float32Array(4096));
  assert.throws(() => new HashEmbedder(3));
});

test('chunker is deterministic, bounded, overlapping and fails instead of truncating', () => {
  const text = Array.from({ length: 60 }, (_, i) => `Sentence number ${i} discusses the synthetic topic ${i % 7}.`).join(' ') + '\n\nSecond paragraph stands alone.';
  const chunks = chunkText('d1', 3, text, { maxChars: 300, overlap: 60 });
  assert.deepEqual(chunks, chunkText('d1', 3, text, { maxChars: 300, overlap: 60 }));
  assert.ok(chunks.length > 5 && chunks.every((c, i) => c.ordinal === i && c.id === `d1#3#${i}` && c.text.length <= 300));
  for (let i = 1; i < chunks.length; i++) {
    const words = chunks[i - 1]!.text.split(' ');
    assert.ok(chunks[i]!.text.startsWith(words.at(-1)!) || chunks[i]!.text.includes(words.at(-1)!), 'overlap carries the previous tail');
  }
  assert.equal(chunkText('d', 1, 'short text').length, 1);
  const long = chunkText('d', 1, 'x'.repeat(5000), { maxChars: 1200, overlap: 150 });
  assert.ok(long.length >= 4 && long.every(c => c.text.length <= 1200));
  assert.throws(() => chunkText('d', 1, 'word '.repeat(10_000), { maxChars: 100, overlap: 10, maxChunks: 20 }), /chunk limit/);
  assert.throws(() => chunkText('d', 1, 'x', { maxChars: 10 }), /Invalid/);
});

test('compartments: a low-clearance caller never queries a higher tier', async () => {
  const { engine, index } = await rig(); const spy = index as SpyIndex;
  await ids(engine, bindings.intern, 'office hours'); await ids(engine, bindings.lead, 'schedule'); await ids(engine, bindings.chief, 'budget');
  assert.deepEqual(spy.queries.map(q => q.compartments), [['public', 'internal'], ['public', 'internal', 'confidential'], [...LEVELS]]);
  assert.ok(spy.queries.every(q => q.tenant === 'acme'));
});

test('pre-filter: ACL, containers, projects and clearance decide admission; results match', async () => {
  const { engine, engineEvents } = await rig();
  assert.deepEqual(await ids(engine, bindings.chief, STRATEGY), ['strategy']);
  assert.equal(await ids(engine, bindings.intern, STRATEGY), null, 'restricted content is not retrievable by an intern');
  assert.deepEqual(await ids(engine, bindings.intern, 'Staff FAQ office hours'), ['staff-faq']);
  assert.deepEqual(await ids(engine, bindings.chief, 'Vault memo reserve figure'), ['vault-memo']);
  assert.equal(await ids(engine, bindings.lead, 'Vault memo reserve figure'), null);
  assert.deepEqual(await ids(engine, bindings.lead, 'Product project alpha schedule launch'), ['project-alpha']);
  assert.equal(await ids(engine, bindings.intern, 'Product project alpha schedule launch'), null);
  assert.equal(engineEvents.filter(e => e.type === 'filter_mismatch').length, 0, 'a correct index needs no engine-side drops');
});

test('index-level pre-filter: container levels are all required, projects are all required', async () => {
  const index = new MemoryVectorIndex(); const v = (await hash.embed(['needle']))[0]!;
  const chunk = (docId: string, extra: Partial<IndexedChunk>): IndexedChunk => ({ tenant: 't', docId, docVersion: 1, chunkId: `${docId}#1#0`, ordinal: 0,
    compartment: 'internal', readTokens: ['role:staff'], requiredProjects: [], containerTokens: [], model: hash.model, vector: v, ...extra });
  await index.upsert([chunk('open', {}), chunk('nested', { containerTokens: [['role:staff'], ['role:exec', 'user:ann']] }),
    chunk('empty-acl', { readTokens: [] }), chunk('empty-level', { containerTokens: [[]] }), chunk('proj', { requiredProjects: ['alpha', 'beta'] }),
    chunk('elsewhere', { tenant: 'u' }), chunk('higher', { compartment: 'restricted' })]);
  const q = (tokens: string[], projects: string[] = [], compartments = ['public', 'internal'] as VectorQuery['compartments']) => index.query({ tenant: 't', compartments, tokens, projects, vector: v, k: 50 }).then(h => h.map(x => x.docId).sort());
  assert.deepEqual(await q(['role:staff']), ['open']);
  assert.deepEqual(await q(['role:staff', 'user:ann']), ['nested', 'open']);
  assert.deepEqual(await q(['role:staff'], ['alpha']), ['open']);
  assert.deepEqual(await q(['role:staff'], ['alpha', 'beta']), ['open', 'proj']);
  assert.deepEqual(await q(['role:staff'], [], [...LEVELS]), ['higher', 'open']);
  assert.deepEqual(await q([]), []);
  assert.deepEqual(await index.query({ tenant: 'u', compartments: [...LEVELS], tokens: ['role:staff'], projects: [], vector: v, k: 5 }).then(h => h.map(x => x.docId)), ['elsewhere']);
  await assert.rejects(index.query({ tenant: 't', compartments: ['public'], tokens: [], projects: [], vector: v, k: 0 }), /Invalid/);
  await assert.rejects(index.query({ tenant: 't', compartments: ['secret' as never], tokens: [], projects: [], vector: v, k: 1 }), /Invalid/);
});

test('tenant isolation: one tenant never sees the other tenant\'s chunks', async () => {
  const { engine, index } = await rig();
  assert.deepEqual(await ids(engine, other, 'Other tenant'), ['o-doc']);
  assert.equal(await ids(engine, bindings.chief, 'Other tenant'), null);
  const v = (await hash.embed(['Other tenant']))[0]!;
  const all = { compartments: [...LEVELS], tokens: ['role:staff', 'role:executive', 'user:chief'], projects: ['alpha'], vector: v, k: 100 };
  assert.ok(!(await index.query({ tenant: 'acme', ...all })).some(h => h.docId === 'o-doc'));
  assert.ok((await index.query({ tenant: 'other', ...all })).every(h => h.docId === 'o-doc'));
});

test('ranking uses only authorized candidates: unauthorized documents leave no trace in scores', async () => {
  const { index } = await rig();
  const clean = new MemoryVectorIndex(), e = hash;
  for (const [docId, text] of [['handbook', 'Product handbook: our public product is a notebook.'], ['staff-faq', 'Staff FAQ: synthetic office hours.']] as const) {
    const state = await index.state('acme'); assert.ok(state.has(docId));
    await clean.upsert([{ tenant: 'acme', docId, docVersion: 1, chunkId: `${docId}#1#0`, ordinal: 0, compartment: docId === 'handbook' ? 'public' : 'internal',
      readTokens: ['role:staff'], requiredProjects: [], containerTokens: docId === 'handbook' ? [] : [['role:staff']], model: e.model, vector: (await e.embed([text]))[0]! }]);
  }
  const q = { tenant: 'acme', compartments: ['public', 'internal'] as VectorQuery['compartments'], tokens: ['role:staff', 'user:intern'], projects: [], vector: (await e.embed([STRATEGY + ' product']))[0]!, k: 10 };
  const real = await index.query(q), reference = await clean.query(q);
  assert.deepEqual(real.map(h => [h.docId, h.score]), reference.map(h => [h.docId, h.score]));
  assert.ok(real.every(h => h.docId !== 'strategy'));
});

test('empty results do not distinguish no match from no authority', async () => {
  const { engine, store } = await rig();
  const last = async () => (await store.auditLog('acme')).at(-1)!.reason;
  const noAuthority = await engine.retrieve(bindings.intern, STRATEGY, 'work');
  const noAuthorityReason = await last();
  const noMatch = await engine.retrieve(bindings.intern, 'zyzzyva qwertz plugh', 'work');
  assert.deepEqual(bare(noAuthority), { ok: false, code: 'NOT_AUTHORIZED' });
  assert.deepEqual(bare(noMatch), bare(noAuthority), 'only the random decision id differs');
  assert.equal(await last(), noAuthorityReason);
});

test('index metadata is a hint: a chunk with wrong tokens is dropped by decide() and counted', async () => {
  const { engine, index, engineEvents } = await rig();
  // Corrupt the index: claim the restricted strategy document is a public, staff-readable one.
  await index.upsert([{ tenant: 'acme', docId: 'strategy', docVersion: 1, chunkId: 'strategy#1#0', ordinal: 0, compartment: 'public', readTokens: ['role:staff'],
    requiredProjects: [], containerTokens: [], model: hash.model, vector: (await hash.embed([STRATEGY]))[0]! }]);
  const result = await engine.retrieve(bindings.intern, STRATEGY, 'work');
  assert.deepEqual(bare(result), { ok: false, code: 'NOT_AUTHORIZED' });
  assert.equal(engineEvents.filter(e => e.type === 'filter_mismatch').length, 1);
  assert.ok(engine.stats().filterMismatches >= 1);
  // A mixed result returns only what decide() allows.
  const mixed = await engine.retrieve(bindings.intern, `${STRATEGY} Staff FAQ office hours`, 'work');
  assert.ok(mixed.ok && mixed.value.documents.map(d => d.id).join() === 'staff-faq');
});

test('unavailable embedder or index denies and is reported', async () => {
  const broken: Embedder = { model: 'x', dimensions: 4096, embed: async () => { throw new Error('offline'); } };
  const { engine, engineEvents } = await rig({ embedder: hash });
  const down = new Engine(new MemoryStore(world()), { clock: () => now, onEvent: e => engineEvents.push(e),
    candidates: new VectorCandidateSource({ index: new MemoryVectorIndex(), embedder: broken }) });
  assert.deepEqual(bare(await down.retrieve(bindings.chief, 'anything', 'work')), { ok: false, code: 'NOT_AUTHORIZED' });
  assert.ok(engineEvents.some(e => e.type === 'candidates_unavailable'));
  assert.ok((await engine.retrieve(bindings.chief, STRATEGY, 'work')).ok);
});

test('ingestion: new version replaces old chunks; container floor sets the compartment; unauthorized admins are refused', async () => {
  const { engine, ingestor, index, ingestEvents } = await rig(); const spy = index as SpyIndex;
  assert.deepEqual(bare(await ingestor.ingest('acme', 'admin', doc('memo', 'alpha bravo charlie.'))), { ok: true, value: { id: 'memo', version: 1, chunks: 1 } });
  assert.deepEqual(await ids(engine, bindings.intern, 'alpha bravo charlie'), ['memo']);
  assert.ok((await ingestor.ingest('acme', 'admin', doc('memo', 'delta echo foxtrot.', { version: 2 }))).ok);
  assert.equal(await ids(engine, bindings.intern, 'alpha bravo charlie'), null);
  assert.deepEqual(await ids(engine, bindings.intern, 'delta echo foxtrot'), ['memo']);
  assert.equal((await index.state('acme')).get('memo')!.version, 2);
  // A lower version can never overwrite a newer one, even if an old write arrives late.
  await index.upsert([{ tenant: 'acme', docId: 'memo', docVersion: 1, chunkId: 'memo#1#0', ordinal: 0, compartment: 'internal', readTokens: ['role:staff'],
    requiredProjects: [], containerTokens: [], model: hash.model, vector: (await hash.embed(['alpha bravo charlie']))[0]! }]);
  assert.equal((await index.state('acme')).get('memo')!.version, 2);
  assert.equal(await ids(engine, bindings.intern, 'alpha bravo charlie'), null);
  // Public document in the restricted folder: indexed in the restricted compartment.
  assert.ok((await ingestor.ingest('acme', 'admin', doc('folder-doc', 'kilo lima mike.', { classification: 'public', container: 'f-vault' }))).ok);
  assert.equal(await ids(engine, bindings.lead, 'kilo lima mike'), null);
  assert.deepEqual(await ids(engine, bindings.chief, 'kilo lima mike'), ['folder-doc']);
  assert.ok(spy.queries.at(-2)!.compartments.every(c => c !== 'restricted'));
  // Authorization and validation happen in the control plane; nothing is indexed on refusal.
  assert.deepEqual(bare(await ingestor.ingest('acme', 'intern', doc('evil', 'oscar papa.'))), { ok: false, code: 'NOT_AUTHORIZED' });
  assert.deepEqual(bare(await ingestor.ingest('acme', 'admin', doc('memo', 'stale.', { version: 9 }))), { ok: false, code: 'CONFLICT' });
  assert.deepEqual(bare(await ingestor.ingest('acme', 'admin', { ...doc('model-made', 'x.'), origin: 'model' })), { ok: false, code: 'INVALID_REQUEST' });
  assert.ok(![...(await index.state('acme')).keys()].includes('evil'));
  assert.ok(ingestEvents.some(e => e.type === 'indexed'));
});

test('embedder failure leaves the document authoritative but unindexed; reconcile repairs it', async () => {
  let failing = true;
  const flaky: Embedder = { model: hash.model, dimensions: 4096, embed: (t, s) => { if (failing) throw new Error('embedding service down'); return hash.embed(t, s); } };
  const { engine, ingestor, store, index, ingestEvents } = await rig({ embedder: hash });
  const bad = new Ingestor({ control: new ControlPlane(store, { clock: () => now }), store, index, embedder: flaky, clock: () => now, onEvent: e => ingestEvents.push(e) });
  assert.deepEqual(bare(await bad.ingest('acme', 'admin', doc('late', 'quebec romeo sierra.'))), { ok: false, code: 'INDEX_PENDING', id: 'late', version: 1 });
  assert.ok(ingestEvents.some(e => e.type === 'index_pending' && e.reason === 'embed'));
  assert.equal((await store.transaction('acme', async tx => tx.state.knowledge.late?.version)), 1, 'authoritative write stayed');
  assert.equal(await ids(engine, bindings.intern, 'quebec romeo sierra'), null);
  assert.deepEqual(await bad.reconcile('acme'), { indexed: 0, removed: 0, failed: 1, truncated: false });
  failing = false;
  assert.deepEqual(await bad.reconcile('acme'), { indexed: 1, removed: 0, failed: 0, truncated: false });
  assert.deepEqual(await ids(engine, bindings.intern, 'quebec romeo sierra'), ['late']);
  assert.deepEqual(await ingestor.reconcile('acme'), { indexed: 0, removed: 0, failed: 0, truncated: false }, 'idempotent');
});

test('removal, revocation and relabeling keep the index consistent', async () => {
  const { engine, ingestor, index, control, store } = await rig();
  assert.deepEqual(await ids(engine, bindings.intern, 'Staff FAQ office hours'), ['staff-faq']);
  // An index outage during removal leaves INDEX_PENDING; reconcile removes chunks of inactive documents.
  const real = index.removeDocument.bind(index); let down = true;
  index.removeDocument = async (t, d) => { if (down) throw new Error('index offline'); return real(t, d); };
  assert.deepEqual(bare(await ingestor.remove('acme', 'admin', 'staff-faq')), { ok: false, code: 'INDEX_PENDING', id: 'staff-faq', version: 0 });
  assert.equal(await ids(engine, bindings.intern, 'Staff FAQ office hours'), null, 'the engine denies a revoked document even while chunks remain');
  assert.ok((await index.state('acme')).has('staff-faq'));
  down = false;
  assert.equal((await ingestor.reconcile('acme')).removed, 1);
  assert.ok(!(await index.state('acme')).has('staff-faq'));
  assert.deepEqual(bare(await ingestor.remove('acme', 'intern', 'handbook')), { ok: false, code: 'NOT_AUTHORIZED' });
  // Raising a container floor moves its documents to a higher compartment on reconcile.
  const before = (await index.state('acme')).get('board-notes')!.digest;
  const folder = await store.transaction('acme', async tx => structuredClone(tx.state.containers['f-executive']!));
  assert.ok((await control.upsertContainer('acme', 'admin', { ...folder, classification: 'restricted' })).ok);
  assert.equal((await ingestor.reconcile('acme')).indexed, 1);
  assert.notEqual((await index.state('acme')).get('board-notes')!.digest, before);
  const v = (await hash.embed(['Board notes synthetic quarterly agenda']))[0]!;
  const probe = (compartments: VectorQuery['compartments']) => index.query({ tenant: 'acme', compartments, tokens: ['role:staff', 'role:executive'], projects: [], vector: v, k: 20 }).then(h => h.some(x => x.docId === 'board-notes'));
  assert.equal(await probe(['public', 'internal', 'confidential']), false);
  assert.equal(await probe([...LEVELS]), true);
  assert.deepEqual(bare(await ingestor.relabel('acme', 'board-notes')), { ok: true, value: { id: 'board-notes', version: 1, chunks: 1 } });
  assert.deepEqual(bare(await ingestor.relabel('acme', 'nonexistent')), { ok: true, value: { id: 'nonexistent', version: 0, chunks: 0 } });
  assert.deepEqual(bare(await ingestor.relabel('acme', '../x')), { ok: false, code: 'INVALID_REQUEST' });
});

test('a model change re-embeds on reconcile', async () => {
  const { store, index } = await rig();
  const next = new HashEmbedder(4096); Object.defineProperty(next, 'model', { value: 'akac-hash-v2' });
  const ingestor = new Ingestor({ control: new ControlPlane(store, { clock: () => now }), store, index, embedder: next, clock: () => now });
  const result = await ingestor.reconcile('acme');
  assert.ok(result.indexed >= 4 && result.failed === 0);
  assert.ok([...(await index.state('acme')).values()].every(s => s.model === 'akac-hash-v2'));
});

test('routed index: the restricted tier lives in a separate backend the low-clearance caller never reaches', async () => {
  const main = new SpyIndex(), vault = new SpyIndex();
  const { engine, ingestor } = await rig({ index: new RoutedVectorIndex({ default: main, restricted: vault }) });
  assert.ok((await main.state('acme')).has('handbook') && !(await main.state('acme')).has('strategy'));
  assert.ok((await vault.state('acme')).has('strategy') && !(await vault.state('acme')).has('handbook'));
  main.queries.length = vault.queries.length = 0;
  assert.equal(await ids(engine, bindings.lead, STRATEGY), null);
  assert.equal(vault.queries.length, 0); assert.equal(main.queries.length, 1);
  assert.deepEqual(await ids(engine, bindings.chief, STRATEGY), ['strategy']);
  // Moving between backends removes the old copy.
  assert.ok((await ingestor.ingest('acme', 'admin', doc('mover', 'tango uniform.'))).ok);
  assert.ok((await main.state('acme')).has('mover'));
  assert.ok((await ingestor.ingest('acme', 'admin', doc('mover', 'tango uniform.', { version: 2, classification: 'restricted' }))).ok);
  assert.ok(!(await main.state('acme')).has('mover') && (await vault.state('acme')).has('mover'));
});

test('label digest is order-insensitive within a list and sensitive to compartment and levels', () => {
  const a = { compartment: 'internal' as const, readTokens: ['b', 'a'], requiredProjects: [], containerTokens: [['x', 'y'], ['z']] };
  assert.equal(labelDigest(a), labelDigest({ ...a, readTokens: ['a', 'b'], containerTokens: [['y', 'x'], ['z']] }));
  assert.notEqual(labelDigest(a), labelDigest({ ...a, compartment: 'restricted' }));
  assert.notEqual(labelDigest(a), labelDigest({ ...a, containerTokens: [['z'], ['x', 'y']] }));
  assert.equal(tokensOf('a').length, 1);
});

// ---- HttpEmbedder against a local stub -------------------------------------------------------
type Seen = { url: string; auth?: string; body: { model: string; input: string[]; dimensions?: number; encoding_format: string } };
async function stub(handler: (req: Seen, res: ServerResponse, raw: IncomingMessage) => void | Promise<void>) {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    let raw = ''; req.on('data', c => { raw += c; });
    req.on('end', () => { const s = { url: req.url!, auth: req.headers.authorization, body: JSON.parse(raw || '{}') } as Seen; seen.push(s); void handler(s, res, req); });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  return { seen, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()); }) };
}
const reply = (res: ServerResponse, body: unknown, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
const vec = (n: number, x: number) => Array.from({ length: n }, () => x);

test('HttpEmbedder: request shape, ordering, batching and API key', async () => {
  const s = await stub((req, res) => reply(res, { data: [...req.body.input].map((t, i) => ({ index: i, embedding: vec(4, i + 1) })).reverse() }));
  try {
    const e = new HttpEmbedder({ baseUrl: s.base + '/', model: 'synthetic-embed', dimensions: 4, apiKey: 'synthetic-key', maxBatch: 2 });
    const out = await e.embed(['a', 'b', 'c', 'd', 'e']);
    assert.equal(out.length, 5); assert.deepEqual(Array.from(out[1]!), [2, 2, 2, 2]); assert.deepEqual(Array.from(out[4]!), [1, 1, 1, 1]);
    assert.equal(s.seen.length, 3);
    assert.ok(s.seen.every(r => r.url === '/v1/embeddings' && r.auth === 'Bearer synthetic-key' && r.body.model === 'synthetic-embed' && r.body.dimensions === undefined));
    assert.deepEqual(await e.embed([]), []);
    await new HttpEmbedder({ baseUrl: s.base, model: 'm', dimensions: 4, requestDimensions: true }).embed(['x']);
    assert.equal(s.seen.at(-1)!.body.dimensions, 4); assert.equal(s.seen.at(-1)!.auth, undefined);
    await assert.rejects(e.embed(['ok', '']), /Invalid embedding input/);
  } finally { await s.close(); }
});

test('HttpEmbedder: strict response validation and no content in errors', async () => {
  const secret = 'SYNTHETIC-SECRET-CONTENT';
  const cases: Record<string, (n: number) => [unknown, number?]> = {
    'wrong dimensions': () => [{ data: [{ index: 0, embedding: vec(3, 1) }] }],
    'too many vectors': () => [{ data: [{ index: 0, embedding: vec(4, 1) }, { index: 1, embedding: vec(4, 1) }] }],
    'duplicate index': () => [{ data: [{ index: 0, embedding: vec(4, 1) }, { index: 0, embedding: vec(4, 1) }] }],
    'index out of range': () => [{ data: [{ index: 5, embedding: vec(4, 1) }] }],
    'non-numeric value': () => [{ data: [{ index: 0, embedding: ['a', 1, 1, 1] }] }],
    'null value': () => [{ data: [{ index: 0, embedding: [null, 1, 1, 1] }] }],
    'missing data': () => [{ error: 'nope' }],
    'data is not a list': () => [{ data: 'x' }],
    'server error with body': () => [{ error: secret }, 500]
  };
  for (const [name, respond] of Object.entries(cases)) {
    const s = await stub((_req, res) => { const [body, status] = respond(1); reply(res, body, status); });
    try {
      const e = new HttpEmbedder({ baseUrl: s.base, model: 'm', dimensions: 4 });
      await assert.rejects(e.embed([secret]), (error: Error) => { assert.ok(!error.message.includes(secret), `${name}: no content in the error`); return true; }, name);
    } finally { await s.close(); }
  }
  const garbage = await stub((_req, res) => { res.writeHead(200); res.end('<html>'); });
  try { await assert.rejects(new HttpEmbedder({ baseUrl: garbage.base, model: 'm', dimensions: 4 }).embed(['x']), /not JSON/); } finally { await garbage.close(); }
});

test('HttpEmbedder: timeout, redirects and endpoint policy', async () => {
  const slow = await stub(() => { /* never answers */ });
  try { await assert.rejects(new HttpEmbedder({ baseUrl: slow.base, model: 'm', dimensions: 4, timeoutMs: 100 }).embed(['x'])); } finally { await slow.close(); }
  const controller = new AbortController();
  const hang = await stub(() => { /* never answers */ });
  try {
    const pending = new HttpEmbedder({ baseUrl: hang.base, model: 'm', dimensions: 4 }).embed(['x'], controller.signal);
    setTimeout(() => controller.abort(), 50);
    await assert.rejects(pending);
  } finally { await hang.close(); }
  const redirect = await stub((_req, res) => { res.writeHead(302, { location: 'http://127.0.0.1:1/steal' }); res.end(); });
  try { await assert.rejects(new HttpEmbedder({ baseUrl: redirect.base, model: 'm', dimensions: 4, apiKey: 'k' }).embed(['x'])); } finally { await redirect.close(); }
  const make = (baseUrl: string, extra = {}) => () => new HttpEmbedder({ baseUrl, model: 'm', dimensions: 4, ...extra });
  assert.throws(make('http://embeddings.example.test'), /https/);
  assert.throws(make('http://192.0.2.10'), /https/);
  assert.throws(make('ftp://127.0.0.1'), /https/);
  const embedded = new URL('https://embeddings.example.test'); embedded.username = 'u'; embedded.password = 'p';
  assert.throws(make(embedded.toString()), /Invalid/);
  assert.throws(make('not a url'), /Invalid/);
  assert.throws(make('https://embeddings.example.test', { apiKey: 'a\r\nx-evil: 1' }), /Invalid API key/);
  assert.throws(make('https://embeddings.example.test', { dimensions: 0 }), /Invalid dimensions/);
  for (const ok of ['https://embeddings.example.test/base', 'http://localhost:8080', 'http://127.0.0.1:1', 'http://[::1]:1']) assert.doesNotThrow(make(ok));
});

test('HttpEmbedder: an oversized chunked response is aborted while streaming, not buffered', async () => {
  const chunk = Buffer.alloc(1024 * 1024, 0x20), total = 256; // 256 MiB offered, the limit is 64 MiB
  let sent = 0;
  const s = await stub((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' }); // no content-length: chunked
    const pump = () => { while (sent < total && !res.destroyed) { sent++; if (!res.write(chunk)) { res.once('drain', pump); return; } } if (!res.destroyed) res.end(); };
    pump();
  });
  try {
    const e = new HttpEmbedder({ baseUrl: s.base, model: 'm', dimensions: 4 });
    await assert.rejects(e.embed(['x']), /too large/);
    await new Promise(resolve => setTimeout(resolve, 300));
    assert.ok(sent < total, `server stopped after ${sent} MiB of ${total}`);
  } finally { await s.close(); }
});
