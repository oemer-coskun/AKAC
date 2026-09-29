// Knowledge lifecycle (0.4, ADR-007, spec/drafts/0.4-knowledge-lifecycle.md):
// quarantine and blast radius (R-LIFE-1..7), retention, legal hold and erasure
// (R-LIFE-8..14). PostgreSQL versions of the key cases live in lifecycle-postgres.test.ts.
import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ControlPlane } from '../reference/control.ts';
import { Engine } from '../reference/engine.ts';
import type { EngineOptions } from '../reference/engine.ts';
import { Ingestor } from '../reference/ingest.ts';
import { HashEmbedder } from '../reference/embedding.ts';
import { MemoryVectorIndex } from '../reference/vector.ts';
import { MemoryStore, SqliteStore, importState } from '../reference/store.ts';
import { decide } from '../reference/policy.ts';
import { bindings } from '../examples/fixture.ts';
import type { Knowledge, State, Store } from '../reference/types.ts';

import { derived, LINEAGE, lifecycleWorld, now } from './lifecycle-fixture.ts';
function setup(change?: (s: State) => void, options: EngineOptions = {}, store: Store = new MemoryStore(lifecycleWorld(change))) {
  const engine = new Engine(store, { clock: () => now, ...options }); stores.set(engine, store);
  return { store, engine, control: new ControlPlane(store, { clock: () => now }) };
}
/** Stores of engines, so each read can use a fresh run (a run whose context went stale stays dead: R-LIFE-5 relies on that). */
const stores = new WeakMap<Engine, Store>();
let runs = 0;
/** Reads one record as chief in a new run (a fresh root grant). */
async function readable(engine: Engine, id: string): Promise<boolean> {
  const store = stores.get(engine)!, grant = `run-${++runs}`;
  await store.transaction('acme', async tx => { await tx.load({ grants: ['chief-run'] }); tx.state.grants[grant] = { ...structuredClone(tx.state.grants['chief-run']!), id: grant }; });
  return (await engine.openContext({ ...bindings.chief, grant }, [id], 'work')).ok;
}
const record = (store: Store, id: string, tenant = 'acme') => store.transaction(tenant, async tx => { await tx.load({ knowledge: [id] }); return structuredClone(tx.state.knowledge[id]); });
/** Content of every record any gate discloses for this query (lexical retrieval). */
async function retrieved(engine: Engine, query: string): Promise<string[]> {
  const store = stores.get(engine)!, grant = `run-${++runs}`;
  await store.transaction('acme', async tx => { await tx.load({ grants: ['chief-run'] }); tx.state.grants[grant] = { ...structuredClone(tx.state.grants['chief-run']!), id: grant }; });
  const r = await engine.retrieve({ ...bindings.chief, grant }, query, 'work', 20);
  return r.ok ? r.value.documents.map(d => d.id) : [];
}

test('baseline: the whole lineage is readable before any lifecycle change', async () => {
  const { engine } = setup();
  for (const id of ['handbook', ...LINEAGE]) assert.ok(await readable(engine, id), id);
});

test('quarantined ancestor denies every descendant at read, derive, write_memory, share, export and retrieval; release restores', async () => {
  const { engine, control, store } = setup();
  const before = await engine.openContext(bindings.chief, ['d2'], 'work');
  assert.ok(before.ok);
  const q = await control.quarantine('acme', 'kbadm', 'handbook', 'suspected_poisoning');
  assert.ok(q.ok); assert.equal(q.value.epoch, 1);
  for (const id of ['handbook', ...LINEAGE]) assert.equal(await readable(engine, id), false, id);
  for (const action of ['read', 'derive', 'write_memory', 'share', 'export'] as const) {
    assert.equal(decide(await store.transaction('acme', async tx => structuredClone(tx.state)), { binding: bindings.chief, resource: 'c', action, purpose: 'work', now }).effect, 'deny', action);
  }
  assert.equal((await engine.derive(bindings.chief, before.value.context, 'summary', 'artifact')).ok, false, 'open contexts die with the epoch');
  assert.equal((await engine.derive(bindings.chief, before.value.context, 'note', 'memory')).ok, false);
  assert.equal((await engine.release(bindings.chief, before.value.context, 'lead', 'reply')).ok, false);
  assert.equal((await engine.release(bindings.chief, before.value.context, 'lead', 'reply', 'export')).ok, false);
  assert.deepEqual((await retrieved(engine, 'Derived synthetic handbook')).filter(id => ['handbook', ...LINEAGE].includes(id)), []);
  assert.equal((await control.release('acme', 'kbadm', 'handbook')).ok, false, 'separation of duty: kb-admin cannot release');
  const r = await control.release('acme', 'sec', 'handbook');
  assert.ok(r.ok); assert.equal(r.value.epoch, 2);
  for (const id of ['handbook', ...LINEAGE]) assert.ok(await readable(engine, id), id);
  const log = await store.auditLog('acme');
  assert.deepEqual(log.filter(e => ['quarantine', 'release'].includes(e.operation)).map(e => `${e.operation}:${e.decision}`), ['quarantine:allow', 'release:deny', 'release:allow']);
  assert.ok(log.find(e => e.operation === 'quarantine')!.decisionId === q.decisionId);
});

test('quarantine of a middle node hides only its own lineage; idempotent; erased cannot be quarantined', async () => {
  const { engine, control } = setup();
  assert.ok((await control.quarantine('acme', 'sec', 'a', 'incident')).ok);
  const again = await control.quarantine('acme', 'sec', 'a', 'incident');
  assert.ok(again.ok); assert.equal(again.value.epoch, 1, 'no second epoch advance');
  assert.equal(await readable(engine, 'c'), false, 'diamond: one quarantined parent suffices');
  for (const id of ['handbook', 'b', 'd1', 'd2']) assert.ok(await readable(engine, id), id);
  assert.equal((await control.quarantine('acme', 'aud', 'b', 'incident')).ok, false, 'auditor cannot quarantine');
  assert.equal((await control.quarantine('acme', 'sec', 'b', 'free text' as never)).ok, false, 'closed reasons only');
  assert.ok((await control.erase('acme', 'sec', 'd2')).ok);
  assert.equal(bareCode(await control.quarantine('acme', 'sec', 'd2', 'incident')), 'CONFLICT');
});
const bareCode = (r: { ok: boolean; code?: string }) => r.ok ? 'OK' : r.code;

test('descendants: diamond and chain, sorted, bounded, auditor or security-admin only, other tenants invisible', async () => {
  const { control } = setup(s => {
    for (let i = 0; i < 140; i++) s.knowledge[`deep-${i}`] = derived(`deep-${i}`, [i ? `deep-${i - 1}` : 'staff-faq']);
  });
  const all = await control.descendants('acme', 'aud', 'handbook');
  assert.ok(all.ok);
  assert.deepEqual(all.value.records.map(r => r.id), LINEAGE);
  assert.equal(all.value.truncated, false);
  assert.deepEqual(all.value.records[0], { id: 'a', version: 1, kind: 'artifact', classification: 'public', active: true }, 'metadata only, no content');
  const two = await control.descendants('acme', 'sec', 'handbook', { limit: 2 });
  assert.ok(two.ok); assert.equal(two.value.records.length, 2); assert.equal(two.value.truncated, true);
  const diamond = await control.descendants('acme', 'aud', 'a');
  assert.ok(diamond.ok); assert.deepEqual(diamond.value.records.map(r => r.id), ['c']);
  const deep = await control.descendants('acme', 'aud', 'staff-faq', { limit: 1000 });
  assert.ok(deep.ok); assert.equal(deep.value.truncated, true, 'deeper than the path bound');
  assert.equal(bareCode(await control.descendants('acme', 'kbadm', 'handbook')), 'NOT_AUTHORIZED');
  assert.equal(bareCode(await control.descendants('acme', 'aud', 'handbook', { limit: 0 })), 'INVALID_REQUEST');
  assert.equal(bareCode(await control.descendants('acme', 'aud', 'o-doc')), 'INVALID_REQUEST', 'another tenant\'s id reads as absent');
  const foreign = await control.descendants('other', 'other-sec', 'handbook');
  assert.equal(bareCode(foreign), 'INVALID_REQUEST');
});

test('revokeLineage deactivates the record and every descendant, advances the epoch, is idempotent', async () => {
  const { engine, control, store } = setup();
  const r = await control.revokeLineage('acme', 'sec', 'handbook');
  assert.ok(r.ok); assert.equal(r.value.revoked, 6); assert.equal(r.value.epoch, 1);
  for (const id of ['handbook', ...LINEAGE]) { assert.equal((await record(store, id))!.active, false, id); assert.equal(await readable(engine, id), false, id); }
  assert.ok(await readable(engine, 'staff-faq'));
  const again = await control.revokeLineage('acme', 'sec', 'handbook');
  assert.ok(again.ok); assert.equal(again.value.revoked, 0);
  assert.equal(bareCode(await control.revokeLineage('acme', 'kbadm', 'handbook')), 'NOT_AUTHORIZED');
});

test('a lineage beyond the cascade bound is a deferred denial that changes nothing', async () => {
  const { control, store } = setup(s => { for (let i = 0; i < 1000; i++) s.knowledge[`w-${i}`] = derived(`w-${i}`, ['staff-faq']); });
  await assert.rejects(control.erase('acme', 'sec', 'staff-faq'), /lineage budget/);
  await assert.rejects(control.revokeLineage('acme', 'sec', 'staff-faq'), /lineage budget/);
  assert.equal((await record(store, 'staff-faq'))!.content, 'Staff FAQ: synthetic office hours.');
  assert.equal((await record(store, 'w-5'))!.active, true);
  assert.deepEqual((await store.auditLog('acme')).slice(-2).map(e => e.reason), ['DEFERRED:BUDGET_EXCEEDED', 'DEFERRED:BUDGET_EXCEEDED']);
});

test('erase cascades to every descendant, removes content and chunks, denies forever, is idempotent and burns the id', async () => {
  const { engine, control, store } = setup();
  const index = new MemoryVectorIndex(), embedder = new HashEmbedder();
  const ingestor = new Ingestor({ control, store, index, embedder, clock: () => now });
  await ingestor.reconcile('acme');
  assert.ok((await index.state('acme')).has('handbook'));
  const ctx = await engine.openContext(bindings.chief, ['c'], 'work'); assert.ok(ctx.ok);
  const e = await ingestor.erase('acme', 'sec', 'handbook');
  assert.ok(e.ok); assert.equal(e.value.erased, 6);
  assert.equal((await index.state('acme')).has('handbook'), false, 'chunks removed');
  for (const id of ['handbook', ...LINEAGE]) {
    const k = (await record(store, id))!;
    assert.equal(k.content, '', id); assert.equal(k.lifecycle, 'erased'); assert.equal(k.active, false); assert.deepEqual(k.readers, []);
    assert.equal(await readable(engine, id), false, id);
  }
  assert.equal((await engine.derive(bindings.chief, ctx.value.context, 'after erasure')).ok, false);
  assert.deepEqual((await retrieved(engine, 'Product handbook notebook Derived')).filter(id => ['handbook', ...LINEAGE].includes(id)), []);
  const again = await control.erase('acme', 'sec', 'handbook');
  assert.ok(again.ok); assert.equal(again.value.erased, 0);
  const revived = await control.upsertKnowledge('acme', 'kbadm', { ...lifecycleWorld().knowledge.handbook!, version: 2, content: 'New text.' });
  assert.equal(bareCode(revived), 'CONFLICT', 'an erased id is never reused');
  assert.equal(bareCode(await control.release('acme', 'sec', 'handbook')), 'CONFLICT', 'erasure is terminal');
  assert.equal(bareCode(await control.erase('acme', 'kbadm', 'staff-faq')), 'NOT_AUTHORIZED');
  assert.equal(bareCode(await control.erase('acme', 'sec', 'o-doc')), 'INVALID_REQUEST', 'other tenant invisible');
  assert.equal((await record(store, 'o-doc', 'other'))!.content, 'Other tenant synthetic notes.');
  const log = await store.auditLog('acme');
  assert.ok(log.some(entry => entry.operation === 'erase' && entry.decisionId === e.decisionId), 'audit entries remain; they carry no content');
});

test('erase without cascade refuses while a live descendant exists', async () => {
  const { control, store } = setup();
  assert.equal(bareCode(await control.erase('acme', 'sec', 'a', { cascade: false })), 'CONFLICT');
  assert.equal((await record(store, 'a'))!.lifecycle, undefined);
  const leaf = await control.erase('acme', 'sec', 'c', { cascade: false });
  assert.ok(leaf.ok); assert.equal(leaf.value.erased, 1);
  assert.ok((await control.erase('acme', 'sec', 'a', { cascade: false })).ok, 'erased descendants do not block');
});

test('legal hold on the record or any descendant blocks erasure with a count only; lifting it allows erasure', async () => {
  const { control, store } = setup();
  assert.equal(bareCode(await control.setLegalHold('acme', 'kbadm', 'c', true, 'matter-1')), 'NOT_AUTHORIZED');
  const h = await control.setLegalHold('acme', 'sec', 'c', true, 'matter-1');
  assert.ok(h.ok); assert.equal(h.value.holds, 1);
  assert.ok((await control.setLegalHold('acme', 'sec', 'c', true, 'matter-1')).ok, 'idempotent');
  assert.ok((await control.setLegalHold('acme', 'sec', 'c', true, 'matter-2')).ok);
  const blocked = await control.erase('acme', 'sec', 'handbook');
  assert.ok(!blocked.ok); assert.equal(blocked.code, 'CONFLICT'); assert.equal(blocked.held, 1);
  for (const id of ['handbook', ...LINEAGE]) assert.equal((await record(store, id))!.lifecycle, undefined, `${id} untouched`);
  assert.equal((await record(store, 'c'))!.content, 'Derived c: synthetic text.');
  assert.ok((await control.setLegalHold('acme', 'sec', 'c', false, 'matter-1')).ok);
  assert.equal(bareCode(await control.erase('acme', 'sec', 'handbook')), 'CONFLICT', 'one hold remains');
  assert.ok((await control.setLegalHold('acme', 'sec', 'c', false, 'matter-2')).ok);
  assert.equal((await record(store, 'c'))!.legalHolds, undefined);
  assert.ok((await control.erase('acme', 'sec', 'handbook')).ok);
  assert.equal(bareCode(await control.setLegalHold('acme', 'sec', 'c', true, 'late')), 'CONFLICT', 'nothing left to hold');
  assert.equal(bareCode(await control.setLegalHold('acme', 'sec', 'a', true, 'bad id!')), 'INVALID_REQUEST');
});

test('a new document version never lifts a quarantine or a legal hold', async () => {
  const { control, store, engine } = setup();
  assert.ok((await control.quarantine('acme', 'kbadm', 'staff-faq', 'suspected_poisoning')).ok);
  assert.ok((await control.setLegalHold('acme', 'sec', 'staff-faq', true, 'm1')).ok);
  // Under a legal hold the content is frozen (R55): only a metadata version is accepted.
  const rewrite = await control.upsertKnowledge('acme', 'kbadm', { ...lifecycleWorld().knowledge['staff-faq']!, version: 2, content: 'Cleaned text.' });
  assert.deepEqual([rewrite.ok, !rewrite.ok && rewrite.code, !rewrite.ok && rewrite.held], [false, 'CONFLICT', 1]);
  const next = await control.upsertKnowledge('acme', 'kbadm', { ...lifecycleWorld().knowledge['staff-faq']!, version: 2, readers: ['chief'] });
  assert.ok(next.ok); assert.equal(next.value.quarantined, true);
  const k = (await record(store, 'staff-faq'))!;
  assert.equal(k.lifecycle, 'quarantined'); assert.deepEqual(k.legalHolds, ['m1']); assert.equal(k.quarantineReason, 'suspected_poisoning');
  assert.equal(await readable(engine, 'staff-faq'), false);
});

test('retention: due records are erased with cascade in resumable batches; held lineages are skipped; access expiry is separate', async () => {
  const { control, store, engine } = setup(s => {
    s.knowledge.handbook!.retainUntil = now - 1;
    s.knowledge['staff-faq']!.retainUntil = now - 1; s.knowledge['staff-faq']!.legalHolds = ['m1'];
    s.knowledge['board-notes']!.retainUntil = now + 1000;
    s.knowledge['vault-memo']!.retainUntil = now - 5;
    s.knowledge.strategy!.retainUntil = now; s.knowledge.x = derived('x', ['strategy']); s.knowledge.x.legalHolds = ['m2'];
  });
  assert.ok(await readable(engine, 'handbook'), 'a passed retention deadline does not end access by itself');
  assert.equal(bareCode(await control.applyRetention('acme', 'kbadm', now)), 'NOT_AUTHORIZED');
  const first = await control.applyRetention('acme', 'sec', now, { limit: 1 });
  assert.ok(first.ok); assert.equal(first.value.next, 'handbook'); assert.equal(first.value.erased, 6);
  const rest = await control.applyRetention('acme', 'sec', now, { after: first.value.next! });
  assert.ok(rest.ok); assert.equal(rest.value.next, undefined);
  assert.equal(rest.value.erased, 1, 'vault-memo'); assert.equal(rest.value.held, 1, 'strategy: its descendant x is held');
  assert.equal((await record(store, 'vault-memo'))!.lifecycle, 'erased');
  for (const id of ['staff-faq', 'board-notes', 'strategy', 'x']) assert.equal((await record(store, id))!.lifecycle, undefined, id);
  const idle = await control.applyRetention('acme', 'sec', now);
  assert.ok(idle.ok); assert.equal(idle.value.erased, 0);
  assert.ok((await store.auditLog('acme')).filter(e => e.operation === 'retention_erase' && e.decision === 'allow').length >= 2);
});

test('derived records inherit the earliest retention deadline of their sources', async () => {
  const { engine, store } = setup(s => { s.knowledge.handbook!.retainUntil = now + 50; s.knowledge.strategy!.retainUntil = now + 10; });
  const ctx = await engine.openContext(bindings.chief, ['handbook', 'strategy'], 'work'); assert.ok(ctx.ok);
  const d = await engine.derive(bindings.chief, ctx.value.context, 'Summary.'); assert.ok(d.ok);
  assert.equal((await record(store, d.value.id))!.retainUntil, now + 10);
});

test('memory review: model-origin memory lands quarantined until a security-admin releases it', async () => {
  const { engine, control } = setup(undefined, { memoryReview: t => t === 'acme' ? 'quarantine' : 'none' });
  const ctx = await engine.openContext(bindings.chief, ['handbook'], 'work'); assert.ok(ctx.ok);
  const memory = await engine.derive(bindings.chief, ctx.value.context, 'Remember this.', 'memory');
  assert.ok(memory.ok); assert.equal(memory.value.quarantined, true);
  const artifact = await engine.derive(bindings.chief, ctx.value.context, 'An artifact.', 'artifact');
  assert.ok(artifact.ok); assert.equal(artifact.value.quarantined, undefined);
  assert.equal(await readable(engine, memory.value.id), false);
  assert.ok(await readable(engine, artifact.value.id));
  assert.ok((await control.release('acme', 'sec', memory.value.id)).ok);
  assert.ok(await readable(engine, memory.value.id));
  const failing = setup(undefined, { memoryReview: () => { throw new Error('settings unavailable'); } });
  const c2 = await failing.engine.openContext(bindings.chief, ['handbook'], 'work'); assert.ok(c2.ok);
  const m2 = await failing.engine.derive(bindings.chief, c2.value.context, 'Remember.', 'memory');
  assert.ok(m2.ok); assert.equal(m2.value.quarantined, true, 'a failing selector quarantines');
  assert.throws(() => new Engine(new MemoryStore(), { memoryReview: 'maybe' as never }));
});

test('ingestion scanner: quarantine and failures never index; reject stores nothing; release indexes via reconcile', async () => {
  const doc = (id: string): Knowledge => ({ ...structuredClone(lifecycleWorld().knowledge['staff-faq']!), id, content: `Scanned ${id} synthetic text.` });
  const run = async (scanner: { scan(d: Knowledge): Promise<'clean' | 'quarantine' | 'reject'> }, scanFailure?: 'quarantine' | 'reject') => {
    const { control, store, engine } = setup();
    const index = new MemoryVectorIndex();
    const ingestor = new Ingestor({ control, store, index, embedder: new HashEmbedder(), clock: () => now, scanner, scanTimeoutMs: 30, ...(scanFailure ? { scanFailure } : {}) });
    return { control, store, engine, index, ingestor, result: await ingestor.ingest('acme', 'kbadm', doc('scanned')) };
  };
  const clean = await run({ scan: async () => 'clean' });
  assert.ok(clean.result.ok); assert.ok((await clean.index.state('acme')).has('scanned'));
  for (const [name, scanner] of [['verdict', { scan: async () => 'quarantine' as const }], ['error', { scan: async () => { throw new Error('scanner down'); } }],
    ['timeout', { scan: () => new Promise<never>(() => {}) }], ['unknown verdict', { scan: async () => 'maybe' as never }]] as const) {
    const q = await run(scanner);
    assert.ok(q.result.ok, name); assert.equal(q.result.value.quarantined, true, name);
    assert.equal((await q.index.state('acme')).has('scanned'), false, `${name}: never indexed`);
    assert.equal(await readable(q.engine, 'scanned'), false, name);
    assert.equal((await record(q.store, 'scanned'))!.quarantineReason, name === 'verdict' ? 'scanner' : 'scanner_unavailable');
    assert.equal((await q.ingestor.reconcile('acme')).indexed >= 0, true);
    assert.equal((await q.index.state('acme')).has('scanned'), false, `${name}: reconcile keeps it out`);
    if (name === 'verdict') {
      const released = await q.ingestor.release('acme', 'sec', 'scanned');
      assert.ok(released.ok); assert.ok((await q.index.state('acme')).has('scanned'), 'released documents are indexed');
      assert.ok(await readable(q.engine, 'scanned'));
    }
  }
  const rejected = await run({ scan: async () => 'reject' });
  assert.equal(bareCode(rejected.result), 'INVALID_REQUEST');
  assert.equal(await record(rejected.store, 'scanned'), undefined);
  assert.equal((await rejected.store.auditLog('acme')).at(-1)!.operation, 'ingest_rejected');
  const strict = await run({ scan: async () => { throw new Error('down'); } }, 'reject');
  assert.equal(bareCode(strict.result), 'INVALID_REQUEST');
  assert.equal(await record(strict.store, 'scanned'), undefined);
});

test('quarantine through the ingestor drops the chunks of every indexed document in the lineage', async () => {
  const { control, store } = setup(s => { s.knowledge['doc-child'] = { ...structuredClone(s.knowledge.handbook!), id: 'doc-child', content: 'Child doc.', sources: [{ id: 'd1', version: 1 }] }; });
  const index = new MemoryVectorIndex(), ingestor = new Ingestor({ control, store, index, embedder: new HashEmbedder(), clock: () => now });
  await ingestor.reconcile('acme');
  assert.ok((await index.state('acme')).has('doc-child'));
  assert.ok((await ingestor.quarantine('acme', 'kbadm', 'handbook', 'incident')).ok);
  const indexed = await index.state('acme');
  assert.equal(indexed.has('handbook'), false); assert.equal(indexed.has('doc-child'), false);
  await ingestor.reconcile('acme');
  assert.equal((await index.state('acme')).has('doc-child'), false, 'reconcile does not re-add a document whose ancestor is quarantined');
  assert.ok((await ingestor.release('acme', 'sec', 'handbook')).ok);
  assert.ok((await index.state('acme')).has('doc-child'));
});

test('sqlite store: lifecycle state persists across reopen', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'akac-life-'));
  try {
    let store: Store = new SqliteStore(join(dir, 's.sqlite'));
    await importState(store, lifecycleWorld());
    let { control } = setup(undefined, {}, store);
    assert.ok((await control.setLegalHold('acme', 'sec', 'd2', true, 'm1')).ok);
    assert.ok((await control.quarantine('acme', 'sec', 'b', 'incident')).ok);
    assert.equal(bareCode(await control.erase('acme', 'sec', 'handbook')), 'CONFLICT');
    await store.close(); store = new SqliteStore(join(dir, 's.sqlite'));
    ({ control } = setup(undefined, {}, store));
    const engine = new Engine(store, { clock: () => now }); stores.set(engine, store);
    assert.equal(await readable(engine, 'c'), false);
    assert.ok((await control.setLegalHold('acme', 'sec', 'd2', false, 'm1')).ok);
    assert.ok((await control.erase('acme', 'sec', 'handbook')).ok);
    await store.close(); store = new SqliteStore(join(dir, 's.sqlite'));
    assert.equal((await record(store, 'd2'))!.content, '');
    assert.ok(await store.ready());
    await store.close();
  } finally { rmSync(dir, { recursive: true }); }
});

test('property: after erase(id), no gate discloses content of id or any descendant', async () => {
  await fc.assert(fc.asyncProperty(
    fc.array(fc.array(fc.nat(), { maxLength: 3 }), { minLength: 1, maxLength: 12 }), fc.nat(), fc.nat(),
    async (parents, pick, holdPick) => {
      // Node i may derive from nodes < i only (a DAG); node 0 derives from handbook.
      const store = new MemoryStore(lifecycleWorld(s => {
        parents.forEach((ps, i) => { const src = i ? [...new Set(ps.map(p => `n${p % i}`))] : ['handbook']; s.knowledge[`n${i}`] = derived(`n${i}`, src.length ? src : ['handbook']); });
      }));
      const { engine, control } = setup(undefined, {}, store);
      const target = `n${pick % parents.length}`;
      const lineage = await control.descendants('acme', 'aud', target, { limit: 1000 });
      assert.ok(lineage.ok);
      const affected = new Set([target, ...lineage.value.records.map(r => r.id)]);
      const holdOn = holdPick % 3 === 0 ? [...affected][holdPick % affected.size] : undefined;
      if (holdOn) assert.ok((await control.setLegalHold('acme', 'sec', holdOn, true, 'm')).ok);
      const erased = await control.erase('acme', 'sec', target);
      if (holdOn) { assert.equal(bareCode(erased), 'CONFLICT'); return; }
      assert.ok(erased.ok); assert.equal(erased.value.erased, affected.size);
      for (const id of affected) {
        assert.equal(await readable(engine, id), false);
        assert.equal((await record(store, id))!.content, '');
      }
      const hits = await retrieved(engine, 'Derived synthetic text');
      assert.deepEqual(hits.filter(id => affected.has(id)), []);
      const snapshot = await store.transaction('acme', async tx => structuredClone(tx.state));
      for (const id of affected) for (const action of ['read', 'derive', 'write_memory', 'share', 'export'] as const) {
        assert.equal(decide(snapshot, { binding: bindings.chief, resource: id, action, purpose: 'work', now }).effect, 'deny');
      }
    }), { numRuns: 40 });
});

test('reconcile alone removes a derived document whose ancestor was quarantined outside the ingestor (R-LIFE-8)', async () => {
  const { control, store } = setup(s => { s.knowledge['doc-child'] = { ...structuredClone(s.knowledge.handbook!), id: 'doc-child', content: 'Child doc.', sources: [{ id: 'd1', version: 1 }] }; });
  const index = new MemoryVectorIndex(), ingestor = new Ingestor({ control, store, index, embedder: new HashEmbedder(), clock: () => now });
  assert.ok((await ingestor.reconcile('acme')).indexed >= 2);
  assert.equal((await ingestor.reconcile('acme')).indexed, 0, 'a live derived document is re-checked but not re-embedded');
  assert.ok((await control.quarantine('acme', 'kbadm', 'd1', 'incident')).ok);
  const run = await ingestor.reconcile('acme');
  assert.equal(run.removed, 1);
  assert.equal((await index.state('acme')).has('doc-child'), false);
  assert.ok((await index.state('acme')).has('handbook'));
});

test('lifecycle fields validate against the closed knowledge schema', async () => {
  const { readFileSync } = await import('node:fs');
  const { Ajv2020 } = await import('ajv/dist/2020.js');
  const validate = new Ajv2020().compile(JSON.parse(readFileSync(new URL('../schemas/knowledge.json', import.meta.url), 'utf8')));
  const base = lifecycleWorld().knowledge.handbook!;
  assert.ok(validate({ ...base, lifecycle: 'quarantined', lifecycleAt: now, quarantineReason: 'scanner', retainUntil: now, legalHolds: ['m1'] }), JSON.stringify(validate.errors));
  assert.ok(validate({ ...base, content: '', readers: [], active: false, lifecycle: 'erased', lifecycleAt: now }));
  assert.equal(validate({ ...base, lifecycle: 'archived' }), false);
  assert.equal(validate({ ...base, quarantineReason: 'free text' }), false);
});
