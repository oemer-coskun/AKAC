// Knowledge semantics (0.6, ADR-022, spec/AKAC-0.6.md): model lineage, session-scoped records,
// the cascade sweeper, pending erasure under legal hold, combination rules and settings administration,
// the supplemental policy input, the placement rule and content encryption with crypto-shredding.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { ControlPlane } from '../reference/control.ts';
import { Engine } from '../reference/engine.ts';
import { EphemeralPartition, EphemeralStore } from '../reference/ephemeral.ts';
import { MemoryStore, SqliteStore } from '../reference/store.ts';
import { Sweeper } from '../reference/sweeper.ts';
import { MemoryJobLock } from '../reference/limits.ts';
import { MemoryVectorIndex } from '../reference/vector.ts';
import { EncryptingStore, LocalDevKeyProvider, isEnvelope, open, seal } from '../reference/content-crypto.ts';
import type { KeyProvider } from '../reference/content-crypto.ts';
import { compareVersions, inRange, placementAllowed, validRange } from '../reference/knowledge.ts';
import { ConfigError, contentEncryption } from '../reference/config.ts';
import { decide } from '../reference/policy.ts';
import type { Knowledge, PolicyHookInput, State, Store } from '../reference/types.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';
import { start, tokens } from './support.ts';

const NOW = Date.now();
/** The kbFixture company at NOW plus the administrators of tests/support.ts. */
function world(): State {
  const s = kbFixture(NOW);
  const admin = (id: string, roles: string[], tenant = 'acme') => { s.actors[id] = { id, tenant, kind: 'user', roles, projects: [], clearance: 'restricted', active: true }; };
  admin('sec', ['security-admin']); admin('kbadm', ['kb-admin']); admin('aud', ['auditor']); admin('other-sec', ['security-admin', 'auditor'], 'other');
  return s;
}
const clock = () => NOW;
const mem = (id: string, sources: string[], extra: Partial<Knowledge> = {}): Knowledge => ({ id, tenant: 'acme', version: 1, kind: 'memory', origin: 'model',
  content: `Synthetic ${id}.`, classification: 'public', projects: [], readerRoles: ['staff'], readers: [], sources: sources.map(s => ({ id: s, version: 1 })), active: true, ...extra });
const codeOf = (r: { ok: boolean }) => (r as { code?: string }).code;
const read = async (store: Store, id: string) => store.transaction('acme', async tx => { await tx.load({ knowledge: [id] }); return structuredClone(tx.state.knowledge[id]); });
const temp = () => mkdtempSync(join(tmpdir(), 'akac-knowledge-'));

test('R191: the model identity comes from configuration or a trusted caller, never from the agent API', async () => {
  const store = new MemoryStore(world());
  const engine = new Engine(store, { clock, model: { id: 'synthetic-model', version: '3.1' } });
  const ctx = await engine.openContext(bindings.chief, ['handbook'], 'work');
  assert.ok(ctx.ok);
  const d = await engine.derive(bindings.chief, ctx.value.context, 'Synthetic note.', 'artifact');
  assert.ok(d.ok);
  assert.deepEqual((await read(store, d.value.id))!.model, { id: 'synthetic-model', version: '3.1' });
  const trusted = await engine.derive(bindings.chief, ctx.value.context, 'Synthetic note two.', 'artifact', undefined, {}, { model: { id: 'runtime-model', version: '1' } });
  assert.ok(trusted.ok);
  assert.deepEqual((await read(store, trusted.value.id))!.model, { id: 'runtime-model', version: '1' });
  const broken = new Engine(store, { clock, model: () => { throw new Error('config'); } });
  const ctx2 = await broken.openContext(bindings.chief, ['handbook'], 'work');
  assert.ok(ctx2.ok);
  assert.equal((await broken.derive(bindings.chief, ctx2.value.context, 'x', 'artifact')).ok, false, 'an unreadable model configuration fails closed');
  // Over HTTP a caller cannot name a model: the member is unknown to the derive request.
  const { agentUrl, call, stop } = await start({ state: world() });
  try {
    const opened = await (await call(tokens.intern, 'POST', '/v1/contexts', { resources: ['handbook'], purpose: 'work' }, {}, agentUrl)).json() as { value: { context: string } };
    const res = await call(tokens.intern, 'POST', '/v1/derive', { context: opened.value.context, content: 'x', kind: 'artifact', model: { id: 'evil', version: '1' } }, {}, agentUrl);
    assert.equal(res.status, 400);
    const ok = await call(tokens.intern, 'POST', '/v1/derive', { context: opened.value.context, content: 'x', kind: 'artifact', modality: 'image' }, {}, agentUrl);
    assert.equal(ok.status, 200);
  } finally { await stop(); }
});

test('R190: session-scoped records never reach a persistent store and end with the session, the expiry or a restart', async () => {
  const dir = temp();
  let now = NOW;
  const sqlite = new SqliteStore(join(dir, 'akac.sqlite'));
  try {
    const { importState } = await import('../reference/store.ts');
    await importState(sqlite, world());
    const engine = new Engine(sqlite, { clock: () => now });
    const ctx = await engine.openContext(bindings.chief, ['handbook'], 'work');
    assert.ok(ctx.ok);
    const d = await engine.derive(bindings.chief, ctx.value.context, 'Session memory.', 'memory', undefined, { session: { id: 's1', ttlMs: 60_000 } });
    assert.ok(d.ok && d.value.ephemeral);
    assert.equal(d.value.ephemeral.expiresAt, NOW + 60_000);
    assert.equal(await read(sqlite, d.value.id), undefined, 'never in SQLite');
    const again = await engine.openContext(bindings.chief, [d.value.id], 'work');
    assert.ok(again.ok, 'visible to its run');
    assert.equal((await engine.openContext(bindings.lead, [d.value.id], 'work')).ok, false, 'invisible to another run');
    // A store refuses to persist one.
    await assert.rejects(sqlite.transaction('acme', async tx => { tx.state.knowledge.x = mem('x', ['handbook'], { ephemeral: { sessionId: 's', run: 'chief-run', expiresAt: NOW + 1 } }); }));
    // Expiry (purged for good).
    now = NOW + 60_000;
    assert.equal((await engine.openContext(bindings.chief, [d.value.id], 'work')).ok, false, 'gone at expiry');
    now = NOW;
    // Session close: only the caller's run (a fresh run: the chief's contexts now cite a purged record).
    const lctx = await engine.openContext(bindings.lead, ['handbook'], 'work');
    assert.ok(lctx.ok);
    const d2 = await engine.derive(bindings.lead, lctx.value.context, 'Session memory two.', 'memory', undefined, { session: { id: 's2' } });
    assert.ok(d2.ok);
    const closed = await engine.closeSession(bindings.chief, 's2');
    assert.ok(closed.ok && closed.value.closed === 0, 'another run closes nothing');
    const mine = await engine.closeSession(bindings.lead, 's2');
    assert.ok(mine.ok && mine.value.closed === 1);
    assert.equal((await engine.openContext(bindings.lead, [d2.value.id], 'work')).ok, false);
    // Restart: a new engine over the same database has no session records.
    const ictx = await engine.openContext(bindings.intern, ['handbook'], 'work');
    assert.ok(ictx.ok);
    const d3 = await engine.derive(bindings.intern, ictx.value.context, 'Session memory three.', 'memory', undefined, { session: { id: 's3' } });
    assert.ok(d3.ok);
    const restarted = new Engine(sqlite, { clock: () => now });
    assert.equal((await restarted.openContext(bindings.intern, [d3.value.id], 'work')).ok, false, 'restart = gone');
  } finally {
    await sqlite.close();
    try { rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); } catch { /* a locked temporary file is left to the OS */ }
  }
});

test('R190: DELETE /v1/sessions/{id} closes the caller\'s session and is audited', async () => {
  const { engine, store, agentUrl, call, stop } = await start({ state: world() });
  try {
    const ctx = await engine.openContext(bindings.intern, ['handbook'], 'work');
    assert.ok(ctx.ok);
    const d = await engine.derive(bindings.intern, ctx.value.context, 'Session memory.', 'memory', undefined, { session: { id: 'chat-1' } });
    assert.ok(d.ok);
    const res = await call(tokens.intern, 'DELETE', '/v1/sessions/chat-1', undefined, {}, agentUrl);
    assert.equal(res.status, 200);
    assert.equal(((await res.json()) as { value: { closed: number } }).value.closed, 1);
    assert.equal((await store.auditLog('acme')).at(-1)!.operation, 'session_close');
    assert.equal((await call(tokens.intern, 'DELETE', '/v1/sessions/bad%20id', undefined, {}, agentUrl)).status, 400);
    assert.equal((await call('not-a-credential-000000000000000000000', 'DELETE', '/v1/sessions/chat-1', undefined, {}, agentUrl)).status, 401);
    const bad = await call(tokens.intern, 'POST', '/v1/derive', { context: ctx.value.context, content: 'x', kind: 'memory', session: { id: 'ok', extra: 1 } }, {}, agentUrl);
    assert.equal(bad.status, 400);
  } finally { await stop(); }
});

test('R190: the partition is bounded per session and purges expired and malformed records', () => {
  const p = new EphemeralPartition(() => NOW);
  p.set('acme', mem('a', [], { ephemeral: { sessionId: 's', run: 'r', expiresAt: NOW + 10 } }));
  p.set('acme', mem('b', [], { ephemeral: { sessionId: 's', run: 'r', expiresAt: NOW } }));
  assert.throws(() => p.set('acme', mem('c', [], { tenant: 'other' })));
  p.purge('acme');
  assert.deepEqual(p.records('acme').map(k => k.id), ['a']);
  assert.ok(p.room('acme', 'r', 's'));
  assert.equal(p.closeSession('acme', 'r', 's'), 1);
  assert.equal(p.size('acme'), 0);
});

async function lineageWorld(): Promise<{ store: MemoryStore; control: ControlPlane }> {
  const s = world();
  s.knowledge.m1 = mem('m1', ['handbook']); s.knowledge.m2 = mem('m2', ['m1']); s.knowledge.m3 = mem('m3', ['m1']);
  s.knowledge.doc2 = { ...mem('doc2', ['m2']), kind: 'document', origin: 'system' };
  s.knowledge.m4 = mem('m4', ['staff-faq']);
  const store = new MemoryStore(s);
  return { store, control: new ControlPlane(store, { clock }) };
}

test('R193: the sweeper quarantines the descendants of a revoked record in bounded, resumable, audited batches', async () => {
  const { store, control } = await lineageWorld();
  const index = new MemoryVectorIndex(), removed: string[] = [];
  const spy = Object.assign(index, { removeDocument: async (_t: string, id: string) => { removed.push(id); } });
  const sweeper = new Sweeper({ control, index: spy, maxBatches: 1 });
  assert.ok((await control.revoke('acme', 'sec', 'knowledge', 'handbook')).ok);
  const one = await control.sweepLineage('acme', 'sec', 'handbook', { after: 'doc2', limit: 2 });
  assert.ok(one.ok && one.value.mode === 'quarantine' && one.value.changed.length === 2 && one.value.next === 'm2', 'a bounded batch, resumable by id');
  const r = await sweeper.sweep('acme', 'sec', 'handbook');
  assert.ok(r.ran && r.changed === 2 && !r.refused);
  for (const id of ['doc2', 'm1', 'm2', 'm3']) {
    const k = (await read(store, id))!;
    assert.equal(k.lifecycle, 'quarantined'); assert.equal(k.quarantineReason, 'ancestor_revoked');
  }
  assert.ok(removed.includes('doc2'), 'the quarantined document leaves the index');
  assert.equal((await control.sweepLineage('acme', 'kbadm', 'handbook')).ok, true, 'kb-admin may sweep');
  assert.equal((await control.sweepLineage('acme', 'aud', 'handbook')).ok, false, 'an auditor may not');
  const audits = await store.auditLog('acme');
  assert.ok(audits.filter(a => a.operation === 'sweep_lineage').length >= 3);
});

test('R193: poisoned roots mark descendants poisoned; an upward relabel raises stale stored classifications; the job lock serializes', async () => {
  const { store, control } = await lineageWorld();
  assert.ok((await control.quarantine('acme', 'kbadm', 'm1', 'poisoned')).ok);
  const sweeper = new Sweeper({ control });
  assert.equal((await sweeper.sweep('acme', 'kbadm', 'm1')).changed, 3);
  assert.equal((await read(store, 'm2'))!.quarantineReason, 'poisoned');
  // Upward relabel of a live root.
  const fresh = await lineageWorld();
  const handbook = (await read(fresh.store, 'handbook'))!;
  assert.ok((await fresh.control.upsertKnowledge('acme', 'kbadm', { ...handbook, version: 2, classification: 'confidential' })).ok);
  const relabel = await fresh.control.sweepLineage('acme', 'sec', 'handbook');
  assert.ok(relabel.ok && relabel.value.mode === 'relabel' && relabel.value.changed.length === 4);
  assert.equal((await read(fresh.store, 'm2'))!.quarantineReason, 'ancestor_revoked', 'descendants citing the superseded version are marked');
  // An in-place upward change (the container of the root) raises the stored classification of descendants.
  const kb = await fresh.store.transaction('acme', async tx => structuredClone(tx.state.containers['kb-corporate']!));
  assert.ok((await fresh.control.upsertContainer('acme', 'kbadm', { ...kb, classification: 'confidential' })).ok);
  const raised = await fresh.control.sweepLineage('acme', 'sec', 'staff-faq');
  assert.ok(raised.ok && raised.value.changed.length === 1);
  assert.equal((await read(fresh.store, 'm4'))!.classification, 'confidential');
  assert.equal((await read(fresh.store, 'm4'))!.lifecycle, undefined);
  // A second sweep of the same tenant while one runs is skipped, not queued.
  const lock = new MemoryJobLock();
  const busy = new Sweeper({ control: fresh.control, lock });
  let inner: Awaited<ReturnType<Sweeper['sweep']>> | undefined;
  await lock.run('sweep', 'acme', async () => { inner = await busy.sweep('acme', 'sec', 'handbook'); });
  assert.equal(inner!.ran, false);
});

test('R191: a model recall quarantines the model\'s records in range and sweeps their lineage', async () => {
  const s = world();
  s.knowledge.a1 = mem('a1', ['handbook'], { model: { id: 'm-x', version: '1.9' } });
  s.knowledge.a2 = mem('a2', ['handbook'], { model: { id: 'm-x', version: '1.10' } });
  s.knowledge.a3 = mem('a3', ['handbook'], { model: { id: 'm-x', version: '2.0' } });
  s.knowledge.b1 = mem('b1', ['handbook'], { model: { id: 'm-y', version: '1.10' } });
  s.knowledge.child = mem('child', ['a2']);
  const store = new MemoryStore(s), control = new ControlPlane(store, { clock });
  const r = await new Sweeper({ control }).recallModel('acme', 'sec', 'm-x', { from: '1.10', to: '1.99' });
  assert.ok(r.ran && r.recalled === 1 && r.changed === 2);
  assert.equal((await read(store, 'a2'))!.quarantineReason, 'model_recall');
  assert.equal((await read(store, 'child'))!.quarantineReason, 'ancestor_revoked');
  for (const id of ['a1', 'a3', 'b1']) assert.equal((await read(store, id))!.lifecycle, undefined);
  assert.equal((await control.quarantineByModel('acme', 'kbadm', 'm-x', {})).ok, false, 'security-admin only');
  assert.equal((await control.quarantineByModel('acme', 'sec', 'm-x', { from: '2', to: '1' })).ok, false, 'an inverted range is invalid');
  assert.ok(compareVersions('1.10', '1.9') > 0 && compareVersions('1.0', '1.0.1') < 0 && compareVersions('2', '2-rc') < 0);
  assert.ok(validRange({}) && !validRange({ from: 'bad id!' }) && inRange('1.5', { to: '1.5' }) && !inRange('1.6', { to: '1.5' }));
});

test('R194: an erasure blocked by a legal hold is stored as pending and runs once the hold is lifted', async () => {
  const { store, control } = await lineageWorld();
  assert.ok((await control.setLegalHold('acme', 'sec', 'm2', true, 'case-1')).ok);
  const refused = await control.erase('acme', 'sec', 'm1');
  assert.ok(!refused.ok && refused.code === 'CONFLICT' && refused.pending === true && refused.held === 1);
  assert.equal((await read(store, 'm1'))!.erasureRequestedAt, NOW);
  assert.equal((await read(store, 'm1'))!.content, 'Synthetic m1.', 'nothing erased');
  const sweeper = new Sweeper({ control });
  const held = await sweeper.applyPendingErasures('acme', 'sec');
  assert.ok(held.ran && held.held === 1 && held.erased === 0);
  assert.ok((await control.setLegalHold('acme', 'sec', 'm2', false, 'case-1')).ok);
  const done = await sweeper.applyPendingErasures('acme', 'sec');
  assert.ok(done.erased >= 3, 'the erasure ran with cascade');
  const m1 = (await read(store, 'm1'))!;
  assert.equal(m1.lifecycle, 'erased'); assert.equal(m1.erasureRequestedAt, undefined);
  assert.ok((await store.auditLog('acme')).some(a => a.operation === 'pending_erase' && a.decision === 'allow'));
  // A non-cascading request is not stored as pending.
  const other = await lineageWorld();
  await other.control.setLegalHold('acme', 'sec', 'm3', true, 'case-2');
  const plain = await other.control.erase('acme', 'sec', 'm3', { cascade: false });
  assert.ok(!plain.ok && plain.pending === undefined);
});

test('R194: the admin API answers 409 with pending: true, and lifting the hold runs pending erasures in the background', async () => {
  const s = world(); s.knowledge.m1 = mem('m1', ['handbook']);
  const { call, store, stop } = await start({ state: s });
  try {
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/knowledge/m1/legal-holds/case-9')).status, 200);
    const res = await call(tokens.sec, 'POST', '/admin/v1/knowledge/m1/erase', {});
    assert.equal(res.status, 409);
    const body = await res.json() as { pending?: boolean; held?: number };
    assert.equal(body.pending, true); assert.equal(body.held, 1);
    const run = await call(tokens.sec, 'POST', '/admin/v1/erasures/apply', {});
    assert.equal(run.status, 200);
    assert.equal((await read(store, 'm1'))!.lifecycle, undefined, 'still held');
  } finally { await stop(); }
});

test('R188 and R182: combination rules and the depth limit are administered by security-admins; relaxations pass the approval gate', async () => {
  const { store, control } = await lineageWorld();
  const rule = { id: 'wall', tenant: 'acme', tagsA: ['fin'], tagsB: ['audit'], effect: 'deny' as const, active: true };
  assert.equal((await control.upsertCombinationRule('acme', 'kbadm', rule)).ok, false);
  assert.equal((await control.upsertCombinationRule('acme', 'sec', { ...rule, effect: 'uplift', upliftTo: 'public' } as never)).ok, true);
  assert.equal((await control.upsertCombinationRule('acme', 'sec', { ...rule, upliftTo: 'restricted' } as never)).ok, false, 'deny carries no uplift');
  assert.ok((await control.upsertCombinationRule('acme', 'sec', rule)).ok);
  assert.deepEqual((await control.readCombinationRule('acme', 'aud', 'wall')).ok, true);
  assert.ok((await control.putSettings('acme', 'sec', { id: 'acme', tenant: 'acme', approvalQuorum: { settings: 2 }, lineageDepth: 4 })).ok);
  const relaxed = await control.upsertCombinationRule('acme', 'sec', { ...rule, active: false });
  assert.ok(!relaxed.ok && relaxed.code === 'APPROVAL_REQUIRED', 'deactivating a rule is a relaxation');
  const deeper = await control.putSettings('acme', 'sec', { id: 'acme', tenant: 'acme', approvalQuorum: { settings: 2 }, lineageDepth: 8 });
  assert.ok(!deeper.ok && deeper.code === 'APPROVAL_REQUIRED', 'a deeper limit is a relaxation');
  assert.ok((await control.putSettings('acme', 'sec', { id: 'acme', tenant: 'acme', approvalQuorum: { settings: 2 }, lineageDepth: 2 })).ok, 'a shallower limit applies at once');
  assert.equal((await control.putSettings('acme', 'sec', { id: 'acme', tenant: 'acme', lineageDepth: 128 })).ok, false);
  const settings = await control.readSettings('acme', 'sec');
  assert.ok(settings.ok && (settings.value as { lineageDepth: number }).lineageDepth === 2);
  assert.ok((await store.auditLog('acme')).some(a => a.operation === 'upsert_combination_rule'));
});

test('R186 and R187: removing a tag or widening residency is a label widening; a destination region change is a destination widening', async () => {
  const s = world();
  s.knowledge.tagged = { ...mem('tagged', []), kind: 'document', origin: 'system', tags: ['fin'], residency: ['DE'] };
  s.destinations!.eu = { id: 'eu', tenant: 'acme', class: 'internal-user', maxClassification: 'restricted', purposes: ['work'], active: true, region: 'DE' };
  const store = new MemoryStore(s), control = new ControlPlane(store, { clock });
  const base = (await read(store, 'tagged'))!;
  assert.equal(codeOf((await control.upsertKnowledge('acme', 'kbadm', { ...base, version: 2, tags: [] }))), 'CONFLICT', 'kb-admin cannot drop a tag');
  assert.equal(codeOf((await control.upsertKnowledge('acme', 'kbadm', { ...base, version: 2, residency: ['DE', 'FR'] }))), 'CONFLICT');
  assert.ok((await control.upsertKnowledge('acme', 'kbadm', { ...base, version: 2, tags: ['fin', 'audit'], residency: [] })).ok, 'narrowing is fine');
  assert.equal(codeOf((await control.upsertKnowledge('acme', 'kbadm', { ...base, version: 3, tags: ['bad tag'] }))), 'INVALID_REQUEST');
  assert.equal(codeOf((await control.upsertKnowledge('acme', 'kbadm', { ...base, version: 3, model: { id: 'x', version: '1' } } as never))), 'INVALID_REQUEST', 'model lineage is never accepted from a caller');
  assert.ok((await control.putSettings('acme', 'sec', { id: 'acme', tenant: 'acme', approvalQuorum: { destination_widening: 2 } })).ok);
  const moved = await control.upsertDestination('acme', 'sec', { ...s.destinations!.eu!, region: 'US' });
  assert.ok(!moved.ok && moved.code === 'APPROVAL_REQUIRED');
  assert.equal(codeOf((await control.upsertDestination('acme', 'sec', { ...s.destinations!.eu!, region: 'de' }))), 'INVALID_REQUEST');
  assert.equal((await control.upsertContainer('acme', 'kbadm', { id: 'kb-x', tenant: 'acme', kind: 'knowledge-base', classification: 'public', readerRoles: [], readers: [], projects: [], active: true, residency: ['EU'], tags: ['x'] })).ok, true);
});

test('R189: the supplemental policy receives effective tags, residency and the run\'s sources', async () => {
  const s = world();
  s.knowledge.handbook = { ...s.knowledge.handbook!, tags: ['fin'], residency: ['DE'] };
  s.containers['kb-corporate'] = { ...s.containers['kb-corporate']!, tags: ['audit'] };
  const seen: PolicyHookInput[] = [];
  const engine = new Engine(new MemoryStore(s), { clock, policy: { revision: 'test', check: async input => { seen.push(input); return true; } } });
  assert.ok((await engine.openContext(bindings.chief, ['handbook', 'staff-faq'], 'work')).ok);
  const h = seen.find(i => i.sources?.length === 2 && i.tags?.includes('fin'))!;
  assert.deepEqual(h.residency, ['DE']); assert.deepEqual(h.sources, ['handbook', 'staff-faq']);
  assert.ok(seen.some(i => i.tags?.includes('audit') && i.residency === undefined), 'container tags are inherited; no residency when none is set');
});

test('R192: an admissible placement never admits a principal that a source does not admit', () => {
  const s = world() as State;
  const sources = [s.knowledge.handbook!, s.knowledge.strategy!];
  const own = { readers: [], readerRoles: ['staff', 'executive'], projects: [] };
  assert.equal(placementAllowed(s, 'acme', sources, own, 'restricted', 'kb-corporate'), false);
  assert.equal(placementAllowed(s, 'acme', sources, own, 'restricted', 'f-executive'), true);
  assert.equal(placementAllowed(s, 'acme', sources, own, 'restricted', 'missing'), false);
  // Every principal that can read the placed record can read every source.
  // Its static label alone (no provenance: an evaluator that skips traversal).
  s.knowledge.placed = mem('placed', [], { ...own, classification: 'restricted', container: 'f-executive' });
  for (const who of ['chief', 'lead', 'intern'] as const) {
    const q = (resource: string) => decide(s, { binding: bindings[who], resource, action: 'read', purpose: 'work', now: NOW }).effect === 'allow';
    if (q('placed')) assert.ok(q('handbook') && q('strategy'), `${who} reads the placed record without its sources`);
  }
});

test('JSON Schemas describe the knowledge attributes and combination rules', () => {
  const ajv = new Ajv2020({ strict: false });
  const schema = (name: string) => ajv.compile(JSON.parse(readFileSync(new URL(`../schemas/${name}.json`, import.meta.url), 'utf8')));
  const rule = schema('combination-rule'), knowledge = schema('knowledge'), destination = schema('destination'), derive = schema('request-derive');
  assert.ok(rule({ id: 'r', tenant: 'acme', tagsA: ['a'], tagsB: ['b'], effect: 'uplift', upliftTo: 'restricted', active: true }));
  assert.ok(!rule({ id: 'r', tenant: 'acme', tagsA: ['a'], tagsB: ['b'], effect: 'deny', upliftTo: 'restricted', active: true }));
  assert.ok(!rule({ id: 'r', tenant: 'acme', tagsA: [], tagsB: ['b'], effect: 'deny', active: true }));
  assert.ok(knowledge({ ...mem('k', []), tags: ['fin'], residency: ['DE'], modality: 'image', model: { id: 'm', version: '1' }, quarantineReason: 'ancestor_revoked' }));
  assert.ok(!knowledge({ ...mem('k', []), residency: ['de'] }));
  assert.ok(destination({ id: 'd', tenant: 'acme', class: 'tool', maxClassification: 'public', purposes: [], active: true, region: 'US-GOV' }));
  assert.ok(derive({ context: 'c', content: 'x', kind: 'memory', session: { id: 's1', ttlMs: 60000 }, container: 'kb', modality: 'text' }));
  assert.ok(!derive({ context: 'c', content: 'x', kind: 'memory', model: { id: 'm', version: '1' } }));
});

test('R195: content is sealed at rest, reads never rewrite it, and erasure destroys the key (backups become unreadable)', async () => {
  const dir = temp();
  try {
    const file = join(dir, 'keys.json');
    const provider = new LocalDevKeyProvider(file);
    const inner = new MemoryStore(world());
    const store = new EncryptingStore(inner, provider);
    const control = new ControlPlane(store, { clock });
    // Seal on write: a new document version.
    const handbook = (await read(store, 'handbook'))!;
    assert.ok((await control.upsertKnowledge('acme', 'kbadm', { ...handbook, version: 2, content: 'Sealed handbook text.' })).ok);
    const raw = await inner.transaction('acme', async tx => structuredClone(tx.state.knowledge.handbook!));
    assert.ok(isEnvelope(raw.content) && !raw.content.includes('Sealed'));
    assert.equal((await read(store, 'handbook'))!.content, 'Sealed handbook text.');
    // A read (and a metadata-only change) keeps the stored ciphertext byte-identical.
    const engine = new Engine(store, { clock });
    assert.ok((await engine.openContext(bindings.chief, ['handbook'], 'work')).ok);
    assert.equal((await inner.transaction('acme', async tx => tx.state.knowledge.handbook!.content)), raw.content);
    assert.ok((await control.quarantine('acme', 'kbadm', 'handbook', 'incident')).ok);
    assert.equal((await inner.transaction('acme', async tx => tx.state.knowledge.handbook!.content)), raw.content);
    assert.ok((await control.release('acme', 'sec', 'handbook')).ok);
    // The associated data binds tenant, id and version.
    await assert.rejects(open(provider, 'acme', { id: 'handbook', version: 3 }, raw.content));
    await assert.rejects(open(provider, 'acme', { id: 'strategy', version: 2 }, raw.content));
    // A backup taken now, then erasure: the key is destroyed and the backup copy no longer opens.
    const backup = await inner.transaction('acme', async tx => structuredClone(tx.state));
    assert.ok((await control.erase('acme', 'sec', 'handbook')).ok);
    assert.ok(!readFileSync(file, 'utf8').includes('acme/handbook'), 'key material destroyed');
    await assert.rejects(open(provider, 'acme', { id: 'handbook', version: 2 }, raw.content));
    const restored = new EncryptingStore(new MemoryStore(backup), new LocalDevKeyProvider(file));
    const from = (await read(restored, 'handbook'))!;
    assert.equal(from.content, ''); assert.equal(from.lifecycle, 'erased', 'unreadable content is treated as erased');
    assert.equal(decide(await restored.transaction('acme', async tx => structuredClone(tx.state)), { binding: bindings.chief, resource: 'handbook', action: 'read', purpose: 'work', now: NOW }).effect, 'deny');
    if (process.platform !== 'win32') assert.equal(statSync(file).mode & 0o777, 0o600);
  } finally { rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }
});

test('R195: a failing key destruction is retried; configuration refuses unsafe modes', async () => {
  let fail = true;
  const keys = new Map<string, Uint8Array>();
  const provider: KeyProvider = { id: 'test-provider',
    wrap: async (t, r, cek) => { keys.set(`${t}/${r}`, Uint8Array.from(cek)); return 'wrapped'; },
    unwrap: async (t, r) => { const k = keys.get(`${t}/${r}`); if (!k) throw new Error('gone'); return Uint8Array.from(k); },
    destroy: async (t, r) => { if (fail) throw new Error('kms down'); keys.delete(`${t}/${r}`); } };
  const events: string[] = [];
  const store = new EncryptingStore(new MemoryStore(world()), provider, { onEvent: e => events.push(e.type) });
  const control = new ControlPlane(store, { clock });
  const doc = (await read(store, 'strategy'))!;
  assert.ok((await control.upsertKnowledge('acme', 'kbadm', { ...doc, version: 2, content: 'Sealed strategy.' })).ok);
  assert.ok((await control.erase('acme', 'sec', 'strategy')).ok, 'the erasure stands even when the key service fails');
  assert.ok(events.includes('shred_failed'));
  fail = false;
  assert.equal(await store.shredPending('acme'), 0);
  assert.ok(!keys.has('acme/strategy'));
  assert.equal(await seal(provider, 'acme', { id: 'x', version: 1 }, 'text').then(e => isEnvelope(e)), true);
  assert.throws(() => contentEncryption(new MemoryStore(), { AKAC_CONTENT_ENCRYPTION: 'local', NODE_ENV: 'production', AKAC_CONTENT_KEY_FILE: 'k.json' }), ConfigError);
  assert.throws(() => contentEncryption(new MemoryStore(), { AKAC_CONTENT_ENCRYPTION: 'provider' }), ConfigError);
  assert.throws(() => contentEncryption(new MemoryStore(), { AKAC_CONTENT_ENCRYPTION: 'on' }), ConfigError);
  assert.ok(contentEncryption(new MemoryStore(), {}) instanceof MemoryStore, 'off by default');
  assert.ok(contentEncryption(new MemoryStore(), { AKAC_CONTENT_ENCRYPTION: 'provider' }, { keyProvider: provider }) instanceof EncryptingStore);
});

test('R190: the ephemeral store keeps a rolled-back derivation out of the partition', async () => {
  const partition = new EphemeralPartition(clock);
  const store = new EphemeralStore(new MemoryStore(world()), partition, clock);
  await assert.rejects(store.transaction('acme', async tx => {
    tx.state.knowledge.e = mem('e', ['handbook'], { ephemeral: { sessionId: 's', run: 'chief-run', expiresAt: NOW + 10 } });
    throw new Error('rolled back');
  }));
  assert.equal(partition.size('acme'), 0);
});
