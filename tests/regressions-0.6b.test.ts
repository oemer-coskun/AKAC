// Regressions of the 0.6 review, second round (0.6b). Each test failed before its fix.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { migrate, PostgresStore } from '../adapters/postgres.ts';
import { ControlPlane } from '../reference/control.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryStore, importState } from '../reference/store.ts';
import { DecisionCache } from '../reference/decision-cache.ts';
import { EncryptingStore, KeyDestroyed } from '../reference/content-crypto.ts';
import type { KeyProvider } from '../reference/content-crypto.ts';
import type { RiskProvider } from '../reference/risk.ts';
import type { Actor, Grant, Knowledge, RiskLevel, State, Store } from '../reference/types.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';

const user = (id: string, roles: string[], extra: Partial<Actor> = {}): Actor => ({ id, tenant: 'acme', kind: 'user', roles, projects: [], clearance: 'restricted', active: true, ...extra });
function world(now = Date.now()): State {
  const s = kbFixture(now);
  s.actors.sec = user('sec', ['security-admin']); s.actors.kbadm = user('kbadm', ['kb-admin']); s.actors.aud = user('aud', ['auditor']);
  return s;
}
const raw = (store: Store, id: string) => store.transaction('acme', async tx => { await tx.load({ knowledge: [id] }); return structuredClone(tx.state.knowledge[id]!); });
const lastReason = async (store: Store) => (await store.auditLog('acme')).at(-1)!.reason;

/** A key service that can be switched off; `destroyed` lists every key destruction. */
function kms() {
  const keys = new Map<string, Uint8Array>(), destroyed: string[] = [];
  const state = { down: false };
  const provider: KeyProvider = { id: 'test-kms',
    wrap: async (t, r, cek) => { if (state.down) throw new Error('KMS timeout'); keys.set(`${t}/${r}`, Uint8Array.from(cek)); return 'wrapped'; },
    unwrap: async (t, r) => { if (state.down) throw new Error('KMS timeout'); const k = keys.get(`${t}/${r}`); if (!k) throw new KeyDestroyed(); return Uint8Array.from(k); },
    destroy: async (t, r) => { if (state.down) throw new Error('KMS timeout'); destroyed.push(r); keys.delete(`${t}/${r}`); } };
  return { provider, keys, destroyed, state };
}
async function sealedHeld(inner: Store, options: { revoke?: boolean } = {}) {
  const k = kms();
  const store = new EncryptingStore(inner, k.provider);
  const control = new ControlPlane(store);
  const doc = await raw(store, 'strategy');
  assert.ok((await control.upsertKnowledge('acme', 'kbadm', { ...doc, version: doc.version + 1, content: 'Synthetic evidence.' })).ok);
  assert.ok((await control.setLegalHold('acme', 'sec', 'strategy', true, 'case-1')).ok);
  if (options.revoke) assert.ok((await control.revoke('acme', 'sec', 'knowledge', 'strategy')).ok);
  return { ...k, store, control };
}

test('0.6b R195: a key service outage during the erasure of a held record changes nothing (was: tombstoned, key shredded)', async () => {
  const inner = new MemoryStore(world());
  const { store, control, state, keys, destroyed } = await sealedHeld(inner);
  const blocked = await control.erase('acme', 'sec', 'strategy');
  assert.ok(!blocked.ok && blocked.code === 'CONFLICT' && blocked.pending, 'with the key service up the hold blocks the erasure');
  const before = await raw(inner, 'strategy');
  state.down = true;
  // The erasure stays pending (nothing to write), and any write touching the unreadable record fails, audited as a deferred store error.
  const again = await control.erase('acme', 'sec', 'strategy');
  assert.ok(!again.ok && again.code === 'CONFLICT' && again.pending, JSON.stringify(again));
  await assert.rejects(control.setLegalHold('acme', 'sec', 'strategy', false, 'case-1'));
  assert.equal(await lastReason(inner), 'DEFERRED:STORE_ERROR');
  await assert.rejects(control.quarantine('acme', 'sec', 'strategy', 'incident'));
  // Reads defer while the content cannot be opened.
  const engine = new Engine(store);
  const read = await engine.evaluate(bindings.chief, 'strategy', 'read', 'work');
  assert.equal(read.decision, false); assert.equal(read.code, 'STORE_ERROR');
  assert.equal((await engine.openContext(bindings.chief, ['strategy'], 'work')).ok, false);
  state.down = false;
  assert.deepEqual(await raw(inner, 'strategy'), before, 'the stored record is unchanged (content, lifecycle, holds, audience)');
  assert.deepEqual(destroyed, []); assert.ok(keys.has('acme/strategy'), 'the content key is intact');
  assert.equal((await engine.evaluate(bindings.chief, 'strategy', 'read', 'work')).decision, true, 'readable again once the key service is back');
});

test('0.6b R195: an inactive (revoked) held record is not tombstoned during an outage either (memory store)', async () => {
  const inner = new MemoryStore(world());
  const { control, state, keys, destroyed } = await sealedHeld(inner, { revoke: true });
  const before = await raw(inner, 'strategy');
  state.down = true;
  // First erasure request: storing it as pending is a write, so it fails (was: tombstoned and shredded).
  await assert.rejects(control.erase('acme', 'sec', 'strategy'));
  assert.equal(await lastReason(inner), 'DEFERRED:STORE_ERROR');
  state.down = false;
  assert.deepEqual(await raw(inner, 'strategy'), before);
  assert.deepEqual(destroyed, []); assert.ok(keys.has('acme/strategy'));
});

test('0.6b R195: only a key the provider reports as destroyed reads as erased', async () => {
  const inner = new MemoryStore(world());
  const { store, keys } = await sealedHeld(inner);
  keys.delete('acme/strategy');
  const shown = await raw(store, 'strategy');
  assert.equal(shown.lifecycle, 'erased'); assert.equal(shown.content, ''); assert.equal(shown.unreadable, undefined);
});

const url = process.env.AKAC_TEST_DATABASE_URL;
test('0.6b R195 (PostgreSQL): an inactive held record passes the tombstone CHECK, so an outage must not reach the write', { skip: !url }, async () => {
  const name = `akac_r6b_${randomBytes(6).toString('hex')}`;
  const owner = async <T>(fn: (c: pg.Client) => Promise<T>) => { const c = new pg.Client({ connectionString: url }); await c.connect(); try { return await fn(c); } finally { await c.end(); } };
  await owner(c => c.query(`CREATE SCHEMA ${name}`));
  const inner = new PostgresStore(url!, { schema: name, migrate: false });
  try {
    await migrate(url!, { schema: name });
    await importState(inner, world());
    const { control, state, keys, destroyed } = await sealedHeld(inner, { revoke: true });
    const before = await raw(inner, 'strategy');
    state.down = true;
    await assert.rejects(control.erase('acme', 'sec', 'strategy'));
    state.down = false;
    assert.deepEqual(await raw(inner, 'strategy'), before);
    assert.deepEqual(destroyed, []); assert.ok(keys.has('acme/strategy'));
  } finally { await inner.close(); await owner(c => c.query(`DROP SCHEMA IF EXISTS ${name} CASCADE`)); }
});

test('0.6b R158: a single security-admin cannot mint the second approver of a four-eyes rule (was: elevate, approve, break-glass)', async () => {
  const s = world(); delete s.actors.admin; // the fixture's other security-admin: `sec` is alone
  const store = new MemoryStore(s), control = new ControlPlane(store);
  const b = bindings.intern;
  const r1 = await control.issueBreakGlass('acme', 'sec', { id: 'bg-1', subject: b.subject, agent: b.agent, resources: ['strategy'], purposes: ['work'], ttlMs: 3_600_000 });
  assert.ok(!r1.ok && r1.code === 'APPROVAL_REQUIRED');
  const elevate = await control.assignRoles('acme', 'sec', 'aud', ['auditor', 'security-admin']);
  assert.ok(!elevate.ok && elevate.code === 'APPROVAL_REQUIRED', 'the elevation itself needs the highest quorum');
  const approved = await control.approve('acme', 'aud', r1.approval!);
  assert.equal(approved.ok, false, 'aud is not an approver');
  assert.equal((await new Engine(store).evaluate({ ...b, grant: 'bg-1' }, 'strategy', 'read', 'work')).decision, false);
  // Every other way to the same end is gated too.
  for (const attempt of [
    () => control.upsertActor('acme', 'sec', user('aud', ['auditor', 'security-admin'])),
    () => control.upsertActor('acme', 'sec', user('fresh', ['security-admin'])),
    () => control.upsertGroup('acme', 'sec', { id: 'admins', tenant: 'acme', members: ['aud'], roles: ['security-admin'], active: true }),
    () => control.upsertRole('acme', 'sec', { id: 'auditor', tenant: 'acme', inherits: ['security-admin'], active: true })
  ]) { const r = await attempt(); assert.ok(!r.ok && r.code === 'APPROVAL_REQUIRED', JSON.stringify(r)); }
  // Reactivating a deactivated administrator is an elevation as well.
  s.actors.old = user('old', ['security-admin'], { active: false });
  const store2 = new MemoryStore(s), control2 = new ControlPlane(store2);
  const back = await control2.upsertActor('acme', 'sec', user('old', ['security-admin']));
  assert.ok(!back.ok && back.code === 'APPROVAL_REQUIRED');
});

test('0.6b R158: an elevation executes with a second standing security-admin, never with the elevated principal', async () => {
  const s = world(); s.actors.sec2 = user('sec2', ['security-admin']);
  const store = new MemoryStore(s), control = new ControlPlane(store);
  const r = await control.upsertGroup('acme', 'sec', { id: 'admins', tenant: 'acme', members: ['aud'], roles: ['security-admin'], active: true });
  assert.ok(!r.ok && r.code === 'APPROVAL_REQUIRED');
  // A target that already is an approver by another path would still be refused as approver of its own elevation.
  const self = await control.assignRoles('acme', 'sec', 'sec2', ['security-admin']);
  assert.equal(self.ok, true, 'no elevation: sec2 already is a security-admin');
  const done = await control.approve('acme', 'sec2', r.approval!);
  assert.ok(done.ok && done.value.execution?.ok, JSON.stringify(done));
  const group = await control.readGroup('acme', 'sec', 'admins');
  assert.ok(group.ok && group.value?.members.includes('aud'));
});

test('0.6b R190: closing a session or its expiry ends a cached allow (was: served from the decision cache)', async () => {
  const NOW = Date.now(); let now = NOW;
  const engine = new Engine(new MemoryStore(kbFixture(NOW)), { clock: () => now, decisionCache: new DecisionCache({ ttlMs: 300_000, clock: () => now }) });
  const ctx = await engine.openContext(bindings.chief, ['handbook'], 'work'); assert.ok(ctx.ok);
  const d = await engine.derive(bindings.chief, ctx.value.context, 'Session memory.', 'artifact', undefined, { session: { id: 's1', ttlMs: 5_000 } });
  assert.ok(d.ok);
  assert.equal((await engine.evaluate(bindings.chief, d.value.id, 'read', 'work')).decision, true);
  assert.ok((await engine.closeSession(bindings.chief, 's1')).ok);
  assert.equal((await engine.evaluate(bindings.chief, d.value.id, 'read', 'work')).decision, false, 'closed session');
  // Expiry without a close.
  const ctx2 = await engine.openContext(bindings.chief, ['handbook'], 'work'); assert.ok(ctx2.ok);
  const d2 = await engine.derive(bindings.chief, ctx2.value.context, 'Session memory 2.', 'artifact', undefined, { session: { id: 's2', ttlMs: 5_000 } });
  assert.ok(d2.ok);
  assert.equal((await engine.evaluate(bindings.chief, d2.value.id, 'read', 'work')).decision, true);
  now = NOW + 60_000;
  assert.equal((await engine.evaluate(bindings.chief, d2.value.id, 'read', 'work')).decision, false, 'past the session expiry');
});

test('0.6b ADR-020: the decision cache key holds the operation and the RiskProvider levels', async () => {
  let level: RiskLevel = 'none';
  const risk: RiskProvider = { level: async () => level };
  const cache = new DecisionCache({ ttlMs: 300_000 });
  const engine = new Engine(new MemoryStore(kbFixture()), { decisionCache: cache, risk });
  assert.equal((await engine.evaluate(bindings.chief, 'strategy', 'read', 'work')).decision, true);
  assert.equal((await engine.evaluate(bindings.chief, 'strategy', 'read', 'work', { operation: 'authzen_evaluate' })).decision, true);
  assert.equal(cache.size, 2, 'one entry per operation (listener)');
  level = 'critical';
  assert.equal((await engine.evaluate(bindings.chief, 'strategy', 'read', 'work')).decision, false, 'a new provider level is never answered from the cache');
});

test('0.6b R147: a runtime principal heartbeats only runs of agents it is bound to', async () => {
  const s = world();
  s.actors.rt = { id: 'rt', tenant: 'acme', kind: 'service', roles: ['runtime'], projects: [], clearance: 'public', active: true, runtimeFor: ['chief-agent'] };
  s.actors.rt2 = { id: 'rt2', tenant: 'acme', kind: 'service', roles: ['runtime'], projects: [], clearance: 'public', active: true };
  const store = new MemoryStore(s), control = new ControlPlane(store);
  const now = Date.now();
  const g = (id: string, subject: string, agent: string): Grant => ({ id, tenant: 'acme', subject, agent, actions: ['read'], resources: ['*'], purposes: ['work'],
    notBefore: now - 1000, expiresAt: now + 3_600_000, active: true, heartbeatTtlMs: 60_000 });
  assert.ok((await control.issueGrant('acme', 'sec', g('hb-chief', 'chief', 'chief-agent'))).ok);
  assert.ok((await control.issueGrant('acme', 'sec', g('hb-intern', 'intern', 'intern-agent'))).ok);
  assert.equal((await control.heartbeat('acme', 'rt', 'hb-chief')).ok, true);
  const other = await control.heartbeat('acme', 'rt', 'hb-intern');
  assert.ok(!other.ok && other.code === 'NOT_AUTHORIZED', 'another agent\'s run');
  const unbound = await control.heartbeat('acme', 'rt2', 'hb-chief');
  assert.ok(!unbound.ok && unbound.code === 'NOT_AUTHORIZED', 'an unbound runtime');
  assert.equal(await lastReason(store), 'DENIED:NOT_ADMIN');
  // The binding is managed by a security-admin (a role widening under the tenant quorum).
  assert.ok((await control.upsertActor('acme', 'sec', { ...s.actors.rt2!, runtimeFor: ['intern-agent'] })).ok);
  assert.equal((await control.heartbeat('acme', 'rt2', 'hb-intern')).ok, true);
});

test('0.6b R188: a combination rule holds across grants of the same user and agent within the window (was: per run only)', async () => {
  const NOW = Date.now(); let now = NOW;
  const s = kbFixture(NOW);
  s.knowledge.handbook = { ...s.knowledge.handbook!, tags: ['fin'] } as Knowledge;
  s.knowledge.strategy = { ...s.knowledge.strategy!, tags: ['hr'] } as Knowledge;
  s.combinationRules = { wall: { id: 'wall', tenant: 'acme', tagsA: ['fin'], tagsB: ['hr'], effect: 'deny', active: true } };
  s.grants['chief-run-2'] = { ...s.grants['chief-run']!, id: 'chief-run-2' };
  const store = new MemoryStore(s), engine = new Engine(store, { clock: () => now });
  const second = { ...bindings.chief, grant: 'chief-run-2' };
  assert.ok((await engine.openContext(bindings.chief, ['handbook'], 'work')).ok);
  assert.equal((await engine.openContext(second, ['strategy'], 'work')).ok, false, 'split across two grants');
  assert.equal((await store.auditLog('acme')).at(-1)!.reason, 'DENIED:COMBINATION');
  // Another agent of the same user is a different pair; after the window the earlier read no longer counts.
  now = NOW + 600_001; // the first context expired at NOW + 300 000; the window is 300 000 after that
  assert.ok((await engine.openContext(second, ['strategy'], 'work')).ok, 'outside the combination window');
  assert.throws(() => new Engine(store, { combinationWindowMs: 1000 }), /combination window/);
});
