import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { Engine } from '../reference/engine.ts';
import { decide, visible } from '../reference/policy.ts';
import { MemoryStore } from '../reference/store.ts';
import { signCheckpoint, verifyCheckpoint } from '../reference/checkpoint.ts';
import { fixture, bindings } from '../examples/fixture.ts';
import type { PolicyInput, State } from '../reference/types.ts';
const now = 1800000000000;

test('bounded DAG evaluator handles heavily shared dependencies without exponential traversal', () => {
  const state = fixture(now);
  for (let i = 0; i < 100; i++) state.knowledge[`node-${i}`] = { ...structuredClone(state.knowledge.handbook!), id: `node-${i}`,
    sources: i < 2 ? [] : [{ id: `node-${i - 1}`, version: 1 }, { id: `node-${i - 2}`, version: 1 }] };
  assert.ok(visible(state, state.actors.intern!, state.knowledge['node-99']!, now));
  state.knowledge['node-0']!.active = false;
  assert.equal(visible(state, state.actors.intern!, state.knowledge['node-99']!, now), false);
});
test('dependency depth and node limits fail closed', () => {
  const state = fixture(now);
  for (let i = 0; i < 129; i++) state.knowledge[`deep-${i}`] = { ...structuredClone(state.knowledge.handbook!), id: `deep-${i}`,
    sources: i ? [{ id: `deep-${i - 1}`, version: 1 }] : [] };
  assert.ok(visible(state, state.actors.intern!, state.knowledge['deep-127']!, now));
  assert.equal(visible(state, state.actors.intern!, state.knowledge['deep-128']!, now), false);
  const root = structuredClone(state.knowledge.handbook!); root.id = 'root';
  for (let i = 0; i < 1025; i++) {
    state.knowledge[`wide-${i}`] = { ...structuredClone(state.knowledge.handbook!), id: `wide-${i}` };
    root.sources.push({ id: `wide-${i}`, version: 1 });
  }
  assert.equal(visible(state, state.actors.intern!, root, now), false);
});
test('malformed and forged decision envelopes deny rather than throw', () => {
  for (const input of [null, {}, { binding: null }, { binding: bindings.chief, action: 'read', resource: 'constructor', purpose: 'work', now }]) {
    assert.equal(decide(fixture(now), input as PolicyInput).effect, 'deny');
  }
  assert.equal(decide({} as State, { binding: bindings.chief, action: 'read', resource: 'strategy', purpose: 'work', now }).effect, 'deny');
});
test('source access expiry invalidates future reads and derived outputs', async () => {
  const state = fixture(now); state.knowledge.strategy!.accessExpiresAt = now + 100;
  let tick = now;
  const engine = new Engine(new MemoryStore(state), { clock: () => tick });
  const context = await engine.openContext(bindings.chief, ['strategy'], 'work'); assert.ok(context.ok);
  tick += 100;
  assert.equal((await engine.derive(bindings.chief, context.value.context, 'expired')).ok, false);
  assert.equal((await engine.openContext(bindings.chief, ['strategy'], 'work')).ok, false);
});
test('changing company policy revision invalidates previously captured contexts', async () => {
  const store = new MemoryStore(fixture(now));
  const first = new Engine(store, { clock: () => now, policy: { revision: 'v1', check: async () => true } });
  const context = await first.openContext(bindings.chief, ['strategy'], 'work'); assert.ok(context.ok);
  const next = new Engine(store, { clock: () => now, policy: { revision: 'v2', check: async () => true } });
  assert.equal((await next.derive(bindings.chief, context.value.context, 'stale policy')).ok, false);
});
test('retrieval candidate budget refuses over-limit work', async () => {
  const state = fixture(now);
  for (let i = 0; i < 1001; i++) state.knowledge[`copy-${i}`] = { ...structuredClone(state.knowledge.handbook!), id: `copy-${i}` };
  const engine = new Engine(new MemoryStore(state), { clock: () => now });
  assert.equal((await engine.retrieve(bindings.intern, 'product', 'work')).ok, false);
});
test('readiness verifies state audit and policy availability', async () => {
  const store = new MemoryStore(fixture(now));
  assert.equal(await new Engine(store).ready(), true);
  assert.equal(await new Engine(store, { policy: { revision: 'test-v1', check: async () => false, ready: async () => false } }).ready(), false);
  await store.transaction('acme', async ({ state: s }) => { s.schema = 'unknown' as never; });
  assert.equal(await new Engine(store).ready(), false);
});
test('signed external checkpoint detects rewrite, truncation, replay and key substitution', async () => {
  const store = new MemoryStore(fixture(now)); const engine = new Engine(store, { clock: () => now });
  await engine.openContext(bindings.intern, ['handbook'], 'work');
  await engine.openContext(bindings.intern, ['strategy'], 'work');
  const entries = await store.transaction('acme', async ({ state: s }) => structuredClone(s.audits));
  const keys = generateKeyPairSync('ed25519');
  const privatePem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicPem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const record = signCheckpoint(entries, privatePem, 'stream-a', 'key-a', now);
  const check = (logs = entries, checkpoint = record, stream = 'stream-a', floor = 2, key = publicPem) => verifyCheckpoint(logs, checkpoint, key, stream, 'key-a', floor);
  assert.ok(check());
  assert.equal(check(entries.slice(0, 1)), false);
  assert.equal(check(entries, { ...record, hash: '0'.repeat(64) }), false);
  assert.equal(check(entries, record, 'stream-b'), false);
  assert.equal(check(entries, record, 'stream-a', 3), false);
  const substituted = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.equal(check(entries, record, 'stream-a', 2, substituted), false);
  const changed = structuredClone(entries); changed[0]!.reason = 'tampered';
  assert.equal(check(changed), false);
});
