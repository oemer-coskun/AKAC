import { bare } from './bare.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { Engine } from '../reference/engine.ts';
import { ProtectedRuntime } from '../reference/runtime.ts';
import { MemoryStore } from '../reference/store.ts';
import { fixture, bindings } from '../examples/fixture.ts';

test('provider without clearance receives no protected input', async () => {
  const state = fixture(); state.actors.provider = { ...state.actors.intern!, id: 'provider', kind: 'service' };
  let invoked = false;
  const runtime = new ProtectedRuntime(new Engine(new MemoryStore(state)), { principal: 'provider', generate: async () => { invoked = true; return 'text'; } });
  assert.equal((await runtime.answer(bindings.chief, ['strategy'], 'work', 'Summarize')).ok, false);
  assert.equal(invoked, false);
});
test('authorized provider receives exact captured sources and output passes recipient gate', async () => {
  const state = fixture(); state.actors.provider = { ...state.actors.chief!, id: 'provider', kind: 'service' };
  const runtime = new ProtectedRuntime(new Engine(new MemoryStore(state)), { principal: 'provider', generate: async request => {
    assert.deepEqual(request.documents.map(r => r.id), ['strategy']); return 'Synthetic answer';
  } });
  assert.deepEqual(bare(await runtime.answer(bindings.chief, ['strategy'], 'work', 'Summarize')), { ok: true, value: { content: 'Synthetic answer' } });
});
test('revocation while provider works blocks the final answer', async () => {
  const state = fixture(); state.actors.provider = { ...state.actors.chief!, id: 'provider', kind: 'service' };
  const engine = new Engine(new MemoryStore(state));
  const runtime = new ProtectedRuntime(engine, { principal: 'provider', generate: async () => {
    await engine.revoke('acme', 'admin', 'knowledge', 'strategy'); return 'Previously learned secret';
  } });
  assert.equal((await runtime.answer(bindings.chief, ['strategy'], 'work', 'Summarize')).ok, false);
});
