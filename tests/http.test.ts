import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createGateway } from '../reference/http.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryStore } from '../reference/store.ts';
import { fixture, bindings } from '../examples/fixture.ts';
import { AkacClient } from '../sdk/typescript/index.ts';
const token = 'test-only-credential-never-deploy-0000000000000';
test('API and SDK: real requests, strict envelopes, binding and output protection', async () => {
  const server = createGateway(new Engine(new MemoryStore(fixture())), [{ token, binding: bindings.intern }]);
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}`;
  const post = (body: unknown, credential = token) => fetch(base + '/v1/contexts', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${credential}` }, body: JSON.stringify(body) });
  try {
    assert.equal((await fetch(base + '/health')).status, 200);
    assert.equal((await post({ resources: ['handbook'], purpose: 'work' }, 'fake')).status, 401);
    for (const extra of [{ subject: 'chief' }, { allowed: true }, { authority: 'admin' }, { role: 'executive' }])
      assert.equal((await post({ resources: ['handbook'], purpose: 'work', ...extra })).status, 400);
    assert.equal((await post({ resources: ['constructor'], purpose: 'work' })).status, 400);
    const denied = await post({ resources: ['strategy'], purpose: 'work' });
    assert.equal(denied.status, 403); assert.equal(denied.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await denied.json(), { ok: false, code: 'NOT_AUTHORIZED' });
    const client = new AkacClient(base, token);
    const result = await client.retrieve('product', 'work'); assert.ok(result.ok);
    assert.deepEqual(result.value.documents.map(d => d.id), ['handbook']);
    const memory = await client.derive(result.value.context, 'Product notes', 'memory'); assert.ok(memory.ok);
    assert.equal(memory.value.classification, 'public');
    assert.ok((await client.release(result.value.context, 'intern', 'Notes')).ok);
    assert.equal((await client.release(result.value.context, 'outsider', 'Notes')).ok, false);
    assert.equal((await fetch(base + '/v1/contexts', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: 'invalid' })).status, 400);
    assert.equal((await post({ resources: ['handbook'], purpose: 'x'.repeat(140000) })).status, 413);
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
test('startup rejects weak and duplicate credentials', () => {
  const engine = new Engine(new MemoryStore(fixture()));
  assert.throws(() => createGateway(engine, [{ token: 'weak', binding: bindings.intern }]));
  assert.throws(() => createGateway(engine, [{ token, binding: bindings.intern }, { token, binding: bindings.chief }]));
});
