import { bare } from './bare.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createGateway } from '../reference/http.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryStore } from '../reference/store.ts';
import { fixture, bindings } from '../examples/fixture.ts';
import { AkacClient } from './http-client.ts';
const token = 'test-only-credential-never-deploy-0000000000000';
test('API and client: real requests, strict envelopes, binding and output protection', async () => {
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
    assert.deepEqual(bare(await denied.json()), { ok: false, code: 'NOT_AUTHORIZED' });
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
async function withGateway(rateLimits: NonNullable<Parameters<typeof createGateway>[2]>['rateLimits'], credentials: { token: string; binding: typeof bindings.intern }[], body: (call: (path: string, credential?: string, payload?: unknown) => Promise<Response>) => Promise<void>) {
  const server = createGateway(new Engine(new MemoryStore(fixture())), credentials, { rateLimits });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const call = (path: string, credential = credentials[0]!.token, payload: unknown = { resources: ['handbook'], purpose: 'work' }) =>
    fetch(`http://127.0.0.1:${address.port}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${credential}` }, body: JSON.stringify(payload) });
  try { await body(call); } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
}
test('rate limits: separate budgets per operation class, per run; 429 carries Retry-After', async () => {
  const other = 'another-test-only-credential-000000000000000';
  let now = 1_800_000_000_000;
  await withGateway({ retrieve: 2, contexts: 3, write: 1, credential: 100, clock: () => now }, [{ token, binding: bindings.intern }, { token: other, binding: bindings.chief }], async call => {
    const q = { query: 'product', purpose: 'work' };
    assert.equal((await call('/v1/retrieve', token, q)).status, 200); assert.equal((await call('/v1/retrieve', token, q)).status, 200);
    const limited = await call('/v1/retrieve', token, q);
    assert.equal(limited.status, 429); assert.deepEqual(await limited.json(), { error: 'RATE_LIMITED' });
    const wait = Number(limited.headers.get('retry-after')); assert.ok(Number.isInteger(wait) && wait >= 1 && wait <= 60);
    // Exhausting retrieve does not spend the contexts or write budgets, nor another run's.
    for (let i = 0; i < 3; i++) assert.equal((await call('/v1/contexts', token)).status, 200);
    assert.equal((await call('/v1/contexts', token)).status, 429);
    assert.equal((await call('/v1/derive', token, { context: 'x', content: 'y', kind: 'memory' })).status, 403);
    assert.equal((await call('/v1/release', token, { context: 'x', recipient: 'intern', content: 'y', action: 'share' })).status, 429, 'derive and release share the write budget');
    assert.equal((await call('/v1/retrieve', other, q)).status, 200);
    now += 60_000;
    assert.equal((await call('/v1/retrieve', token, q)).status, 200, 'the window resets');
  });
});
test('rate limits: bounded memory fails closed with 503 instead of evicting counters', async () => {
  const other = 'another-test-only-credential-000000000000000';
  await withGateway({ maxBuckets: 1, retrieve: 100 }, [{ token, binding: bindings.intern }, { token: other, binding: bindings.chief }], async call => {
    assert.equal((await call('/v1/contexts', token)).status, 200);
    // The second credential needs a new bucket in each limiter, which no longer fit.
    const full = await call('/v1/contexts', other);
    assert.equal(full.status, 503); assert.ok(Number(full.headers.get('retry-after')) >= 1);
    assert.equal((await call('/v1/contexts', token)).status, 200, 'existing buckets keep working');
  });
});
test('rate limit configuration is validated at startup', () => {
  const engine = new Engine(new MemoryStore(fixture()));
  for (const bad of [{ retrieve: 0 }, { write: 1.5 }, { maxBuckets: -1 }, { windowMs: 0 }]) assert.throws(() => createGateway(engine, [{ token, binding: bindings.intern }], { rateLimits: bad }));
});
