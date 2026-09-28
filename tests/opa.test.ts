import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { OpaPolicy } from '../adapters/opa.ts';
const input = { action: 'read' as const, tenant: 'acme', classification: 'internal' as const, purpose: 'work' };
test('OPA adapter rejects undefined, string truth, malformed and failed responses', async () => {
  const accepted = '{"result":{"allow":true,"revision":"akac-company/0.2"}}';
  for (const body of ['{}', '{"result":"true"}', '{"result":false}', 'invalid', '{"result":true}',
    '{"result":{"allow":true,"revision":"stale"}}', accepted]) {
    const server = createServer((_req, res) => res.end(body)); server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const address = server.address(); assert.ok(address && typeof address !== 'string');
    try { assert.equal(await new OpaPolicy(`http://127.0.0.1:${address.port}`).check(input), body === accepted); }
    finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  }
  assert.equal(await new OpaPolicy('http://127.0.0.1:1').check(input), false);
});
test('real OPA server evaluates checked-in Rego', { skip: !process.env.OPA_BIN }, async () => {
  const proc = spawn(process.env.OPA_BIN!, ['run', '--server', '--addr=127.0.0.1:18181', 'policies/'], { stdio: 'ignore' });
  try {
    let ready = false;
    for (let i = 0; i < 100; i++) {
      try { ready = (await fetch('http://127.0.0.1:18181/health')).ok; } catch {}
      if (ready) break; await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.ok(ready, 'OPA failed to start');
    const policy = new OpaPolicy('http://127.0.0.1:18181/v1/data/akac/decision');
    assert.equal(await policy.ready(), true);
    assert.equal(await policy.check(input), true);
    assert.equal(await policy.check({ ...input, tenant: 'other' }), false);
    assert.equal(await policy.check({ ...input, action: 'declassify' }), false);
  } finally { proc.kill(); await once(proc, 'exit'); }
});
