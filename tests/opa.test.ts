import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { OpaPolicy } from '../adapters/opa.ts';
/**
 * Starts `opa run --server` on a free-looking port and waits (up to 20 s, polling
 * /health) until it answers. A process that exits early (for example a port in
 * use) is retried on another port.
 */
async function startOpa(args: string[] = []): Promise<{ port: number; proc: ChildProcess }> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const port = 18000 + Math.floor(Math.random() * 2000);
    const proc = spawn(process.env.OPA_BIN!, ['run', '--server', `--addr=127.0.0.1:${port}`, ...args], { stdio: 'ignore' });
    let exited = false; proc.once('exit', () => { exited = true; });
    const deadline = Date.now() + 20_000;
    while (!exited && Date.now() < deadline) {
      try { if ((await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(1000) })).ok) return { port, proc }; } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!exited) { proc.kill(); await once(proc, 'exit'); }
  }
  throw new Error('OPA failed to start within 20 s');
}
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
  const { port, proc } = await startOpa(['policies/']);
  try {
    const policy = new OpaPolicy(`http://127.0.0.1:${port}/v1/data/akac/decision`);
    assert.equal(await policy.ready(), true);
    assert.equal(await policy.check(input), true);
    assert.equal(await policy.check({ ...input, tenant: 'other' }), false);
    assert.equal(await policy.check({ ...input, action: 'declassify' }), false);
  } finally { proc.kill(); await once(proc, 'exit'); }
});
