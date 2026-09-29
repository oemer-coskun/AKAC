// Embedding-anchor re-baseline route (0.6, ADR-020): authority, effect, audit, fail-closed embedder outage.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AnchorMonitor, RetrievalDisabled } from '../reference/anchors.ts';
import type { Embedder } from '../reference/embedding.ts';
import { AdminClient } from '../sdk/typescript/index.ts';
import { start, tokens } from './support.ts';

/** Embedder whose output can be rotated (drift) or made to fail. */
function drifting(): Embedder & { shift: number; down: boolean } {
  const e = { model: 'm', dimensions: 4, shift: 0, down: false,
    async embed(texts: string[]) {
      if (e.down) throw new Error('down');
      return texts.map((t, i) => Float32Array.from([1, 2, 3, 4].map((x, j) => (j === (i + e.shift) % 4 ? x + 10 : x))));
    } };
  return e;
}

test('POST /admin/v1/index/anchors/rebaseline: security-admin only, re-enables retrieval, audited', async () => {
  const embedder = drifting(), monitor = new AnchorMonitor({ embedder, anchors: ['alpha', 'beta'], bootstrap: true });
  await monitor.start();
  const w = await start({ admin: { anchors: monitor } });
  try {
    embedder.shift = 1; await monitor.check();
    assert.equal(monitor.state, 'drifted'); assert.throws(() => monitor.assertEnabled(), RetrievalDisabled);
    const path = '/admin/v1/index/anchors/rebaseline';
    assert.equal((await w.call(tokens.kb, 'POST', path)).status, 403, 'kb-admin is not enough');
    assert.equal((await w.call(tokens.aud, 'POST', path)).status, 403);
    assert.equal(monitor.state, 'drifted', 'a refused call changes nothing');
    embedder.down = true;
    const outage = await w.call(tokens.sec, 'POST', path);
    assert.equal(outage.status, 503); assert.equal(monitor.state, 'drifted', 'fail closed while the embedder is down');
    embedder.down = false;
    const ok = await w.call(tokens.sec, 'POST', path);
    assert.equal(ok.status, 200);
    const body = await ok.json() as { ok: boolean; value: { state: string }; decisionId: string };
    assert.equal(body.value.state, 'ok'); assert.match(body.decisionId, /^[0-9a-f-]{36}$/);
    assert.doesNotThrow(() => monitor.assertEnabled());
    const log = await w.control.auditLog('acme', 'aud');
    assert.ok(log.ok && log.value.some(a => a.operation === 'index_rebaseline' && a.decision === 'allow'));
    assert.ok(log.ok && log.value.some(a => a.operation === 'index_rebaseline' && a.decision === 'deny'));
  } finally { await w.stop(); }
});

test('rebaseline route: creates the first baseline from the pending state', async () => {
  const embedder = drifting(), monitor = new AnchorMonitor({ embedder, anchors: ['alpha'] });
  await monitor.start();
  assert.equal(monitor.state, 'pending');
  const w = await start({ admin: { anchors: monitor } });
  try {
    assert.equal((await w.call(tokens.sec, 'POST', '/admin/v1/index/anchors/rebaseline')).status, 200);
    assert.equal(monitor.state, 'ok');
  } finally { await w.stop(); }
});

test('rebaseline route: 404 without anchors, SDK method', async () => {
  const w = await start();
  try {
    assert.equal((await w.call(tokens.sec, 'POST', '/admin/v1/index/anchors/rebaseline')).status, 404);
  } finally { await w.stop(); }
  const embedder = drifting(), monitor = new AnchorMonitor({ embedder, anchors: ['alpha'], bootstrap: true });
  await monitor.start(); embedder.shift = 2; await monitor.check();
  const w2 = await start({ admin: { anchors: monitor } });
  try {
    const result = await new AdminClient(w2.adminUrl, tokens.sec).rebaselineAnchors();
    assert.ok(result.ok); assert.equal(result.ok && result.value.state, 'ok');
  } finally { await w2.stop(); }
});
