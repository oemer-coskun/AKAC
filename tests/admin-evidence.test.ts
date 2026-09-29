import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { ControlPlane } from '../reference/control.ts';
import { createAdminGateway } from '../reference/admin.ts';
import { MemoryStore } from '../reference/store.ts';
import { verifyCheckpointV2, verifyCheckpointExtension } from '../reference/checkpoint.ts';
import { verifyConsistency, verifyInclusion } from '../reference/merkle.ts';
import { auditLeaf } from '../reference/audit.ts';
import { validDecisionId } from '../reference/decision.ts';
import { close, listen, tokens, world } from './support.ts';

async function setup(signing = true) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const store = new MemoryStore(world());
  const control = new ControlPlane(store, signing ? { checkpoint: { privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), keyId: 'test-key-1' } } : {});
  const server = createAdminGateway(control, { credentials: [
    { token: tokens.sec, binding: { tenant: 'acme', admin: 'sec' } }, { token: tokens.aud, binding: { tenant: 'acme', admin: 'aud' } }] });
  const base = await listen(server);
  const get = (path: string, token = tokens.aud, headers: Record<string, string> = {}) => fetch(base + path, { headers: { authorization: `Bearer ${token}`, ...headers } });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return { store, get, base, publicPem, stop: () => close(server) };
}
const revoke = (base: string, id: string) => fetch(base + '/admin/v1/revocations', { method: 'POST', headers: { authorization: `Bearer ${tokens.sec}`, 'content-type': 'application/json' }, body: JSON.stringify({ type: 'knowledge', id }) });

test('checkpoint, inclusion proof and consistency proof are served to auditors and verify independently', async () => {
  const t = await setup();
  try {
    await revoke(t.base, 'handbook'); await revoke(t.base, 'staff-faq');
    const first = await (await t.get('/admin/v1/audit/checkpoint')).json() as any;
    assert.equal(first.ok, true); assert.ok(validDecisionId(first.decisionId));
    const c1 = first.value.checkpoint;
    assert.equal(c1.format, 'akac-audit-checkpoint/2'); assert.equal(c1.stream, 'acme');
    assert.ok(verifyCheckpointV2(c1, t.publicPem, 'acme', 'test-key-1'));
    assert.deepEqual([c1.treeSize, c1.rootHash], [first.value.head.treeSize, first.value.head.rootHash]);
    await revoke(t.base, 'strategy');
    const c2 = (await (await t.get('/admin/v1/audit/checkpoint')).json() as any).value.checkpoint;
    assert.ok(c2.treeSize > c1.treeSize);
    const cons = await (await t.get(`/admin/v1/audit/consistency?first=${c1.treeSize}&second=${c2.treeSize}`)).json() as any;
    assert.equal(cons.ok, true);
    assert.ok(verifyConsistency(c1.treeSize, c2.treeSize, c1.rootHash, c2.rootHash, cons.value.path));
    assert.ok(verifyCheckpointExtension(c1, c2, cons.value.path));
    const log = await t.store.auditLog('acme');
    for (const index of [0, 2, c1.treeSize - 1]) {
      const proof = await (await t.get(`/admin/v1/audit/proof?leafIndex=${index}&treeSize=${c1.treeSize}`)).json() as any;
      assert.equal(proof.ok, true);
      assert.equal(proof.value.leafHash, auditLeaf(log[index]!));
      assert.ok(verifyInclusion(proof.value.leafHash, index, c1.treeSize, proof.value.path, c1.rootHash));
    }
  } finally { await t.stop(); }
});

test('without a checkpoint key only the unsigned tree head is returned', async () => {
  const t = await setup(false);
  try {
    const r = await (await t.get('/admin/v1/audit/checkpoint')).json() as any;
    assert.equal(r.ok, true); assert.equal(r.value.checkpoint, undefined); assert.equal(r.value.head.stream, 'acme');
  } finally { await t.stop(); }
});

test('evidence routes: auditor role only, strict queries, decision id on every failure', async () => {
  const t = await setup();
  try {
    await revoke(t.base, 'handbook');
    for (const path of ['/admin/v1/audit/checkpoint', '/admin/v1/audit/proof?leafIndex=0&treeSize=1', '/admin/v1/audit/consistency?first=1&second=1']) {
      const denied = await t.get(path, tokens.sec);
      assert.equal(denied.status, 403);
      const body = await denied.json() as any;
      assert.equal(body.code, 'NOT_AUTHORIZED'); assert.ok(validDecisionId(body.decisionId));
      assert.equal((await fetch(t.base + path, { method: 'POST', headers: { authorization: `Bearer ${tokens.aud}` } })).status, 405);
    }
    for (const bad of ['/admin/v1/audit/checkpoint?x=1', '/admin/v1/audit/proof', '/admin/v1/audit/proof?leafIndex=0', '/admin/v1/audit/proof?leafIndex=0&treeSize=1&extra=1',
      '/admin/v1/audit/proof?leafIndex=-1&treeSize=1', '/admin/v1/audit/proof?leafIndex=0x1&treeSize=1', '/admin/v1/audit/proof?leafIndex=1&leafIndex=1&treeSize=2',
      '/admin/v1/audit/proof?leafIndex=0&treeSize=1e3', '/admin/v1/audit/consistency?first=1', '/admin/v1/audit/consistency?first=a&second=2'])
      assert.equal((await t.get(bad)).status, 400, bad);
    // Well-formed but outside the stream: a refusal that is audited and carries its decision id.
    for (const path of ['/admin/v1/audit/proof?leafIndex=5&treeSize=999', '/admin/v1/audit/proof?leafIndex=3&treeSize=3', '/admin/v1/audit/consistency?first=0&second=1', '/admin/v1/audit/consistency?first=2&second=999']) {
      const r = await t.get(path); assert.equal(r.status, 400, path);
      const body = await r.json() as any; assert.deepEqual([body.ok, body.code, validDecisionId(body.decisionId)], [false, 'INVALID_REQUEST', true]);
    }
    const log = await t.store.auditLog('acme');
    assert.ok(log.some(e => e.operation === 'audit_proof' && e.decision === 'deny'));
  } finally { await t.stop(); }
});

test('a valid W3C traceparent is recorded with the audited decision; an invalid one never is', async () => {
  const t = await setup();
  try {
    const traceId = '4bf92f3577b34da6a3ce929d0e0e4736';
    await t.get('/admin/v1/audit/checkpoint', tokens.aud, { traceparent: `00-${traceId}-00f067aa0ba902b7-01` });
    await t.get('/admin/v1/audit/checkpoint', tokens.aud, { traceparent: '00-not-a-trace-id' });
    const log = await t.store.auditLog('acme');
    const marked = log.filter(e => e.operation === 'audit_checkpoint');
    assert.equal(marked[0]!.traceId, traceId);
    // Without a valid header the gateway starts a fresh trace: still a valid id, and never the invalid header text.
    assert.match(marked[1]!.traceId ?? '', /^[0-9a-f]{32}$/);
    assert.notEqual(marked[1]!.traceId, traceId);
  } finally { await t.stop(); }
});

test('agent gateway records a valid traceparent with the audited decision', async () => {
  const { createGateway } = await import('../reference/http.ts');
  const { Engine } = await import('../reference/engine.ts');
  const { bindings } = await import('../examples/fixture.ts');
  const store = new MemoryStore(world());
  const server = createGateway(new Engine(store), [{ token: tokens.intern, binding: bindings.intern }]);
  const base = await listen(server);
  try {
    const traceId = '0af7651916cd43dd8448eb211c80319c';
    const r = await fetch(base + '/v1/contexts', { method: 'POST', headers: { authorization: `Bearer ${tokens.intern}`, 'content-type': 'application/json', traceparent: `00-${traceId}-b7ad6b7169203331-01` },
      body: JSON.stringify({ resources: ['handbook'], purpose: 'work' }) });
    const body = await r.json() as any;
    assert.equal(r.status, 200);
    const entry = (await store.auditLog('acme')).find(e => e.decisionId === body.decisionId);
    assert.equal(entry?.traceId, traceId);
  } finally { await close(server); }
});
