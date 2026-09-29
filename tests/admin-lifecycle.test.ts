// Lifecycle administration over real HTTP (0.4, ADR-007): routes, per-role authority, index following, metrics.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAdminGateway } from '../reference/admin.ts';
import { ControlPlane } from '../reference/control.ts';
import { HashEmbedder } from '../reference/embedding.ts';
import { Ingestor } from '../reference/ingest.ts';
import { Metrics } from '../reference/metrics.ts';
import { MemoryStore } from '../reference/store.ts';
import { MemoryVectorIndex } from '../reference/vector.ts';
import { AdminClient } from '../sdk/typescript/index.ts';
import { close, listen, tokens } from './support.ts';
import { derived, lifecycleWorld, LINEAGE, now } from './lifecycle-fixture.ts';
import type { State } from '../reference/types.ts';

const traceparent = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';
async function boot(withIngestor: boolean, change?: (s: State) => void) {
  const store = new MemoryStore(lifecycleWorld(change)), control = new ControlPlane(store, { clock: () => now }), metrics = new Metrics();
  const index = new MemoryVectorIndex(), ingestor = withIngestor ? new Ingestor({ control, store, index, embedder: new HashEmbedder(64), clock: () => now }) : undefined;
  const admin = createAdminGateway(control, { metrics, ...(ingestor ? { ingestor } : {}), credentials: [
    { token: tokens.sec, binding: { tenant: 'acme', admin: 'sec' } }, { token: tokens.kb, binding: { tenant: 'acme', admin: 'kbadm' } },
    { token: tokens.aud, binding: { tenant: 'acme', admin: 'aud' } }, { token: tokens.other, binding: { tenant: 'other', admin: 'other-sec' } }] });
  const url = await listen(admin);
  const call = (token: string, method: string, path: string, body?: unknown, headers: Record<string, string> = {}) =>
    fetch(url + path, { method, headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const json = async (r: Promise<Response>, status: number) => { const res = await r; assert.equal(res.status, status); return await res.json() as Record<string, any>; };
  return { store, control, metrics, index, ingestor, url, call, json, stop: () => close(admin) };
}

test('lifecycle routes: each is authorized by the matching standing role and carries the decision id', async () => {
  const { call, json, stop } = await boot(false);
  try {
    const q = '/admin/v1/knowledge/handbook';
    assert.equal((await call(tokens.aud, 'POST', `${q}/quarantine`, { reason: 'incident' })).status, 403);
    const quarantined = await json(call(tokens.kb, 'POST', `${q}/quarantine`, { reason: 'suspected_poisoning' }, { traceparent }), 200);
    assert.equal(quarantined.value.epoch, 1); assert.match(quarantined.decisionId, /^[0-9a-f-]{36}$/);
    assert.equal((await call(tokens.kb, 'POST', `${q}/release`)).status, 403, 'separation of duty: kb-admin cannot release');
    const denied = await json(call(tokens.kb, 'POST', `${q}/release`), 403); assert.equal(denied.code, 'NOT_AUTHORIZED'); assert.match(denied.decisionId, /^[0-9a-f-]{36}$/);
    assert.equal((await json(call(tokens.sec, 'POST', `${q}/release`), 200)).value.epoch, 2);
    assert.equal((await call(tokens.sec, 'POST', `${q}/quarantine`, { reason: 'incident' })).status, 200, 'security-admin may quarantine too');
    assert.equal((await call(tokens.sec, 'POST', `${q}/release`)).status, 200);
    const d = await json(call(tokens.aud, 'GET', `${q}/descendants?limit=3`), 200);
    assert.equal(d.value.records.length, 3); assert.equal(d.value.truncated, true);
    assert.deepEqual((await json(call(tokens.sec, 'GET', `${q}/descendants`), 200)).value.records.map((r: { id: string }) => r.id), LINEAGE);
    assert.equal((await call(tokens.kb, 'GET', `${q}/descendants`)).status, 403);
    assert.equal((await call(tokens.kb, 'POST', `${q}/revoke-lineage`)).status, 403);
    assert.equal((await json(call(tokens.sec, 'POST', `${q}/revoke-lineage`), 200)).value.revoked, 6);
    assert.equal((await call(tokens.kb, 'POST', '/admin/v1/knowledge/staff-faq/erase', {})).status, 403);
    assert.equal((await call(tokens.aud, 'PUT', `${q}/legal-holds/m1`)).status, 403);
    // Another tenant's record reads as absent.
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/knowledge/o-doc/erase', {})).status, 400);
    assert.equal((await call(tokens.aud, 'POST', '/admin/v1/retention/apply', {})).status, 403);
  } finally { await stop(); }
});

test('lifecycle routes: strict validation', async () => {
  const { call, stop } = await boot(false);
  try {
    const q = '/admin/v1/knowledge/handbook';
    for (const body of [{}, { reason: 'because' }, { reason: 'incident', extra: 1 }, { reason: 7 }, { reason: 'toString' }]) assert.equal((await call(tokens.sec, 'POST', `${q}/quarantine`, body)).status, 400, JSON.stringify(body));
    assert.equal((await call(tokens.sec, 'POST', `${q}/quarantine`, 'not json')).status, 400);
    for (const bad of ['?limit=0', '?limit=1001', '?limit=x', '?limit=1&limit=2', '?after=1', '?limit=-1']) assert.equal((await call(tokens.aud, 'GET', `${q}/descendants${bad}`)).status, 400, bad);
    for (const body of [{ cascade: 'yes' }, { cascade: 1 }, { extra: true }]) assert.equal((await call(tokens.sec, 'POST', `${q}/erase`, body)).status, 400, JSON.stringify(body));
    for (const body of [{ now: -1 }, { now: 1.5 }, { limit: 0 }, { limit: 101 }, { after: 'a/b' }, { after: 3 }, { x: 1 }]) assert.equal((await call(tokens.sec, 'POST', '/admin/v1/retention/apply', body)).status, 400, JSON.stringify(body));
    assert.equal((await call(tokens.sec, 'PUT', `${q}/legal-holds/bad%2Fid`)).status, 400);
    assert.equal((await call(tokens.sec, 'GET', `${q}/erase`)).status, 405);
    assert.equal((await call(tokens.sec, 'POST', `${q}/quarantine`, { reason: 'incident' })).status, 200);
    const dest = { class: 'model-provider', maxClassification: 'internal', purposes: ['work'], active: true };
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/destinations/dest-1', {})).status, 400);
    assert.equal((await call(tokens.kb, 'PUT', '/admin/v1/destinations/dest-1', dest)).status, 403);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/destinations/dest-1', { ...dest, tenant: 'other' })).status, 400);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/destinations/external', dest)).status, 400, 'a class name is not a profile id');
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/destinations/dest-1', dest)).status, 200);
    assert.equal((await call(tokens.sec, 'GET', '/admin/v1/destinations/dest-1')).status, 200);
    assert.equal((await call(tokens.aud, 'GET', '/admin/v1/destinations/dest-1')).status, 200);
    assert.equal((await call(tokens.kb, 'GET', '/admin/v1/destinations/dest-1')).status, 403);
    assert.equal((await call(tokens.sec, 'GET', '/admin/v1/destinations/missing')).status, 404);
  } finally { await stop(); }
});

test('legal hold blocks erasure with a held count; lifting it allows it; erasure is idempotent', async () => {
  const { call, json, store, stop } = await boot(false);
  try {
    const hold = '/admin/v1/knowledge/c/legal-holds/matter-1';
    assert.equal((await json(call(tokens.sec, 'PUT', hold), 200)).value.holds, 1);
    const blocked = await json(call(tokens.sec, 'POST', '/admin/v1/knowledge/handbook/erase', {}), 409);
    assert.equal(blocked.code, 'CONFLICT'); assert.equal(blocked.held, 1); assert.match(blocked.decisionId, /^[0-9a-f-]{36}$/);
    assert.equal(await store.transaction('acme', async tx => { await tx.load({ knowledge: ['handbook'] }); return tx.state.knowledge.handbook!.lifecycle; }), undefined, 'nothing erased');
    assert.equal((await json(call(tokens.sec, 'DELETE', hold), 200)).value.holds, 0);
    assert.equal((await json(call(tokens.sec, 'POST', '/admin/v1/knowledge/handbook/erase', {}), 200)).value.erased, 6);
    assert.equal((await json(call(tokens.sec, 'POST', '/admin/v1/knowledge/handbook/erase', { cascade: true }), 200)).value.erased, 0);
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/knowledge/handbook/release')).status, 409, 'erasure is terminal');
  } finally { await stop(); }
});

test('retention apply erases due records, skips held lineages and resumes with after', async () => {
  const { call, json, stop } = await boot(false, s => {
    s.knowledge.handbook!.retainUntil = now - 1; s.knowledge.handbook!.legalHolds = ['m1'];
    s.knowledge['staff-faq']!.retainUntil = now - 1; s.knowledge['board-notes']!.retainUntil = now - 1; s.knowledge['vault-memo']!.retainUntil = now + 10_000;
  });
  try {
    const first = await json(call(tokens.sec, 'POST', '/admin/v1/retention/apply', { now, limit: 1 }), 200);
    assert.equal(first.value.erased, 1); assert.ok(first.value.next);
    const rest = await json(call(tokens.sec, 'POST', '/admin/v1/retention/apply', { now, after: first.value.next }), 200);
    assert.equal(first.value.erased + rest.value.erased, 2, 'a record under legal hold is never listed, and one not yet due is left alone');
    assert.equal(first.value.held + rest.value.held, 0);
    assert.equal(rest.value.next, undefined);
  } finally { await stop(); }
});

test('with an ingestor the vector index follows quarantine, release, erase and retention', async () => {
  const { call, json, index, ingestor, stop } = await boot(true, s => { s.knowledge['staff-faq']!.retainUntil = now - 1; });
  try {
    await ingestor!.reconcile('acme');
    const indexed = async (id: string) => (await index.state('acme')).has(id);
    assert.ok(await indexed('handbook') && await indexed('staff-faq'));
    await json(call(tokens.kb, 'POST', '/admin/v1/knowledge/handbook/quarantine', { reason: 'scanner' }), 200);
    assert.equal(await indexed('handbook'), false, 'quarantine drops the chunks');
    await json(call(tokens.sec, 'POST', '/admin/v1/knowledge/handbook/release'), 200);
    assert.ok(await indexed('handbook'), 'release re-indexes where eligible');
    await json(call(tokens.sec, 'POST', '/admin/v1/knowledge/handbook/erase', {}), 200);
    assert.equal(await indexed('handbook'), false);
    assert.ok(await indexed('staff-faq'));
    const r = await json(call(tokens.sec, 'POST', '/admin/v1/retention/apply', { now }), 200);
    assert.ok(r.value.erased >= 1);
    assert.equal(await indexed('staff-faq'), false, 'retention erasure drops chunks through reconcile');
  } finally { await stop(); }
});

test('with an ingestor, revoke-lineage drops the lineage chunks and held erase still reports held', async () => {
  const { call, json, index, ingestor, stop } = await boot(true, s => { s.knowledge.x = derived('x', ['staff-faq']); s.knowledge.x.legalHolds = ['m9']; });
  try {
    await ingestor!.reconcile('acme');
    const blocked = await json(call(tokens.sec, 'POST', '/admin/v1/knowledge/staff-faq/erase', {}), 409);
    assert.equal(blocked.held, 1);
    assert.ok((await index.state('acme')).has('staff-faq'));
    await json(call(tokens.sec, 'POST', '/admin/v1/knowledge/handbook/revoke-lineage'), 200);
    for (const id of ['handbook', ...LINEAGE]) assert.equal((await index.state('acme')).has(id), false, id);
  } finally { await stop(); }
});

test('AdminClient covers every lifecycle route', async () => {
  const { url, stop } = await boot(false);
  try {
    const sec = new AdminClient(url, tokens.sec), kb = new AdminClient(url, tokens.kb), aud = new AdminClient(url, tokens.aud);
    assert.equal((await kb.quarantine('handbook', 'memory_review')).ok, true);
    const denied = await kb.release('handbook'); assert.equal(denied.ok, false);
    assert.equal((await sec.release('handbook')).ok, true);
    const d = await aud.descendants('handbook', 2); assert.ok(d.ok && d.value.records.length === 2 && d.value.truncated);
    assert.ok((await sec.setLegalHold('c', 'm1')).ok);
    const held = await sec.erase('handbook'); assert.ok(!held.ok && held.code === 'CONFLICT' && held.held === 1);
    assert.ok((await sec.liftLegalHold('c', 'm1')).ok);
    assert.ok((await sec.revokeLineage('handbook')).ok);
    const e = await sec.erase('handbook', { cascade: true }); assert.ok(e.ok && e.value.erased === 6);
    const r = await sec.applyRetention({ now }); assert.ok(r.ok && r.value.erased === 0);
  } finally { await stop(); }
});

test('metrics: lifecycle operations are counted by a closed operation and result set', async () => {
  const { call, metrics, stop } = await boot(false);
  try {
    await call(tokens.kb, 'POST', '/admin/v1/knowledge/handbook/quarantine', { reason: 'incident' });
    await call(tokens.kb, 'POST', '/admin/v1/knowledge/handbook/release');
    await call(tokens.sec, 'POST', '/admin/v1/knowledge/handbook/release');
    const text = metrics.expose();
    assert.match(text, /akac_lifecycle_operations_total\{operation="quarantine",result="ok"\} 1/);
    assert.match(text, /akac_lifecycle_operations_total\{operation="release",result="denied"\} 1/);
    assert.match(text, /akac_lifecycle_operations_total\{operation="release",result="ok"\} 1/);
    assert.doesNotMatch(text, /handbook/, 'no record id becomes a label');
  } finally { await stop(); }
});

test('reinstate route: only a security-admin lifts a security revocation; the kb-admin cannot republish before it', async () => {
  for (const withIngestor of [false, true]) {
    const { call, json, stop, store } = await boot(withIngestor);
    try {
      const doc = await store.transaction('acme', async tx => { await tx.load({ knowledge: ['staff-faq'] }); return structuredClone(tx.state.knowledge['staff-faq']!); });
      const { lifecycle: _l, lifecycleAt: _a, quarantineReason: _q, legalHolds: _h, revokedAt: _r, ...body } = doc;
      assert.equal((await call(tokens.sec, 'POST', '/admin/v1/knowledge/staff-faq/revoke-lineage')).status, 200);
      assert.equal((await call(tokens.kb, 'PUT', '/admin/v1/knowledge/staff-faq', { ...body, version: 2, active: true })).status, 409);
      assert.equal((await call(tokens.kb, 'POST', '/admin/v1/knowledge/staff-faq/reinstate')).status, 403);
      const ok = await json(call(tokens.sec, 'POST', '/admin/v1/knowledge/staff-faq/reinstate'), 200);
      assert.match(ok.decisionId, /^[0-9a-f-]{36}$/);
      assert.ok([200, 201].includes((await call(tokens.kb, 'PUT', '/admin/v1/knowledge/staff-faq', { ...body, version: 2, active: true })).status));
    } finally { await stop(); }
  }
});
