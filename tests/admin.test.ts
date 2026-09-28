import test from 'node:test';
import assert from 'node:assert/strict';
import { createAdminGateway } from '../reference/admin.ts';
import { ControlPlane } from '../reference/control.ts';
import { MemoryStore } from '../reference/store.ts';
import { verifyAudit } from '../reference/audit.ts';
import type { Audit, Knowledge } from '../reference/types.ts';
import { AdminClient } from '../sdk/typescript/index.ts';
import { start, tokens, world } from './support.ts';

test('admin API: each route is authorized by the matching standing role', async () => {
  const { call, stop } = await start();
  try {
    const actor = { kind: 'user', roles: ['staff'], projects: [], clearance: 'internal', active: true };
    const container = { kind: 'knowledge-base', classification: 'internal', readerRoles: ['staff'], readers: [], projects: [], active: true };
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/newbie', actor)).status, 200);
    assert.equal((await call(tokens.kb, 'PUT', '/admin/v1/actors/newbie2', actor)).status, 403);
    assert.equal((await call(tokens.aud, 'PUT', '/admin/v1/actors/newbie3', actor)).status, 403);
    assert.equal((await call(tokens.kb, 'PUT', '/admin/v1/containers/kb-new', container)).status, 200);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/containers/kb-new2', container)).status, 403);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/roles/analyst', { inherits: ['staff'], active: true })).status, 200);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/groups/analysts', { members: ['newbie'], roles: ['analyst'], active: true })).status, 200);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/constraints/dsd-x', { kind: 'dynamic', roles: ['analyst', 'project'], cardinality: 2 })).status, 200);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/newbie/roles', { roles: ['staff', 'analyst'] })).status, 200);
    const denied = await call(tokens.kb, 'PUT', '/admin/v1/actors/newbie/roles', { roles: ['staff'] });
    assert.equal(denied.status, 403); assert.deepEqual(await denied.json(), { ok: false, code: 'NOT_AUTHORIZED' });
    const doc = { version: 1, kind: 'document', origin: 'human', content: 'Synthetic onboarding note.', classification: 'internal', projects: [], readerRoles: ['staff'], readers: [], sources: [], active: true, container: 'kb-new' };
    assert.equal((await call(tokens.kb, 'PUT', '/admin/v1/knowledge/onboarding', doc)).status, 200);
    assert.equal((await call(tokens.kb, 'PUT', '/admin/v1/knowledge/onboarding', doc)).status, 409, 'versions are monotonic');
    assert.equal((await call(tokens.kb, 'PUT', '/admin/v1/knowledge/model-note', { ...doc, kind: 'memory' })).status, 400);
    assert.equal((await call(tokens.kb, 'PUT', '/admin/v1/knowledge/model-note', { ...doc, origin: 'model' })).status, 400);
    assert.equal((await call(tokens.sec, 'DELETE', '/admin/v1/knowledge/onboarding')).status, 403, 'document removal is a kb-admin operation');
    assert.equal((await call(tokens.kb, 'DELETE', '/admin/v1/knowledge/onboarding')).status, 200);
    assert.equal((await call(tokens.aud, 'DELETE', '/admin/v1/knowledge/onboarding')).status, 403);
    assert.equal((await call(tokens.aud, 'GET', '/admin/v1/audit')).status, 200);
    assert.equal((await call(tokens.sec, 'GET', '/admin/v1/audit')).status, 403);
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/revocations', { type: 'actor', id: 'newbie' })).status, 200);
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/revocations', { type: 'actor', id: 'newbie', extra: 1 })).status, 400);
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/revocations', { type: 'context', id: 'newbie' })).status, 400);
    const page = await (await call(tokens.aud, 'GET', '/admin/v1/audit?after=0&limit=3')).json() as { value: { entries: Audit[]; next: number } };
    assert.equal(page.value.entries.length, 3); assert.equal(page.value.next, 3);
    for (const bad of ['?limit=0', '?limit=10001', '?after=-1', '?after=x', '?foo=1', '?limit=1&limit=2']) assert.equal((await call(tokens.aud, 'GET', '/admin/v1/audit' + bad)).status, 400, bad);
  } finally { await stop(); }
});

test('admin API: tenant comes from the credential, never from the body', async () => {
  const { call, store, stop } = await start();
  try {
    const actor = { kind: 'user', roles: [], projects: [], clearance: 'public', active: true };
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/x1', { ...actor, tenant: 'other' })).status, 400);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/x1', { ...actor, id: 'x2' })).status, 400);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/x1', { ...actor, tenant: 'acme' })).status, 200);
    assert.equal((await call(tokens.other, 'PUT', '/admin/v1/actors/x3', actor)).status, 200);
    await store.transaction('acme', async tx => { assert.equal(tx.state.actors.x1!.tenant, 'acme'); assert.equal(tx.state.actors.x3, undefined, 'another tenant is invisible'); });
    await store.transaction('other', async tx => { assert.equal(tx.state.actors.x3!.tenant, 'other'); });
    // The other tenant's security-admin cannot revoke acme records.
    assert.equal((await call(tokens.other, 'POST', '/admin/v1/revocations', { type: 'actor', id: 'intern' })).status, 400);
    await store.transaction('acme', async tx => { assert.equal(tx.state.actors.intern!.active, true); });
    const otherAudit = (await (await call(tokens.other, 'GET', '/admin/v1/audit')).json()) as { value: { entries: Audit[] } };
    assert.ok(otherAudit.value.entries.length > 0 && otherAudit.value.entries.every(e => e.tenant === 'other'));
    for (const id of ['__proto__', 'constructor', 'a%2Fb', '%E0%A4%A']) assert.equal((await call(tokens.sec, 'PUT', `/admin/v1/actors/${id}`, actor)).status, 400, id);
  } finally { await stop(); }
});

test('admin API: static separation of duty rejects role assignment with 409', async () => {
  const { call, stop } = await start();
  try {
    const r = await call(tokens.sec, 'PUT', '/admin/v1/actors/intern/roles', { roles: ['requester', 'approver'] });
    assert.equal(r.status, 409); assert.deepEqual(await r.json(), { ok: false, code: 'SOD_VIOLATION' });
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/intern/roles', { roles: ['requester'] })).status, 200);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/intern/roles', { roles: ['requester'], extra: 1 })).status, 400);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/ghost/roles', { roles: ['staff'] })).status, 400);
  } finally { await stop(); }
});

test('admin API: grants are idempotent per Idempotency-Key and reject mismatches', async () => {
  const { call, stop } = await start();
  const grant = { id: 'g-new', subject: 'intern', agent: 'intern-agent', actions: ['read'], resources: ['handbook'], purposes: ['work'],
    notBefore: Date.now() - 1000, expiresAt: Date.now() + 3_600_000, active: true };
  try {
    const first = await call(tokens.sec, 'POST', '/admin/v1/grants', grant, { 'idempotency-key': 'k-1' });
    assert.equal(first.status, 201); assert.equal(first.headers.get('idempotent-replayed'), null);
    const replay = await call(tokens.sec, 'POST', '/admin/v1/grants', grant, { 'idempotency-key': 'k-1' });
    assert.equal(replay.status, 201); assert.equal(replay.headers.get('idempotent-replayed'), 'true');
    assert.deepEqual(await replay.json(), await first.json());
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/grants', { ...grant, resources: ['*'] }, { 'idempotency-key': 'k-1' })).status, 422);
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/grants', grant)).status, 409, 'without a key a duplicate id conflicts');
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/grants', grant, { 'idempotency-key': 'bad key!' })).status, 400);
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/grants', { ...grant, id: 'g-x', tenant: 'other' })).status, 400);
    assert.equal((await call(tokens.kb, 'POST', '/admin/v1/grants', { ...grant, id: 'g-y' }, { 'idempotency-key': 'k-1' })).status, 403);
  } finally { await stop(); }
});

test('admin API: audit export streams a verifiable NDJSON chain', async () => {
  const { call, stop, adminUrl } = await start();
  try {
    for (let i = 0; i < 4; i++) await call(tokens.sec, 'PUT', `/admin/v1/actors/u${i}`, { kind: 'user', roles: [], projects: [], clearance: 'public', active: true });
    await call(tokens.kb, 'PUT', '/admin/v1/actors/nope', {});
    const res = await call(tokens.aud, 'GET', '/admin/v1/audit/export');
    assert.equal(res.status, 200); assert.equal(res.headers.get('content-type'), 'application/x-ndjson'); assert.equal(res.headers.get('cache-control'), 'no-store');
    const entries = (await res.text()).trimEnd().split('\n').map(l => JSON.parse(l) as Audit);
    assert.ok(entries.length >= 6 && entries.every(e => e.tenant === 'acme'));
    assert.ok(verifyAudit(entries));
    assert.ok(entries.some(e => e.operation === 'upsert_actor' && e.decision === 'deny' && e.reason === 'DENIED:NOT_ADMIN'));
    assert.equal((await call(tokens.aud, 'GET', '/admin/v1/audit/export?after=3')).status, 200);
    assert.equal((await call(tokens.sec, 'GET', '/admin/v1/audit/export')).status, 403);
    const client = new AdminClient(adminUrl, tokens.aud); const seen: Audit[] = [];
    for await (const e of client.auditExport()) seen.push(e);
    assert.ok(seen.length >= entries.length);
  } finally { await stop(); }
});

test('admin API: agent and admin credentials are not interchangeable', async () => {
  const { call, stop, agentUrl, adminUrl } = await start();
  try {
    assert.equal((await call(tokens.intern, 'GET', '/admin/v1/audit')).status, 401);
    assert.equal((await call(tokens.sec, 'POST', '/v1/contexts', { resources: ['handbook'], purpose: 'work' }, {}, agentUrl)).status, 401);
    assert.equal((await fetch(adminUrl + '/admin/v1/audit')).status, 401);
    assert.equal((await call(tokens.sec, 'POST', '/v1/contexts', { resources: ['handbook'], purpose: 'work' })).status, 404, 'agent routes do not exist on the admin listener');
    assert.equal((await fetch(adminUrl + '/health')).status, 200);
  } finally { await stop(); }
});

test('admin API: envelopes, limits and headers', async () => {
  const { call, stop, adminUrl } = await start();
  try {
    const ok = await call(tokens.aud, 'GET', '/admin/v1/audit');
    assert.match(ok.headers.get('x-request-id') ?? '', /^[0-9a-f-]{36}$/);
    for (const [h, v] of [['cache-control', 'no-store'], ['x-content-type-options', 'nosniff'], ['content-security-policy', "default-src 'none'"]] as const) assert.equal(ok.headers.get(h), v);
    assert.notEqual(ok.headers.get('x-request-id'), (await call(tokens.aud, 'GET', '/admin/v1/audit')).headers.get('x-request-id'));
    assert.equal((await call(tokens.sec, 'GET', '/admin/v1/nothing')).status, 404);
    assert.equal((await call(tokens.sec, 'PATCH', '/admin/v1/actors/x')).status, 405);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/x', 'not json')).status, 400);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/x', '[]')).status, 400);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/x', { pad: 'x'.repeat(300000) })).status, 413);
    assert.equal((await call(tokens.sec, 'PUT', '/admin/v1/actors/x', '{}', { 'content-type': 'text/plain' })).status, 400);
    assert.equal((await fetch(adminUrl + '/admin/v1/audit', { headers: { authorization: 'Bearer ' + 'x'.repeat(2000) } })).status, 401);
  } finally { await stop(); }
});

test('admin API: an ingestor takes over document writes and removal', async () => {
  const calls: string[] = [];
  const ingestor = {
    ingest: async (tenant: string, admin: string, d: Knowledge) => { calls.push(`ingest:${tenant}:${admin}:${d.id}`); return { ok: true as const, value: { id: d.id, version: d.version, chunks: 3 } }; },
    remove: async (tenant: string, admin: string, id: string) => { calls.push(`remove:${tenant}:${admin}:${id}`); return { ok: true as const, value: null }; }
  };
  const { call, stop } = await start({ admin: { ingestor } });
  try {
    const doc = { version: 1, kind: 'document', origin: 'human', content: 'x', classification: 'public', projects: [], readerRoles: [], readers: [], sources: [], active: true };
    const r = await call(tokens.kb, 'PUT', '/admin/v1/knowledge/d1', { ...doc, tenant: 'acme' });
    assert.deepEqual(await r.json(), { ok: true, value: { id: 'd1', version: 1, chunks: 3 } });
    assert.equal((await call(tokens.kb, 'DELETE', '/admin/v1/knowledge/d1')).status, 200);
    assert.deepEqual(calls, ['ingest:acme:kbadm:d1', 'remove:acme:kbadm:d1']);
  } finally { await stop(); }
});

test('admin gateway configuration fails closed', () => {
  const control = new ControlPlane(new MemoryStore(world()));
  const binding = { tenant: 'acme', admin: 'sec' };
  assert.throws(() => createAdminGateway(control));
  assert.throws(() => createAdminGateway(control, { credentials: [{ token: 'short', binding }] }));
  assert.throws(() => createAdminGateway(control, { credentials: [{ token: tokens.sec, binding }, { token: tokens.sec, binding }] }));
  assert.throws(() => createAdminGateway(control, { credentials: [{ token: tokens.sec, binding: { ...binding, extra: 'x' } as never }] }));
  assert.throws(() => createAdminGateway(control, { credentials: [{ token: tokens.sec, binding }], authenticator: { authenticate: async () => null } }));
});
