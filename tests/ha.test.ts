import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryIdempotency, MemoryJobLock, MemoryRateLimits } from '../reference/limits.ts';
import type { JobLock } from '../reference/limits.ts';
import { Metrics } from '../reference/metrics.ts';
import { verifyAudit } from '../reference/audit.ts';
import { start, tokens } from './support.ts';

const H = 'a'.repeat(64);

test('HA seams: in-memory rate windows count per (tenant, scope, key), reset per window and refuse when full', async () => {
  let now = 60_000;
  const l = new MemoryRateLimits({ maxBuckets: 2, clock: () => now });
  assert.deepEqual(await l.take('t1', 'agent-run', H, 2, 60_000), { ok: true });
  assert.deepEqual(await l.take('t1', 'agent-run', H, 2, 60_000), { ok: true });
  const third = await l.take('t1', 'agent-run', H, 2, 60_000);
  assert.equal(third.ok, false); assert.equal(!third.ok && third.status, 429); assert.equal(!third.ok && third.reason, 'limited');
  assert.deepEqual(await l.take('t2', 'agent-run', H, 2, 60_000), { ok: true }, 'another tenant has its own window');
  assert.deepEqual(await l.take('t1', 'admin', H, 2, 60_000), { ok: true }, 'another scope has its own window');
  const full = await l.take('t3', 'agent-run', H, 2, 60_000);
  assert.equal(!full.ok && full.status, 503); assert.equal(!full.ok && full.reason, 'full');
  now += 60_000;
  assert.deepEqual(await l.take('t3', 'agent-run', H, 2, 60_000), { ok: true }, 'a new window frees stale buckets');
  assert.deepEqual(await l.take('t1', 'agent-run', H, 5, 60_000, 5), { ok: true }, 'a cost counts that many units');
  assert.equal((await l.take('t1', 'agent-run', H, 5, 60_000)).ok, false);
  await assert.rejects(l.take('t1', 'Bad Scope', H, 1, 1000));
  await assert.rejects(l.take('t1', 'x', H, 0, 1000));
});

test('HA seams: in-memory idempotency claims once, replays the stored response and forgets released keys', async () => {
  const i = new MemoryIdempotency({ keys: 2, owners: 2 });
  assert.deepEqual(await i.claim('t', H, 'k1', 'f'.repeat(64)), { state: 'new' });
  assert.deepEqual(await i.claim('t', H, 'k1', 'f'.repeat(64)), { state: 'seen', fingerprint: 'f'.repeat(64) }, 'in flight');
  await i.complete('t', H, 'k1', { status: 201, body: { ok: true } });
  assert.deepEqual(await i.claim('t', H, 'k1', 'e'.repeat(64)), { state: 'seen', fingerprint: 'f'.repeat(64), response: { status: 201, body: { ok: true } } });
  assert.deepEqual(await i.claim('u', H, 'k1', 'f'.repeat(64)), { state: 'new' }, 'records are per tenant');
  await i.release('u', H, 'k1');
  assert.deepEqual(await i.claim('u', H, 'k1', 'f'.repeat(64)), { state: 'new' });
});

test('HA seams: the job lock runs one job per (job, tenant) at a time and skips a concurrent run', async () => {
  const lock = new MemoryJobLock();
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const first = lock.run('retention', 'acme', async () => { await held; return 1; });
  assert.deepEqual(await lock.run('retention', 'acme', async () => 2), { ran: false });
  assert.deepEqual(await lock.run('retention', 'other', async () => 3), { ran: true, value: 3 }, 'other tenants are independent');
  assert.deepEqual(await lock.run('reconcile', 'acme', async () => 4), { ran: true, value: 4 }, 'other jobs are independent');
  release();
  assert.deepEqual(await first, { ran: true, value: 1 });
  assert.deepEqual(await lock.run('retention', 'acme', async () => 5), { ran: true, value: 5 }, 'released after the run');
  await assert.rejects(lock.run('rm -rf', 'acme', async () => 0));
  await assert.rejects(lock.run('retention', 'acme', async () => { throw new Error('boom'); }));
  assert.deepEqual(await lock.run('retention', 'acme', async () => 6), { ran: true, value: 6 }, 'released after a failure');
});

test('admin API: a retention run held by another instance is refused 409, audited and counted', async () => {
  const busy: JobLock = { shared: true, run: async () => ({ ran: false }) };
  const metrics = new Metrics();
  const { call, store, stop } = await start({ admin: { jobs: busy, metrics } });
  try {
    const r = await call(tokens.sec, 'POST', '/admin/v1/retention/apply', {});
    assert.equal(r.status, 409); assert.deepEqual(await r.json(), { ok: false, code: 'CONFLICT' });
    assert.equal((await call(tokens.aud, 'POST', '/admin/v1/retention/apply', {})).status, 403, 'the role is still checked');
    const audit = await store.auditLog('acme');
    assert.ok(verifyAudit(audit));
    const last = audit.filter(e => e.operation === 'retention_apply').at(-2)!;
    assert.equal(last.decision, 'deny'); assert.equal(last.reason, 'DENIED:CONFLICT');
    assert.match(metrics.expose(), /akac_job_runs_total\{job="retention",result="skipped"\} 2/);
  } finally { await stop(); }
});

test('agent and admin listeners fail closed (503) when the rate limiter store is unavailable', async () => {
  const broken = { shared: true, take: async () => { throw new Error('database unreachable'); } };
  const metrics = new Metrics();
  const { call, stop } = await start({ admin: { limiter: broken, metrics } });
  try {
    assert.equal((await call(tokens.sec, 'GET', '/admin/v1/audit')).status, 503);
    assert.match(metrics.expose(), /akac_rate_limit_rejections_total\{listener="admin",reason="unavailable"\} 1/);
  } finally { await stop(); }
  // The agent listener: construct it directly with a failing limiter.
  const { createGateway } = await import('../reference/http.ts');
  const { Engine } = await import('../reference/engine.ts');
  const { MemoryStore } = await import('../reference/store.ts');
  const { world, listen, close } = await import('./support.ts');
  const { bindings } = await import('../examples/fixture.ts');
  const server = createGateway(new Engine(new MemoryStore(world())), [{ token: tokens.intern, binding: bindings.intern }], { limiter: broken, metrics });
  const url = await listen(server);
  try {
    const r = await fetch(url + '/v1/contexts', { method: 'POST', headers: { authorization: `Bearer ${tokens.intern}`, 'content-type': 'application/json' }, body: JSON.stringify({ resources: ['handbook'], purpose: 'work' }) });
    assert.equal(r.status, 503); assert.deepEqual(await r.json(), { error: 'UNAVAILABLE' });
    assert.match(metrics.expose(), /akac_rate_limit_rejections_total\{listener="agent",reason="unavailable"\} 1/);
  } finally { await close(server); }
});
