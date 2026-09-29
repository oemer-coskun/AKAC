import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { migrate, PostgresStore } from '../adapters/postgres.ts';
import { JOB_LOCK_CLASS, PostgresIdempotency, PostgresJobLock, PostgresRateLimits } from '../adapters/postgres-ha.ts';
import { Engine } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { createGateway } from '../reference/http.ts';
import { createAdminGateway } from '../reference/admin.ts';
import { importState } from '../reference/store.ts';
import { verifyAudit } from '../reference/audit.ts';
import { bindings } from '../examples/fixture.ts';
import { close, listen, tokens, world } from './support.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url && 'AKAC_TEST_DATABASE_URL not set';
const APP_ROLE = 'akac_ha_app_test', APP_PASSWORD = 'synthetic_ha_only_' + randomBytes(8).toString('hex');
const H = (c: string) => c.repeat(64);

async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
/** A fresh schema at the current migration and a runtime role subject to RLS (not owner, no BYPASSRLS). */
async function setup(): Promise<{ schema: string; appUrl: string; drop: () => Promise<void> }> {
  const schema = `akac_ha_${randomBytes(6).toString('hex')}`;
  await owner(c => c.query(`CREATE SCHEMA ${schema}`));
  await migrate(url!, { schema });
  await owner(async c => {
    await c.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_ROLE}') THEN
      CREATE ROLE ${APP_ROLE} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END $$`);
    await c.query(`ALTER ROLE ${APP_ROLE} PASSWORD '${APP_PASSWORD}'`);
    await c.query(`GRANT USAGE ON SCHEMA ${schema} TO ${APP_ROLE}`);
    await c.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${schema} TO ${APP_ROLE}`);
  });
  const app = new URL(url!); app.username = APP_ROLE; app.password = APP_PASSWORD;
  return { schema, appUrl: app.toString(), drop: () => owner(async c => { await c.query(`DROP SCHEMA ${schema} CASCADE`); }) };
}
test.after(async () => {
  if (!url) return;
  await owner(async c => {
    if ((await c.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [APP_ROLE])).rowCount) { await c.query(`DROP OWNED BY ${APP_ROLE}`); await c.query(`DROP ROLE ${APP_ROLE}`); }
  });
});

test('PostgreSQL HA: migration 009 tables are tenant-scoped with forced RLS and pass the runtime-role posture check', { skip }, async () => {
  const { schema, appUrl, drop } = await setup();
  const store = new PostgresStore(appUrl, { schema, migrate: false, requireRls: true });
  const limits = new PostgresRateLimits(appUrl, { schema });
  try {
    await store.verify();
    const rows = (await owner(c => c.query(`SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
      WHERE relnamespace = '${schema}'::regnamespace AND relname IN ('akac_rate_limits', 'akac_idempotency_keys') ORDER BY relname`))).rows;
    assert.deepEqual(rows, [{ relname: 'akac_idempotency_keys', relrowsecurity: true, relforcerowsecurity: true },
      { relname: 'akac_rate_limits', relrowsecurity: true, relforcerowsecurity: true }]);
    await limits.take('acme', 'agent-run', H('a'), 5, 60_000);
    // The runtime role sees another tenant's rows only under that tenant.
    const app = new pg.Client({ connectionString: appUrl, options: `-c search_path=${schema}` }); await app.connect();
    try {
      await app.query("SELECT set_config('akac.tenant', 'other', false)");
      assert.equal((await app.query('SELECT count(*)::int AS n FROM akac_rate_limits')).rows[0].n, 0);
      await assert.rejects(app.query(`INSERT INTO akac_rate_limits VALUES ('acme', 'agent-run', '${H('b')}', 0, 1, now())`), /row-level security/);
      await app.query("SELECT set_config('akac.tenant', 'acme', false)");
      assert.equal((await app.query('SELECT count(*)::int AS n FROM akac_rate_limits')).rows[0].n, 1);
    } finally { await app.end(); }
  } finally { await limits.close(); await store.close(); await drop(); }
});

test('PostgreSQL HA: two gateway instances on one database share rate windows (agent) and fail closed without it', { skip }, async () => {
  const { schema, appUrl, drop } = await setup();
  const seed = new PostgresStore(url!, { schema, migrate: false });
  await importState(seed, world()); await seed.close();
  const instances = [0, 1].map(() => {
    const store = new PostgresStore(appUrl, { schema, migrate: false, requireRls: true });
    const limiter = new PostgresRateLimits(appUrl, { schema });
    const server = createGateway(new Engine(store), [{ token: tokens.intern, binding: bindings.intern }], { limiter, rateLimits: { credential: 4, contexts: 100 } });
    return { store, limiter, server };
  });
  const urls = await Promise.all(instances.map(i => listen(i.server)));
  const call = (base: string) => fetch(base + '/v1/contexts', { method: 'POST', headers: { authorization: `Bearer ${tokens.intern}`, 'content-type': 'application/json' },
    body: JSON.stringify({ resources: ['handbook'], purpose: 'work' }) });
  try {
    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) statuses.push((await call(urls[i % 2]!)).status);
    assert.deepEqual(statuses, [200, 200, 200, 200]);
    const a = await call(urls[0]!), b = await call(urls[1]!);
    assert.deepEqual([a.status, b.status], [429, 429], 'the fifth request is limited on whichever instance it reaches');
    assert.ok(Number(a.headers.get('retry-after')) >= 1);
    // Concurrent requests never exceed the shared budget in total.
    const limiter = new PostgresRateLimits(appUrl, { schema });
    try {
      const verdicts = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? limiter : instances[0]!.limiter).take('acme', 'race', H('c'), 7, 60_000)));
      assert.equal(verdicts.filter(v => v.ok).length, 7);
    } finally { await limiter.close(); }
  } finally { await close(...instances.map(i => i.server)); for (const i of instances) { await i.limiter.close(); await i.store.close(); } await drop(); }
  await assert.rejects(new PostgresRateLimits('postgresql://nobody@127.0.0.1:1/none').take('acme', 'agent-run', H('a'), 1, 1000), 'unreachable database rejects (fail closed)');
});

test('PostgreSQL HA: admin Idempotency-Key records are shared across instances; one concurrent claim wins; leases lapse; expired rows are swept', { skip }, async () => {
  const { schema, appUrl, drop } = await setup();
  const seed = new PostgresStore(url!, { schema, migrate: false });
  await importState(seed, world()); await seed.close();
  const instances = [0, 1].map(() => {
    const store = new PostgresStore(appUrl, { schema, migrate: false, requireRls: true });
    const idempotency = new PostgresIdempotency(appUrl, { schema }), limiter = new PostgresRateLimits(appUrl, { schema }), jobs = new PostgresJobLock(appUrl, { schema });
    const server = createAdminGateway(new ControlPlane(store), { credentials: [{ token: tokens.sec, binding: { tenant: 'acme', admin: 'sec' } }], idempotency, limiter, jobs });
    return { store, idempotency, limiter, jobs, server };
  });
  const urls = await Promise.all(instances.map(i => listen(i.server)));
  const at = Date.now();
  const grant = (id: string) => ({ id, subject: 'intern', agent: 'intern-agent', actions: ['read'], resources: ['handbook'], purposes: ['work'],
    notBefore: at - 1000, expiresAt: at + 3_600_000, active: true });
  const post = (base: string, body: unknown, key: string) => fetch(base + '/admin/v1/grants', { method: 'POST',
    headers: { authorization: `Bearer ${tokens.sec}`, 'content-type': 'application/json', 'idempotency-key': key }, body: JSON.stringify(body) });
  try {
    const first = await post(urls[0]!, grant('g-ha'), 'k-1');
    assert.equal(first.status, 201);
    const replay = await post(urls[1]!, grant('g-ha'), 'k-1');
    assert.equal(replay.status, 201); assert.equal(replay.headers.get('idempotent-replayed'), 'true', 'a retry that reaches the other instance is deduplicated');
    assert.deepEqual(await replay.json(), await first.json());
    assert.equal((await post(urls[1]!, { ...grant('g-ha'), resources: ['*'] }, 'k-1')).status, 422);
    // Two instances receive the same new key at once: exactly one issues the grant.
    const race = await Promise.all([post(urls[0]!, grant('g-race'), 'k-2'), post(urls[1]!, grant('g-race'), 'k-2')]);
    const codes = race.map(r => r.status);
    assert.ok(codes.includes(201) && codes.every(c => c === 201 || c === 409), `one winner: ${codes}`);
    const audit = await instances[0]!.store.auditLog('acme');
    assert.ok(verifyAudit(audit));
    assert.equal(audit.filter(e => e.operation === 'issue_grant' && e.decision === 'allow' && e.reason === 'AUTHORIZED').length, 2, 'two grants issued in total');

    // Lease: an in-flight claim of a dead instance lapses and the key can be claimed again.
    const short = new PostgresIdempotency(appUrl, { schema, leaseMs: 1000, ttlMs: 2000 });
    try {
      assert.deepEqual(await short.claim('acme', H('d'), 'k-lease', H('e')), { state: 'new' });
      assert.equal((await short.claim('acme', H('d'), 'k-lease', H('e'))).state, 'seen');
      await new Promise(r => setTimeout(r, 1200));
      assert.deepEqual(await short.claim('acme', H('d'), 'k-lease', H('e')), { state: 'new' }, 'lapsed lease');
      await short.complete('acme', H('d'), 'k-lease', { status: 201, body: { ok: true } });
      assert.deepEqual(await short.claim('other', H('d'), 'k-lease', H('e')), { state: 'new' }, 'another tenant never sees the record');
    } finally { await short.close(); }
    await new Promise(r => setTimeout(r, 2100));
    // TTL cleanup: a fresh instance sweeps the tenant's expired rows on first use.
    const sweeper = new PostgresIdempotency(appUrl, { schema });
    try { await sweeper.claim('acme', H('f'), 'k-sweep', H('f')); } finally { await sweeper.close(); }
    const left = (await owner(c => c.query(`SELECT key FROM ${schema}.akac_idempotency_keys WHERE key = 'k-lease' AND tenant = 'acme'`))).rowCount;
    assert.equal(left, 0, 'expired record swept');
  } finally { await close(...instances.map(i => i.server)); for (const i of instances) { await i.idempotency.close(); await i.limiter.close(); await i.jobs.close(); await i.store.close(); } await drop(); }
});

test('PostgreSQL HA: retention/reconcile job locks serialize across instances without a leader and never outlive their session', { skip }, async () => {
  const { schema, appUrl, drop } = await setup();
  const a = new PostgresJobLock(appUrl, { schema }), b = new PostgresJobLock(appUrl, { schema });
  try {
    let release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    const running = a.run('retention', 'acme', async () => { await held; return 'a'; });
    await new Promise(r => setTimeout(r, 200));
    assert.deepEqual(await b.run('retention', 'acme', async () => 'b'), { ran: false }, 'the other instance skips');
    assert.deepEqual(await b.run('retention', 'other', async () => 'b'), { ran: true, value: 'b' }, 'per tenant');
    assert.deepEqual(await b.run('reconcile', 'acme', async () => 'b'), { ran: true, value: 'b' }, 'per job');
    release();
    assert.deepEqual(await running, { ran: true, value: 'a' });
    assert.deepEqual(await b.run('retention', 'acme', async () => 'b2'), { ran: true, value: 'b2' });
    // A crashed holder: its session ends and PostgreSQL drops the lock.
    const crashed = new pg.Client({ connectionString: appUrl }); await crashed.connect();
    assert.equal((await crashed.query('SELECT pg_try_advisory_lock($1, hashtext($2)) AS ok', [JOB_LOCK_CLASS, 'retention/acme'])).rows[0].ok, true);
    assert.deepEqual(await b.run('retention', 'acme', async () => 'b3'), { ran: false });
    await crashed.end();
    assert.deepEqual(await b.run('retention', 'acme', async () => 'b4'), { ran: true, value: 'b4' });
  } finally { await a.close(); await b.close(); await drop(); }
});
