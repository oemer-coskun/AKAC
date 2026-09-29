// PostgreSQL versions of the identity and authority cases (0.6, ADR-019, migration 010), run as a runtime role
// subject to forced row-level security. Skipped without AKAC_TEST_DATABASE_URL.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { MIGRATIONS, migrate, PostgresStore } from '../adapters/postgres.ts';
import { Engine } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { importState } from '../reference/store.ts';
import { verifyAudit } from '../reference/audit.ts';
import { attachActorChain } from '../reference/delegation.ts';
import type { State } from '../reference/types.ts';
import { bindings } from '../examples/fixture.ts';
import { world } from './support.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url;
const APP_ROLE = 'akac_identity_app_test', APP_PASSWORD = 'synthetic_rls_only_' + randomBytes(8).toString('hex');
const schemas: string[] = [];
async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
async function schema(): Promise<string> {
  const name = `akac_i_${randomBytes(6).toString('hex')}`; schemas.push(name);
  await owner(c => c.query(`CREATE SCHEMA ${name}`)); return name;
}
async function appAccess(name: string): Promise<string> {
  await owner(async c => {
    await c.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_ROLE}') THEN
      CREATE ROLE ${APP_ROLE} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END $$`);
    await c.query(`ALTER ROLE ${APP_ROLE} PASSWORD '${APP_PASSWORD}'`);
    await c.query(`GRANT USAGE ON SCHEMA ${name} TO ${APP_ROLE}`);
    await c.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${name} TO ${APP_ROLE}`);
  });
  const app = new URL(url!); app.username = APP_ROLE; app.password = APP_PASSWORD; return app.toString();
}
test.after(async () => {
  if (skip) return;
  await owner(async c => {
    for (const name of schemas) await c.query(`DROP SCHEMA IF EXISTS ${name} CASCADE`);
    if ((await c.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [APP_ROLE])).rowCount) {
      await c.query(`DROP OWNED BY ${APP_ROLE}`); await c.query(`DROP ROLE ${APP_ROLE}`);
    }
  });
});
function state(): State {
  const s = world();
  const add = (id: string, kind: 'user' | 'service', roles: string[]) => { s.actors[id] = { id, tenant: 'acme', kind, roles, projects: [], clearance: 'restricted', active: true }; };
  add('sec2', 'user', ['security-admin']); add('runtime-1', 'service', ['runtime']); s.actors['runtime-1']!.runtimeFor = ['chief-agent']; add('risk-1', 'service', ['risk-ingest']);
  return s;
}

test('PostgreSQL identity: migration 010 upgrades a database at 009; forced RLS on the new tables; checks refuse malformed rows', { skip }, async () => {
  const name = await schema();
  const dir = mkdtempSync(join(tmpdir(), 'akac-at-009-'));
  try {
    cpSync(MIGRATIONS, dir, { recursive: true });
    for (const f of readdirSync(dir)) if (/^01\d_/.test(f)) rmSync(join(dir, f));
    const first = await migrate(url!, { schema: name, directory: dir });
    assert.ok(first.includes('009_shared_limits') && !first.some(v => v.startsWith('010')));
    assert.ok((await migrate(url!, { schema: name })).includes('010_identity_authority'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
  const store = new PostgresStore(url!, { schema: name, migrate: false });
  try {
    await importState(store, state());
    // An entry without the new members stays byte-identical to a 0.5 entry, next to one with them.
    await new Engine(store).openContext(bindings.chief, ['handbook'], 'work');
    await new Engine(store).openContext(attachActorChain({ ...bindings.chief }, ['spiffe://example.test/agent/chief', 'orchestrator-7']), ['handbook'], 'work');
    const log = await store.auditLog('acme');
    assert.equal(Object.hasOwn(log[0]!, 'actorChain'), false);
    assert.deepEqual(log[1]!.actorChain, ['spiffe://example.test/agent/chief', 'orchestrator-7']);
    assert.ok(verifyAudit(log)); assert.equal(await store.ready('acme'), true);
  } finally { await store.close(); }
  await owner(async c => {
    for (const table of ['akac_risk_signals', 'akac_tenant_settings', 'akac_approvals']) {
      const t = (await c.query(`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = '${name}.${table}'::regclass`)).rows[0];
      assert.equal(t.relrowsecurity, true, table); assert.equal(t.relforcerowsecurity, true, table);
    }
    await assert.rejects(c.query(`INSERT INTO ${name}.akac_grants (id, tenant, subject, agent, actions, resources, purposes, not_before, expires_at, active, break_glass)
      VALUES ('bg', 'acme', 'chief', 'chief-agent', ARRAY['read','derive'], ARRAY['handbook'], ARRAY['x'], 0, 1000, true, true)`), /check/i, 'break-glass is read-only');
    await assert.rejects(c.query(`INSERT INTO ${name}.akac_grants (id, tenant, subject, agent, actions, resources, purposes, not_before, expires_at, active, break_glass)
      VALUES ('bg', 'acme', 'chief', 'chief-agent', ARRAY['read'], ARRAY['*'], ARRAY['x'], 0, 1000, true, true)`), /check/i, 'named resources');
    await assert.rejects(c.query(`INSERT INTO ${name}.akac_approvals (id, tenant, class, operation, requester, payload, digest, approvers, required, external, created_at, expires_at, status)
      VALUES ('a', 'acme', 'break_glass', 'issue_break_glass', 'sec', '[]', '${'0'.repeat(64)}', ARRAY['sec'], 2, false, 1, 2, 'pending')`), /check/i, 'the requester never approves');
    await assert.rejects(c.query(`INSERT INTO ${name}.akac_risk_signals (id, tenant, principal, level, source, issued_at, expires_at)
      VALUES ('${'a'.repeat(64)}', 'acme', 'chief', 'severe', 'risk-1', 1, 2)`), /check/i, 'closed levels');
  });
});

test('PostgreSQL identity as the RLS runtime role: heartbeats, break-glass with approval, risk caps and tenant isolation', { skip }, async () => {
  const name = await schema();
  const seeder = new PostgresStore(url!, { schema: name });
  try { await importState(seeder, state()); } finally { await seeder.close(); }
  const app = await appAccess(name);
  const store = new PostgresStore(app, { schema: name, migrate: false, requireRls: true });
  try {
    await store.verify();
    let now = Date.now();
    const clock = () => now;
    const control = new ControlPlane(store, { clock }), engine = new Engine(store, { clock });
    const can = async (grant: string, id: string, purpose = 'work', b = bindings.chief) => (await engine.evaluate({ ...b, grant }, id, 'read', purpose)).decision;
    // Heartbeat-bound grant and a child; the parent lapses and takes the child with it.
    const g = { id: 'hb', tenant: 'acme', subject: 'chief', agent: 'chief-agent', actions: ['read' as const], resources: ['*'], purposes: ['work'],
      notBefore: now - 1000, expiresAt: now + 3_600_000, active: true, heartbeatTtlMs: 10_000 };
    assert.ok((await control.issueGrant('acme', 'sec', g)).ok);
    assert.ok((await control.issueGrant('acme', 'sec', { ...g, id: 'hb-c', parent: 'hb', heartbeatTtlMs: 5_000, expiresAt: now + 60_000 })).ok);
    assert.equal(await can('hb-c', 'handbook'), true);
    now += 4_000; assert.ok((await control.heartbeat('acme', 'runtime-1', 'hb-c')).ok);
    now += 7_000;
    assert.equal(await can('hb', 'handbook'), false);
    assert.equal(await can('hb-c', 'handbook'), false, 'the lapsed parent invalidates the child');
    assert.equal((await control.heartbeat('acme', 'runtime-1', 'hb')).ok, false);
    // Break-glass through the approval store.
    const req = await control.issueBreakGlass('acme', 'sec', { id: 'bg-1', subject: 'intern', agent: 'intern-agent', resources: ['strategy', 'handbook'], purposes: ['incident'], ttlMs: 600_000 });
    assert.equal(!req.ok && req.code, 'APPROVAL_REQUIRED');
    const approval = !req.ok ? req.approval! : '';
    const listed = await control.listApprovals('acme', 'sec');
    assert.ok(listed.ok && listed.value.length === 1 && listed.value[0]!.id === approval);
    assert.equal((await control.approve('acme', 'sec', approval)).ok, false);
    const done = await control.approve('acme', 'sec2', approval);
    assert.ok(done.ok && done.value.execution?.ok && done.value.approval.status === 'executed');
    assert.equal(await can('bg-1', 'handbook', 'incident', bindings.intern), true);
    assert.equal(await can('bg-1', 'strategy', 'incident', bindings.intern), false, 'clearance still applies');
    // Risk signal from a connector caps the next decision.
    assert.equal(await can('chief-run', 'strategy'), true);
    assert.ok((await control.putRiskSignal('acme', 'risk-1', { principal: 'chief', level: 'high' })).ok);
    assert.equal(await can('chief-run', 'strategy'), false);
    assert.equal(await can('chief-run', 'handbook'), true);
    assert.ok((await control.putSettings('acme', 'sec', { id: 'acme', tenant: 'acme', riskCaps: { high: 'public' } })).ok);
    const read = await control.readSettings('acme', 'aud');
    assert.ok(read.ok && (read.value as { riskCaps: Record<string, string> }).riskCaps.high === 'public');
    const log = await store.auditLog('acme');
    assert.ok(log.filter(e => e.breakGlass).length >= 4);
    assert.ok(log.some(e => e.reasonCode === 'RISK_CAP'));
    assert.ok(verifyAudit(log)); assert.equal(await store.ready('acme'), true);
    // Another tenant never sees the rows.
    const other = await control.approve('other', 'other-sec', approval);
    assert.equal(!other.ok && other.code, 'CONFLICT');
    const client = new pg.Client({ connectionString: app }); await client.connect();
    try {
      await client.query(`SET search_path=${name}`);
      for (const table of ['akac_risk_signals', 'akac_tenant_settings', 'akac_approvals']) {
        assert.equal((await client.query(`SELECT 1 FROM ${table}`)).rowCount, 0, `${table}: no tenant set, no rows`);
      }
      await client.query('BEGIN'); await client.query("SELECT set_config('akac.tenant', 'other', true)");
      assert.equal((await client.query('SELECT 1 FROM akac_approvals')).rowCount, 0);
      await assert.rejects(client.query(`INSERT INTO akac_risk_signals (id, tenant, principal, level, source, issued_at, expires_at) VALUES ('${'b'.repeat(64)}', 'acme', 'chief', 'none', 'x', 1, 2)`), /row-level security/);
      await client.query('ROLLBACK');
    } finally { await client.end(); }
  } finally { await store.close(); }
});
