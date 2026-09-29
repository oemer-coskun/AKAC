// PostgreSQL versions of the runtime containment cases (0.5 draft, ADR-012), run as a
// runtime role subject to forced row-level security. Skipped without AKAC_TEST_DATABASE_URL.
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
import type { RuntimeProfilePolicy, State } from '../reference/types.ts';
import { bindings } from '../examples/fixture.ts';
import { world } from './support.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url;
const APP_ROLE = 'akac_runtime_app_test', APP_PASSWORD = 'synthetic_rls_only_' + randomBytes(8).toString('hex');
const schemas: string[] = [];
async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
async function schema(): Promise<string> {
  const name = `akac_r_${randomBytes(6).toString('hex')}`; schemas.push(name);
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
const policy = (id: string, classification: RuntimeProfilePolicy['classification'], profiles: RuntimeProfilePolicy['profiles'], extra: Partial<RuntimeProfilePolicy> = {}): RuntimeProfilePolicy =>
  ({ id, tenant: 'acme', classification, ...extra, profiles, active: true });
function contained(): State {
  const s = world();
  s.runtimeProfiles = { 'rt-restricted': policy('rt-restricted', 'restricted', { network: 'deny-all', credential: 'none' }),
    'rt-llm': policy('rt-llm', 'confidential', { filesystem: 'read-only-workspace' }, { destinationClass: 'model-provider' }),
    'other-rt': { ...policy('other-rt', 'public', { network: 'internal-only' }), tenant: 'other' } };
  return s;
}

test('PostgreSQL runtime profiles: migration 008 upgrades a database at 007; entries with and without the new members verify; forced RLS and checks', { skip }, async () => {
  const name = await schema();
  const dir = mkdtempSync(join(tmpdir(), 'akac-at-007-'));
  try {
    cpSync(MIGRATIONS, dir, { recursive: true });
    for (const f of readdirSync(dir)) if (f.startsWith('008')) rmSync(join(dir, f));
    const first = await migrate(url!, { schema: name, directory: dir });
    assert.ok(first.includes('007_token_binding') && !first.some(v => v.startsWith('008')));
    assert.deepEqual(await migrate(url!, { schema: name }), ['008_runtime_profiles']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
  const store = new PostgresStore(url!, { schema: name, migrate: false });
  try {
    // An entry without the new members (NULL columns) is byte-identical to a 0.4 entry and stays verifiable next to one with them.
    await importState(store, world());
    await new Engine(store).openContext(bindings.chief, ['strategy'], 'work');
    await new Engine(store).openContext(bindings.chief, ['strategy'], 'work', { trace: { executionId: 'job-1' } });
    const log = await store.auditLog('acme');
    assert.equal(log.length, 2); assert.equal(Object.hasOwn(log[0]!, 'executionId'), false); assert.equal(log[1]!.executionId, 'job-1');
    assert.ok(verifyAudit(log));
    assert.equal(await store.ready('acme'), true, 'the audit tail and Merkle leaves verify against the stored nodes');
  } finally { await store.close(); }
  await owner(async c => {
    const t = (await c.query(`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = '${name}.akac_runtime_profiles'::regclass`)).rows[0];
    assert.equal(t.relrowsecurity, true); assert.equal(t.relforcerowsecurity, true);
    await assert.rejects(c.query(`INSERT INTO ${name}.akac_runtime_profiles (id, tenant, classification, active) VALUES ('p', 'acme', 'public', true)`), /check/i, 'at least one profile');
    await assert.rejects(c.query(`INSERT INTO ${name}.akac_runtime_profiles (id, tenant, classification, profile_network, active) VALUES ('p', 'acme', 'public', 'allow all', true)`), /check/i, 'profile ids only');
    await assert.rejects(c.query(`INSERT INTO ${name}.akac_runtime_profiles (id, tenant, classification, destination_class, profile_tool, active) VALUES ('p', 'acme', 'public', 'partner', 'x', true)`), /check/i);
  });
});

test('PostgreSQL runtime profiles as the RLS runtime role: derivation, administration, evidence correlation, tenant isolation', { skip }, async () => {
  const name = await schema();
  const seeder = new PostgresStore(url!, { schema: name });
  try { await importState(seeder, contained()); } finally { await seeder.close(); }
  const app = await appAccess(name);
  const store = new PostgresStore(app, { schema: name, migrate: false, requireRls: true });
  try {
    const engine = new Engine(store), control = new ControlPlane(store);
    const context = await engine.openContext(bindings.chief, ['strategy'], 'work', { trace: { executionId: 'job-9', runtimeRevision: 'rev-3' } });
    assert.ok(context.ok);
    assert.deepEqual(context.obligations.filter(o => o.type === 'runtime_profile' || o.type === 'max_output_classification'), [
      { type: 'runtime_profile', domain: 'network', profile: 'deny-all' }, { type: 'runtime_profile', domain: 'credential', profile: 'none' },
      { type: 'max_output_classification', value: 'restricted' }], 'another tenant\'s policy never applies; the narrowed one does not apply to a read');
    const read = await control.readRuntimeProfile('acme', 'aud', 'rt-llm');
    assert.ok(read.ok); assert.deepEqual(read.value, contained().runtimeProfiles!['rt-llm']);
    assert.ok((await control.readRuntimeProfile('acme', 'aud', 'other-rt')).ok && (await control.readRuntimeProfile('acme', 'aud', 'other-rt') as { value: unknown }).value === null);
    const updated = await control.traced({ executionId: 'change-1' }).upsertRuntimeProfile('acme', 'sec', policy('rt-restricted', 'restricted', { network: 'internal-only', tool: 'read-only-http' }));
    assert.ok(updated.ok);
    const again = await control.readRuntimeProfile('acme', 'sec', 'rt-restricted');
    assert.ok(again.ok); assert.deepEqual(again.value, policy('rt-restricted', 'restricted', { network: 'internal-only', tool: 'read-only-http' }), 'a removed domain reads back absent');
    const stale = await engine.derive(bindings.chief, context.value.context, 'Synthetic note');
    assert.equal(stale.ok, false, 'the change advanced the epoch');
    const log = await store.auditLog('acme');
    assert.ok(log.some(e => e.operation === 'read' && e.executionId === 'job-9' && e.runtimeRevision === 'rev-3'));
    assert.ok(log.some(e => e.operation === 'upsert_runtime_profile' && e.executionId === 'change-1'));
    assert.ok(verifyAudit(log)); assert.equal(await store.ready('acme'), true);
    await owner(async c => {
      const client = new pg.Client({ connectionString: app }); await client.connect();
      try {
        await client.query(`SET search_path=${name}`);
        assert.equal((await client.query('SELECT id FROM akac_runtime_profiles')).rowCount, 0, 'no tenant set: no rows');
        await client.query('BEGIN'); await client.query("SELECT set_config('akac.tenant', 'acme', true)");
        assert.deepEqual((await client.query('SELECT id FROM akac_runtime_profiles ORDER BY id')).rows.map(r => r.id), ['rt-llm', 'rt-restricted']);
        await client.query('ROLLBACK');
      } finally { await client.end(); }
      void c;
    });
  } finally { await store.close(); }
});
