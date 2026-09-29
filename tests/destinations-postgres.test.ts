// PostgreSQL versions of the destination profile cases (0.4, ADR-008), run as a
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
import type { Binding, State, Store } from '../reference/types.ts';
import { bindings } from '../examples/fixture.ts';
import { destination, destinationWorld, now } from './destinations-fixture.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url;
const APP_ROLE = 'akac_destinations_app_test', APP_PASSWORD = 'synthetic_rls_only_' + randomBytes(8).toString('hex');
const schemas: string[] = [];
async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
async function schema(): Promise<string> {
  const name = `akac_d_${randomBytes(6).toString('hex')}`; schemas.push(name);
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
async function seeded(state: State = destinationWorld()): Promise<{ name: string; store: PostgresStore; app: string }> {
  const name = await schema();
  const seeder = new PostgresStore(url!, { schema: name });
  try { await importState(seeder, state); } finally { await seeder.close(); }
  const app = await appAccess(name);
  return { name, app, store: new PostgresStore(app, { schema: name, migrate: false, requireRls: true }) };
}
let runs = 0;
async function share(store: Store, ids: string[], recipient: string): Promise<boolean> {
  const grant = `run-${++runs}`;
  await store.transaction('acme', async tx => { await tx.load({ grants: ['chief-run'] }); tx.state.grants[grant] = { ...structuredClone(tx.state.grants['chief-run']!), id: grant }; });
  const engine = new Engine(store, { clock: () => now }), b: Binding = { ...bindings.chief, grant };
  const context = await engine.openContext(b, ids, 'work');
  return context.ok && (await engine.release(b, context.value.context, recipient, 'Synthetic answer')).ok;
}

test('PostgreSQL destinations: migration 006 upgrades a database at 005 and 007; existing rows keep 0.3 behaviour; forced RLS', { skip }, async () => {
  const name = await schema();
  const dir = mkdtempSync(join(tmpdir(), 'akac-at-007-'));
  try {
    cpSync(MIGRATIONS, dir, { recursive: true });
    // 011 (knowledge semantics) builds on 006, so a database without 006 cannot have it either.
    for (const f of readdirSync(dir)) if (f.startsWith('006') || f >= '011') rmSync(join(dir, f));
    const first = await migrate(url!, { schema: name, directory: dir });
    assert.ok(first.includes('005_knowledge_lifecycle') && first.includes('007_token_binding') && !first.some(v => v.startsWith('006')));
  } finally { rmSync(dir, { recursive: true }); }
  // A row written before 006 (no destination columns yet).
  await owner(c => c.query(`INSERT INTO ${name}.akac_actors (id, tenant, kind, roles, projects, clearance, active) VALUES ('legacy-svc', 'acme', 'service', '{staff}', '{}', 'restricted', true)`));
  assert.deepEqual(await migrate(url!, { schema: name }), ['006_destinations', '011_knowledge_semantics']);
  const store = new PostgresStore(await appAccess(name), { schema: name, migrate: false, requireRls: true });
  try {
    await store.verify();
    assert.ok(await store.ready());
    const legacy = await store.transaction('acme', async tx => { await tx.load({ actors: ['legacy-svc'] }); return structuredClone(tx.state.actors['legacy-svc']); });
    assert.equal(legacy!.destination, undefined, 'existing rows have no profile');
  } finally { await store.close(); }
  await owner(async c => {
    const t = (await c.query(`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = '${name}.akac_destinations'::regclass`)).rows[0];
    assert.deepEqual(t, { relrowsecurity: true, relforcerowsecurity: true });
    await assert.rejects(c.query(`INSERT INTO ${name}.akac_destinations (id, tenant, class, max_classification, purposes, active) VALUES ('tool', 'acme', 'tool', 'public', '{}', true)`), /check/i,
      'a profile id is never a class name');
    await assert.rejects(c.query(`INSERT INTO ${name}.akac_destinations (id, tenant, class, max_classification, purposes, active) VALUES ('p', 'acme', 'partner', 'public', '{}', true)`), /check/i);
    await assert.rejects(c.query(`INSERT INTO ${name}.akac_grants (id, tenant, subject, agent, actions, resources, purposes, not_before, expires_at, active, max_results)
      VALUES ('g', 'acme', 's', 'a', '{read}', '{*}', '{work}', 0, 1, true, 0)`), /check/i);
  });
});

test('PostgreSQL destinations: fresh schema, control plane, release gate and round trip as the RLS-bound runtime role', { skip }, async () => {
  const { store } = await seeded(destinationWorld(s => { s.grants['chief-run']!.maxResults = 2; }));
  const control = new ControlPlane(store, { clock: () => now });
  try {
    await store.verify();
    assert.ok(await share(store, ['project-alpha'], 'llm'));
    assert.equal(await share(store, ['strategy'], 'llm'), false, 'restricted content above the provider profile');
    assert.equal(await share(store, ['handbook'], 'xt'), false, 'a profile of another tenant is invisible under RLS');
    assert.ok((await control.upsertDestination('acme', 'sec', { ...destination('eu-llm', 'model-provider', 'restricted') })).ok);
    assert.ok(await share(store, ['strategy'], 'llm'), 'the updated profile applies');
    assert.ok((await control.upsertDestination('acme', 'sec', { ...destination('eu-llm', 'model-provider', 'restricted'), active: false })).ok);
    assert.equal(await share(store, ['handbook'], 'llm'), false, 'inactive');
    assert.equal((await control.upsertDestination('acme', 'sec', destination('crm-tool', 'tool', 'internal', ['work'], 'other'))).ok, false);
    const read = await control.readDestination('acme', 'sec', 'crm-tool');
    assert.ok(read.ok); assert.deepEqual(read.value, destination('crm-tool', 'tool', 'internal'));
    const theirs = await control.readDestination('other', 'other-sec', 'crm-tool');
    assert.ok(theirs.ok); assert.equal(theirs.value, null);
    // Grant columns round-trip; the run limit applies.
    const fresh = { ...structuredClone(destinationWorld().grants['chief-run']!), id: 'pg-run', destinations: ['internal-user', 'eu-llm'], maxResults: 3 };
    assert.ok((await control.issueGrant('acme', 'sec', fresh)).ok);
    const stored = await store.transaction('acme', async tx => { await tx.load({ grants: ['pg-run'] }); return structuredClone(tx.state.grants['pg-run']); });
    assert.deepEqual(stored, fresh);
    const engine = new Engine(store, { clock: () => now });
    assert.equal((await engine.openContext(bindings.chief, ['handbook', 'strategy', 'project-alpha'], 'work')).ok, false, 'maxResults 2');
    assert.ok(await store.ready('acme'));
  } finally { await store.close(); }
});

test('PostgreSQL destinations: row-level security isolates profiles by tenant', { skip }, async () => {
  const { name, store, app } = await seeded();
  await store.close();
  const client = new pg.Client({ connectionString: app }); await client.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL search_path = ${name}`);
    assert.equal((await client.query('SELECT id FROM akac_destinations')).rowCount, 0, 'no tenant set: no rows');
    await client.query("SELECT set_config('akac.tenant', 'other', true)");
    assert.deepEqual((await client.query('SELECT id FROM akac_destinations ORDER BY id')).rows.map(r => r.id), ['other-dest']);
    await assert.rejects(client.query(`INSERT INTO akac_destinations (id, tenant, class, max_classification, purposes, active) VALUES ('x', 'acme', 'tool', 'public', '{}', true)`),
      /row-level security/);
  } finally { await client.query('ROLLBACK').catch(() => {}); await client.end(); }
});
