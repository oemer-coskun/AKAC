// PostgreSQL versions of the key knowledge lifecycle cases (0.4, ADR-007), run as a
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
import { bindings } from '../examples/fixture.ts';
import type { Knowledge, State, Store } from '../reference/types.ts';
import { derived, LINEAGE, lifecycleWorld, now } from './lifecycle-fixture.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url;
const APP_ROLE = 'akac_lifecycle_app_test', APP_PASSWORD = 'synthetic_rls_only_' + randomBytes(8).toString('hex');
const schemas: string[] = [];
async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
async function schema(): Promise<string> {
  const name = `akac_l_${randomBytes(6).toString('hex')}`; schemas.push(name);
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
/** Migrated, seeded schema and a store connected as the RLS-bound runtime role. */
async function seeded(state: State = lifecycleWorld()): Promise<{ name: string; store: PostgresStore }> {
  const name = await schema();
  const seeder = new PostgresStore(url!, { schema: name });
  try { await importState(seeder, state); } finally { await seeder.close(); }
  return { name, store: new PostgresStore(await appAccess(name), { schema: name, migrate: false, requireRls: true }) };
}
let runs = 0;
async function readable(store: Store, id: string): Promise<boolean> {
  const grant = `run-${++runs}`;
  await store.transaction('acme', async tx => { await tx.load({ grants: ['chief-run'] }); tx.state.grants[grant] = { ...structuredClone(tx.state.grants['chief-run']!), id: grant }; });
  return (await new Engine(store, { clock: () => now }).openContext({ ...bindings.chief, grant }, [id], 'work')).ok;
}
const row = (store: Store, id: string, tenant = 'acme') => store.transaction(tenant, async tx => { await tx.load({ knowledge: [id] }); return structuredClone(tx.state.knowledge[id]) as Knowledge | undefined; });
const code = (r: { ok: boolean; code?: string }) => r.ok ? 'OK' : r.code;

test('PostgreSQL lifecycle: migration 005 upgrades a database at 004 and 007 and keeps forced RLS', { skip }, async () => {
  const name = await schema();
  const dir = mkdtempSync(join(tmpdir(), 'akac-at-007-'));
  try {
    cpSync(MIGRATIONS, dir, { recursive: true });
    for (const f of readdirSync(dir)) if (f.startsWith('005') || f.startsWith('006')) rmSync(join(dir, f));
    const first = await migrate(url!, { schema: name, directory: dir });
    assert.ok(first.includes('004_audit_evidence') && first.includes('007_token_binding') && !first.some(v => v.startsWith('005')));
  } finally { rmSync(dir, { recursive: true }); }
  await owner(c => c.query(`INSERT INTO ${name}.akac_knowledge (id, tenant, version, kind, origin, content, classification, projects, reader_roles, readers, sources, active)
    VALUES ('legacy', 'acme', 1, 'artifact', 'model', 'Legacy synthetic.', 'public', '{}', '{staff}', '{}', '[{"id":"handbook","version":1}]', true)`));
  assert.ok((await migrate(url!, { schema: name })).includes('005_knowledge_lifecycle'));
  const store = new PostgresStore(await appAccess(name), { schema: name, migrate: false, requireRls: true });
  try {
    await store.verify();
    assert.ok(await store.ready());
    const legacy = await row(store, 'legacy');
    assert.equal(legacy!.lifecycle, undefined, 'existing rows keep 0.3 behavior');
    assert.deepEqual(await store.transaction('acme', async tx => (await tx.descendants!(['handbook'], 10)).records.map(r => r.id)), ['legacy'], 'existing rows are traversable without backfill');
  } finally { await store.close(); }
  await owner(async c => {
    await assert.rejects(c.query(`UPDATE ${name}.akac_knowledge SET lifecycle='erased', active=false WHERE id='legacy'`), /akac_knowledge_tombstone/, 'an erased row must hold no content');
    await assert.rejects(c.query(`UPDATE ${name}.akac_knowledge SET lifecycle='deleted' WHERE id='legacy'`), /check/i);
  });
});

test('PostgreSQL lifecycle: quarantine hides the lineage, release (security-admin only) restores it', { skip }, async () => {
  const { store } = await seeded();
  const control = new ControlPlane(store, { clock: () => now });
  try {
    assert.ok(await readable(store, 'c'));
    assert.ok((await control.quarantine('acme', 'kbadm', 'handbook', 'suspected_poisoning')).ok);
    for (const id of ['handbook', ...LINEAGE]) assert.equal(await readable(store, id), false, id);
    assert.equal(code(await control.release('acme', 'kbadm', 'handbook')), 'NOT_AUTHORIZED');
    assert.ok((await control.release('acme', 'sec', 'handbook')).ok);
    for (const id of ['handbook', ...LINEAGE]) assert.ok(await readable(store, id), id);
    assert.ok(await store.ready('acme'));
  } finally { await store.close(); }
});

test('PostgreSQL lifecycle: descendants via recursive SQL match the in-memory traversal and are bounded', { skip }, async () => {
  const { store } = await seeded(lifecycleWorld(s => {
    for (let i = 0; i < 140; i++) s.knowledge[`deep-${i}`] = derived(`deep-${i}`, [i ? `deep-${i - 1}` : 'staff-faq']);
    s.knowledge['o-child'] = derived('o-child', ['handbook'], 'other');
  }));
  const control = new ControlPlane(store, { clock: () => now });
  try {
    const all = await control.descendants('acme', 'aud', 'handbook');
    assert.ok(all.ok); assert.deepEqual(all.value.records.map(r => r.id), LINEAGE, 'the other tenant\'s o-child is invisible');
    assert.equal(all.value.truncated, false);
    const two = await control.descendants('acme', 'aud', 'handbook', { limit: 2 });
    assert.ok(two.ok); assert.deepEqual(two.value.records.map(r => r.id), ['a', 'b']); assert.equal(two.value.truncated, true);
    const deep = await control.descendants('acme', 'aud', 'staff-faq', { limit: 1000 });
    assert.ok(deep.ok); assert.equal(deep.value.truncated, true);
    assert.equal(code(await control.descendants('acme', 'aud', 'o-doc')), 'INVALID_REQUEST');
    const theirs = await control.descendants('other', 'other-sec', 'handbook');
    assert.equal(code(theirs), 'INVALID_REQUEST');
  } finally { await store.close(); }
});

test('PostgreSQL lifecycle: legal hold blocks erasure; erase cascades, tombstones and is idempotent; revokeLineage; retention', { skip }, async () => {
  const { store } = await seeded(lifecycleWorld(s => { s.knowledge['vault-memo']!.retainUntil = now - 1; s.knowledge['board-notes']!.retainUntil = now - 1; s.knowledge['board-notes']!.legalHolds = ['m9']; }));
  const control = new ControlPlane(store, { clock: () => now });
  try {
    assert.ok((await control.setLegalHold('acme', 'sec', 'd2', true, 'matter-1')).ok);
    const blocked = await control.erase('acme', 'sec', 'handbook');
    assert.ok(!blocked.ok); assert.equal(blocked.code, 'CONFLICT'); assert.equal(blocked.held, 1);
    assert.deepEqual((await row(store, 'd2'))!.legalHolds, ['matter-1']);
    assert.ok((await control.setLegalHold('acme', 'sec', 'd2', false, 'matter-1')).ok);
    assert.equal((await row(store, 'd2'))!.legalHolds, undefined);
    const erased = await control.erase('acme', 'sec', 'handbook');
    assert.ok(erased.ok); assert.equal(erased.value.erased, 6);
    for (const id of ['handbook', ...LINEAGE]) {
      const k = (await row(store, id))!;
      assert.equal(k.content, ''); assert.equal(k.lifecycle, 'erased'); assert.equal(await readable(store, id), false, id);
    }
    assert.equal((await control.erase('acme', 'sec', 'handbook')).ok, true);
    assert.equal((await row(store, 'o-doc', 'other'))!.content, 'Other tenant synthetic notes.');
    const revoked = await control.revokeLineage('acme', 'sec', 'staff-faq');
    assert.ok(revoked.ok); assert.equal(revoked.value.revoked, 1);
    const retention = await control.applyRetention('acme', 'sec', now);
    assert.ok(retention.ok); assert.equal(retention.value.erased, 1, 'vault-memo; board-notes is held');
    assert.equal((await row(store, 'vault-memo'))!.content, '');
    assert.equal((await row(store, 'board-notes'))!.lifecycle, undefined);
    assert.ok(await store.ready('acme'));
  } finally { await store.close(); }
});
