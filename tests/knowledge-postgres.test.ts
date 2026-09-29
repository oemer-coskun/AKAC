// PostgreSQL versions of the knowledge semantics (0.6, ADR-022, migration 011), run as a runtime role subject
// to forced row-level security. Skipped without AKAC_TEST_DATABASE_URL.
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
import { Sweeper } from '../reference/sweeper.ts';
import { importState } from '../reference/store.ts';
import { EncryptingStore, LocalDevKeyProvider, isEnvelope } from '../reference/content-crypto.ts';
import type { Knowledge, State } from '../reference/types.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url;
const APP_ROLE = 'akac_knowledge_app_test', APP_PASSWORD = 'synthetic_rls_only_' + randomBytes(8).toString('hex');
const NOW = Date.now();
const schemas: string[] = [];
async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
async function schema(): Promise<string> {
  const name = `akac_k_${randomBytes(6).toString('hex')}`; schemas.push(name);
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
const mem = (id: string, sources: string[], extra: Partial<Knowledge> = {}): Knowledge => ({ id, tenant: 'acme', version: 1, kind: 'memory', origin: 'model',
  content: `Synthetic ${id}.`, classification: 'public', projects: [], readerRoles: ['staff'], readers: [], sources: sources.map(s => ({ id: s, version: 1 })), active: true, ...extra });
function state(): State {
  const s = kbFixture(NOW);
  const admin = (id: string, roles: string[]) => { s.actors[id] = { id, tenant: 'acme', kind: 'user', roles, projects: [], clearance: 'restricted', active: true }; };
  admin('sec', ['security-admin']); admin('kbadm', ['kb-admin']);
  s.knowledge.handbook = { ...s.knowledge.handbook!, tags: ['fin'], residency: ['DE'], modality: 'text' };
  s.containers['kb-corporate'] = { ...s.containers['kb-corporate']!, tags: ['audit'], residency: ['DE', 'FR'] };
  s.knowledge.m1 = mem('m1', ['handbook'], { model: { id: 'm-x', version: '1.2' } });
  s.knowledge.m2 = mem('m2', ['m1']);
  s.destinations = { 'd-de': { id: 'd-de', tenant: 'acme', class: 'internal-user', maxClassification: 'restricted', purposes: ['work'], active: true, region: 'DE' } };
  s.settings = { acme: { id: 'acme', tenant: 'acme', lineageDepth: 3 } };
  s.combinationRules = { wall: { id: 'wall', tenant: 'acme', tagsA: ['fin'], tagsB: ['audit'], effect: 'deny', active: true } };
  return s;
}

test('PostgreSQL knowledge: migration 011 upgrades a database at 010; forced RLS on combination rules; checks refuse malformed rows', { skip }, async () => {
  const name = await schema();
  const dir = mkdtempSync(join(tmpdir(), 'akac-at-010-'));
  try {
    cpSync(MIGRATIONS, dir, { recursive: true });
    for (const f of readdirSync(dir)) if (/^01[1-9]_/.test(f)) rmSync(join(dir, f));
    const first = await migrate(url!, { schema: name, directory: dir });
    assert.ok(first.includes('010_identity_authority') && !first.some(v => v.startsWith('011')));
    assert.ok((await migrate(url!, { schema: name })).includes('011_knowledge_semantics'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
  await owner(async c => {
    const t = (await c.query(`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname='akac_combination_rules' AND relnamespace=$1::regnamespace`, [name])).rows[0];
    assert.equal(t.relrowsecurity, true); assert.equal(t.relforcerowsecurity, true);
    await c.query(`SET search_path=${name}`);
    await assert.rejects(c.query(`INSERT INTO akac_combination_rules (id, tenant, tags_a, tags_b, effect, uplift_to, active) VALUES ('r', 'acme', '{a}', '{b}', 'deny', 'restricted', true)`));
    await assert.rejects(c.query(`INSERT INTO akac_combination_rules (id, tenant, tags_a, tags_b, effect, active) VALUES ('r', 'acme', '{}', '{b}', 'deny', true)`));
    await assert.rejects(c.query(`INSERT INTO akac_destinations (id, tenant, class, max_classification, purposes, active, region) VALUES ('d', 'acme', 'tool', 'public', '{}', true, 'de')`));
    await assert.rejects(c.query(`INSERT INTO akac_tenant_settings (id, tenant, lineage_depth) VALUES ('acme', 'acme', 200)`));
    await assert.rejects(c.query(`INSERT INTO akac_knowledge (id, tenant, version, kind, origin, content, classification, projects, reader_roles, readers, sources, active, quarantine_reason, lifecycle)
      VALUES ('k', 'acme', 1, 'document', 'system', 'x', 'public', '{}', '{}', '{}', '[]', true, 'bogus', 'quarantined')`));
    await c.query(`SELECT set_config('akac.tenant', 'acme', false)`);
    await c.query(`INSERT INTO akac_knowledge (id, tenant, version, kind, origin, content, classification, projects, reader_roles, readers, sources, active, quarantine_reason, lifecycle)
      VALUES ('k', 'acme', 1, 'document', 'system', 'x', 'public', '{}', '{}', '{}', '[]', true, 'poisoned', 'quarantined')`);
  });
});

test('PostgreSQL knowledge: attributes round-trip, rules and settings load with every decision, session records never reach the database', { skip }, async () => {
  const name = await schema();
  await migrate(url!, { schema: name });
  const store = new PostgresStore(await appAccess(name), { schema: name, migrate: false, requireRls: true });
  try {
    await importState(store, state());
    const engine = new Engine(store, { clock: () => NOW, model: { id: 'm-y', version: '2' } });
    // The combination rule is loaded: handbook (fin) with staff-faq (audit, from its container) is refused.
    assert.equal((await engine.openContext(bindings.chief, ['handbook', 'staff-faq'], 'work')).ok, false);
    assert.equal((await store.auditLog('acme')).at(-1)!.reasonCode, 'COMBINATION');
    const ctx = await engine.openContext(bindings.chief, ['m2'], 'work');
    assert.ok(ctx.ok);
    // Depth limit 3 from the settings row: m2 is generation 2, its derivation 3.
    const d = await engine.derive(bindings.chief, ctx.value.context, 'Synthetic derived.', 'memory', undefined, { modality: 'table' });
    assert.ok(d.ok);
    const stored = await store.transaction('acme', async tx => { await tx.load({ knowledge: [d.value.id] }); return structuredClone(tx.state.knowledge[d.value.id]!); });
    assert.deepEqual(stored.tags, ['fin']); assert.deepEqual(stored.residency, ['DE']); assert.equal(stored.modality, 'table'); assert.deepEqual(stored.model, { id: 'm-y', version: '2' });
    // Session-scoped: visible to the run, absent from the database.
    const e = await engine.derive(bindings.chief, ctx.value.context, 'Session note.', 'memory', undefined, { session: { id: 's1' } });
    assert.ok(e.ok);
    assert.equal(await owner(async c => (await c.query(`SELECT count(*)::int AS n FROM ${name}.akac_knowledge WHERE id=$1`, [e.value.id])).rows[0].n), 0);
    const again = await engine.openContext(bindings.chief, [d.value.id], 'work');
    assert.ok(again.ok);
    assert.equal((await engine.derive(bindings.chief, again.value.context, 'Too deep.', 'artifact')).ok, false);
    assert.equal((await store.auditLog('acme')).at(-1)!.reasonCode, 'LINEAGE_DEPTH');
    await assert.rejects(store.transaction('acme', async tx => { tx.state.knowledge.x = mem('x', [], { ephemeral: { sessionId: 's', run: 'chief-run', expiresAt: NOW + 1 } }); }));
    // Model lineage and pending erasure queries.
    const control = new ControlPlane(store, { clock: () => NOW });
    const recall = await new Sweeper({ control }).recallModel('acme', 'sec', 'm-x', { from: '1', to: '1.5' });
    assert.ok(recall.ran && recall.recalled === 1 && recall.changed >= 2);
    await control.setLegalHold('acme', 'sec', 'handbook', true, 'case-1');
    const pending = await control.erase('acme', 'sec', 'handbook');
    assert.ok(!pending.ok && pending.pending === true);
    await control.setLegalHold('acme', 'sec', 'handbook', false, 'case-1');
    const done = await control.applyPendingErasures('acme', 'sec');
    assert.ok(done.ok && done.value.erased >= 1);
    const settings = await control.readSettings('acme', 'sec');
    assert.ok(settings.ok && (settings.value as { lineageDepth: number }).lineageDepth === 3);
    assert.equal(await store.ready('acme'), true);
  } finally { await store.close(); }
});

test('PostgreSQL knowledge: content encryption keeps ciphertext at rest and reads rewrite nothing', { skip }, async () => {
  const name = await schema();
  await migrate(url!, { schema: name });
  const dir = mkdtempSync(join(tmpdir(), 'akac-keys-'));
  const inner = new PostgresStore(await appAccess(name), { schema: name, migrate: false, requireRls: true });
  const store = new EncryptingStore(inner, new LocalDevKeyProvider(join(dir, 'keys.json')));
  try {
    await importState(store, state());
    const control = new ControlPlane(store, { clock: () => NOW });
    const strategy = await store.transaction('acme', async tx => { await tx.load({ knowledge: ['strategy'] }); return structuredClone(tx.state.knowledge.strategy!); });
    assert.ok((await control.upsertKnowledge('acme', 'kbadm', { ...strategy, version: 2, content: 'Sealed strategy text.' })).ok);
    const raw = async () => owner(async c => (await c.query(`SELECT content FROM ${name}.akac_knowledge WHERE tenant='acme' AND id='strategy'`)).rows[0].content as string);
    const sealed = await raw();
    assert.ok(isEnvelope(sealed) && !sealed.includes('Sealed'));
    const ctx = await new Engine(store, { clock: () => NOW }).openContext(bindings.chief, ['strategy'], 'work');
    assert.ok(ctx.ok && ctx.value.documents[0]!.content === 'Sealed strategy text.');
    assert.equal(await raw(), sealed, 'a read rewrites nothing');
    assert.ok((await control.erase('acme', 'sec', 'strategy')).ok);
    assert.equal(await raw(), '');
  } finally { await store.close(); rmSync(dir, { recursive: true, force: true }); }
});
