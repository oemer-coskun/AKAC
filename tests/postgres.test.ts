import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { spawn } from 'node:child_process';
import { MIGRATIONS, migrate, PostgresStore } from '../adapters/postgres.ts';
import { Engine, verifyAudit } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { MemoryStore, importState } from '../reference/store.ts';
import { BudgetExceeded } from '../reference/hydrate.ts';
import { configuredStore } from '../reference/config.ts';
import { Ingestor } from '../reference/ingest.ts';
import { HashEmbedder } from '../reference/embedding.ts';
import { MemoryVectorIndex } from '../reference/vector.ts';
import { fixture, kbFixture, bindings } from '../examples/fixture.ts';
import { emptyState } from '../reference/types.ts';
import type { Actor, Binding, Need, State, Store, Tx } from '../reference/types.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url;
const now = 1800000000000;
const other: Binding = { tenant: 'other', subject: 'o-user', agent: 'o-agent', grant: 'o-run' };
const APP_ROLE = 'akac_rls_app_test', APP_PASSWORD = 'synthetic_rls_only_' + randomBytes(8).toString('hex');
const schemas: string[] = [];

function twoTenants(): State {
  const s = fixture(now);
  s.actors['o-user'] = { id: 'o-user', tenant: 'other', kind: 'user', roles: ['staff'], projects: [], clearance: 'restricted', active: true };
  s.actors['o-agent'] = { ...s.actors['o-user']!, id: 'o-agent', kind: 'agent' };
  s.grants['o-run'] = { ...s.grants['chief-run']!, id: 'o-run', tenant: 'other', subject: 'o-user', agent: 'o-agent' };
  s.actors['o-admin'] = { ...s.actors.admin!, id: 'o-admin', tenant: 'other' };
  s.knowledge['o-doc'] = { ...s.knowledge.handbook!, id: 'o-doc', tenant: 'other', content: 'Other tenant product notes.' };
  return s;
}
async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
async function schema(): Promise<string> {
  const name = `akac_t_${randomBytes(6).toString('hex')}`; schemas.push(name);
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

test('PostgreSQL: migrations are idempotent, serialized and checksum-verified', { skip }, async () => {
  const name = await schema();
  const runs = await Promise.all([1, 2, 3].map(() => migrate(url!, { schema: name })));
  assert.deepEqual(runs.flat(), ['001_normalized_schema', '002_vector_compartments', '003_tenant_scoped_keys']);
  assert.deepEqual(await migrate(url!, { schema: name }), []);
  const dir = mkdtempSync(join(tmpdir(), 'akac-migrations-'));
  try {
    cpSync(MIGRATIONS, dir, { recursive: true });
    const file = join(dir, '001_normalized_schema.sql');
    writeFileSync(file, readFileSync(file, 'utf8') + '\n-- edited after release\n');
    await assert.rejects(migrate(url!, { schema: name, directory: dir }), /checksum mismatch/);
    rmSync(file);
    await assert.rejects(migrate(url!, { schema: name, directory: dir }), /Unknown applied migration/);
  } finally { rmSync(dir, { recursive: true }); }
});

test('PostgreSQL: row-level security isolates tenants for the runtime role', { skip }, async () => {
  const name = await schema();
  const seeded = new PostgresStore(url!, { schema: name });
  const privileged = new PostgresStore(url!, { schema: name, migrate: false, requireRls: true });
  try {
    await importState(seeded, twoTenants()); assert.equal(await seeded.ready(), true);
    assert.equal(await privileged.ready(), false, 'superuser must not pass an RLS-required readiness check');
  } finally { await seeded.close(); await privileged.close(); }
  const appUrl = await appAccess(name);
  const store = new PostgresStore(appUrl, { schema: name, migrate: false, requireRls: true });
  const client = new pg.Client({ connectionString: appUrl, options: `-c search_path=${name}` }); await client.connect();
  try {
    assert.equal(await store.ready('acme'), true);
    await client.query('BEGIN');
    assert.equal((await client.query('SELECT count(*)::int AS n FROM akac_actors')).rows[0].n, 0, 'unset tenant sees nothing');
    await client.query("SELECT set_config('akac.tenant', 'acme', true)");
    assert.equal((await client.query("SELECT count(*)::int AS n FROM akac_actors WHERE tenant='other'")).rows[0].n, 0);
    assert.equal((await client.query("SELECT count(*)::int AS n FROM akac_knowledge WHERE id='o-doc'")).rows[0].n, 0);
    assert.ok((await client.query('SELECT count(*)::int AS n FROM akac_actors')).rows[0].n > 0);
    assert.equal((await client.query("UPDATE akac_actors SET active=false WHERE tenant='other'")).rowCount, 0);
    await assert.rejects(client.query("INSERT INTO akac_roles (id, tenant, inherits, active) VALUES ('forged', 'other', '{}', true)"), /row-level security/);
    await client.query('ROLLBACK');
    // The store API cannot hydrate another tenant's records either.
    const seen = await store.transaction('acme', async tx => { await tx.load({ actors: ['o-user', 'chief'], knowledge: ['o-doc'] });
      return [Object.keys(tx.state.actors), Object.keys(tx.state.knowledge)]; });
    assert.deepEqual(seen, [['chief'], []]);
    await assert.rejects(store.transaction('acme', async tx => { tx.state.actors.forged = { ...fixture(now).actors.intern!, id: 'forged', tenant: 'other' }; }), /Cross-tenant/);
    const engine = new Engine(store, { clock: () => now });
    assert.equal((await engine.openContext({ ...bindings.chief, tenant: 'other' }, ['o-doc'], 'work')).ok, false);
    assert.ok((await engine.openContext(other, ['o-doc'], 'work')).ok);
    // The runtime role cannot rewrite audit history.
    await client.query('BEGIN'); await client.query("SELECT set_config('akac.tenant', 'other', true)");
    await assert.rejects(client.query("UPDATE akac_audit SET reason='rewritten'"), /append-only/);
    await client.query('ROLLBACK');
  } finally { await client.end(); await store.close(); }
});

test('PostgreSQL: tenants run in parallel; one tenant is serialized', { skip }, async () => {
  const name = await schema();
  const store = new PostgresStore(url!, { schema: name });
  try {
    await importState(store, twoTenants());
    let open!: () => void; const gate = new Promise<void>(resolve => { open = resolve; });
    const order: string[] = [];
    const held = store.transaction('acme', async () => { order.push('acme-1 start'); await gate; order.push('acme-1 end'); });
    await new Promise(resolve => setTimeout(resolve, 100));
    const queued = store.transaction('acme', async () => { order.push('acme-2'); });
    await store.transaction('other', async () => { order.push('other'); });
    order.push('other committed');
    open(); await held; await queued;
    assert.deepEqual(order, ['acme-1 start', 'other', 'other committed', 'acme-1 end', 'acme-2']);
  } finally { await store.close(); }
});

test('PostgreSQL: persistence, rollback, per-tenant revocation and audit streams', { skip }, async () => {
  const name = await schema();
  const first = new PostgresStore(url!, { schema: name }), second = new PostgresStore(url!, { schema: name, migrate: false });
  try {
    await importState(first, twoTenants());
    const a = new Engine(first, { clock: () => now }), b = new Engine(second, { clock: () => now });
    const read = await a.openContext(bindings.chief, ['strategy'], 'work'); assert.ok(read.ok);
    const mine = await b.openContext(other, ['o-doc'], 'work'); assert.ok(mine.ok);
    assert.ok((await b.derive(bindings.chief, read.value.context, 'Across connections')).ok);
    await assert.rejects(first.transaction('acme', async tx => { await tx.load({ epoch: true }); tx.state.epochs.acme = 100; throw new Error('rollback'); }));
    assert.equal(await second.transaction('acme', async tx => { await tx.load({ epoch: true }); return tx.state.epochs.acme ?? 0; }), 0);
    const revoked = await a.revoke('acme', 'admin', 'grant', 'lead-run'); assert.ok(revoked.ok); assert.equal(revoked.value.epoch, 1);
    assert.equal((await b.derive(bindings.chief, read.value.context, 'After revocation')).ok, false, 'acme contexts invalidated');
    assert.ok((await b.derive(other, mine.value.context, 'Unaffected tenant')).ok, 'other tenant contexts survive');
    assert.equal(await second.transaction('other', async tx => { await tx.load({ epoch: true }); return tx.state.epochs.other ?? 0; }), 0);
    assert.equal((await a.revoke('other', 'admin', 'grant', 'o-run')).ok, false, 'admin of acme cannot revoke in other');
    for (const tenant of ['acme', 'other']) {
      const log = await first.auditLog(tenant);
      assert.ok(log.length > 0 && log.every(e => e.tenant === tenant) && verifyAudit(log));
      assert.equal(await second.ready(tenant), true);
    }
    await owner(c => c.query(`UPDATE ${name}.akac_audit_head SET hash=repeat('f', 64) WHERE tenant='acme'`));
    assert.equal(await second.ready('acme'), false, 'head/tail mismatch is detected');
    assert.equal(await second.ready('other'), true);
  } finally { await first.close(); await second.close(); }
});

test('PostgreSQL: hierarchy, groups, SoD and containers hydrate from normalized tables', { skip }, async () => {
  const name = await schema();
  const store = new PostgresStore(url!, { schema: name });
  try {
    const s = fixture(now);
    s.actors.admin!.roles = ['security-admin', 'kb-admin', 'auditor'];
    await importState(store, s);
    const control = new ControlPlane(store, { clock: () => now }), engine = new Engine(store, { clock: () => now });
    assert.ok((await control.upsertRole('acme', 'admin', { id: 'board', tenant: 'acme', inherits: ['executive'], active: true })).ok);
    assert.ok((await control.upsertGroup('acme', 'admin', { id: 'board-members', tenant: 'acme', members: ['lead', 'lead-agent'], roles: ['board'], active: true })).ok);
    assert.ok((await control.upsertContainer('acme', 'admin', { id: 'kb', tenant: 'acme', kind: 'knowledge-base', classification: 'internal', readerRoles: ['staff'], readers: [], projects: [], active: true })).ok);
    assert.ok((await control.upsertContainer('acme', 'admin', { id: 'secret', tenant: 'acme', kind: 'folder', parent: 'kb', classification: 'confidential', readerRoles: ['executive'], readers: [], projects: [], active: true })).ok);
    const doc = { ...s.knowledge.handbook!, id: 'minutes', content: 'Board minutes', container: 'secret' };
    assert.ok((await control.upsertKnowledge('acme', 'admin', doc)).ok);
    assert.ok((await engine.openContext(bindings.lead, ['minutes'], 'work')).ok, 'group -> board -> executive');
    assert.equal((await engine.openContext(bindings.intern, ['minutes'], 'work')).ok, false);
    const sod = { id: 'sod', tenant: 'acme', kind: 'static' as const, roles: ['project', 'board'], cardinality: 2 };
    const refused = await control.upsertConstraint('acme', 'admin', sod);
    assert.ok(!refused.ok && refused.code === 'SOD_VIOLATION' && refused.holders! >= 1, 'a constraint that current holders violate is refused with a count');
    assert.ok((await engine.openContext(bindings.lead, ['minutes'], 'work')).ok, 'the refused constraint did not apply');
    await store.transaction('acme', async tx => { tx.state.constraints.sod = sod; });
    assert.equal((await engine.openContext(bindings.lead, ['minutes'], 'work')).ok, false, 'static SoD stored out of band still denies the holder');
    assert.equal((await control.upsertRole('acme', 'admin', { id: 'executive', tenant: 'acme', inherits: ['board'], active: true })).ok, false, 'cycle rejected');
    const audit = await control.auditLog('acme', 'admin'); assert.ok(audit.ok && verifyAudit(audit.value));
  } finally { await store.close(); }
});

test('PostgreSQL: a 0.2 single-row state is imported once and preserved as legacy', { skip }, async () => {
  const name = await schema();
  const legacy = structuredClone(fixture(now)) as unknown as Record<string, unknown>;
  for (const k of Object.values(legacy.knowledge as Record<string, Record<string, unknown>>)) delete k.origin;
  for (const key of ['epochs', 'roles', 'groups', 'containers', 'constraints']) delete legacy[key];
  Object.assign(legacy, { schema: 'akac-state/0.1', policyVersion: 'akac-reference/0.2.0', epoch: 3 });
  await owner(async c => {
    await c.query(`CREATE TABLE ${name}.akac_state (id INTEGER PRIMARY KEY CHECK(id=1), body JSONB NOT NULL)`);
    await c.query(`INSERT INTO ${name}.akac_state (id, body) VALUES (1, $1)`, [JSON.stringify(legacy)]);
  });
  const store = new PostgresStore(url!, { schema: name });
  try {
    const engine = new Engine(store, { clock: () => now });
    assert.ok((await engine.openContext(bindings.chief, ['strategy'], 'work')).ok);
    assert.equal(await store.transaction('acme', async tx => { await tx.load({ epoch: true, knowledge: ['strategy'] });
      return `${tx.state.epochs.acme}:${tx.state.knowledge.strategy!.origin}`; }), '3:system');
    assert.deepEqual(await migrate(url!, { schema: name }), []);
    const tables = await owner(c => c.query('SELECT table_name FROM information_schema.tables WHERE table_schema=$1 AND table_name LIKE $2', [name, 'akac_state%']));
    assert.deepEqual(tables.rows.map(r => r.table_name), ['akac_state_legacy']);
  } finally { await store.close(); }
});

// ---- Regressions from the 0.3 adversarial review ------------------------------

/** A deactivated role D gates `secret`; nine SCIM groups each list 64 legacy role names before it. */
function roleNames(groupsActive: boolean): State {
  const s = emptyState();
  const actor = (id: string, kind: Actor['kind']): Actor => ({ id, tenant: 't', kind, roles: [], projects: [], clearance: 'restricted', active: true });
  s.actors.u = actor('u', 'user'); s.actors.a = actor('a', 'agent');
  s.grants.g = { id: 'g', tenant: 't', subject: 'u', agent: 'a', actions: ['read'], resources: ['*'], purposes: ['work'], notBefore: now - 1000, expiresAt: now + 3_600_000, active: true };
  s.roles.D = { id: 'D', tenant: 't', inherits: [], active: false };
  for (let i = 1; i <= 9; i++) s.groups[`g0${i}`] = { id: `g0${i}`, tenant: 't', members: ['u'], roles: Array.from({ length: 64 }, (_, j) => `old${i}-${j}`), active: groupsActive };
  s.groups.zz = { id: 'zz', tenant: 't', members: ['u'], roles: ['D'], active: true };
  s.knowledge.secret = { id: 'secret', tenant: 't', version: 1, kind: 'document', origin: 'system', content: 'D-only synthetic secret', classification: 'public',
    projects: [], readerRoles: ['D'], readers: ['a'], sources: [], active: true };
  return s;
}
const tb: Binding = { tenant: 't', subject: 'u', agent: 'a', grant: 'g' };

test('PostgreSQL: a deactivated role is never read as a flat active role, however many role names precede it', { skip }, async () => {
  assert.equal((await new Engine(new MemoryStore(roleNames(false)), { clock: () => now }).openContext(tb, ['secret'], 'work')).ok, false, 'reference result');
  const name = await schema();
  const store = new PostgresStore(url!, { schema: name });
  try {
    await importState(store, roleNames(false));
    assert.equal((await new Engine(store, { clock: () => now }).openContext(tb, ['secret'], 'work')).ok, false);
  } finally { await store.close(); }
});

test('PostgreSQL: loads never truncate; an over-bound closure is a deferred, audited denial', { skip }, async () => {
  const name = await schema();
  const store = new PostgresStore(url!, { schema: name });
  try {
    const s = roleNames(true);
    s.roles.wide = { id: 'wide', tenant: 't', inherits: Array.from({ length: 600 }, (_, i) => `junior-${i}`), active: true };
    await importState(store, s);
    const load = (need: Need) => store.transaction('t', async tx => { await tx.load(need); });
    const many = (n: number, prefix: string) => Array.from({ length: n }, (_, i) => `${prefix}-${i}`);
    await assert.rejects(load({ roles: ['wide'] }), BudgetExceeded, 'a closure above the bound (by name, with or without records)');
    await assert.rejects(load({ roles: many(513, 'r') }), BudgetExceeded);
    await assert.rejects(load({ knowledge: many(1101, 'k') }), BudgetExceeded);
    await assert.rejects(load({ containers: many(257, 'c') }), BudgetExceeded);
    await assert.rejects(load({ grants: many(65, 'g') }), BudgetExceeded);
    await load({ roles: many(512, 'r') });
    const result = await new Engine(store, { clock: () => now }).openContext(tb, ['secret'], 'work');
    assert.equal(result.ok, false);
    const entry = (await store.auditLog('t')).at(-1)!;
    assert.deepEqual([entry.operation, entry.decision, entry.reason], ['read', 'deny', 'DEFERRED:BUDGET_EXCEEDED']);
  } finally { await store.close(); }
});

test('PostgreSQL: record keys are (tenant, id) for a bypassing and an RLS-bound runtime role alike', { skip }, async () => {
  const name = await schema();
  const seeded = new PostgresStore(url!, { schema: name });
  try { await importState(seeded, twoTenants()); } finally { await seeded.close(); }
  const appUrl = await appAccess(name);
  for (const [runtime, id] of [[url!, 'intern'], [appUrl, 'chief']] as const) {
    const store = new PostgresStore(runtime, { schema: name, migrate: false });
    try {
      const control = new ControlPlane(store, { clock: () => now });
      const original = (await control.readActor('acme', 'admin', id)) as { value: Actor };
      const alien: Actor = { id, tenant: 'other', kind: 'user', roles: [], projects: [], clearance: 'public', active: false };
      assert.deepEqual(await control.upsertActor('other', 'o-admin', alien), { ok: true, value: { id } }, 'same answer as for an unused id');
      assert.deepEqual(await control.readActor('acme', 'admin', id), { ok: true, value: original.value }, 'the owning tenant is untouched');
      assert.deepEqual(await control.readActor('other', 'o-admin', id), { ok: true, value: alien });
      assert.ok((await new Engine(store, { clock: () => now }).openContext(id === 'chief' ? bindings.chief : bindings.intern, ['handbook'], 'work')).ok);
    } finally { await store.close(); }
  }
  const keys = await owner(c => c.query(`SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum = ANY(i.indkey)
    WHERE i.indrelid='${name}.akac_actors'::regclass AND i.indisprimary ORDER BY array_position(i.indkey::int2[], a.attnum)`));
  assert.deepEqual(keys.rows.map(r => r.attname), ['tenant', 'id']);
});

test('PostgreSQL: migration 003 upgrades a database already at 002; 001 and 002 are unchanged', { skip }, async () => {
  const name = await schema();
  const dir = mkdtempSync(join(tmpdir(), 'akac-at-002-'));
  try {
    cpSync(MIGRATIONS, dir, { recursive: true }); rmSync(join(dir, '003_tenant_scoped_keys.sql'));
    assert.deepEqual(await migrate(url!, { schema: name, directory: dir }), ['001_normalized_schema', '002_vector_compartments']);
  } finally { rmSync(dir, { recursive: true }); }
  await owner(async c => {
    await c.query(`INSERT INTO ${name}.akac_actors (id, tenant, kind, roles, projects, clearance, active) VALUES ('shared', 'acme', 'user', '{staff}', '{}', 'internal', true)`);
    await c.query(`INSERT INTO ${name}.akac_knowledge (id, tenant, version, kind, origin, content, classification, projects, reader_roles, readers, sources, active)
      VALUES ('note', 'acme', 1, 'document', 'system', 'Synthetic note.', 'public', '{}', '{staff}', '{}', '[]', true)`);
  });
  // Applied 001/002 checksums are verified against the current files; an edit would refuse here.
  assert.deepEqual(await migrate(url!, { schema: name }), ['003_tenant_scoped_keys']);
  assert.deepEqual(await migrate(url!, { schema: name }), []);
  const store = new PostgresStore(url!, { schema: name, migrate: false });
  try {
    assert.equal(await store.ready(), true);
    assert.equal(await store.transaction('acme', async tx => { await tx.load({ actors: ['shared'], knowledge: ['note'] }); return `${tx.state.actors.shared?.clearance}:${tx.state.knowledge.note?.version}`; }), 'internal:1');
    await store.transaction('other', async tx => { tx.state.actors.shared = { id: 'shared', tenant: 'other', kind: 'agent', roles: [], projects: [], clearance: 'public', active: true }; });
    const rows = await owner(c => c.query(`SELECT tenant, kind FROM ${name}.akac_actors WHERE id='shared' ORDER BY tenant`));
    assert.deepEqual(rows.rows, [{ tenant: 'acme', kind: 'user' }, { tenant: 'other', kind: 'agent' }]);
    const dropped = await owner(c => c.query(`SELECT indexname FROM pg_indexes WHERE schemaname=$1 AND indexname LIKE '%\\_tenant'`, [name]));
    assert.deepEqual(dropped.rows, [], 'redundant (tenant, id) indexes are replaced by the primary keys');
  } finally { await store.close(); }
});

test('PostgreSQL: a runtime role that bypasses RLS is refused unless explicitly allowed for development', { skip }, async () => {
  const strict = configuredStore({ DATABASE_URL: url!, AKAC_AUTO_MIGRATE: 'false' }) as PostgresStore;
  try {
    await assert.rejects(strict.verify(), /bypasses row-level security/);
    await assert.rejects(strict.transaction('acme', async () => 1), /bypasses row-level security/);
    assert.equal(await strict.ready(), false);
  } finally { await strict.close(); }
  const warnings: string[] = [];
  const allowed = configuredStore({ DATABASE_URL: url!, AKAC_AUTO_MIGRATE: 'false', AKAC_PG_ALLOW_BYPASS_RLS: 'true' }, { warn: m => warnings.push(m) }) as PostgresStore;
  try { await allowed.verify(); assert.equal(warnings.length, 1); assert.match(warnings[0]!, /development only/); }
  finally { await allowed.close(); }
  // The gateway refuses to start.
  const dir = mkdtempSync(join(tmpdir(), 'akac-start-'));
  try {
    const credentials = join(dir, 'agent.json'); writeFileSync(credentials, JSON.stringify([{}]));
    const env: Record<string, string | undefined> = { ...process.env, DATABASE_URL: url!, AKAC_AUTO_MIGRATE: 'false', AKAC_CREDENTIALS_FILE: credentials, PORT: '0', AKAC_METRICS_PORT: '0', NODE_ENV: 'test' };
    delete env.AKAC_PG_ALLOW_BYPASS_RLS;
    const child = spawn(process.execPath, ['reference/server.ts'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = ''; child.stdout.on('data', d => { output += d; }); child.stderr.on('data', d => { output += d; });
    const timer = setTimeout(() => child.kill(), 20_000);
    const code = await new Promise<number | null>(resolve => child.on('exit', resolve));
    clearTimeout(timer);
    assert.equal(code, 2, output); assert.match(output, /store start-up check failed/);
  } finally { rmSync(dir, { recursive: true }); }
});

/** Records every Need a store receives. */
function recording(store: Store, needs: Need[]): Store {
  return {
    transaction<T>(tenant: string, fn: (tx: Tx) => Promise<T>) {
      return store.transaction(tenant, tx => fn({ state: tx.state, complete: tx.complete, load: (need: Need) => { needs.push(need); return tx.load(need); },
        ...(tx.catalog ? { catalog: (limit: number) => tx.catalog!(limit) } : {}) }));
    },
    ready: tenant => store.ready(tenant), auditLog: (tenant, after, limit) => store.auditLog(tenant, after, limit), close: () => store.close()
  };
}
test('PostgreSQL: lexical retrieval has a content byte budget; reconcile reads metadata first and content in batches', { skip }, async () => {
  const name = await schema();
  const store = new PostgresStore(url!, { schema: name });
  try {
    const s = kbFixture(now);
    s.actors.admin!.roles = ['security-admin', 'kb-admin'];
    for (let i = 0; i < 40; i++) s.knowledge[`bulk-${i}`] = { ...structuredClone(s.knowledge.handbook!), id: `bulk-${i}`, content: `Synthetic bulk product note ${i}.` };
    await importState(store, s);
    assert.ok((await new Engine(store, { clock: () => now }).retrieve(bindings.intern, 'product', 'work')).ok);
    assert.equal((await new Engine(store, { clock: () => now, contentBytes: 256 }).retrieve(bindings.intern, 'product', 'work')).ok, false);
    const entry = (await store.auditLog('acme')).at(-1)!;
    assert.deepEqual([entry.operation, entry.reason], ['retrieve', 'DEFERRED:BUDGET_EXCEEDED']);

    const needs: Need[] = [];
    const control = new ControlPlane(store, { clock: () => now });
    const ingestor = new Ingestor({ control, store: recording(store, needs), index: new MemoryVectorIndex(), embedder: new HashEmbedder(256), clock: () => now });
    const documents = Object.values(s.knowledge).filter(k => k.kind === 'document' && k.active).length;
    assert.deepEqual(await ingestor.reconcile('acme'), { indexed: documents, removed: 0, failed: 0, truncated: false });
    assert.ok(!needs.some(n => n.corpus), 'no whole-corpus load');
    assert.ok(needs.every(n => (n.knowledge?.length ?? 0) <= 32), 'content is loaded in batches');
    assert.deepEqual(await ingestor.reconcile('acme'), { indexed: 0, removed: 0, failed: 0, truncated: false });
  } finally { await store.close(); }
});
