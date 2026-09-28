import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import fc from 'fast-check';
import { PostgresStore } from '../adapters/postgres.ts';
import { ControlPlane } from '../reference/control.ts';
import { BudgetExceeded } from '../reference/hydrate.ts';
import { countSodHolders, effectiveRoles } from '../reference/policy.ts';
import { MemoryStore, importState } from '../reference/store.ts';
import { emptyState } from '../reference/types.ts';
import type { Actor, State } from '../reference/types.ts';
import { fixture } from '../examples/fixture.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url;
const now = 1800000000000;
const schemas: string[] = [];
const roleNames = ['akac_hold_owner_test', 'akac_hold_member_test', 'akac_hold_app_test'];
const password = 'synthetic_rls_only_' + randomBytes(8).toString('hex');

async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
async function schema(): Promise<string> {
  const name = `akac_h_${randomBytes(6).toString('hex')}`; schemas.push(name);
  await owner(c => c.query(`CREATE SCHEMA ${name}`)); return name;
}
const as = (role: string) => { const u = new URL(url!); u.username = role; u.password = password; return u.toString(); };
async function dropRoles(c: pg.Client) {
  for (const role of roleNames) {
    if ((await c.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [role])).rowCount) { await c.query(`DROP OWNED BY ${role}`); await c.query(`DROP ROLE ${role}`); }
  }
}
test.after(async () => {
  if (skip) return;
  await owner(async c => { for (const name of schemas) await c.query(`DROP SCHEMA IF EXISTS ${name} CASCADE`); await dropRoles(c); });
});

const person = (tenant: string, id: string, roles: string[], active = true): Actor => ({ id, tenant, kind: 'user', roles, projects: [], clearance: 'public', active });

test('PostgreSQL: a tenant beyond the principal budget can still add SoD constraints and is refused unsafe role widening', { skip }, async () => {
  const name = await schema();
  const store = new PostgresStore(url!, { schema: name });
  try {
    const s = emptyState();
    s.actors.admin = { ...person('big', 'admin', ['security-admin']), clearance: 'restricted' };
    for (let i = 0; i < 2050; i++) s.actors[`u${i}`] = person('big', `u${i}`, [i === 7 ? 'approver' : 'requester']);
    s.actors.dual = person('big', 'dual', ['requester', 'approver']);
    s.roles.lead = { id: 'lead', tenant: 'big', inherits: [], active: true };
    s.actors.boss = person('big', 'boss', ['lead']);
    for (let i = 0; i < 17; i++) s.roles[`c${i}`] = { id: `c${i}`, tenant: 'big', inherits: i < 16 ? [`c${i + 1}`] : [], active: true };
    await importState(store, s);
    const control = new ControlPlane(store, { clock: () => now });
    await assert.rejects(store.transaction('big', tx => tx.load({ principals: true })), BudgetExceeded, 'the principal load budget really is exceeded');
    const ssd = { id: 'ssd', tenant: 'big', kind: 'static' as const, roles: ['requester', 'approver'], cardinality: 2 };
    assert.deepEqual(await control.upsertConstraint('big', 'admin', ssd), { ok: false, code: 'SOD_VIOLATION', holders: 1 }, 'counted in SQL and refused');
    const stored = () => store.transaction('big', async tx => { await tx.load({ constraints: true }); return Object.keys(tx.state.constraints); });
    assert.deepEqual(await stored(), []);
    await store.transaction('big', async tx => { await tx.load({ actors: ['dual'] }); tx.state.actors.dual!.roles = ['requester']; });
    assert.deepEqual(await control.upsertConstraint('big', 'admin', ssd), { ok: true, value: { id: 'ssd' } });
    // Widening that would put a holder into a violation is refused with the count; unheld roles can be widened.
    assert.deepEqual(await control.upsertRole('big', 'admin', { id: 'lead', tenant: 'big', inherits: ['requester', 'approver'], active: true }),
      { ok: false, code: 'SOD_VIOLATION', holders: 1 });
    assert.deepEqual(await control.upsertRole('big', 'admin', { id: 'unused', tenant: 'big', inherits: ['requester', 'approver'], active: true }), { ok: true, value: { id: 'unused' } });
    // A 17-role path cannot be established: the count is unknown. Tightening is accepted and says so; widening is refused.
    await store.transaction('big', async tx => { await tx.load({ actors: ['u1'] }); tx.state.actors.u1!.roles = ['c0']; });
    assert.deepEqual(await control.upsertConstraint('big', 'admin', { ...ssd, id: 'ssd-2', roles: ['requester', 'approver', 'lead'], cardinality: 3 }),
      { ok: true, value: { id: 'ssd-2', holders: 'unknown' } });
    assert.deepEqual(await stored(), ['ssd', 'ssd-2']);
    await assert.rejects(control.upsertRole('big', 'admin', { id: 'unused', tenant: 'big', inherits: ['lead'], active: true }), BudgetExceeded);
    const last = (await store.auditLog('big')).at(-1)!;
    assert.deepEqual([last.operation, last.decision, last.reason], ['upsert_role', 'deny', 'DEFERRED:BUDGET_EXCEEDED']);
  } finally { await store.close(); }
});

type Fixture = { roles: [number[], boolean][]; actors: [number[], boolean][]; groups: [number[], number[], boolean][]; constraints: [number[], number][]; override?: number[] };
const ints = (min: number, max: number, minLength = 0, maxLength = 4) => fc.uniqueArray(fc.integer({ min, max }), { minLength, maxLength });
const fixtureArb: fc.Arbitrary<Fixture> = fc.record({
  // Role i inherits only roles of a higher index (acyclic); r8 and r9 have no record (flat roles).
  roles: fc.array(fc.tuple(ints(1, 9), fc.boolean()), { minLength: 8, maxLength: 8 }),
  actors: fc.array(fc.tuple(ints(0, 9), fc.boolean()), { minLength: 1, maxLength: 12 }),
  groups: fc.array(fc.tuple(ints(0, 11, 0, 5), ints(0, 9, 0, 3), fc.boolean()), { maxLength: 4 }),
  constraints: fc.array(fc.tuple(ints(0, 9, 2, 5), fc.integer({ min: 2, max: 5 })), { minLength: 1, maxLength: 3 }),
  override: fc.option(ints(0, 9), { nil: undefined })
});
const build = (tenant: string, f: Fixture): State => {
  const s = emptyState(), r = (i: number) => `r${i}`;
  f.roles.forEach(([inherits, active], i) => { s.roles[r(i)] = { id: r(i), tenant, inherits: inherits.filter(j => j > i).map(r), active }; });
  f.actors.forEach(([roles, active], i) => { s.actors[`a${i}`] = person(tenant, `a${i}`, roles.map(r), active); });
  f.groups.forEach(([members, roles, active], i) => { s.groups[`g${i}`] = { id: `g${i}`, tenant, members: members.filter(m => m < f.actors.length).map(m => `a${m}`), roles: roles.map(r), active }; });
  return s;
};
const queryOf = (tenant: string, f: Fixture) => ({
  constraints: f.constraints.map(([roles, cardinality]) => ({ roles: roles.map(i => `r${i}`), cardinality: Math.min(cardinality, roles.length) })),
  ...(f.override ? { role: { id: 'r0', tenant, inherits: f.override.filter(j => j > 0).map(j => `r${j}`), active: true } } : {})
});

test('holder counting: memory transactions match an independent effectiveRoles computation', async () => {
  await fc.assert(fc.asyncProperty(fixtureArb, async f => {
    const s = build('acme', f), q = queryOf('acme', f);
    // Another tenant with the same ids must not leak into the count.
    for (const a of Object.values(build('noise', f).actors)) s.actors[`n-${a.id}`] = { ...a, id: `n-${a.id}` };
    const store = new MemoryStore(); await importState(store, s);
    const got = await store.transaction('acme', tx => tx.countSodHolders!(q));
    const view = { ...s, roles: { ...s.roles, ...(q.role ? { r0: q.role } : {}) } };
    let expected = 0;
    for (const a of Object.values(s.actors)) {
      if (a.tenant !== 'acme' || !a.active) continue;
      const roles = effectiveRoles(view, a)!;
      if (q.constraints.some(c => c.roles.filter(x => roles.has(x)).length >= c.cardinality)) expected++;
    }
    assert.equal(got, expected);
  }), { numRuns: 200 });
});

test('holder counting: the SQL count equals policy effectiveRoles semantics', { skip }, async () => {
  const name = await schema();
  const store = new PostgresStore(url!, { schema: name });
  let n = 0;
  try {
    await fc.assert(fc.asyncProperty(fixtureArb, async f => {
      const tenant = `fx${n++}`, q = queryOf(tenant, f), s = build(tenant, f);
      // Same ids in a neighbouring tenant, with different roles, must not leak in.
      for (const a of Object.values(build(`${tenant}x`, f).actors)) s.actors[`n-${a.id}`] = { ...a, id: `n-${a.id}`, roles: ['r0', 'r1', 'r2', 'r3'] };
      await importState(store, s);
      assert.equal(await store.transaction(tenant, tx => tx.countSodHolders!(q)), countSodHolders(s, tenant, q), JSON.stringify(f));
    }), { numRuns: 60 });
  } finally { await store.close(); }
});

test('PostgreSQL: the runtime role must not own the tables, nor be a member of their owner', { skip }, async () => {
  const name = await schema();
  const [owned, member] = roleNames as [string, string];
  const seeded = new PostgresStore(url!, { schema: name });
  try {
    await importState(seeded, fixture(now));
    await owner(async c => {
      await dropRoles(c);
      for (const role of [owned, member]) {
        await c.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '${password}'`);
        await c.query(`GRANT USAGE ON SCHEMA ${name} TO ${role}`);
      }
      const tables = await c.query('SELECT relname FROM pg_class WHERE relnamespace=$1::regnamespace AND relkind=$2', [name, 'r']);
      for (const t of tables.rows) await c.query(`ALTER TABLE ${name}.${t.relname} OWNER TO ${owned}`);
      await c.query(`GRANT ${owned} TO ${member}`);
    });
    for (const role of [owned, member]) {
      const store = new PostgresStore(as(role), { schema: name, migrate: false, requireRls: true });
      try {
        assert.equal(await store.ready('acme'), false, `${role} must fail readiness`);
        await assert.rejects(store.verify(), /runtime role/);
        await assert.rejects(store.transaction('acme', async () => 1), /runtime role/);
      } finally { await store.close(); }
    }
    const dev = new PostgresStore(as(owned), { schema: name, migrate: false });
    try { assert.equal(await dev.ready(), true, 'development mode does not require the posture'); } finally { await dev.close(); }
  } finally { await seeded.close(); }
});

test('PostgreSQL: every tenant table must have forced row-level security', { skip }, async () => {
  const name = await schema();
  const app = roleNames[2]!;
  const seeded = new PostgresStore(url!, { schema: name });
  try { await importState(seeded, fixture(now)); } finally { await seeded.close(); }
  await owner(async c => {
    await dropRoles(c);
    await c.query(`CREATE ROLE ${app} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '${password}'`);
    await c.query(`GRANT USAGE ON SCHEMA ${name} TO ${app}`);
    await c.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${name} TO ${app}`);
  });
  const check = async () => { const s = new PostgresStore(as(app), { schema: name, migrate: false, requireRls: true }); try { return await s.ready('acme'); } finally { await s.close(); } };
  assert.equal(await check(), true, 'a non-owner runtime role over forced tables passes');
  for (const change of ['NO FORCE ROW LEVEL SECURITY', 'DISABLE ROW LEVEL SECURITY']) {
    await owner(c => c.query(`ALTER TABLE ${name}.akac_actors ${change}`));
    assert.equal(await check(), false, change);
    const store = new PostgresStore(as(app), { schema: name, migrate: false, requireRls: true });
    try { await assert.rejects(store.transaction('acme', async () => 1), /runtime role/); } finally { await store.close(); }
    await owner(c => c.query(`ALTER TABLE ${name}.akac_actors ENABLE ROW LEVEL SECURITY; ALTER TABLE ${name}.akac_actors FORCE ROW LEVEL SECURITY`));
  }
  assert.equal(await check(), true);
});
