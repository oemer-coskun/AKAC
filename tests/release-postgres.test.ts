import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { migrate } from '../adapters/postgres.ts';
import { PostgresRateLimits } from '../adapters/postgres-ha.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryStore } from '../reference/store.ts';
import { VolumeBudget } from '../reference/protection.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url && 'AKAC_TEST_DATABASE_URL not set';
const APP_ROLE = 'akac_rel_app_test', APP_PASSWORD = 'synthetic_rel_only_' + randomBytes(8).toString('hex');
async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
test.after(async () => {
  if (!url) return;
  await owner(async c => { if ((await c.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [APP_ROLE])).rowCount) { await c.query(`DROP OWNED BY ${APP_ROLE}`); await c.query(`DROP ROLE ${APP_ROLE}`); } });
});

test('PostgreSQL: volume budgets are shared by every instance through the rate-limit tables (no new table), read without charging, and count large byte costs', { skip }, async () => {
  const schema = `akac_rel_${randomBytes(6).toString('hex')}`;
  await owner(c => c.query(`CREATE SCHEMA ${schema}`));
  await migrate(url!, { schema });
  await owner(async c => {
    await c.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_ROLE}') THEN CREATE ROLE ${APP_ROLE} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END $$`);
    await c.query(`ALTER ROLE ${APP_ROLE} PASSWORD '${APP_PASSWORD}'`);
    await c.query(`GRANT USAGE ON SCHEMA ${schema} TO ${APP_ROLE}`);
    await c.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${schema} TO ${APP_ROLE}`);
  });
  const app = new URL(url!); app.username = APP_ROLE; app.password = APP_PASSWORD;
  const a = new PostgresRateLimits(app.toString(), { schema }), b = new PostgresRateLimits(app.toString(), { schema });
  try {
    const limits = { confidential: { documents: 2, bytes: 5_000_000_000 } };
    const one = new VolumeBudget({ limiter: a, windowMs: 3_600_000, limits }), two = new VolumeBudget({ limiter: b, windowMs: 3_600_000, limits });
    const chief = bindings.chief;
    assert.equal(await one.charge(chief, 'confidential', 3_000_000_000, 1), 'ok');
    assert.equal(await two.exhausted(chief), false, 'reading does not charge');
    assert.equal(await two.charge(chief, 'confidential', 1_000_000_000, 1), 'ok', 'the second instance shares the window');
    assert.equal(await one.charge(chief, 'confidential', 1, 1), 'exceeded', 'documents: two already spent across the instances');
    assert.equal(await two.exhausted(chief), true);
    assert.equal(await two.exhausted(bindings.intern), false);
    assert.equal(await one.charge(chief, 'public', 10, 1), 'ok', 'a classification without a limit is not counted');
    // Through the engine: the second instance's engine sees the budget the first one spent.
    const store = new MemoryStore(kbFixture());
    const budget = new VolumeBudget({ limiter: a, windowMs: 3_600_000, limits: { confidential: { documents: 1 } } });
    const first = new Engine(store, { volume: budget }), second = new Engine(store, { volume: new VolumeBudget({ limiter: b, windowMs: 3_600_000, limits: { confidential: { documents: 1 } } }) });
    assert.ok((await first.openContext(bindings.lead, ['project-alpha'], 'work')).ok);
    assert.equal((await second.openContext(bindings.lead, ['project-alpha'], 'work')).ok, false);
  } finally {
    await a.close(); await b.close();
    await owner(c => c.query(`DROP SCHEMA ${schema} CASCADE`));
  }
});
