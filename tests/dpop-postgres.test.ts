import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { migrate } from '../adapters/postgres.ts';
import { PostgresReplayCache } from '../adapters/dpop-postgres.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const jkt = 'A'.repeat(43), later = () => Math.floor(Date.now() / 1000) + 120;

test('PostgreSQL DPoP replay cache is shared across instances, keyed by (jti, jkt), and lets expired identifiers be reused', { skip: !url && 'AKAC_TEST_DATABASE_URL not set' }, async () => {
  const schema = `akac_t_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: url }); await admin.connect();
  await admin.query(`CREATE SCHEMA ${schema}`);
  const one = new PostgresReplayCache(url!, { schema }), two = new PostgresReplayCache(url!, { schema });
  try {
    await migrate(url!, { schema });
    const jti = randomBytes(8).toString('hex');
    assert.equal(await one.consume(jti, jkt, later()), true);
    assert.equal(await two.consume(jti, jkt, later()), false, 'another instance sees the proof');
    assert.equal(await two.consume(jti, 'B'.repeat(43), later()), true, 'keyed by jkt as well');
    const concurrent = await Promise.all([1, 2, 3, 4, 5].map(i => (i % 2 ? one : two).consume('race', jkt, later())));
    assert.equal(concurrent.filter(Boolean).length, 1, 'exactly one concurrent request wins');
    assert.equal(await one.consume('old', jkt, Math.floor(Date.now() / 1000) - 5), true);
    assert.equal(await two.consume('old', jkt, later()), true, 'expired entry is replaced');
    assert.equal(await one.consume('old', jkt, later()), false);
    const table = (await admin.query(`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relnamespace = '${schema}'::regnamespace AND relname = 'akac_dpop_replay'`)).rows[0];
    assert.deepEqual(table, { relrowsecurity: true, relforcerowsecurity: true });
  } finally {
    await one.close(); await two.close();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end();
  }
  await assert.rejects(new PostgresReplayCache('postgresql://nobody@127.0.0.1:1/none').consume('x', jkt, later()), 'unreachable database rejects (fail closed)');
});
