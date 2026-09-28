import test from 'node:test';
import assert from 'node:assert/strict';
import { PostgresStore } from '../adapters/postgres.ts';
import { Engine, verifyAudit } from '../reference/engine.ts';
import { fixture, bindings } from '../examples/fixture.ts';
test('PostgreSQL: persistence, rollback, concurrent connections and revocation', { skip: !process.env.AKAC_TEST_DATABASE_URL }, async () => {
  const first = new PostgresStore(process.env.AKAC_TEST_DATABASE_URL!);
  const second = new PostgresStore(process.env.AKAC_TEST_DATABASE_URL!);
  try {
    await first.transaction(async s => { Object.assign(s, fixture()); });
    const a = new Engine(first), b = new Engine(second);
    const read = await a.openContext(bindings.chief, ['strategy'], 'work'); assert.ok(read.ok);
    assert.ok((await b.derive(bindings.chief, read.value.context, 'Across connections')).ok);
    await assert.rejects(first.transaction(async s => { s.epoch += 100; throw new Error('rollback'); }));
    assert.equal(await second.transaction(async s => s.epoch), 0);
    await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? first : second).transaction(async s => { s.epoch++; })));
    assert.equal(await first.transaction(async s => s.epoch), 10);
    await a.revoke('admin', 'knowledge', 'strategy');
    assert.equal((await b.openContext(bindings.chief, ['strategy'], 'work')).ok, false);
    assert.ok(await second.transaction(async s => verifyAudit(s.audits)));
  } finally { await first.close(); await second.close(); }
});
