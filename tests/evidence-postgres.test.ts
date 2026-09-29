import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { cpSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { MIGRATIONS, migrate, PostgresStore } from '../adapters/postgres.ts';
import { Engine } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { importState } from '../reference/store.ts';
import { auditHash, auditLeaf, GENESIS, verifyAudit } from '../reference/audit.ts';
import { rootOf, verifyConsistency, verifyInclusion } from '../reference/merkle.ts';
import { signCheckpointV2, verifyCheckpointExtension, verifyCheckpointV2 } from '../reference/checkpoint.ts';
import { consistencyProof, inclusionProof, treeHead } from '../reference/evidence.ts';
import { fixture, bindings } from '../examples/fixture.ts';
import type { Audit } from '../reference/types.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url;
const now = 1800000000000;
const APP_ROLE = 'akac_evidence_app_test', APP_PASSWORD = 'synthetic_rls_only_' + randomBytes(8).toString('hex');
const schemas: string[] = [];
async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
async function schema(): Promise<string> {
  const name = `akac_e_${randomBytes(6).toString('hex')}`; schemas.push(name);
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
const leaves = (entries: Audit[]) => entries.map(auditLeaf);
async function decisions(store: PostgresStore, count: number) {
  const engine = new Engine(store, { clock: () => now });
  const ids: string[] = [];
  for (let i = 0; i < count; i++) ids.push((await engine.openContext(bindings.intern, [i % 3 ? 'handbook' : 'strategy'], 'work', { trace: { traceId: '4bf92f3577b34da6a3ce929d0e0e4736' } })).decisionId);
  return ids;
}

test('PostgreSQL evidence: fresh database stores format 2 entries and Merkle nodes; proofs verify for an RLS-bound runtime role', { skip }, async () => {
  const name = await schema();
  const applied = await migrate(url!, { schema: name });
  assert.ok(applied.includes('004_audit_evidence'));
  const app = new PostgresStore(await appAccess(name), { schema: name, migrate: false, requireRls: true });
  try {
    await app.verify();
    await importState(app, fixture(now));
    const ids = await decisions(app, 21);
    const entries = await app.auditLog('acme');
    assert.equal(entries.length, 21); assert.ok(verifyAudit(entries));
    assert.deepEqual(entries.map(e => e.decisionId), ids, 'the caller-visible id is the audited id');
    assert.ok(entries.every(e => e.formatVersion === 2 && e.runId === 'intern-run' && e.traceId === '4bf92f3577b34da6a3ce929d0e0e4736' && Array.isArray(e.obligations)));
    const head = await treeHead(app, 'acme');
    assert.deepEqual(head, { stream: 'acme', treeSize: 21, rootHash: rootOf(leaves(entries)) }, 'incremental tree equals a recomputation');
    const nodes = await owner(c => c.query(`SELECT count(*)::int AS n FROM ${name}.akac_audit_node WHERE tenant='acme'`));
    assert.equal(nodes.rows[0].n, 2 * 21 - 3, 'exactly the complete perfect subtrees (2n - popcount(n))');
    for (const [m, n] of [[0, 21], [20, 21], [7, 16], [15, 17]] as const) {
      const p = await inclusionProof(app, 'acme', m, n);
      assert.ok(verifyInclusion(auditLeaf(entries[m]!), m, n, p.path, rootOf(leaves(entries.slice(0, n)))));
    }
    const c = await consistencyProof(app, 'acme', 5, 21);
    assert.ok(verifyConsistency(5, 21, rootOf(leaves(entries.slice(0, 5))), head.rootHash, c.path));
    await assert.rejects(app.auditTree!('acme', [{ level: 0, index: 21 }]), /outside/);
    assert.deepEqual((await app.auditTree!('other', [])).size, 0, 'another tenant sees an empty tree');
    assert.equal(await app.ready('acme'), true);
    // The node table is append-only for the runtime role, like the audit table.
    const appClient = new pg.Client({ connectionString: await appAccess(name), options: `-c search_path=${name}` }); await appClient.connect();
    try {
      await appClient.query("SELECT set_config('akac.tenant', 'acme', false)");
      await assert.rejects(appClient.query("UPDATE akac_audit_node SET hash=repeat('0', 64) WHERE tenant='acme' AND level=0 AND idx=0"), /append-only/);
      await assert.rejects(appClient.query("DELETE FROM akac_audit_node WHERE tenant='acme'"), /append-only/);
    } finally { await appClient.end(); }
    // A node rewritten below the application (trigger disabled by the owner) fails readiness and proofs.
    await owner(async o => {
      await o.query(`ALTER TABLE ${name}.akac_audit_node DISABLE TRIGGER akac_audit_node_immutable`);
      await o.query(`UPDATE ${name}.akac_audit_node SET hash=repeat('0', 64) WHERE tenant='acme' AND level=0 AND idx=20`);
      await o.query(`ALTER TABLE ${name}.akac_audit_node ENABLE TRIGGER akac_audit_node_immutable`);
    });
    assert.equal(await app.ready('acme'), false, 'tail leaves are checked against stored nodes');
    const tampered = await inclusionProof(app, 'acme', 20, 21);
    assert.equal(verifyInclusion(auditLeaf(entries[20]!), 20, 21, tampered.path, head.rootHash) && tampered.rootHash === head.rootHash, false);
  } finally { await app.close(); }
});

test('PostgreSQL evidence: migration 004 upgrades a database at 003, backfills format 1 leaves and the chain continues', { skip }, async () => {
  const name = await schema();
  const dir = mkdtempSync(join(tmpdir(), 'akac-at-003-'));
  try {
    cpSync(MIGRATIONS, dir, { recursive: true });
    for (const f of readdirSync(dir)) if (f > '004') rmSync(join(dir, f));
    assert.deepEqual(await migrate(url!, { schema: name, directory: dir }), ['001_normalized_schema', '002_vector_compartments', '003_tenant_scoped_keys']);
  } finally { rmSync(dir, { recursive: true }); }
  // Format 1 entries as a 0.3 deployment wrote them, including strings JCS must escape.
  const legacy: Audit[] = []; let previous = GENESIS;
  const odd = ['plain', 'quote " and \\ backslash', 'line\nbreak\ttab\u0001', 'unicode ö€😀  ', '/slash'];
  for (let i = 1; i <= 11; i++) {
    const body = { sequence: i, time: now + i, tenant: 'acme', actor: `actor-${i}`, operation: 'read', decision: (i % 2 ? 'deny' : 'allow') as Audit['decision'],
      reason: odd[i % odd.length]!, policyVersion: 'akac-reference/0.3.0|v|core-only', epoch: i, previous };
    const hash = auditHash(body); legacy.push({ ...body, hash }); previous = hash;
  }
  await owner(async c => {
    for (const e of legacy) {
      await c.query(`INSERT INTO ${name}.akac_audit (tenant, sequence, time, actor, operation, decision, reason, policy_version, epoch, previous, hash)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [e.tenant, e.sequence, e.time, e.actor, e.operation, e.decision, e.reason, e.policyVersion, e.epoch, e.previous, e.hash]);
    }
    await c.query(`INSERT INTO ${name}.akac_audit_head (tenant, sequence, hash) VALUES ('acme', 11, $1)`, [previous]);
  });
  assert.ok((await migrate(url!, { schema: name })).includes('004_audit_evidence'));
  const store = new PostgresStore(url!, { schema: name, migrate: false });
  try {
    assert.equal(await store.ready('acme'), true);
    const before = await treeHead(store, 'acme');
    assert.equal(before.rootHash, rootOf(leaves(legacy)), 'SQL backfill equals auditLeaf() for format 1 entries, byte for byte');
    const { privatePem, publicPem } = (() => {
      const pair = generateKeyPairSync('ed25519');
      return { privatePem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), publicPem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString() };
    })();
    const older = signCheckpointV2(await store.auditLog('acme'), privatePem, 'acme', 'k', now);
    assert.deepEqual([older.treeSize, older.rootHash], [11, before.rootHash]);
    await importState(store, fixture(now));
    await decisions(store, 6);
    const all = await store.auditLog('acme');
    assert.equal(all.length, 17); assert.ok(verifyAudit(all), 'format 1 then format 2 in one chain');
    assert.equal(all[11]!.previous, legacy.at(-1)!.hash); assert.equal(all[11]!.formatVersion, 2); assert.equal(all[10]!.formatVersion, undefined);
    const newer = signCheckpointV2(all, privatePem, 'acme', 'k', now + 1);
    assert.equal((await treeHead(store, 'acme')).rootHash, newer.rootHash);
    assert.ok(verifyCheckpointV2(newer, publicPem, 'acme', 'k', { entries: all, minimumSize: older.treeSize }));
    const proof = await consistencyProof(store, 'acme', 11, 17);
    assert.ok(verifyCheckpointExtension(older, newer, proof.path), 'the upgraded stream extends the pre-upgrade checkpoint');
    // Audited proof access through the control plane.
    await owner(c => c.query(`INSERT INTO ${name}.akac_actors (id, tenant, kind, roles, projects, clearance, active) VALUES ('aud', 'acme', 'user', '{auditor}', '{}', 'public', true)`));
    const control = new ControlPlane(store, { clock: () => now });
    const inclusion = await control.auditProof('acme', 'aud', 3, 17); assert.ok(inclusion.ok);
    assert.ok(verifyInclusion(auditLeaf(all[3]!), 3, 17, inclusion.value.path, newer.rootHash));
    const consistency = await control.auditConsistency('acme', 'aud', 11, 17); assert.ok(consistency.ok);
    assert.deepEqual(consistency.value.path, proof.path);
    const logged = (await store.auditLog('acme')).filter(e => e.operation.startsWith('audit_'));
    assert.deepEqual(logged.map(e => [e.operation, e.decisionId]), [['audit_proof', inclusion.decisionId], ['audit_consistency', consistency.decisionId]]);
  } finally { await store.close(); }
});
