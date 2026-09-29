import { bare } from './bare.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { migrate, PostgresStore } from '../adapters/postgres.ts';
import { PgVectorIndex } from '../adapters/pgvector.ts';
import { Engine } from '../reference/engine.ts';
import type { EngineEvent } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { importState } from '../reference/store.ts';
import { HashEmbedder } from '../reference/embedding.ts';
import type { Embedder } from '../reference/embedding.ts';
import { MemoryVectorIndex } from '../reference/vector.ts';
import type { IndexedChunk, VectorQuery } from '../reference/vector.ts';
import { VectorCandidateSource } from '../reference/retrieval.ts';
import { Ingestor } from '../reference/ingest.ts';
import { kbFixture, bindings } from '../examples/fixture.ts';
import { LEVELS } from '../reference/types.ts';
import type { Binding, Knowledge, State } from '../reference/types.ts';

const url = process.env.AKAC_TEST_DATABASE_URL;
const skip = !url;
const now = 1800000000000;
const other: Binding = { tenant: 'other', subject: 'o-user', agent: 'o-agent', grant: 'o-run' };
const APP_ROLE = 'akac_vec_app_test', APP_PASSWORD = 'synthetic_vec_only_' + randomBytes(8).toString('hex');
const schemas: string[] = [];
const hash = new HashEmbedder(256);

function world(): State {
  const s = kbFixture(now);
  s.actors.admin!.roles = ['security-admin', 'kb-admin', 'auditor'];
  s.actors['o-user'] = { id: 'o-user', tenant: 'other', kind: 'user', roles: ['staff'], projects: [], clearance: 'restricted', active: true };
  s.actors['o-agent'] = { ...s.actors['o-user']!, id: 'o-agent', kind: 'agent' };
  s.actors['o-admin'] = { ...s.actors.admin!, id: 'o-admin', tenant: 'other' };
  s.grants['o-run'] = { ...s.grants['chief-run']!, id: 'o-run', tenant: 'other', subject: 'o-user', agent: 'o-agent' };
  s.knowledge['o-doc'] = { ...s.knowledge.handbook!, id: 'o-doc', tenant: 'other', content: 'Other tenant notes.' };
  return s;
}
async function owner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url }); await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
/** Fresh schema, migrated as the owner; returns the runtime-role URL that neither owns tables nor bypasses RLS. */
async function fresh(): Promise<{ name: string; appUrl: string }> {
  const name = `akac_v_${randomBytes(6).toString('hex')}`; schemas.push(name);
  await owner(c => c.query(`CREATE SCHEMA ${name}`));
  await migrate(url!, { schema: name });
  await owner(async c => {
    await c.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_ROLE}') THEN
      CREATE ROLE ${APP_ROLE} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END $$`);
    await c.query(`ALTER ROLE ${APP_ROLE} PASSWORD '${APP_PASSWORD}'`);
    await c.query(`GRANT USAGE ON SCHEMA ${name} TO ${APP_ROLE}`);
    // The runtime role needs USAGE on the schema that holds the vector extension (deploy/postgres/init.sql grants it).
    await c.query(`GRANT USAGE ON SCHEMA public TO ${APP_ROLE}`);
    await c.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${name} TO ${APP_ROLE}`);
  });
  const app = new URL(url!); app.username = APP_ROLE; app.password = APP_PASSWORD;
  return { name, appUrl: app.toString() };
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
const doc = (id: string, content: string, extra: Partial<Knowledge> = {}): Knowledge => ({ id, tenant: 'acme', version: 1, kind: 'document', origin: 'human',
  content, classification: 'internal', projects: [], readerRoles: ['staff'], readers: [], sources: [], active: true, ...extra });
const count = (c: pg.Client, table: string, where = 'true') => c.query(`SELECT count(*)::int AS n FROM ${table} WHERE ${where}`).then(r => r.rows[0].n as number);

test('PostgreSQL vector: migration 002 is applied once, checksum-verified and creates one table per compartment', { skip }, async () => {
  const name = `akac_v_${randomBytes(6).toString('hex')}`; schemas.push(name);
  await owner(c => c.query(`CREATE SCHEMA ${name}`));
  assert.deepEqual((await migrate(url!, { schema: name })).slice(0, 3), ['001_normalized_schema', '002_vector_compartments', '003_tenant_scoped_keys']);
  assert.deepEqual(await migrate(url!, { schema: name }), []);
  await owner(async c => {
    for (const level of LEVELS) {
      const t = `${name}.akac_chunks_${level}`;
      const row = (await c.query(`SELECT c.relrowsecurity AS rls, c.relforcerowsecurity AS forced FROM pg_class c WHERE c.oid = to_regclass($1)`, [t])).rows[0];
      assert.deepEqual(row, { rls: true, forced: true }, `${level} table has forced RLS`);
      const indexes = (await c.query('SELECT indexdef FROM pg_indexes WHERE schemaname=$1 AND tablename=$2', [name, `akac_chunks_${level}`])).rows.map(r => r.indexdef as string).join('\n');
      assert.match(indexes, /USING hnsw/); assert.match(indexes, /vector_cosine_ops/); assert.match(indexes, /USING gin \(read_tokens\)/);
    }
  });
});

test('PostgreSQL vector: refuses a mismatching dimension and a missing schema', { skip }, async () => {
  const { name, appUrl } = await fresh();
  const wrong = new PgVectorIndex(appUrl, { schema: name, dimensions: 128 });
  await assert.rejects(wrong.query({ tenant: 'acme', compartments: ['public'], tokens: [], projects: [], vector: new Float32Array(128), k: 1 }), /dimension/);
  await wrong.close();
  const empty = `akac_v_${randomBytes(6).toString('hex')}`; schemas.push(empty);
  await owner(async c => { await c.query(`CREATE SCHEMA ${empty}`); await c.query(`GRANT USAGE ON SCHEMA ${empty} TO ${APP_ROLE}`); });
  const missing = new PgVectorIndex(appUrl, { schema: empty });
  await assert.rejects(missing.state('acme'), /Missing akac_chunks_public/);
  await missing.close();
  assert.throws(() => new PgVectorIndex(appUrl, { schema: 'x; drop' }), /Invalid schema/);
});

test('PostgreSQL vector: SQL pre-filter agrees with the in-memory reference filter', { skip }, async () => {
  const { name, appUrl } = await fresh();
  const pgIndex = new PgVectorIndex(appUrl, { schema: name }), memory = new MemoryVectorIndex();
  try {
    const v = (await hash.embed(['needle in a haystack']))[0]!;
    const chunk = (docId: string, extra: Partial<IndexedChunk>): IndexedChunk => ({ tenant: 't', docId, docVersion: 1, chunkId: `${docId}#1#0`, ordinal: 0,
      compartment: 'internal', readTokens: ['role:staff'], requiredProjects: [], containerTokens: [], model: hash.model, vector: v, ...extra });
    const chunks = [chunk('open', {}), chunk('nested', { containerTokens: [['role:staff'], ['role:exec', 'user:ann']] }), chunk('empty-acl', { readTokens: [] }),
      chunk('empty-level', { containerTokens: [[]] }), chunk('no-levels-match', { containerTokens: [['role:nobody']] }), chunk('proj', { requiredProjects: ['alpha', 'beta'] }),
      chunk('elsewhere', { tenant: 'u' }), chunk('higher', { compartment: 'restricted' }), chunk('pub', { compartment: 'public', readTokens: ['user:ann'] })];
    await pgIndex.upsert(chunks); await memory.upsert(chunks);
    const cases: [string[], string[], VectorQuery['compartments']][] = [
      [['role:staff'], [], ['public', 'internal']], [['role:staff', 'user:ann'], [], ['public', 'internal']], [['role:staff'], ['alpha'], ['internal']],
      [['role:staff'], ['alpha', 'beta'], ['internal']], [['role:staff', 'user:ann'], ['alpha', 'beta'], [...LEVELS]], [[], [], [...LEVELS]], [['role:nobody'], [], [...LEVELS]],
      [['role:staff', 'role:exec'], [], ['restricted']]];
    for (const [tokens, projects, compartments] of cases) {
      const q = { tenant: 't', compartments, tokens, projects, vector: v, k: 50 };
      const [a, b] = [await pgIndex.query(q), await memory.query(q)];
      assert.deepEqual(a.map(h => h.docId).sort(), b.map(h => h.docId).sort(), JSON.stringify([tokens, projects, compartments]));
    }
    assert.deepEqual(await pgIndex.state('t'), await memory.state('t'), 'stored labels digest identically');
    // Replacement across compartments, and a stale (lower) version is ignored.
    await pgIndex.upsert([chunk('open', { docVersion: 2, chunkId: 'open#2#0', compartment: 'restricted' })]);
    assert.equal((await pgIndex.state('t')).get('open')!.version, 2);
    await pgIndex.upsert([chunk('open', { docVersion: 1 })]);
    assert.equal((await pgIndex.state('t')).get('open')!.version, 2);
    const q = (compartments: VectorQuery['compartments']) => pgIndex.query({ tenant: 't', compartments, tokens: ['role:staff'], projects: [], vector: v, k: 50 }).then(h => h.some(x => x.docId === 'open'));
    assert.equal(await q(['public', 'internal', 'confidential']), false);
    assert.equal(await q(['restricted']), true);
    await pgIndex.removeDocument('t', 'open');
    assert.equal(await q([...LEVELS]), false);
    await assert.rejects(pgIndex.upsert([chunk('short', { vector: new Float32Array(3) })]), /dimension/);
  } finally { await pgIndex.close(); }
});

test('PostgreSQL vector: row-level security isolates tenants in every chunk table', { skip }, async () => {
  const { name, appUrl } = await fresh();
  const index = new PgVectorIndex(appUrl, { schema: name });
  const client = new pg.Client({ connectionString: appUrl, options: `-c search_path=${name}` }); await client.connect();
  try {
    const v = (await hash.embed(['shared words here']))[0]!;
    for (const [tenant, level] of [['acme', 'public'], ['acme', 'restricted'], ['other', 'public'], ['other', 'restricted']] as const) {
      await index.upsert([{ tenant, docId: `${tenant}-${level}`, docVersion: 1, chunkId: `${tenant}-${level}#1#0`, ordinal: 0, compartment: level,
        readTokens: ['role:staff'], requiredProjects: [], containerTokens: [], model: hash.model, vector: v }]);
    }
    await client.query('BEGIN');
    for (const level of LEVELS) assert.equal(await count(client, `akac_chunks_${level}`), 0, `${level}: unset tenant sees nothing`);
    await client.query("SELECT set_config('akac.tenant', 'acme', true)");
    for (const level of ['public', 'restricted'] as const) {
      assert.equal(await count(client, `akac_chunks_${level}`), 1);
      assert.equal(await count(client, `akac_chunks_${level}`, "tenant='other'"), 0);
      assert.equal((await client.query(`UPDATE akac_chunks_${level} SET model='x' WHERE tenant='other'`)).rowCount, 0);
      assert.equal((await client.query(`DELETE FROM akac_chunks_${level} WHERE tenant='other'`)).rowCount, 0);
      await client.query('SAVEPOINT s');
      await assert.rejects(client.query(`INSERT INTO akac_chunks_${level} (tenant, doc_id, doc_version, chunk_id, ordinal, read_tokens, required_projects, container_tokens, model, embedding)
        VALUES ('other', 'forged', 1, 'forged#1#0', 0, '{}', '{}', '[]', 'm', $1::public.vector)`, [`[${Array.from(v).join(',')}]`]), /row-level security/);
      await client.query('ROLLBACK TO s');
    }
    await client.query('ROLLBACK');
    // The index API is scoped the same way: a query for one tenant cannot surface the other's chunks.
    const hits = await index.query({ tenant: 'acme', compartments: [...LEVELS], tokens: ['role:staff'], projects: [], vector: v, k: 10 });
    assert.deepEqual(hits.map(h => h.docId).sort(), ['acme-public', 'acme-restricted']);
    // The runtime role is not privileged.
    assert.deepEqual((await client.query('SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user')).rows[0], { rolsuper: false, rolbypassrls: false });
  } finally { await client.end(); await index.close(); }
});

test('PostgreSQL vector: ingestion, reconciliation and permission-aware retrieval end to end', { skip }, async () => {
  const { name, appUrl } = await fresh();
  const seed = new PostgresStore(url!, { schema: name, migrate: false });
  await importState(seed, world()); await seed.close();
  const store = new PostgresStore(appUrl, { schema: name, migrate: false, requireRls: true });
  const index = new PgVectorIndex(appUrl, { schema: name });
  const events: EngineEvent[] = [];
  let failing = false;
  const embedder: Embedder = { model: hash.model, dimensions: 256, embed: (t, s) => { if (failing) throw new Error('embedder down'); return hash.embed(t, s); } };
  const control = new ControlPlane(store, { clock: () => now });
  const ingestor = new Ingestor({ control, store, index, embedder, clock: () => now });
  const engine = new Engine(store, { clock: () => now, onEvent: e => events.push(e), candidates: new VectorCandidateSource({ index, embedder, minScore: 0.3 }) });
  const audit = new pg.Client({ connectionString: url, options: `-c search_path=${name}` }); await audit.connect();
  let runs = 0;
  const ask = async (b: Binding, query: string) => {
    const grant = `${b.grant}-${++runs}`;
    await store.transaction(b.tenant, async tx => { await tx.load({ grants: [b.grant] }); tx.state.grants[grant] = { ...structuredClone(tx.state.grants[b.grant]!), id: grant }; });
    const r = await engine.retrieve({ ...b, grant }, query, 'work', 10);
    return r.ok ? r.value.documents.map(d => d.id).sort() : null;
  };
  try {
    assert.equal(await store.ready(), true);
    assert.deepEqual(await ingestor.reconcile('acme'), { indexed: 6, removed: 0, failed: 0, truncated: false });
    assert.deepEqual(await ingestor.reconcile('other'), { indexed: 1, removed: 0, failed: 0, truncated: false });
    assert.deepEqual(await ingestor.reconcile('acme'), { indexed: 0, removed: 0, failed: 0, truncated: false }, 'idempotent');
    // Physical partitioning: the effective (container-floored) classification selects the table.
    assert.equal(await count(audit, 'akac_chunks_restricted', "doc_id IN ('strategy', 'vault-memo')"), 2);
    assert.equal(await count(audit, 'akac_chunks_public', "doc_id='handbook'"), 1);
    assert.equal(await count(audit, 'akac_chunks_confidential', "doc_id IN ('board-notes', 'project-alpha')"), 2);
    assert.equal(await count(audit, 'akac_chunks_restricted', "doc_id='handbook' OR tenant='other'"), 0);
    const strategy = 'acquisition strategy confidential purchase budget';
    assert.deepEqual(await ask(bindings.chief, strategy), ['strategy']);
    assert.equal(await ask(bindings.intern, strategy), null);
    assert.equal(await ask(bindings.lead, strategy), null);
    assert.deepEqual(await ask(bindings.chief, 'Vault memo reserve figure'), ['vault-memo']);
    assert.equal(await ask(bindings.lead, 'Vault memo reserve figure'), null);
    assert.deepEqual(await ask(bindings.lead, 'Product project alpha schedule launch'), ['project-alpha']);
    assert.equal(await ask(bindings.intern, 'Product project alpha schedule launch'), null);
    assert.deepEqual(await ask(other, 'Other tenant notes'), ['o-doc']);
    assert.equal(await ask(bindings.chief, 'Other tenant notes'), null);
    assert.equal(events.filter(e => e.type === 'filter_mismatch').length, 0);
    // A wrong index row is still caught by the authoritative re-check.
    await index.upsert([{ tenant: 'acme', docId: 'strategy', docVersion: 1, chunkId: 'strategy#1#0', ordinal: 0, compartment: 'public', readTokens: ['role:staff'],
      requiredProjects: [], containerTokens: [], model: hash.model, vector: (await hash.embed([strategy]))[0]! }]);
    assert.equal(await ask(bindings.intern, strategy), null);
    assert.equal(events.filter(e => e.type === 'filter_mismatch').length, 1);
    assert.equal((await ingestor.reconcile('acme')).indexed, 1, 'reconcile detects and repairs the corrupted labels');
    assert.equal(await count(audit, 'akac_chunks_restricted', "doc_id='strategy'"), 1);
    assert.equal(await count(audit, 'akac_chunks_public', "doc_id='strategy'"), 0);
    // New version replaces the old chunks; embedder failure yields INDEX_PENDING, then reconcile repairs.
    assert.deepEqual(bare(await ingestor.ingest('acme', 'admin', doc('memo', 'alpha bravo charlie.'))), { ok: true, value: { id: 'memo', version: 1, chunks: 1 } });
    failing = true;
    assert.deepEqual(bare(await ingestor.ingest('acme', 'admin', doc('memo', 'delta echo foxtrot.', { version: 2 }))), { ok: false, code: 'INDEX_PENDING', id: 'memo', version: 2 });
    failing = false;
    assert.deepEqual(await ask(bindings.intern, 'alpha bravo charlie'), ['memo'], 'stale chunks remain until repaired; the engine still serves the authoritative record');
    assert.deepEqual(await ingestor.reconcile('acme'), { indexed: 1, removed: 0, failed: 0, truncated: false });
    assert.equal(await ask(bindings.intern, 'alpha bravo charlie'), null);
    assert.deepEqual(await ask(bindings.intern, 'delta echo foxtrot'), ['memo']);
    // Removal revokes and deletes the chunks.
    assert.ok((await ingestor.remove('acme', 'admin', 'memo')).ok);
    assert.equal(await count(audit, 'akac_chunks_internal', "doc_id='memo'"), 0);
    assert.equal(await ask(bindings.intern, 'delta echo foxtrot'), null);
  } finally { await audit.end(); await index.close(); await store.close(); }
});

test('PostgreSQL vector: filtered nearest-neighbour search keeps recall under a selective filter', { skip }, async () => {
  const { name, appUrl } = await fresh();
  const index = new PgVectorIndex(appUrl, { schema: name, efSearch: 100 });
  try {
    // Deterministic pseudo-random unit vectors: 2000 chunks, 4% readable by role:rare.
    let seed = 12345; const rand = () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed / 2 ** 32 - 0.5; };
    const unit = () => { const v = Float32Array.from({ length: 256 }, rand); const n = Math.hypot(...v); return v.map(x => x / n); };
    const rows: IndexedChunk[] = [];
    for (let d = 0; d < 200; d++) {
      const rare = d % 25 === 0, chunks: IndexedChunk[] = [];
      for (let o = 0; o < 10; o++) chunks.push({ tenant: 'acme', docId: `d${d}`, docVersion: 1, chunkId: `d${d}#1#${o}`, ordinal: o, compartment: 'internal',
        readTokens: [rare ? 'role:rare' : 'role:common'], requiredProjects: [], containerTokens: [], model: 'random', vector: unit() });
      rows.push(...chunks); await index.upsert(chunks);
    }
    const cosine = (a: Float32Array, b: Float32Array) => a.reduce((n, x, i) => n + x * b[i]!, 0);
    let hits = 0, total = 0;
    for (let trial = 0; trial < 10; trial++) {
      const vector = unit(), k = 10;
      const expected = rows.filter(r => r.readTokens[0] === 'role:rare').map(r => ({ id: r.chunkId, s: cosine(vector, r.vector) })).sort((a, b) => b.s - a.s).slice(0, k).map(x => x.id);
      const found = await index.query({ tenant: 'acme', compartments: ['internal'], tokens: ['role:rare'], projects: [], vector, k });
      assert.ok(found.every(h => rows.find(r => r.chunkId === h.chunkId)!.readTokens[0] === 'role:rare'), 'only admitted chunks are ever returned');
      assert.ok(found.every((h, i) => i === 0 || found[i - 1]!.score >= h.score), 'ranked best first');
      hits += found.filter(h => expected.includes(h.chunkId)).length; total += expected.length;
    }
    assert.ok(hits / total >= 0.9, `filtered recall ${hits}/${total}`);
    assert.deepEqual(await index.query({ tenant: 'acme', compartments: ['internal'], tokens: ['role:none'], projects: [], vector: unit(), k: 10 }), []);
  } finally { await index.close(); }
});
