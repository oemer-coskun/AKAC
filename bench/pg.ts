import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { migrate, PostgresStore } from '../adapters/postgres.ts';
import { PgVectorIndex } from '../adapters/pgvector.ts';
import type { IndexedChunk } from '../reference/vector.ts';

/**
 * A throwaway PostgreSQL schema for one benchmark run. The connection URL (an owner
 * that may create schemas and roles, as in CI) comes from AKAC_BENCH_DATABASE_URL or
 * AKAC_TEST_DATABASE_URL; nothing is hard-coded. The measured store and vector index
 * connect as a freshly created runtime role (NOSUPERUSER NOBYPASSRLS, not the owner)
 * with a password generated for this run, so forced row-level security is in effect
 * exactly as in production (requireRls: true). Everything is dropped by close().
 */
export type BenchDb = { store: PostgresStore; index: PgVectorIndex; owner: pg.Client; schema: string; version: string; pgvector: string;
  loadChunks(chunks: IndexedChunk[]): Promise<void>; analyze(): Promise<void>; close(): Promise<void> };
export async function openBenchDb(url: string, options: { max?: number } = {}): Promise<BenchDb> {
  const schema = `akac_bench_${randomBytes(5).toString('hex')}`, role = `${schema}_app`, password = randomBytes(18).toString('hex');
  const owner = new pg.Client({ connectionString: url });
  await owner.connect();
  await owner.query(`CREATE SCHEMA ${schema}`);
  let store: PostgresStore | undefined, index: PgVectorIndex | undefined;
  const close = async () => {
    await store?.close().catch(() => {}); await index?.close().catch(() => {});
    await owner.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(() => {});
    if ((await owner.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [role]).catch(() => ({ rowCount: 0 }))).rowCount) {
      await owner.query(`DROP OWNED BY ${role}`).catch(() => {}); await owner.query(`DROP ROLE ${role}`).catch(() => {});
    }
    await owner.end().catch(() => {});
  };
  try {
    await migrate(url, { schema });
    await owner.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '${password}'`);
    await owner.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role}`);
    await owner.query(`GRANT USAGE ON SCHEMA public TO ${role}`);
    await owner.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${schema} TO ${role}`);
    const app = new URL(url); app.username = role; app.password = password;
    const max = options.max ?? 16;
    store = new PostgresStore(app.toString(), { schema, migrate: false, requireRls: true, max });
    await store.verify();
    index = new PgVectorIndex(app.toString(), { schema, max });
    const version = (await owner.query('SHOW server_version')).rows[0].server_version as string;
    const pgvector = ((await owner.query("SELECT extversion FROM pg_extension WHERE extname='vector'")).rows[0]?.extversion as string | undefined) ?? 'none';
    const ext = (await owner.query("SELECT n.nspname AS s FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='vector'")).rows[0].s as string;
    return {
      store, index, owner, schema, version, pgvector, close,
      // Bulk load as the owner: the same rows PgVectorIndex.upsert writes, in multi-row statements (loading is not measured).
      async loadChunks(chunks) {
        for (const level of ['public', 'internal', 'confidential', 'restricted']) {
          const rows = chunks.filter(c => c.compartment === level);
          for (let i = 0; i < rows.length; i += 500) {
            const params: unknown[] = [];
            const values = rows.slice(i, i + 500).map((x, n) => {
              params.push(x.tenant, x.docId, x.docVersion, x.chunkId, x.ordinal, x.readTokens, x.requiredProjects, JSON.stringify(x.containerTokens), x.model, `[${Array.from(x.vector).join(',')}]`);
              const p = n * 10;
              return `($${p + 1},$${p + 2},$${p + 3},$${p + 4},$${p + 5},$${p + 6}::text[],$${p + 7}::text[],$${p + 8}::jsonb,$${p + 9},$${p + 10}::${ext}.vector)`;
            });
            await owner.query(`INSERT INTO ${schema}.akac_chunks_${level} (tenant, doc_id, doc_version, chunk_id, ordinal, read_tokens, required_projects, container_tokens, model, embedding) VALUES ${values.join(',')}`, params);
          }
        }
      },
      async analyze() {
        for (const r of (await owner.query('SELECT tablename FROM pg_tables WHERE schemaname=$1', [schema])).rows) await owner.query(`ANALYZE ${schema}.${r.tablename}`);
      }
    };
  } catch (error) { await close(); throw error; }
}
