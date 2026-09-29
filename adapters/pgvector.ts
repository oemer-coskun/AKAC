import pg from 'pg';
import { LEVELS } from '../reference/types.ts';
import type { Level } from '../reference/types.ts';
import { byDocument, byScore, checkChunk, checkQuery, labelDigest } from '../reference/vector.ts';
import type { IndexedChunk, IndexedDocument, VectorHit, VectorIndex, VectorQuery } from '../reference/vector.ts';
import { validId } from '../reference/validation.ts';

export type PgVectorOptions = {
  /** Schema holding the akac_chunks_* tables (search_path). Default: the connection's. */
  schema?: string;
  /** Must equal the vector(N) column created by the migrations (default 256). */
  dimensions?: number;
  /** HNSW candidate list size per query (pgvector default 40). Higher = better filtered recall, slower. */
  efSearch?: number;
  /** Cap on tuples an iterative HNSW scan may visit (pgvector default 20000). */
  maxScanTuples?: number;
  max?: number;
};
const table = (level: Level) => `akac_chunks_${level}`;
const literal = (v: Float32Array) => `[${Array.from(v).join(',')}]`;
const IDENT = /^[a-z_][a-z0-9_]{0,62}$/;
const ROWS = 50;

/**
 * pgvector implementation of VectorIndex. Migration 002 provides one table per
 * classification compartment with forced row-level security on `akac.tenant`; this
 * class sets that setting in every transaction and must connect as a role that
 * neither owns the schema nor bypasses RLS. A query reads only the tables of the
 * compartments it names, applies the token pre-filter in the same statement as
 * the nearest-neighbour ORDER BY, and uses iterative HNSW scans (pgvector >= 0.8)
 * so a selective filter does not starve the result. Chunk text is never stored.
 */
export class PgVectorIndex implements VectorIndex {
  private pool: pg.Pool;
  private dimensions: number;
  private ef: number;
  private scanTuples?: number;
  private ready?: Promise<{ ext: string; iterative: boolean }>;
  constructor(connectionString: string, options: PgVectorOptions = {}) {
    if (options.schema !== undefined && !IDENT.test(options.schema)) throw new Error('Invalid schema name');
    this.dimensions = options.dimensions ?? 256; this.ef = options.efSearch ?? 100; this.scanTuples = options.maxScanTuples;
    if (!Number.isInteger(this.dimensions) || this.dimensions < 1 || this.dimensions > 2000 || !Number.isInteger(this.ef) || this.ef < 1 || this.ef > 1000
      || (this.scanTuples !== undefined && (!Number.isInteger(this.scanTuples) || this.scanTuples < 1 || this.scanTuples > 10_000_000))) throw new Error('Invalid vector options');
    this.pool = new pg.Pool({ connectionString, connectionTimeoutMillis: 5000, statement_timeout: 10000, idle_in_transaction_session_timeout: 15000,
      max: options.max ?? 10, ...(options.schema ? { options: `-c search_path=${options.schema}` } : {}) });
  }
  /** Verifies extension, tables and dimension once; any mismatch fails every operation (closed). */
  private async init() {
    this.ready ??= (async () => {
      const client = await this.pool.connect();
      try {
        const ext = (await client.query("SELECT n.nspname AS schema, e.extversion AS version FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='vector'")).rows[0];
        if (!ext || !IDENT.test(ext.schema)) throw new Error('pgvector extension is not installed');
        for (const level of LEVELS) {
          const row = (await client.query(`SELECT a.atttypmod AS dims FROM pg_attribute a WHERE a.attrelid = to_regclass($1) AND a.attname='embedding' AND NOT a.attisdropped`, [table(level)])).rows[0];
          if (!row) throw new Error(`Missing ${table(level)}; run the migrations`);
          if (Number(row.dims) !== this.dimensions) throw new Error(`${table(level)} has dimension ${row.dims}, expected ${this.dimensions}`);
        }
        const [major = 0, minor = 0] = String(ext.version).split('.').map(Number);
        return { ext: ext.schema as string, iterative: major > 0 || minor >= 8 };
      } finally { client.release(); }
    })();
    try { return await this.ready; } catch (error) { this.ready = undefined; throw error; }
  }
  private async tx<T>(tenant: string, write: boolean, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
    if (!validId(tenant)) throw new Error('Invalid tenant');
    await this.init();
    const client = await this.pool.connect();
    try {
      await client.query(write ? 'BEGIN' : 'BEGIN READ ONLY');
      await client.query("SELECT set_config('akac.tenant', $1, true)", [tenant]);
      const value = await fn(client);
      await client.query('COMMIT'); return value;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
    finally { client.release(); }
  }
  async removeDocument(tenant: string, docId: string): Promise<void> {
    if (!validId(docId)) throw new Error('Invalid document');
    await this.tx(tenant, true, async c => { for (const level of LEVELS) await c.query(`DELETE FROM ${table(level)} WHERE tenant=$1 AND doc_id=$2`, [tenant, docId]); });
  }
  async upsert(chunks: IndexedChunk[]): Promise<void> {
    chunks.forEach(checkChunk);
    if (chunks.some(c => c.vector.length !== this.dimensions)) throw new Error('Vector dimension mismatch');
    const { ext } = await this.init();
    for (const [key, list] of byDocument(chunks)) {
      const { tenant, docId, docVersion } = list[0]!;
      await this.tx(tenant, true, async c => {
        // Serialize writers of one document; a lower version never replaces a higher one.
        await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 1))', [key]);
        let stored = 0;
        for (const level of LEVELS) stored = Math.max(stored, Number((await c.query(`SELECT COALESCE(max(doc_version), 0) AS v FROM ${table(level)} WHERE tenant=$1 AND doc_id=$2`, [tenant, docId])).rows[0].v));
        if (stored > docVersion) return;
        for (const level of LEVELS) await c.query(`DELETE FROM ${table(level)} WHERE tenant=$1 AND doc_id=$2`, [tenant, docId]);
        for (const level of LEVELS) {
          const rows = list.filter(x => x.compartment === level);
          for (let i = 0; i < rows.length; i += ROWS) {
            const batch = rows.slice(i, i + ROWS), params: unknown[] = [];
            const values = batch.map((x, n) => {
              params.push(x.tenant, x.docId, x.docVersion, x.chunkId, x.ordinal, x.readTokens, x.requiredProjects, JSON.stringify(x.containerTokens), x.model, literal(x.vector));
              const p = n * 10;
              return `($${p + 1},$${p + 2},$${p + 3},$${p + 4},$${p + 5},$${p + 6}::text[],$${p + 7}::text[],$${p + 8}::jsonb,$${p + 9},$${p + 10}::${ext}.vector)`;
            });
            await c.query(`INSERT INTO ${table(level)} (tenant, doc_id, doc_version, chunk_id, ordinal, read_tokens, required_projects, container_tokens, model, embedding) VALUES ${values.join(',')}`, params);
          }
        }
      });
    }
  }
  async query(q: VectorQuery): Promise<VectorHit[]> {
    checkQuery(q);
    if (q.vector.length !== this.dimensions) throw new Error('Vector dimension mismatch');
    const { ext, iterative } = await this.init();
    const vector = literal(q.vector), tokens = [...new Set(q.tokens)], projects = [...new Set(q.projects)];
    const distance = `embedding OPERATOR(${ext}.<=>) $1::${ext}.vector`;
    return this.tx(q.tenant, false, async c => {
      await c.query("SELECT set_config('hnsw.ef_search', $1, true)", [String(this.ef)]);
      if (iterative) await c.query("SELECT set_config('hnsw.iterative_scan', 'relaxed_order', true)");
      if (this.scanTuples) await c.query("SELECT set_config('hnsw.max_scan_tuples', $1, true)", [String(this.scanTuples)]);
      const hits: VectorHit[] = [];
      // Only the permitted compartments are ever queried.
      for (const level of new Set(q.compartments)) {
        // With the agent's audience (ADR-020) a chunk must be admitted for the agent as well ($6, $7).
        const both = q.agent ? ' AND read_tokens && $6::text[] AND required_projects <@ $7::text[] AND akac_levels_ok(container_tokens, $6::text[])' : '';
        const rows = (await c.query(`SELECT doc_id, chunk_id, ${distance} AS distance FROM ${table(level)}
          WHERE tenant=$2 AND read_tokens && $3::text[] AND required_projects <@ $4::text[] AND akac_levels_ok(container_tokens, $3::text[])${both}
          ORDER BY ${distance} LIMIT $5`, [vector, q.tenant, tokens, projects, q.k, ...(q.agent ? [[...new Set(q.agent.tokens)], [...new Set(q.agent.projects)]] : [])])).rows;
        for (const r of rows) hits.push({ docId: r.doc_id, chunkId: r.chunk_id, score: 1 - Number(r.distance) });
      }
      // relaxed_order scans return approximately ordered rows; rank exactly here.
      return hits.filter(h => Number.isFinite(h.score)).sort(byScore).slice(0, q.k);
    });
  }
  async state(tenant: string): Promise<Map<string, IndexedDocument>> {
    return this.tx(tenant, false, async c => {
      const out = new Map<string, IndexedDocument>();
      for (const level of LEVELS) {
        const rows = (await c.query(`SELECT DISTINCT ON (doc_id) doc_id, doc_version, model, read_tokens, required_projects, container_tokens FROM ${table(level)} WHERE tenant=$1 ORDER BY doc_id, ordinal`, [tenant])).rows;
        for (const r of rows) {
          const next = { version: Number(r.doc_version), model: r.model as string,
            digest: labelDigest({ compartment: level, readTokens: r.read_tokens, requiredProjects: r.required_projects, containerTokens: r.container_tokens }) };
          out.set(r.doc_id, out.has(r.doc_id) ? { ...next, digest: 'conflict' } : next);
        }
      }
      return out;
    });
  }
  async close() { await this.pool.end(); }
}
