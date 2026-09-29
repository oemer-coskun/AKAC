import { mkdirSync, writeFileSync, appendFileSync } from 'node:fs';
import { cpus, totalmem } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { randomBytes } from 'node:crypto';
import { HashEmbedder } from '../../reference/embedding.ts';
import type { Embedder } from '../../reference/embedding.ts';
import type { VectorIndex } from '../../reference/vector.ts';
import { buildCorpus, PRINCIPALS, TOPICS } from './corpus.ts';
import { evaluateQuality, markdown } from './quality.ts';
import type { QualityResult } from './quality.ts';
import { HERE, fetchModel, lock, transformersEmbedder } from './model.ts';

/**
 * Usage: node bench/quality/eval.ts [--documents 3000] [--embedders hash,minilm]
 *   [--backends memory,pgvector] [--out bench/results/quality.json] [--fetch]
 * pgvector needs AKAC_TEST_DATABASE_URL (a disposable database; a schema is created
 * and dropped). For a model whose dimension differs from the shipped vector(256)
 * column, the throwaway schema applies the procedure documented in migration 002
 * (ALTER the embedding column, recreate the HNSW index).
 */
const { values } = parseArgs({ options: {
  documents: { type: 'string', default: '3000' }, embedders: { type: 'string', default: 'hash,minilm' },
  backends: { type: 'string', default: 'memory' }, out: { type: 'string', default: join(HERE, '..', 'results', 'quality.json') },
  fetch: { type: 'boolean', default: false }, seed: { type: 'string', default: '20260929' }
} });
const log = (m: string) => console.error(`[quality] ${m}`);
if (values.fetch) { await fetchModel({ log }); log('model files verified'); }
const documents = Number(values.documents), seed = Number(values.seed);
if (!Number.isSafeInteger(documents) || documents < TOPICS.length) throw new Error('--documents must be an integer >= 30');
const corpus = buildCorpus({ documents, seed });

async function pgIndex(dimensions: number): Promise<{ index: VectorIndex; close(): Promise<void> }> {
  const url = process.env.AKAC_TEST_DATABASE_URL;
  if (!url) throw new Error('--backends pgvector needs AKAC_TEST_DATABASE_URL');
  const { default: pg } = await import('pg');
  const { migrate } = await import('../../adapters/postgres.ts');
  const { PgVectorIndex } = await import('../../adapters/pgvector.ts');
  const schema = `akac_quality_${randomBytes(5).toString('hex')}`;
  const admin = new pg.Client({ connectionString: url }); await admin.connect();
  await admin.query(`CREATE SCHEMA ${schema}`);
  await migrate(url, { schema });
  if (dimensions !== 256) {
    const ext = (await admin.query("SELECT n.nspname AS s FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='vector'")).rows[0].s as string;
    for (const level of ['public', 'internal', 'confidential', 'restricted']) {
      const t = `${schema}.akac_chunks_${level}`;
      await admin.query(`DROP INDEX ${schema}.akac_chunks_${level}_hnsw`);
      await admin.query(`TRUNCATE ${t}`);
      await admin.query(`ALTER TABLE ${t} ALTER COLUMN embedding TYPE ${ext}.vector(${dimensions})`);
      await admin.query(`CREATE INDEX akac_chunks_${level}_hnsw ON ${t} USING hnsw (embedding ${ext}.vector_cosine_ops) WITH (m = 16, ef_construction = 64)`);
    }
  }
  const index = new PgVectorIndex(url, { schema, dimensions });
  return { index, close: async () => { await index.close().catch(() => {}); await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end(); } };
}

const embedders: Embedder[] = [];
for (const name of values.embedders!.split(',')) {
  if (name === 'hash') embedders.push(new HashEmbedder(256));
  else if (name === 'minilm') embedders.push(await transformersEmbedder());
  else throw new Error(`unknown embedder ${name}`);
}
const results: QualityResult[] = [];
for (const backend of values.backends!.split(',')) {
  for (const embedder of embedders) {
    if (backend === 'memory') results.push(await evaluateQuality(corpus, embedder, { backend, log }));
    else if (backend === 'pgvector') {
      const pg = await pgIndex(embedder.dimensions);
      try { results.push(await evaluateQuality(corpus, embedder, { backend: 'pgvector (HNSW, ef_search 100)', index: pg.index, log })); }
      finally { await pg.close(); }
    } else throw new Error(`unknown backend ${backend}`);
  }
}
const l = lock();
const meta = {
  'Corpus': `${corpus.docs.length} acme documents (+${Object.keys(corpus.state.knowledge).length - corpus.docs.length} globex), ${TOPICS.length} topics, ${corpus.queries.length} queries (${corpus.queries.filter(q => q.kind === 'paraphrase').length} paraphrased, ${corpus.queries.filter(q => q.kind === 'keyword').length} keyword) x ${PRINCIPALS.length} principals, seed ${seed}`,
  'Real model': `${l.model} (base ${l.baseModel}, ${l.license}) at revision ${l.revision}, ${l.dimensions} dimensions, ${l.dtype} ONNX on onnxruntime-node CPU`,
  'Machine': `${process.platform}/${process.arch}, ${cpus().length} x ${cpus()[0]?.model.trim() ?? 'unknown CPU'}, ${Math.round(totalmem() / 2 ** 30)} GiB, Node ${process.version}`,
  'Date': new Date().toISOString().slice(0, 10)
};
const md = markdown(results, meta);
const out = resolve(values.out!);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ meta, results }, null, 2) + '\n');
writeFileSync(out.replace(/\.json$/, '') + '.md', md);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
console.log(md);
const leaks = results.reduce((n, r) => n + r.overall.disclosures + r.overall.crossTenant, 0);
if (leaks) { console.error(`[quality] FAIL: ${leaks} unauthorized or cross-tenant results`); process.exit(1); }
