import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ConfigError, loadConfig, loadRetrievalConfig } from '../reference/config.ts';

const dir = mkdtempSync(join(tmpdir(), 'akac-retrieval-'));
const file = (name: string, body: string) => { const p = join(dir, name); writeFileSync(p, body); return p; };
const base = { AKAC_CREDENTIALS_FILE: file('agent.json', JSON.stringify([{}])), AKAC_RETRIEVAL: 'vector' };
const pg = { DATABASE_URL: 'postgresql://app@db.invalid:5432/akac' };
const vault = 'postgresql://app@vault.invalid:5432/akac';
const problems = (env: Record<string, string>) => { try { loadConfig({ ...base, ...env }); return []; } catch (error) { assert.ok(error instanceof ConfigError); return error.problems; } };
const rejects = (env: Record<string, string>, part: string) => assert.ok(problems(env).some(p => p.includes(part)), `${part} in ${JSON.stringify(problems(env))}`);
test.after(() => rmSync(dir, { recursive: true, force: true }));

test('config: retrieval defaults to lexical and vector-only settings are refused without vector mode', () => {
  assert.equal(loadConfig({ AKAC_CREDENTIALS_FILE: base.AKAC_CREDENTIALS_FILE }).retrieval, undefined);
  assert.equal(loadConfig({ AKAC_CREDENTIALS_FILE: base.AKAC_CREDENTIALS_FILE, AKAC_RETRIEVAL: 'lexical' }).retrieval, undefined);
  assert.equal(loadRetrievalConfig({}), undefined);
  rejects({ AKAC_RETRIEVAL: 'lexical', AKAC_VECTOR_BACKEND: 'pgvector' }, 'AKAC_VECTOR_BACKEND requires AKAC_RETRIEVAL=vector');
  rejects({ AKAC_RETRIEVAL: 'semantic' }, 'AKAC_RETRIEVAL must be lexical or vector');
});
test('config: pgvector needs a database and an embedder; dimensions and score are validated', () => {
  rejects({ AKAC_EMBEDDINGS: 'hash' }, 'requires DATABASE_URL');
  rejects({ ...pg }, 'needs an embedder');
  rejects({ ...pg, AKAC_EMBEDDINGS: 'onnx' }, 'AKAC_EMBEDDINGS must be hash');
  rejects({ ...pg, AKAC_VECTOR_BACKEND: 'sqlite', AKAC_EMBEDDINGS: 'hash' }, 'AKAC_VECTOR_BACKEND must be');
  for (const bad of ['abc', '0', '2001', '1.5', '-1']) rejects({ ...pg, AKAC_EMBEDDINGS: 'hash', AKAC_EMBEDDINGS_DIMENSIONS: bad }, 'AKAC_EMBEDDINGS_DIMENSIONS');
  rejects({ ...pg, AKAC_EMBEDDINGS: 'hash', AKAC_EMBEDDINGS_DIMENSIONS: '4' }, 'hash embedder');
  for (const bad of ['high', '2', '-1.5']) rejects({ ...pg, AKAC_EMBEDDINGS: 'hash', AKAC_RETRIEVAL_MIN_SCORE: bad }, 'AKAC_RETRIEVAL_MIN_SCORE');
  rejects({ ...pg, AKAC_EMBEDDINGS: 'hash', AKAC_VECTOR_RESTRICTED_DATABASE_URL: pg.DATABASE_URL }, 'must differ');
  const c = loadConfig({ ...base, ...pg, AKAC_EMBEDDINGS: 'hash', AKAC_RETRIEVAL_MIN_SCORE: '0.25', AKAC_VECTOR_RESTRICTED_DATABASE_URL: vault }).retrieval;
  assert.deepEqual(c, { backend: 'pgvector', databaseUrl: pg.DATABASE_URL, restrictedDatabaseUrl: vault, embedder: { kind: 'hash', dimensions: 256 }, minScore: 0.25 });
  assert.equal(loadConfig({ ...base, ...pg, AKAC_VECTOR_DATABASE_URL: 'postgresql://other@other.invalid/akac', AKAC_EMBEDDINGS: 'hash' }).retrieval?.databaseUrl, 'postgresql://other@other.invalid/akac');
});
test('config: HTTP embedder settings, API key from a file only', () => {
  const key = file('key', 'synthetic-embedding-key\n');
  const http = { ...pg, AKAC_EMBEDDINGS_URL: 'https://embeddings.example.invalid', AKAC_EMBEDDINGS_MODEL: 'synthetic-model' };
  const c = loadConfig({ ...base, ...http, AKAC_EMBEDDINGS_DIMENSIONS: '256', AKAC_EMBEDDINGS_API_KEY_FILE: key }).retrieval;
  assert.deepEqual(c?.embedder, { kind: 'http', url: 'https://embeddings.example.invalid', model: 'synthetic-model', dimensions: 256, apiKey: 'synthetic-embedding-key' });
  rejects({ ...http, AKAC_EMBEDDINGS_MODEL: '' }, 'AKAC_EMBEDDINGS_MODEL is required');
  rejects({ ...http, AKAC_EMBEDDINGS_URL: 'http://embeddings.example.invalid' }, 'https');
  rejects({ ...http, AKAC_EMBEDDINGS_API_KEY_FILE: join(dir, 'missing') }, 'AKAC_EMBEDDINGS_API_KEY_FILE');
  rejects({ ...http, AKAC_EMBEDDINGS_API_KEY_FILE: file('empty', '\n') }, 'single-line key');
  rejects({ ...http, AKAC_EMBEDDINGS_API_KEY: 'synthetic' }, 'not an environment value');
  assert.ok(loadConfig({ ...base, ...pg, AKAC_EMBEDDINGS_URL: 'http://127.0.0.1:9', AKAC_EMBEDDINGS_MODEL: 'm' }).retrieval, 'loopback http is allowed');
});
test('config: production refuses the memory index and the hash embedder unless explicitly accepted', () => {
  rejects({ NODE_ENV: 'production', AKAC_VECTOR_BACKEND: 'memory', AKAC_EMBEDDINGS: 'hash', AKAC_ALLOW_HASH_EMBEDDER: 'true' }, 'development only');
  rejects({ NODE_ENV: 'production', ...pg, AKAC_EMBEDDINGS: 'hash' }, 'AKAC_ALLOW_HASH_EMBEDDER=true');
  rejects({ NODE_ENV: 'production', ...pg, AKAC_EMBEDDINGS: 'hash', AKAC_ALLOW_HASH_EMBEDDER: 'perhaps' }, 'AKAC_ALLOW_HASH_EMBEDDER must be');
  assert.equal(loadConfig({ ...base, NODE_ENV: 'production', ...pg, AKAC_EMBEDDINGS: 'hash', AKAC_ALLOW_HASH_EMBEDDER: 'true' }).retrieval?.backend, 'pgvector');
  assert.equal(loadConfig({ ...base, VECTOR: '', AKAC_VECTOR_BACKEND: 'memory', AKAC_EMBEDDINGS: 'hash' }).retrieval?.backend, 'memory');
  rejects({ AKAC_VECTOR_BACKEND: 'memory', AKAC_EMBEDDINGS: 'hash', AKAC_VECTOR_DATABASE_URL: 'postgresql://x' }, 'pgvector backend only');
});
test('config: AKAC_PG_ALLOW_BYPASS_RLS is a validated, development-only opt-out', () => {
  rejects({ AKAC_RETRIEVAL: 'lexical', AKAC_PG_ALLOW_BYPASS_RLS: 'maybe' }, 'AKAC_PG_ALLOW_BYPASS_RLS must be true or false');
  rejects({ AKAC_RETRIEVAL: 'lexical', NODE_ENV: 'production', AKAC_PG_ALLOW_BYPASS_RLS: 'true' }, 'refused when NODE_ENV=production');
  assert.equal(loadConfig({ AKAC_CREDENTIALS_FILE: base.AKAC_CREDENTIALS_FILE, AKAC_PG_ALLOW_BYPASS_RLS: 'true' }).retrieval, undefined);
  assert.equal(loadConfig({ AKAC_CREDENTIALS_FILE: base.AKAC_CREDENTIALS_FILE, NODE_ENV: 'production', AKAC_PG_ALLOW_BYPASS_RLS: 'false' }).retrieval, undefined);
});

test('config: database passwords come from *_PASSWORD_FILE, are URL-encoded and validated up front', () => {
  const secret = randomBytes(12).toString('hex') + ' /@:%#?', pw = file('pw', secret + '\n');
  const withPassword = new URL(pg.DATABASE_URL); withPassword.password = encodeURIComponent(secret);
  const decoded = (u: string | undefined) => decodeURIComponent(new URL(u!).password);
  const env = { ...base, AKAC_EMBEDDINGS: 'hash', ...pg, AKAC_DATABASE_PASSWORD_FILE: pw };
  assert.equal(loadConfig(env).retrieval?.databaseUrl, withPassword.toString());
  assert.equal(decoded(loadConfig(env).retrieval?.databaseUrl), secret);
  assert.equal(new URL(loadConfig(env).retrieval!.databaseUrl!).username, 'app');
  const c = loadConfig({ ...env, AKAC_VECTOR_DATABASE_URL: 'postgresql://vec@vec.invalid/akac', AKAC_VECTOR_DATABASE_PASSWORD_FILE: pw, AKAC_VECTOR_RESTRICTED_DATABASE_URL: vault, AKAC_VECTOR_RESTRICTED_DATABASE_PASSWORD_FILE: pw }).retrieval;
  assert.equal(decoded(c?.databaseUrl), secret); assert.equal(decoded(c?.restrictedDatabaseUrl), secret);
  assert.equal(new URL(c!.restrictedDatabaseUrl!).hostname, 'vault.invalid');
  assert.equal(loadConfig({ ...env, AKAC_DATABASE_PASSWORD_FILE: file('crlf', 'abc\r\n') }).retrieval?.databaseUrl, Object.assign(new URL(pg.DATABASE_URL), { password: 'abc' }).toString());
  rejects({ ...env, AKAC_DATABASE_PASSWORD_FILE: join(dir, 'missing') }, 'AKAC_DATABASE_PASSWORD_FILE: file not readable');
  for (const body of ['', '\n', 'two\nlines\n']) rejects({ ...env, AKAC_DATABASE_PASSWORD_FILE: file('bad', body) }, 'single-line password');
  rejects({ ...env, DATABASE_URL: withPassword.toString() }, 'already contains a password');
  rejects({ ...base, AKAC_EMBEDDINGS: 'hash', AKAC_DATABASE_PASSWORD_FILE: pw }, 'AKAC_DATABASE_PASSWORD_FILE requires DATABASE_URL');
  rejects({ ...env, AKAC_MIGRATION_DATABASE_PASSWORD_FILE: pw }, 'AKAC_MIGRATION_DATABASE_PASSWORD_FILE requires AKAC_MIGRATION_DATABASE_URL');
  rejects({ ...env, AKAC_MIGRATION_DATABASE_URL: 'postgresql://owner@db.invalid/akac', AKAC_MIGRATION_DATABASE_PASSWORD_FILE: join(dir, 'missing') }, 'AKAC_MIGRATION_DATABASE_PASSWORD_FILE: file not readable');
  rejects({ AKAC_RETRIEVAL: 'lexical', AKAC_VECTOR_DATABASE_PASSWORD_FILE: pw }, 'requires AKAC_RETRIEVAL=vector');
  rejects({ ...env, DATABASE_URL: 'not a url' }, 'not a valid connection URL');
});
test('config: NODE_ENV=production refuses inline database passwords and accepts password files', () => {
  const secret = randomBytes(12).toString('hex'), pw = file('pw-prod', secret + '\n');
  const inline = new URL(pg.DATABASE_URL); inline.password = secret;
  const prod = { NODE_ENV: 'production', AKAC_EMBEDDINGS: 'hash', AKAC_ALLOW_HASH_EMBEDDER: 'true' };
  rejects({ ...prod, DATABASE_URL: inline.toString() }, 'must not embed a password when NODE_ENV=production');
  rejects({ ...prod, ...pg, AKAC_MIGRATION_DATABASE_URL: inline.toString() }, 'AKAC_MIGRATION_DATABASE_URL must not embed a password');
  assert.equal(new URL(loadConfig({ ...base, ...prod, ...pg, AKAC_DATABASE_PASSWORD_FILE: pw }).retrieval!.databaseUrl!).password, secret);
  assert.equal(loadConfig({ ...base, ...prod, ...pg }).retrieval?.databaseUrl, pg.DATABASE_URL, 'no password at all (certificate or peer authentication) is allowed');
});
