import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { SqliteStore } from './store.ts';
import { PostgresStore } from '../adapters/postgres.ts';
import type { Store } from './types.ts';
import type { Credential } from './http.ts';
import type { AdminCredential } from './admin.ts';
import type { AdminJwtConfiguration, JwtConfiguration } from '../adapters/jwt.ts';
import type { Level } from './log.ts';
import { PgVectorIndex } from '../adapters/pgvector.ts';
import { Ingestor } from './ingest.ts';
import type { IngestEvent } from './ingest.ts';
import { ControlPlane } from './control.ts';
import { HashEmbedder, HttpEmbedder } from './embedding.ts';
import type { Embedder } from './embedding.ts';
import { VectorCandidateSource } from './retrieval.ts';
import { MemoryVectorIndex, RoutedVectorIndex } from './vector.ts';
import type { VectorIndex } from './vector.ts';
import type { CandidateSource } from './engine.ts';

type Env = Record<string, string | undefined>;
const truthy = (v: string | undefined) => v === undefined ? undefined : /^(1|true|yes)$/i.test(v) ? true : /^(0|false|no)$/i.test(v) ? false : null;
/** Each connection string has a `_PASSWORD_FILE` companion so the secret is mounted as a file (Docker/Kubernetes secret), never embedded in the URL or committed. */
const PASSWORD_FILES: Record<string, string> = {
  DATABASE_URL: 'AKAC_DATABASE_PASSWORD_FILE',
  AKAC_MIGRATION_DATABASE_URL: 'AKAC_MIGRATION_DATABASE_PASSWORD_FILE',
  AKAC_VECTOR_DATABASE_URL: 'AKAC_VECTOR_DATABASE_PASSWORD_FILE',
  AKAC_VECTOR_RESTRICTED_DATABASE_URL: 'AKAC_VECTOR_RESTRICTED_DATABASE_PASSWORD_FILE'
};
/**
 * Resolves one connection string: the password comes from the companion file (one trailing newline removed) and
 * is set through the URL API, so it is percent-encoded. A URL that already carries a password together with a
 * password file is ambiguous and refused; with NODE_ENV=production an inline password is refused outright.
 * Problems are appended (the raw value is returned so validation can continue).
 */
export function connectionUrl(env: Env, name: string, problems: string[]): string | undefined {
  const raw = env[name] || undefined, fileVar = PASSWORD_FILES[name]!, file = env[fileVar] || undefined;
  if (!raw) { if (file) problems.push(`${fileVar} requires ${name}`); return undefined; }
  const production = env.NODE_ENV === 'production';
  let url: URL;
  try { url = new URL(raw); } catch { if (file || production) problems.push(`${name} is not a valid connection URL`); return raw; }
  if (url.password) {
    if (file) problems.push(`${name} already contains a password; remove it or unset ${fileVar}`);
    else if (production) problems.push(`${name} must not embed a password when NODE_ENV=production; supply it with ${fileVar}`);
    return raw;
  }
  if (!file) return raw;
  let password: string | undefined;
  try { password = readFileSync(file, 'utf8').replace(/\r?\n$/, ''); } catch { problems.push(`${fileVar}: file not readable`); return raw; }
  if (!password || /[\r\n]/.test(password)) { problems.push(`${fileVar} must contain a single-line password`); return raw; }
  url.password = encodeURIComponent(password);
  return url.toString();
}
/** Same as connectionUrl, throwing ConfigError (for scripts and store construction). */
export function requireConnectionUrl(env: Env, name: string): string | undefined {
  const problems: string[] = [], url = connectionUrl(env, name, problems);
  if (problems.length) throw new ConfigError(problems);
  return url;
}
/**
 * DATABASE_URL selects PostgreSQL. AKAC_AUTO_MIGRATE (default true, development) lets the
 * process migrate on startup: with AKAC_MIGRATION_DATABASE_URL as the schema owner, else
 * with DATABASE_URL. Set it to false in production: `scripts/migrate.ts` runs as a separate
 * job under the owner role and the runtime role needs no DDL rights.
 *
 * The runtime role MUST be subject to row-level security (R30): a superuser or BYPASSRLS
 * role is refused at start-up (PostgresStore.verify) and by readiness, and every
 * transaction fails closed. AKAC_PG_ALLOW_BYPASS_RLS=true disables the check for local
 * development only (a warning is logged; refused when NODE_ENV=production).
 */
export function configuredStore(env: Env = process.env, options: { warn?: (message: string) => void } = {}): Store {
  const databaseUrl = requireConnectionUrl(env, 'DATABASE_URL');
  if (databaseUrl) {
    const auto = truthy(env.AKAC_AUTO_MIGRATE) ?? true;
    const owner = requireConnectionUrl(env, 'AKAC_MIGRATION_DATABASE_URL');
    const bypass = truthy(env.AKAC_PG_ALLOW_BYPASS_RLS) === true;
    if (bypass) options.warn?.('AKAC_PG_ALLOW_BYPASS_RLS=true: the PostgreSQL runtime role is not required to be subject to row-level security; tenant isolation then rests on the application alone (development only)');
    return new PostgresStore(databaseUrl, { migrate: auto ? owner ?? true : false, requireRls: !bypass });
  }
  const path = env.AKAC_DB ?? 'data/akac.sqlite';
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  return new SqliteStore(path);
}

export type RetrievalConfig = {
  backend: 'pgvector' | 'memory';
  /** pgvector: the runtime connection (default DATABASE_URL) and an optional dedicated database for the restricted compartment. */
  databaseUrl?: string; restrictedDatabaseUrl?: string;
  embedder: { kind: 'http'; url: string; model: string; dimensions: number; apiKey?: string } | { kind: 'hash'; dimensions: number };
  minScore?: number;
};
export const DEFAULT_DIMENSIONS = 256;
const int = (v: string) => /^\d{1,5}$/.test(v) ? Number(v) : NaN;
/** AKAC_RETRIEVAL=vector selects permission-aware vector retrieval; anything else is bounded lexical retrieval. */
function retrievalConfig(env: Env, problems: string[]): RetrievalConfig | undefined {
  const mode = env.AKAC_RETRIEVAL || 'lexical';
  if (!['lexical', 'vector'].includes(mode)) { problems.push('AKAC_RETRIEVAL must be lexical or vector'); return undefined; }
  if (mode === 'lexical') {
    for (const name of ['AKAC_VECTOR_BACKEND', 'AKAC_VECTOR_DATABASE_URL', 'AKAC_VECTOR_DATABASE_PASSWORD_FILE', 'AKAC_VECTOR_RESTRICTED_DATABASE_URL', 'AKAC_VECTOR_RESTRICTED_DATABASE_PASSWORD_FILE', 'AKAC_RETRIEVAL_MIN_SCORE'])
      if (env[name]) problems.push(`${name} requires AKAC_RETRIEVAL=vector`);
    return undefined;
  }
  const production = env.NODE_ENV === 'production';
  const before = problems.length;
  const backend = env.AKAC_VECTOR_BACKEND || 'pgvector';
  if (!['pgvector', 'memory'].includes(backend)) problems.push('AKAC_VECTOR_BACKEND must be pgvector or memory');
  if (backend === 'memory' && production) problems.push('AKAC_VECTOR_BACKEND=memory is for development only and is refused when NODE_ENV=production');
  const vectorUrl = connectionUrl(env, 'AKAC_VECTOR_DATABASE_URL', problems), restrictedDatabaseUrl = connectionUrl(env, 'AKAC_VECTOR_RESTRICTED_DATABASE_URL', problems);
  const databaseUrl = vectorUrl || connectionUrl(env, 'DATABASE_URL', problems);
  if (backend === 'pgvector' && !databaseUrl) problems.push('AKAC_VECTOR_BACKEND=pgvector requires DATABASE_URL (or AKAC_VECTOR_DATABASE_URL)');
  if (backend === 'memory' && (env.AKAC_VECTOR_DATABASE_URL || env.AKAC_VECTOR_RESTRICTED_DATABASE_URL)) problems.push('AKAC_VECTOR_DATABASE_URL and AKAC_VECTOR_RESTRICTED_DATABASE_URL apply to the pgvector backend only');
  if (restrictedDatabaseUrl && restrictedDatabaseUrl === databaseUrl) problems.push('AKAC_VECTOR_RESTRICTED_DATABASE_URL must differ from the default vector database');

  const dimensions = env.AKAC_EMBEDDINGS_DIMENSIONS ? int(env.AKAC_EMBEDDINGS_DIMENSIONS) : DEFAULT_DIMENSIONS;
  if (!Number.isInteger(dimensions) || dimensions < 1 || dimensions > 2000) problems.push('AKAC_EMBEDDINGS_DIMENSIONS must be an integer 1-2000 matching the pgvector column');
  let embedder: RetrievalConfig['embedder'] | undefined;
  if (env.AKAC_EMBEDDINGS_URL) {
    let apiKey: string | undefined;
    if (env.AKAC_EMBEDDINGS_API_KEY_FILE) {
      try { apiKey = readFileSync(env.AKAC_EMBEDDINGS_API_KEY_FILE, 'utf8').trim(); } catch { problems.push('AKAC_EMBEDDINGS_API_KEY_FILE: file not readable'); }
      if (apiKey !== undefined && (!apiKey || /[\r\n]/.test(apiKey))) problems.push('AKAC_EMBEDDINGS_API_KEY_FILE must contain a single-line key');
    }
    if (env.AKAC_EMBEDDINGS_API_KEY) problems.push('Provide the embedding API key with AKAC_EMBEDDINGS_API_KEY_FILE, not an environment value');
    if (!env.AKAC_EMBEDDINGS_MODEL) problems.push('AKAC_EMBEDDINGS_MODEL is required with AKAC_EMBEDDINGS_URL');
    else if (Number.isInteger(dimensions)) {
      try { new HttpEmbedder({ baseUrl: env.AKAC_EMBEDDINGS_URL, model: env.AKAC_EMBEDDINGS_MODEL, dimensions, ...(apiKey ? { apiKey } : {}) }); }
      catch (error) { problems.push(`AKAC_EMBEDDINGS_URL: ${error instanceof Error ? error.message : 'invalid'}`); }
    }
    embedder = { kind: 'http', url: env.AKAC_EMBEDDINGS_URL, model: env.AKAC_EMBEDDINGS_MODEL ?? '', dimensions, ...(apiKey ? { apiKey } : {}) };
  } else if (env.AKAC_EMBEDDINGS === 'hash') {
    const allow = truthy(env.AKAC_ALLOW_HASH_EMBEDDER);
    if (allow === null) problems.push('AKAC_ALLOW_HASH_EMBEDDER must be true or false');
    if (production && allow !== true) problems.push('AKAC_EMBEDDINGS=hash is lexical feature hashing, not a semantic model; set AKAC_ALLOW_HASH_EMBEDDER=true to accept it in production');
    if (Number.isInteger(dimensions)) { try { new HashEmbedder(dimensions); } catch { problems.push('AKAC_EMBEDDINGS_DIMENSIONS must be 8-4096 for the hash embedder'); } }
    embedder = { kind: 'hash', dimensions };
  } else problems.push(env.AKAC_EMBEDDINGS ? 'AKAC_EMBEDDINGS must be hash' : 'Vector retrieval needs an embedder: set AKAC_EMBEDDINGS_URL (with AKAC_EMBEDDINGS_MODEL) or AKAC_EMBEDDINGS=hash');
  let minScore: number | undefined;
  if (env.AKAC_RETRIEVAL_MIN_SCORE) {
    minScore = /^-?\d+(\.\d+)?$/.test(env.AKAC_RETRIEVAL_MIN_SCORE) ? Number(env.AKAC_RETRIEVAL_MIN_SCORE) : NaN;
    if (!(minScore >= -1 && minScore <= 1)) { problems.push('AKAC_RETRIEVAL_MIN_SCORE must be a number between -1 and 1'); minScore = undefined; }
  }
  if (problems.length > before || !embedder) return undefined;
  return { backend: backend as 'pgvector' | 'memory', ...(databaseUrl && backend === 'pgvector' ? { databaseUrl } : {}), ...(restrictedDatabaseUrl ? { restrictedDatabaseUrl } : {}), embedder, ...(minScore !== undefined ? { minScore } : {}) };
}
/** Retrieval settings alone (for tools such as scripts/reconcile.ts); throws ConfigError. */
export function loadRetrievalConfig(env: Env = process.env): RetrievalConfig | undefined {
  const problems: string[] = [], config = retrievalConfig(env, problems);
  if (problems.length) throw new ConfigError(problems);
  return config;
}
export type Retrieval = { candidates: CandidateSource; ingestor: Ingestor; close(): Promise<void> };
/** Builds the index, embedder, candidate source and ingestor. Index pools are released by close(). */
export function configuredRetrieval(config: RetrievalConfig, store: Store, control: ControlPlane, onEvent?: (event: IngestEvent) => void): Retrieval {
  const embedder: Embedder = config.embedder.kind === 'http'
    ? new HttpEmbedder({ baseUrl: config.embedder.url, model: config.embedder.model, dimensions: config.embedder.dimensions, ...(config.embedder.apiKey ? { apiKey: config.embedder.apiKey } : {}) })
    : new HashEmbedder(config.embedder.dimensions);
  const pools: PgVectorIndex[] = [];
  const open = (url: string) => { const p = new PgVectorIndex(url, { dimensions: embedder.dimensions }); pools.push(p); return p; };
  let index: VectorIndex;
  if (config.backend === 'memory') index = new MemoryVectorIndex();
  else {
    const main = open(config.databaseUrl!);
    index = config.restrictedDatabaseUrl ? new RoutedVectorIndex({ default: main, restricted: open(config.restrictedDatabaseUrl) }) : main;
  }
  return {
    candidates: new VectorCandidateSource({ index, embedder, ...(config.minScore !== undefined ? { minScore: config.minScore } : {}) }),
    ingestor: new Ingestor({ control, store, index, embedder, ...(onEvent ? { onEvent } : {}) }),
    close: async () => { await Promise.all(pools.map(p => p.close())); }
  };
}

export type Listener = { host: string; port: number };
export type ServerConfig = {
  agent: Listener & { credentials: Credential[]; jwt?: JwtConfiguration };
  admin?: Listener & { credentials: AdminCredential[]; jwt?: AdminJwtConfiguration };
  metrics: Listener;
  opa?: { url: string; revision?: string };
  retrieval?: RetrievalConfig;
  logLevel: Level;
};
export class ConfigError extends Error {
  problems: string[];
  constructor(problems: string[]) { super(`Invalid configuration:\n- ${problems.join('\n- ')}`); this.problems = problems; }
}
/** Validates the whole environment up front and reports every problem at once. */
export function loadConfig(env: Env = process.env): ServerConfig {
  const problems: string[] = [];
  const port = (name: string, ...alias: string[]) => {
    const key = [name, ...alias].find(k => env[k] !== undefined) ?? name, raw = env[key];
    return { key, value: raw === undefined || raw === '' ? undefined : /^\d{1,5}$/.test(raw) && Number(raw) <= 65535 ? Number(raw) : (problems.push(`${key} must be a port number 0-65535`), NaN) };
  };
  const host = (name: string, fallback: string) => {
    const v = env[name] ?? fallback;
    if (!v || /\s/.test(v)) problems.push(`${name} must be a host name or address`);
    return v;
  };
  const json = <T>(name: string): T | undefined => {
    const path = env[name];
    if (!path) return undefined;
    if (!existsSync(path)) { problems.push(`${name}: file not found: ${path}`); return undefined; }
    try { return JSON.parse(readFileSync(path, 'utf8')) as T; } catch { problems.push(`${name}: not readable JSON`); return undefined; }
  };
  const one = (a: string, b: string, what: string) => {
    if (env[a] && env[b]) problems.push(`Set only one of ${a} or ${b} (${what} authentication modes cannot be mixed)`);
  };
  const auto = truthy(env.AKAC_AUTO_MIGRATE);
  if (auto === null) problems.push('AKAC_AUTO_MIGRATE must be true or false');
  const bypass = truthy(env.AKAC_PG_ALLOW_BYPASS_RLS);
  if (bypass === null) problems.push('AKAC_PG_ALLOW_BYPASS_RLS must be true or false');
  if (bypass === true && env.NODE_ENV === 'production') problems.push('AKAC_PG_ALLOW_BYPASS_RLS=true is for local development only and is refused when NODE_ENV=production');
  const level = (env.AKAC_LOG_LEVEL ?? 'info') as Level;
  if (!['debug', 'info', 'warn', 'error'].includes(level)) problems.push('AKAC_LOG_LEVEL must be debug, info, warn or error');

  if (Boolean(env.AKAC_CREDENTIALS_FILE) === Boolean(env.AKAC_JWT_CONFIG_FILE)) problems.push('Set exactly one of AKAC_CREDENTIALS_FILE or AKAC_JWT_CONFIG_FILE');
  const credentials = json<Credential[]>('AKAC_CREDENTIALS_FILE'), jwt = json<JwtConfiguration>('AKAC_JWT_CONFIG_FILE');
  if (credentials !== undefined && (!Array.isArray(credentials) || !credentials.length)) problems.push('AKAC_CREDENTIALS_FILE must contain a non-empty array');
  const agentPort = port('PORT', 'AKAC_PORT');
  const agent = { host: host('HOST', '127.0.0.1'), port: agentPort.value ?? 8787, credentials: credentials ?? [], ...(jwt ? { jwt } : {}) };

  one('AKAC_ADMIN_CREDENTIALS_FILE', 'AKAC_ADMIN_JWT_CONFIG_FILE', 'admin');
  const adminCredentials = json<AdminCredential[]>('AKAC_ADMIN_CREDENTIALS_FILE'), adminJwt = json<AdminJwtConfiguration>('AKAC_ADMIN_JWT_CONFIG_FILE');
  if (adminCredentials !== undefined && (!Array.isArray(adminCredentials) || !adminCredentials.length)) problems.push('AKAC_ADMIN_CREDENTIALS_FILE must contain a non-empty array');
  if (adminJwt && jwt && adminJwt.audience === jwt.audience) problems.push('The admin JWT audience must differ from the agent JWT audience');
  const adminPort = port('AKAC_ADMIN_PORT', 'ADMIN_PORT');
  const admin = adminCredentials || adminJwt
    ? { host: host('AKAC_ADMIN_HOST', '127.0.0.1'), port: adminPort.value ?? 8788, credentials: adminCredentials ?? [], ...(adminJwt ? { jwt: adminJwt } : {}) } : undefined;

  const metricsPort = port('AKAC_METRICS_PORT', 'METRICS_PORT');
  const metrics = { host: host('AKAC_METRICS_HOST', '127.0.0.1'), port: metricsPort.value ?? 9464 };
  const ports = [['agent', agent.port], ...(admin ? [['admin', admin.port]] : []), ['metrics', metrics.port]] as [string, number][];
  for (const [i, [n, p]] of ports.entries()) if (p !== 0 && ports.some(([m, q], j) => j < i && q === p && (m !== n))) problems.push(`The ${n} listener port ${p} is already used by another listener`);
  if (env.OPA_URL) { try { if (!/^https?:$/.test(new URL(env.OPA_URL).protocol)) throw new Error(); } catch { problems.push('OPA_URL must be an http(s) URL'); } }
  connectionUrl(env, 'DATABASE_URL', problems); connectionUrl(env, 'AKAC_MIGRATION_DATABASE_URL', problems);
  const retrieval = retrievalConfig(env, problems);
  if (problems.length) throw new ConfigError(problems);
  return { agent, ...(retrieval ? { retrieval } : {}), ...(admin ? { admin } : {}), metrics, ...(env.OPA_URL ? { opa: { url: env.OPA_URL, ...(env.OPA_REVISION ? { revision: env.OPA_REVISION } : {}) } } : {}), logLevel: level };
}
