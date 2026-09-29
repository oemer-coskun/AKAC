import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { createHash, createPrivateKey } from 'node:crypto';
import { dirname } from 'node:path';
import { SqliteStore } from './store.ts';
import { PostgresStore } from '../adapters/postgres.ts';
import type { Store } from './types.ts';
import { RUNTIME_OBLIGATION_MODES } from './http.ts';
import type { Credential, RuntimeObligationMode } from './http.ts';
import type { AdminCredential } from './admin.ts';
import type { AdminJwtConfiguration, JwtConfiguration, PepJwtConfiguration } from '../adapters/jwt.ts';
import type { PepCredential } from './authzen.ts';
import type { Level } from './log.ts';
import { DPOP_ALGORITHMS, DPOP_LIMITS, checkPublicUrl } from '../adapters/dpop.ts';
import type { DpopAlgorithm, DpopMode } from '../adapters/dpop.ts';
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
import { FileCheckpointSigner, VaultTransitSigner } from './custody.ts';
import type { CheckpointSigner } from './custody.ts';
import { LEVELS } from './types.ts';
import { validId } from './validation.ts';
import { ANCHORS, AnchorMonitor, FileAnchorBaseline } from './anchors.ts';
import type { AnchorOptions } from './anchors.ts';
import { HOOK_LIMITS } from './hooks.ts';
import { BACKOFF, TIMING_LIMITS, VOLUME_LIMITS } from './protection.ts';
import { DECISION_CACHE } from './decision-cache.ts';
import { COMBINATION_WINDOW } from './knowledge.ts';
import { ALGORITHMS, isAlgorithm, keyIdMatches } from './crypto/algorithms.ts';
import { EncryptingStore, LocalDevKeyProvider } from './content-crypto.ts';
import type { KeyProvider } from './content-crypto.ts';
import type { AlgorithmId } from './crypto/algorithms.ts';

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
/**
 * Content encryption at rest (0.6, R195): AKAC_CONTENT_ENCRYPTION=off (default),
 * `local` (LocalDevKeyProvider with AKAC_CONTENT_KEY_FILE; development only, refused when
 * NODE_ENV=production) or `provider` (the KeyProvider an extension passes as
 * options.keyProvider, for example a KMS or HSM provider; refused without one).
 */
export function contentEncryption(store: Store, env: Env, options: { warn?: (message: string) => void; keyProvider?: KeyProvider } = {}): Store {
  const mode = env.AKAC_CONTENT_ENCRYPTION ?? 'off';
  if (mode === 'off') return store;
  if (mode === 'provider') {
    if (!options.keyProvider) throw new ConfigError(['AKAC_CONTENT_ENCRYPTION=provider requires a key provider supplied by an extension']);
    return new EncryptingStore(store, options.keyProvider);
  }
  if (mode !== 'local') throw new ConfigError(['AKAC_CONTENT_ENCRYPTION must be off, local or provider']);
  if (env.NODE_ENV === 'production') throw new ConfigError(['AKAC_CONTENT_ENCRYPTION=local is for development only and is refused when NODE_ENV=production']);
  const file = env.AKAC_CONTENT_KEY_FILE;
  if (!file) throw new ConfigError(['AKAC_CONTENT_ENCRYPTION=local requires AKAC_CONTENT_KEY_FILE']);
  options.warn?.('AKAC_CONTENT_ENCRYPTION=local: content keys are kept in a local file (development only; keep the file out of database backups)');
  return new EncryptingStore(store, new LocalDevKeyProvider(file));
}
export function configuredStore(env: Env = process.env, options: { warn?: (message: string) => void; keyProvider?: KeyProvider } = {}): Store {
  const databaseUrl = requireConnectionUrl(env, 'DATABASE_URL');
  if (databaseUrl) {
    const auto = truthy(env.AKAC_AUTO_MIGRATE) ?? true;
    const owner = requireConnectionUrl(env, 'AKAC_MIGRATION_DATABASE_URL');
    const bypass = truthy(env.AKAC_PG_ALLOW_BYPASS_RLS) === true;
    if (bypass) options.warn?.('AKAC_PG_ALLOW_BYPASS_RLS=true: the PostgreSQL runtime role is not required to be subject to row-level security; tenant isolation then rests on the application alone (development only)');
    return contentEncryption(new PostgresStore(databaseUrl, { migrate: auto ? owner ?? true : false, requireRls: !bypass }), env, options);
  }
  const path = env.AKAC_DB ?? 'data/akac.sqlite';
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  return contentEncryption(new SqliteStore(path), env, options);
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
/** `monitor`: the embedding anchor monitor when AKAC_ANCHOR_TEXTS_FILE is set (0.6, ADR-020); the caller starts and schedules it. */
export type Retrieval = { candidates: CandidateSource; ingestor: Ingestor; monitor?: AnchorMonitor; close(): Promise<void> };
/** Builds the index, embedder, candidate source and ingestor. Index pools are released by close(). */
export function configuredRetrieval(config: RetrievalConfig, store: Store, control: ControlPlane, onEvent?: (event: IngestEvent) => void,
  anchors?: { texts: string[]; threshold: number; baselineFile?: string; bootstrap?: boolean; onCheck?: AnchorOptions['onCheck'] }): Retrieval {
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
  const monitor = anchors ? new AnchorMonitor({ embedder, anchors: anchors.texts, threshold: anchors.threshold,
    ...(anchors.baselineFile ? { store: new FileAnchorBaseline(anchors.baselineFile) } : {}), ...(anchors.bootstrap ? { bootstrap: true } : {}), ...(anchors.onCheck ? { onCheck: anchors.onCheck } : {}) }) : undefined;
  return {
    candidates: new VectorCandidateSource({ index, embedder, ...(config.minScore !== undefined ? { minScore: config.minScore } : {}), ...(monitor ? { monitor } : {}) }),
    ingestor: new Ingestor({ control, store, index, embedder, ...(onEvent ? { onEvent } : {}) }),
    ...(monitor ? { monitor } : {}),
    close: async () => { monitor?.stop(); await Promise.all(pools.map(p => p.close())); }
  };
}

export type Listener = { host: string; port: number };
/** Per-listener DPoP settings (absent = off). */
export type ListenerDpop = { mode: DpopMode; publicUrl: string };
export type DpopConfig = { algorithms: DpopAlgorithm[]; skewSeconds: number; replay: 'memory' | 'postgres' };
export type ServerConfig = {
  agent: Listener & { credentials: Credential[]; jwt?: JwtConfiguration; dpop?: ListenerDpop; runtimeObligations: RuntimeObligationMode };
  admin?: Listener & { credentials: AdminCredential[]; jwt?: AdminJwtConfiguration; dpop?: ListenerDpop };
  /** Optional AuthZEN PDP listener for trusted enforcement points (default off). */
  authzen?: Listener & { credentials: PepCredential[]; jwt?: PepJwtConfiguration; dpop?: ListenerDpop; reasons: 'none' | 'admin'; publicUrl?: string };
  /** Ed25519 key with which the control plane signs format 2 audit checkpoints (server-held; anchor offline-signed checkpoints for independence). */
  checkpoint?: { privatePem: string; keyId: string };
  /** Post-quantum or hybrid file key (0.6, ADR-021; AKAC_CHECKPOINT_ALG other than ed25519): signs format 3 checkpoints. The key lives in KeyObjects, never as a PEM string. */
  checkpointSigner?: CheckpointSigner;
  /** Alternative to `checkpoint` (0.6): a Vault Transit key at a pinned version (AKAC_CHECKPOINT_SIGNER=vault-transit). */
  checkpointVault?: VaultCheckpointConfig;
  /** AKAC_CHECKPOINT_SIGNER=extension (0.6, ADR-023): the signer (for example an HSM) is supplied by an extension; the stock server has none and refuses to start. */
  checkpointExtension?: ExtensionCheckpointConfig;
  /** Shared DPoP verification settings; present when either listener enables DPoP. */
  dpop?: DpopConfig;
  metrics: Listener;
  opa?: { url: string; revision?: string };
  retrieval?: RetrievalConfig;
  /**
   * Where rate windows, admin Idempotency-Key records and job locks live (0.6, ADR-016):
   * `memory` (per instance) or `postgres` (shared by every instance on DATABASE_URL).
   */
  sharedState: { mode: 'memory' | 'postgres'; idempotencyTtlSeconds: number };
  /** Release and retrieval protections (0.6, ADR-020). Everything is off or fail-closed by default. */
  protection: ProtectionConfig;
  logLevel: Level;
};
type Classification = typeof LEVELS[number];
/**
 * Release and retrieval protection settings (0.6, ADR-020):
 * - AKAC_MIN_RESPONSE_MS / AKAC_RESPONSE_JITTER_MS: response-time floor and jitter for retrieve, contexts and AuthZEN evaluation.
 * - AKAC_DENIAL_HINTS=true: closed denial hints from the caller's own state (default false).
 * - AKAC_BACKOFF_FREE_DENIALS (enables), AKAC_BACKOFF_BASE_SECONDS, AKAC_BACKOFF_MAX_SECONDS: progressive backoff after repeated denials.
 * - AKAC_VOLUME_LIMITS=confidential:bytes=1048576,documents=100;restricted:bytes=65536,documents=10, AKAC_VOLUME_WINDOW_SECONDS, AKAC_VOLUME_ON_EXCEED=deny|approval.
 * - AKAC_DECISION_CACHE_TTL_MS (enables; at most 300000), AKAC_DECISION_CACHE_MAX.
 * - AKAC_RELEASE_REQUIRED_FILTERS=confidential=pii;restricted=pii,dlp: filter ids every release at that classification or above must pass.
 * - AKAC_HOOK_TIMEOUT_MS, AKAC_HOOK_FAILURE=deny|skip (default deny), AKAC_HOOKS_MODULE: an ES module exporting releaseFilters and deriveSanitizers.
 * - AKAC_ANCHOR_TEXTS_FILE (JSON array of strings; enables), AKAC_ANCHOR_THRESHOLD, AKAC_ANCHOR_INTERVAL_SECONDS, AKAC_ANCHOR_BASELINE_FILE (vector retrieval only).
 */
export type ProtectionConfig = {
  timing?: { minMs: number; jitterMs: number };
  denialHints: boolean;
  backoff?: { freeDenials: number; baseSeconds: number; maxSeconds: number };
  volume?: { windowSeconds: number; limits: Partial<Record<Classification, { bytes?: number; documents?: number }>>; onExceed: 'deny' | 'approval' };
  decisionCache?: { ttlMs: number; maxEntries: number };
  /** AKAC_COMBINATION_WINDOW_MS (0.6b, R188): combination rules span every grant of a (user, agent) pair within this window. */
  combinationWindowMs?: number;
  hooks: { timeoutMs: number; failure: 'deny' | 'skip'; requiredFilters: Partial<Record<Classification, string[]>>; module?: string };
  /** `bootstrap` (AKAC_ANCHOR_BOOTSTRAP): the first start may create the baseline when none exists (one-time; remove afterwards). */
  anchors?: { texts: string[]; threshold: number; intervalSeconds: number; baselineFile?: string; bootstrap?: boolean };
};
/**
 * AKAC_CHECKPOINT_KEY_FILE holds an Ed25519 private key as PKCS#8/traditional PEM or as a JWK; AKAC_CHECKPOINT_KEY_ID
 * names it (verifiers pin the id). With NODE_ENV=production the file must not be readable by group or others
 * (checked where the platform reports POSIX modes): no access for others and no group write; group read is allowed because
 * mounted Kubernetes secrets are group-readable under fsGroup. The key is normalised to PKCS#8 PEM in memory only.
 */
export type VaultCheckpointConfig = { address: string; keyName: string; keyVersion: number; publicPem: string; tokenFile: string; keyId?: string; mount?: string; namespace?: string };
const VAULT_VARS = ['AKAC_VAULT_ADDR', 'AKAC_VAULT_TRANSIT_KEY', 'AKAC_VAULT_KEY_VERSION', 'AKAC_VAULT_TOKEN_FILE', 'AKAC_VAULT_TRANSIT_MOUNT', 'AKAC_VAULT_NAMESPACE', 'AKAC_CHECKPOINT_PUBLIC_KEY_FILE'];
/**
 * AKAC_CHECKPOINT_SIGNER=vault-transit (0.6, ADR-016): checkpoints are signed by a HashiCorp Vault Transit
 * ed25519 key at a pinned version; the private key never reaches the gateway. The public key of that version
 * (AKAC_CHECKPOINT_PUBLIC_KEY_FILE, SPKI PEM) is pinned too, and every signature is verified before use.
 */
function vaultCheckpointConfig(env: Env, problems: string[]): { vault: VaultCheckpointConfig } | undefined {
  const before = problems.length;
  if (env.AKAC_CHECKPOINT_KEY_FILE) problems.push('AKAC_CHECKPOINT_KEY_FILE cannot be combined with AKAC_CHECKPOINT_SIGNER=vault-transit');
  for (const name of ['AKAC_VAULT_ADDR', 'AKAC_VAULT_TRANSIT_KEY', 'AKAC_VAULT_KEY_VERSION', 'AKAC_VAULT_TOKEN_FILE', 'AKAC_CHECKPOINT_PUBLIC_KEY_FILE'])
    if (!env[name]) problems.push(`${name} is required with AKAC_CHECKPOINT_SIGNER=vault-transit`);
  if (env.AKAC_VAULT_TOKEN) problems.push('Provide the Vault token with AKAC_VAULT_TOKEN_FILE, not an environment value');
  const version = env.AKAC_VAULT_KEY_VERSION && /^\d{1,9}$/.test(env.AKAC_VAULT_KEY_VERSION) ? Number(env.AKAC_VAULT_KEY_VERSION) : NaN;
  if (env.AKAC_VAULT_KEY_VERSION && !(version >= 1)) problems.push('AKAC_VAULT_KEY_VERSION must be a positive integer (the pinned Transit key version)');
  let publicPem = '';
  if (env.AKAC_CHECKPOINT_PUBLIC_KEY_FILE) { try { publicPem = readFileSync(env.AKAC_CHECKPOINT_PUBLIC_KEY_FILE, 'utf8'); } catch { problems.push('AKAC_CHECKPOINT_PUBLIC_KEY_FILE: file not readable'); } }
  if (problems.length > before) return undefined;
  const vault: VaultCheckpointConfig = { address: env.AKAC_VAULT_ADDR!, keyName: env.AKAC_VAULT_TRANSIT_KEY!, keyVersion: version, publicPem, tokenFile: env.AKAC_VAULT_TOKEN_FILE!,
    ...(env.AKAC_CHECKPOINT_KEY_ID ? { keyId: env.AKAC_CHECKPOINT_KEY_ID } : {}), ...(env.AKAC_VAULT_TRANSIT_MOUNT ? { mount: env.AKAC_VAULT_TRANSIT_MOUNT } : {}),
    ...(env.AKAC_VAULT_NAMESPACE ? { namespace: env.AKAC_VAULT_NAMESPACE } : {}) };
  try { vaultSigner(vault); } catch (error) { problems.push(`Vault checkpoint signer: ${error instanceof Error ? error.message : 'invalid'}`); return undefined; }
  return { vault };
}
/** Builds the Vault Transit signer; the token file is re-read on every signature (Vault Agent rotates it). */
export function vaultSigner(v: VaultCheckpointConfig): VaultTransitSigner {
  return new VaultTransitSigner({ address: v.address, keyName: v.keyName, keyVersion: v.keyVersion, publicPem: v.publicPem,
    token: () => readFileSync(v.tokenFile, 'utf8').trim(), ...(v.keyId ? { keyId: v.keyId } : {}), ...(v.mount ? { mount: v.mount } : {}), ...(v.namespace ? { namespace: v.namespace } : {}) });
}
/**
 * AKAC_CHECKPOINT_ALG (0.6, ADR-021) selects the checkpoint signature algorithm: ed25519 (default; format 2 checkpoints, readable by every
 * 0.4+ verifier) or a registered post-quantum or hybrid algorithm (format 3). The key file then holds PKCS#8 PEM (the hybrid: an Ed25519
 * block followed by an ML-DSA-65 block) and AKAC_CHECKPOINT_KEY_ID must be <alg>:<label>. Vault Transit stays Ed25519 only.
 */
function pqCheckpointConfig(env: Env, problems: string[], alg: AlgorithmId): { signer: CheckpointSigner } | undefined {
  const file = env.AKAC_CHECKPOINT_KEY_FILE, keyId = env.AKAC_CHECKPOINT_KEY_ID;
  if (!file || !keyId) { problems.push('AKAC_CHECKPOINT_ALG=' + alg + ' requires AKAC_CHECKPOINT_KEY_FILE and AKAC_CHECKPOINT_KEY_ID'); return undefined; }
  if (!keyIdMatches(keyId, alg)) { problems.push(`AKAC_CHECKPOINT_KEY_ID must be ${alg}:<label> (1-128 characters of A-Z a-z 0-9 . _ : + -) for AKAC_CHECKPOINT_ALG=${alg}`); return undefined; }
  let raw: Buffer;
  try {
    if (env.NODE_ENV === 'production' && process.platform !== 'win32' && (statSync(file).mode & 0o027) !== 0) {
      problems.push('AKAC_CHECKPOINT_KEY_FILE must not be accessible by others or writable by group (chmod 600 or 640) when NODE_ENV=production'); return undefined;
    }
    raw = readFileSync(file);
  } catch { problems.push('AKAC_CHECKPOINT_KEY_FILE: file not readable'); return undefined; }
  try { return { signer: new FileCheckpointSigner(raw, keyId, alg) }; } // erases raw after parsing
  catch { raw.fill(0); problems.push(`AKAC_CHECKPOINT_KEY_FILE: not readable ${alg} private key material (PKCS#8 PEM)`); return undefined; }
}
/**
 * AKAC_CHECKPOINT_SIGNER=extension (0.6, ADR-023): checkpoints are signed by a CheckpointSigner that an extension supplies (for
 * example an HSM holding the Ed25519 and ML-DSA-65 keys of a hybrid algorithm). Only the algorithm and the <alg>:<label> key id are
 * configured here; no key file or Vault variable is accepted. The stock server has no such signer and refuses to start (R164).
 */
export type ExtensionCheckpointConfig = { alg: AlgorithmId; keyId: string };
function extensionCheckpointConfig(env: Env, problems: string[], alg: AlgorithmId): { extension: ExtensionCheckpointConfig } | undefined {
  const keyId = env.AKAC_CHECKPOINT_KEY_ID;
  if (env.AKAC_CHECKPOINT_KEY_FILE) problems.push('AKAC_CHECKPOINT_KEY_FILE cannot be combined with AKAC_CHECKPOINT_SIGNER=extension');
  for (const name of VAULT_VARS) if (env[name]) problems.push(`${name} requires AKAC_CHECKPOINT_SIGNER=vault-transit`);
  if (!keyId || !keyIdMatches(keyId, alg)) problems.push(`AKAC_CHECKPOINT_KEY_ID must be ${alg}:<label> (1-128 characters of A-Z a-z 0-9 . _ : + -) with AKAC_CHECKPOINT_SIGNER=extension`);
  return problems.length ? undefined : { extension: { alg, keyId: keyId! } };
}
function checkpointConfig(env: Env, problems: string[]): { privatePem: string; keyId: string } | { vault: VaultCheckpointConfig } | { signer: CheckpointSigner } | { extension: ExtensionCheckpointConfig } | undefined {
  const signer = env.AKAC_CHECKPOINT_SIGNER || 'file';
  const alg = env.AKAC_CHECKPOINT_ALG || 'ed25519';
  if (!isAlgorithm(alg)) { problems.push(`AKAC_CHECKPOINT_ALG must be one of ${ALGORITHMS.join(', ')}`); return undefined; }
  if (signer === 'extension') return extensionCheckpointConfig(env, problems, alg);
  if (alg !== 'ed25519' && signer === 'vault-transit') { problems.push('AKAC_CHECKPOINT_SIGNER=vault-transit signs Ed25519 only (AKAC_CHECKPOINT_ALG must be ed25519); see docs/CRYPTO-AGILITY.md'); return undefined; }
  if (alg !== 'ed25519' && signer === 'file') return pqCheckpointConfig(env, problems, alg);
  if (!['file', 'vault-transit'].includes(signer)) { problems.push('AKAC_CHECKPOINT_SIGNER must be file or vault-transit (or extension, with a signer an extension supplies)'); return undefined; }
  if (signer === 'vault-transit') return vaultCheckpointConfig(env, problems);
  for (const name of VAULT_VARS) if (env[name]) problems.push(`${name} requires AKAC_CHECKPOINT_SIGNER=vault-transit`);
  const file = env.AKAC_CHECKPOINT_KEY_FILE, keyId = env.AKAC_CHECKPOINT_KEY_ID;
  if (!file && !keyId) return undefined;
  if (!file || !keyId) { problems.push('AKAC_CHECKPOINT_KEY_FILE and AKAC_CHECKPOINT_KEY_ID must be set together'); return undefined; }
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(keyId)) { problems.push('AKAC_CHECKPOINT_KEY_ID must be 1-128 characters of A-Z a-z 0-9 . _ : -'); return undefined; }
  let raw: string;
  try {
    if (env.NODE_ENV === 'production' && process.platform !== 'win32' && (statSync(file).mode & 0o027) !== 0) {
      problems.push('AKAC_CHECKPOINT_KEY_FILE must not be accessible by others or writable by group (chmod 600 or 640) when NODE_ENV=production'); return undefined;
    }
    raw = readFileSync(file, 'utf8');
  } catch { problems.push('AKAC_CHECKPOINT_KEY_FILE: file not readable'); return undefined; }
  try {
    const key = raw.trimStart().startsWith('{') ? createPrivateKey({ key: JSON.parse(raw), format: 'jwk' }) : createPrivateKey(raw);
    if (key.asymmetricKeyType !== 'ed25519') { problems.push('AKAC_CHECKPOINT_KEY_FILE must contain an Ed25519 private key'); return undefined; }
    return { privatePem: key.export({ type: 'pkcs8', format: 'pem' }).toString(), keyId };
  } catch { problems.push('AKAC_CHECKPOINT_KEY_FILE: not a readable Ed25519 private key (PEM or JWK)'); return undefined; }
}
/** The checkpoint signer alone (scripts/checkpoint.ts sign); throws ConfigError. Undefined when none is configured. */
export function loadCheckpointSigner(env: Env = process.env): CheckpointSigner | undefined {
  const problems: string[] = [], c = checkpointConfig(env, problems);
  if (c && 'extension' in c) problems.push('AKAC_CHECKPOINT_SIGNER=extension requires a checkpoint signer supplied by an extension; none is available here');
  if (problems.length) throw new ConfigError(problems);
  return !c || 'extension' in c ? undefined : 'vault' in c ? vaultSigner(c.vault) : 'signer' in c ? c.signer : new FileCheckpointSigner(c.privatePem, c.keyId);
}
export class ConfigError extends Error {
  problems: string[];
  constructor(problems: string[]) { super(`Invalid configuration:\n- ${problems.join('\n- ')}`); this.problems = problems; }
}
const number = (env: Env, name: string, problems: string[], min: number, max: number, fallback?: number): number | undefined => {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = /^\d{1,10}$/.test(raw) ? Number(raw) : NaN;
  if (!(n >= min && n <= max)) { problems.push(`${name} must be an integer ${min}-${max}`); return undefined; }
  return n;
};
/** `a=1,b=2` -> entries; anything else is a problem. */
const pairs = (name: string, text: string, problems: string[]): [string, string][] | undefined => {
  const out: [string, string][] = [];
  for (const part of text.split(',')) {
    const m = /^([a-z_]+)=(\d{1,15})$/.exec(part.trim());
    if (!m) { problems.push(`${name}: expected name=number pairs`); return undefined; }
    out.push([m[1]!, m[2]!]);
  }
  return out;
};
function protectionConfig(env: Env, problems: string[], vector: boolean): ProtectionConfig {
  const minMs = number(env, 'AKAC_MIN_RESPONSE_MS', problems, 0, TIMING_LIMITS.maxMinMs), jitterMs = number(env, 'AKAC_RESPONSE_JITTER_MS', problems, 0, TIMING_LIMITS.maxJitterMs);
  if (env.AKAC_RESPONSE_JITTER_MS && !env.AKAC_MIN_RESPONSE_MS) problems.push('AKAC_RESPONSE_JITTER_MS requires AKAC_MIN_RESPONSE_MS');
  const hints = truthy(env.AKAC_DENIAL_HINTS);
  if (hints === null) problems.push('AKAC_DENIAL_HINTS must be true or false');
  const free = number(env, 'AKAC_BACKOFF_FREE_DENIALS', problems, 1, 1000), base = number(env, 'AKAC_BACKOFF_BASE_SECONDS', problems, 1, 3600, BACKOFF.baseSeconds), max = number(env, 'AKAC_BACKOFF_MAX_SECONDS', problems, 1, 86_400, BACKOFF.maxSeconds);
  if (!env.AKAC_BACKOFF_FREE_DENIALS && (env.AKAC_BACKOFF_BASE_SECONDS || env.AKAC_BACKOFF_MAX_SECONDS)) problems.push('AKAC_BACKOFF_BASE_SECONDS and AKAC_BACKOFF_MAX_SECONDS require AKAC_BACKOFF_FREE_DENIALS');
  if (base !== undefined && max !== undefined && max < base) problems.push('AKAC_BACKOFF_MAX_SECONDS must be at least AKAC_BACKOFF_BASE_SECONDS');
  let volume: ProtectionConfig['volume'];
  if (env.AKAC_VOLUME_LIMITS) {
    const limits: NonNullable<ProtectionConfig['volume']>['limits'] = {};
    for (const entry of env.AKAC_VOLUME_LIMITS.split(';')) {
      const [level, rest, ...extra] = entry.trim().split(':');
      if (!level || !(LEVELS as readonly string[]).includes(level) || !rest || extra.length || Object.hasOwn(limits, level)) { problems.push('AKAC_VOLUME_LIMITS must be level:bytes=N,documents=N entries separated by ;'); break; }
      const kv = pairs('AKAC_VOLUME_LIMITS', rest, problems);
      if (!kv) break;
      const l: { bytes?: number; documents?: number } = {};
      for (const [k, v] of kv) {
        if ((k !== 'bytes' && k !== 'documents') || Object.hasOwn(l, k) || !(Number(v) >= 1 && Number(v) <= VOLUME_LIMITS.max)) { problems.push('AKAC_VOLUME_LIMITS: use bytes and documents once each, as positive integers'); break; }
        l[k] = Number(v);
      }
      limits[level as Classification] = l;
    }
    const window = number(env, 'AKAC_VOLUME_WINDOW_SECONDS', problems, 1, 86_400, 3600), onExceed = env.AKAC_VOLUME_ON_EXCEED || 'deny';
    if (!['deny', 'approval'].includes(onExceed)) problems.push('AKAC_VOLUME_ON_EXCEED must be deny or approval');
    if (window !== undefined) volume = { windowSeconds: window, limits, onExceed: onExceed as 'deny' | 'approval' };
  } else for (const name of ['AKAC_VOLUME_WINDOW_SECONDS', 'AKAC_VOLUME_ON_EXCEED']) if (env[name]) problems.push(`${name} requires AKAC_VOLUME_LIMITS`);
  const combinationWindowMs = number(env, 'AKAC_COMBINATION_WINDOW_MS', problems, COMBINATION_WINDOW.defaultMs, COMBINATION_WINDOW.maxMs);
  const ttl = number(env, 'AKAC_DECISION_CACHE_TTL_MS', problems, 1, DECISION_CACHE.maxTtlMs), cacheMax = number(env, 'AKAC_DECISION_CACHE_MAX', problems, 1, 1_000_000, DECISION_CACHE.maxEntries);
  if (!env.AKAC_DECISION_CACHE_TTL_MS && env.AKAC_DECISION_CACHE_MAX) problems.push('AKAC_DECISION_CACHE_MAX requires AKAC_DECISION_CACHE_TTL_MS');
  const requiredFilters: ProtectionConfig['hooks']['requiredFilters'] = {};
  if (env.AKAC_RELEASE_REQUIRED_FILTERS) {
    for (const entry of env.AKAC_RELEASE_REQUIRED_FILTERS.split(';')) {
      const m = /^([a-z]+)=([^=;]+)$/.exec(entry.trim()), ids = m?.[2]!.split(',').map(x => x.trim());
      if (!m || !(LEVELS as readonly string[]).includes(m[1]!) || Object.hasOwn(requiredFilters, m[1]!) || !ids!.length || ids!.length > 16 || !ids!.every(validId) || new Set(ids).size !== ids!.length) { problems.push('AKAC_RELEASE_REQUIRED_FILTERS must be level=id,id entries separated by ;'); break; }
      requiredFilters[m[1] as Classification] = ids!;
    }
  }
  const timeoutMs = number(env, 'AKAC_HOOK_TIMEOUT_MS', problems, 1, HOOK_LIMITS.maxTimeoutMs, HOOK_LIMITS.timeoutMs), failure = env.AKAC_HOOK_FAILURE || 'deny';
  if (!['deny', 'skip'].includes(failure)) problems.push('AKAC_HOOK_FAILURE must be deny or skip');
  let anchors: ProtectionConfig['anchors'];
  if (env.AKAC_ANCHOR_TEXTS_FILE) {
    if (!vector) problems.push('AKAC_ANCHOR_TEXTS_FILE requires AKAC_RETRIEVAL=vector');
    let texts: unknown = [];
    try { texts = JSON.parse(readFileSync(env.AKAC_ANCHOR_TEXTS_FILE, 'utf8')); } catch { problems.push('AKAC_ANCHOR_TEXTS_FILE: not readable JSON'); }
    if (!Array.isArray(texts) || !texts.length || texts.length > ANCHORS.maxAnchors || texts.some(t => typeof t !== 'string' || !t.trim() || t.length > ANCHORS.maxText) || new Set(texts).size !== texts.length) {
      problems.push(`AKAC_ANCHOR_TEXTS_FILE must be a JSON array of 1-${ANCHORS.maxAnchors} distinct non-empty strings`); texts = [];
    }
    const t = env.AKAC_ANCHOR_THRESHOLD ? (/^(0?\.\d{1,6}|1(\.0+)?)$/.test(env.AKAC_ANCHOR_THRESHOLD) ? Number(env.AKAC_ANCHOR_THRESHOLD) : NaN) : ANCHORS.threshold;
    if (!(t > 0 && t <= 1)) problems.push('AKAC_ANCHOR_THRESHOLD must be a number above 0 and at most 1');
    const interval = number(env, 'AKAC_ANCHOR_INTERVAL_SECONDS', problems, 1, 86_400, 300);
    // The baseline must survive restarts (0.6 review): without a file every restart would silently re-baseline.
    if (!env.AKAC_ANCHOR_BASELINE_FILE) problems.push('AKAC_ANCHOR_TEXTS_FILE requires AKAC_ANCHOR_BASELINE_FILE (a persistent baseline)');
    const bootstrap = truthy(env.AKAC_ANCHOR_BOOTSTRAP);
    if (bootstrap === null) problems.push('AKAC_ANCHOR_BOOTSTRAP must be true or false');
    anchors = { texts: texts as string[], threshold: t, intervalSeconds: interval ?? 300, ...(env.AKAC_ANCHOR_BASELINE_FILE ? { baselineFile: env.AKAC_ANCHOR_BASELINE_FILE } : {}),
      ...(bootstrap === true ? { bootstrap: true } : {}) };
  } else for (const name of ['AKAC_ANCHOR_THRESHOLD', 'AKAC_ANCHOR_INTERVAL_SECONDS', 'AKAC_ANCHOR_BASELINE_FILE', 'AKAC_ANCHOR_BOOTSTRAP']) if (env[name]) problems.push(`${name} requires AKAC_ANCHOR_TEXTS_FILE`);
  return { ...(minMs !== undefined ? { timing: { minMs, jitterMs: jitterMs ?? 0 } } : {}), denialHints: hints === true,
    ...(free !== undefined ? { backoff: { freeDenials: free, baseSeconds: base ?? BACKOFF.baseSeconds, maxSeconds: max ?? BACKOFF.maxSeconds } } : {}), ...(volume ? { volume } : {}),
    ...(ttl !== undefined ? { decisionCache: { ttlMs: ttl, maxEntries: cacheMax ?? DECISION_CACHE.maxEntries } } : {}),
    ...(combinationWindowMs !== undefined ? { combinationWindowMs } : {}),
    hooks: { timeoutMs: timeoutMs ?? HOOK_LIMITS.timeoutMs, failure: failure as 'deny' | 'skip', requiredFilters, ...(env.AKAC_HOOKS_MODULE ? { module: env.AKAC_HOOKS_MODULE } : {}) }, ...(anchors ? { anchors } : {}) };
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
  const dpopMode = (name: string, urlName: string, signed: boolean, listener: string): ListenerDpop | undefined => {
    const raw = env[name] || 'off', url = env[urlName];
    if (!['off', 'optional', 'required'].includes(raw)) { problems.push(`${name} must be off, optional or required`); return undefined; }
    if (raw === 'off') { if (url) problems.push(`${urlName} requires ${name} to be optional or required`); return undefined; }
    if (!signed) problems.push(`${name}=${raw} requires JWT authentication on the ${listener} listener; opaque credentials cannot be sender-constrained`);
    if (!url) { problems.push(`${urlName} is required with ${name}=${raw} (the externally visible base URL; the Host header is not trusted)`); return undefined; }
    try { checkPublicUrl(url); if (env.NODE_ENV === 'production' && new URL(url).protocol !== 'https:') problems.push(`${urlName} must be https when NODE_ENV=production`); }
    catch { problems.push(`${urlName} must be an http(s) URL without credentials, query or fragment`); return undefined; }
    return { mode: raw as DpopMode, publicUrl: url };
  };
  const agentDpop = dpopMode('AKAC_DPOP', 'AKAC_PUBLIC_URL', jwt !== undefined, 'agent');
  // AKAC_RUNTIME_OBLIGATIONS (0.6, R123): deny (default) or trusted-enforcer (clients run inside a runtime enforcer).
  const runtimeObligations = (env.AKAC_RUNTIME_OBLIGATIONS || 'deny') as RuntimeObligationMode;
  if (!RUNTIME_OBLIGATION_MODES.includes(runtimeObligations)) problems.push(`AKAC_RUNTIME_OBLIGATIONS must be one of ${RUNTIME_OBLIGATION_MODES.join(', ')}`);
  const agent = { host: host('HOST', '127.0.0.1'), port: agentPort.value ?? 8787, credentials: credentials ?? [], ...(jwt ? { jwt } : {}), ...(agentDpop ? { dpop: agentDpop } : {}), runtimeObligations };

  one('AKAC_ADMIN_CREDENTIALS_FILE', 'AKAC_ADMIN_JWT_CONFIG_FILE', 'admin');
  const adminCredentials = json<AdminCredential[]>('AKAC_ADMIN_CREDENTIALS_FILE'), adminJwt = json<AdminJwtConfiguration>('AKAC_ADMIN_JWT_CONFIG_FILE');
  if (adminCredentials !== undefined && (!Array.isArray(adminCredentials) || !adminCredentials.length)) problems.push('AKAC_ADMIN_CREDENTIALS_FILE must contain a non-empty array');
  if (adminJwt && jwt && adminJwt.audience === jwt.audience) problems.push('The admin JWT audience must differ from the agent JWT audience');
  const adminPort = port('AKAC_ADMIN_PORT', 'ADMIN_PORT');
  const adminDpop = dpopMode('AKAC_ADMIN_DPOP', 'AKAC_ADMIN_PUBLIC_URL', adminJwt !== undefined, 'admin');
  if (adminDpop && !adminCredentials && !adminJwt) problems.push('AKAC_ADMIN_DPOP requires the admin listener (AKAC_ADMIN_JWT_CONFIG_FILE)');
  const admin = adminCredentials || adminJwt
    ? { host: host('AKAC_ADMIN_HOST', '127.0.0.1'), port: adminPort.value ?? 8788, credentials: adminCredentials ?? [], ...(adminJwt ? { jwt: adminJwt } : {}), ...(adminDpop ? { dpop: adminDpop } : {}) } : undefined;
  // Optional AuthZEN PDP listener for trusted enforcement points: its own credentials, audience and port.
  const azNames = ['AKAC_AUTHZEN_HOST', 'AKAC_AUTHZEN_CREDENTIALS_FILE', 'AKAC_AUTHZEN_JWT_CONFIG_FILE', 'AKAC_AUTHZEN_REASONS', 'AKAC_AUTHZEN_PUBLIC_URL', 'AKAC_AUTHZEN_DPOP'];
  const azPort = port('AKAC_AUTHZEN_PORT');
  let authzen: ServerConfig['authzen'], authzenDpop: ListenerDpop | undefined;
  if (azPort.value === undefined && !Number.isNaN(azPort.value)) { for (const n of azNames) if (env[n]) problems.push(`${n} requires AKAC_AUTHZEN_PORT`); }
  else if (azPort.value !== undefined) {
    one('AKAC_AUTHZEN_CREDENTIALS_FILE', 'AKAC_AUTHZEN_JWT_CONFIG_FILE', 'AuthZEN');
    if (!env.AKAC_AUTHZEN_CREDENTIALS_FILE && !env.AKAC_AUTHZEN_JWT_CONFIG_FILE) problems.push('AKAC_AUTHZEN_PORT requires AKAC_AUTHZEN_CREDENTIALS_FILE or AKAC_AUTHZEN_JWT_CONFIG_FILE');
    const pepCredentials = json<PepCredential[]>('AKAC_AUTHZEN_CREDENTIALS_FILE'), pepJwt = json<PepJwtConfiguration>('AKAC_AUTHZEN_JWT_CONFIG_FILE');
    if (pepCredentials !== undefined && (!Array.isArray(pepCredentials) || !pepCredentials.length)) problems.push('AKAC_AUTHZEN_CREDENTIALS_FILE must contain a non-empty array');
    if (pepJwt && ((jwt && pepJwt.audience === jwt.audience) || (adminJwt && pepJwt.audience === adminJwt.audience))) problems.push('The AuthZEN JWT audience must differ from the agent and admin JWT audiences');
    // A credential is valid on exactly one listener.
    const digests = (list: { token?: unknown }[] | undefined) => (Array.isArray(list) ? list : []).flatMap(c => typeof c?.token === 'string' ? [createHash('sha256').update(c.token).digest('hex')] : []);
    const others = new Set([...digests(credentials), ...digests(adminCredentials)]);
    if (digests(pepCredentials).some(d => others.has(d))) problems.push('AuthZEN credentials must not reuse agent or admin credentials');
    // The public URL also serves the metadata document, so it is valid without DPoP.
    if (env.AKAC_AUTHZEN_DPOP && env.AKAC_AUTHZEN_DPOP !== 'off') authzenDpop = dpopMode('AKAC_AUTHZEN_DPOP', 'AKAC_AUTHZEN_PUBLIC_URL', pepJwt !== undefined, 'AuthZEN');
    const reasons = env.AKAC_AUTHZEN_REASONS || 'none';
    if (!['none', 'admin'].includes(reasons)) problems.push('AKAC_AUTHZEN_REASONS must be none or admin');
    const publicUrl = env.AKAC_AUTHZEN_PUBLIC_URL || undefined;
    if (publicUrl) {
      try { checkPublicUrl(publicUrl); if (new URL(publicUrl).pathname !== '/') problems.push('AKAC_AUTHZEN_PUBLIC_URL must be an origin without a path'); if (env.NODE_ENV === 'production' && new URL(publicUrl).protocol !== 'https:') problems.push('AKAC_AUTHZEN_PUBLIC_URL must be https when NODE_ENV=production'); }
      catch { problems.push('AKAC_AUTHZEN_PUBLIC_URL must be an http(s) URL without credentials, query or fragment'); }
    }
    authzen = { host: env.AKAC_AUTHZEN_HOST ? host('AKAC_AUTHZEN_HOST', '127.0.0.1') : '127.0.0.1', port: azPort.value, credentials: pepCredentials ?? [], ...(pepJwt ? { jwt: pepJwt } : {}),
      ...(authzenDpop ? { dpop: authzenDpop } : {}), reasons: reasons as 'none' | 'admin', ...(publicUrl ? { publicUrl } : {}) };
  }
  let dpop: DpopConfig | undefined;
  if (agentDpop || adminDpop || authzenDpop) {
    const algs = (env.AKAC_DPOP_ALGS || DPOP_ALGORITHMS.join(',')).split(',').map(a => a.trim());
    if (!algs.length || algs.some(a => !(DPOP_ALGORITHMS as readonly string[]).includes(a)) || new Set(algs).size !== algs.length) problems.push(`AKAC_DPOP_ALGS must be a comma-separated subset of ${DPOP_ALGORITHMS.join(', ')}`);
    const skew = env.AKAC_DPOP_SKEW_SECONDS ? int(env.AKAC_DPOP_SKEW_SECONDS) : DPOP_LIMITS.defaultSkewSeconds;
    if (!Number.isInteger(skew) || skew < 1 || skew > DPOP_LIMITS.maxSkewSeconds) problems.push(`AKAC_DPOP_SKEW_SECONDS must be an integer 1-${DPOP_LIMITS.maxSkewSeconds}`);
    const replay = env.AKAC_DPOP_REPLAY || (env.DATABASE_URL ? 'postgres' : 'memory');
    if (!['memory', 'postgres'].includes(replay)) problems.push('AKAC_DPOP_REPLAY must be memory or postgres');
    else if (replay === 'postgres' && !env.DATABASE_URL) problems.push('AKAC_DPOP_REPLAY=postgres requires DATABASE_URL');
    dpop = { algorithms: algs as DpopAlgorithm[], skewSeconds: skew, replay: replay as 'memory' | 'postgres' };
  } else for (const name of ['AKAC_DPOP_ALGS', 'AKAC_DPOP_SKEW_SECONDS', 'AKAC_DPOP_REPLAY']) if (env[name]) problems.push(`${name} requires AKAC_DPOP, AKAC_ADMIN_DPOP or AKAC_AUTHZEN_DPOP`);

  const metricsPort = port('AKAC_METRICS_PORT', 'METRICS_PORT');
  const metrics = { host: host('AKAC_METRICS_HOST', '127.0.0.1'), port: metricsPort.value ?? 9464 };
  const ports = [['agent', agent.port], ...(admin ? [['admin', admin.port]] : []), ...(authzen ? [['authzen', authzen.port]] : []), ['metrics', metrics.port]] as [string, number][];
  for (const [i, [n, p]] of ports.entries()) if (p !== 0 && ports.some(([m, q], j) => j < i && q === p && (m !== n))) problems.push(`The ${n} listener port ${p} is already used by another listener`);
  if (env.OPA_URL) { try { if (!/^https?:$/.test(new URL(env.OPA_URL).protocol)) throw new Error(); } catch { problems.push('OPA_URL must be an http(s) URL'); } }
  connectionUrl(env, 'DATABASE_URL', problems); connectionUrl(env, 'AKAC_MIGRATION_DATABASE_URL', problems);
  const retrieval = retrievalConfig(env, problems);
  const signed = checkpointConfig(env, problems);
  const checkpoint = signed && 'privatePem' in signed ? signed : undefined, checkpointVault = signed && 'vault' in signed ? signed.vault : undefined, checkpointSigner = signed && 'signer' in signed ? signed.signer : undefined,
    checkpointExtension = signed && 'extension' in signed ? signed.extension : undefined;
  // AKAC_SHARED_STATE (0.6): postgres by default when DATABASE_URL is set, so replicas share limits and idempotency records.
  const shared = env.AKAC_SHARED_STATE || (env.DATABASE_URL ? 'postgres' : 'memory');
  if (!['memory', 'postgres'].includes(shared)) problems.push('AKAC_SHARED_STATE must be memory or postgres');
  else if (shared === 'postgres' && !env.DATABASE_URL) problems.push('AKAC_SHARED_STATE=postgres requires DATABASE_URL');
  const ttl = env.AKAC_IDEMPOTENCY_TTL_SECONDS ? (/^\d{1,7}$/.test(env.AKAC_IDEMPOTENCY_TTL_SECONDS) ? Number(env.AKAC_IDEMPOTENCY_TTL_SECONDS) : NaN) : 86400;
  if (!(ttl >= 60 && ttl <= 604800)) problems.push('AKAC_IDEMPOTENCY_TTL_SECONDS must be an integer 60-604800');
  if (env.AKAC_IDEMPOTENCY_TTL_SECONDS && shared !== 'postgres') problems.push('AKAC_IDEMPOTENCY_TTL_SECONDS applies to AKAC_SHARED_STATE=postgres only');
  const sharedState = { mode: shared as 'memory' | 'postgres', idempotencyTtlSeconds: ttl };
  const protection = protectionConfig(env, problems, retrieval !== undefined);
  if (problems.length) throw new ConfigError(problems);
  return { agent, protection, ...(authzen ? { authzen } : {}), ...(checkpoint ? { checkpoint } : {}), ...(checkpointVault ? { checkpointVault } : {}), ...(checkpointSigner ? { checkpointSigner } : {}), ...(checkpointExtension ? { checkpointExtension } : {}), ...(dpop ? { dpop } : {}), ...(retrieval ? { retrieval } : {}), ...(admin ? { admin } : {}), metrics, sharedState, ...(env.OPA_URL ? { opa: { url: env.OPA_URL, ...(env.OPA_REVISION ? { revision: env.OPA_REVISION } : {}) } } : {}), logLevel: level };
}
