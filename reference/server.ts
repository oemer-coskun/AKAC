import type { Server } from 'node:http';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { Engine } from './engine.ts';
import { DecisionCache } from './decision-cache.ts';
import { VolumeBudget } from './protection.ts';
import { LEVELS } from './types.ts';
import type { Level } from './types.ts';
import type { DeriveSanitizer, ReleaseFilter } from './hooks.ts';
import type { RiskProvider } from './risk.ts';
import { ControlPlane } from './control.ts';
import { createGateway } from './http.ts';
import { createAdminGateway } from './admin.ts';
import { createAuthzenGateway } from './authzen.ts';
import { ConfigError, configuredRetrieval, configuredStore, loadConfig, requireConnectionUrl, vaultSigner } from './config.ts';
import { createLogger } from './log.ts';
import { createMetricsServer, Metrics } from './metrics.ts';
import { OpaPolicy } from '../adapters/opa.ts';
import { AdminJwtAuthenticator, JwtAuthenticator, PepJwtAuthenticator } from '../adapters/jwt.ts';
import { PostgresStore } from '../adapters/postgres.ts';
import { MemoryReplayCache } from '../adapters/dpop.ts';
import type { DpopOptions, DpopReplayCache } from '../adapters/dpop.ts';
import { PostgresReplayCache } from '../adapters/dpop-postgres.ts';
import { PostgresIdempotency, PostgresJobLock, PostgresRateLimits } from '../adapters/postgres-ha.ts';
import { MemoryIdempotency, MemoryJobLock, MemoryRateLimits } from './limits.ts';
import type { IdempotencyStore, JobLock, RateLimitStore } from './limits.ts';
import { EncryptingStore } from './content-crypto.ts';
import { Sweeper } from './sweeper.ts';
import { validModel } from './knowledge.ts';

const logger = createLogger({ level: (process.env.AKAC_LOG_LEVEL as 'info' | undefined) ?? 'info' });
let config;
try { config = loadConfig(); }
catch (error) {
  if (error instanceof ConfigError) { for (const problem of error.problems) logger.error('configuration error', { problem }); process.exit(2); }
  throw error;
}
const fatal = (msg: string, error: unknown) => {
  logger.error(msg, { error: error instanceof Error ? error.name : typeof error });
  process.exit(1);
};
process.on('unhandledRejection', reason => fatal('unhandled rejection', reason));
process.on('uncaughtException', error => fatal('uncaught exception', error));

const metrics = new Metrics();
const store = configuredStore(process.env, { warn: message => logger.warn(message) });
// Refuse to serve over a store that failed migration verification or whose runtime role bypasses row-level security.
// Content encryption (R195) wraps the database store; the start-up gate checks the database itself.
const database = store instanceof EncryptingStore ? store.inner : store;
if (database instanceof PostgresStore) {
  try { await database.verify(); }
  catch (error) { logger.error('store start-up check failed', { error: error instanceof Error ? error.message : 'unknown' }); await store.close().catch(() => {}); process.exit(2); }
}
const policy = config.opa ? new OpaPolicy(config.opa.url, config.opa.revision) : undefined;
// Checkpoint signing: a key file in memory, or a Vault Transit key (0.6, reference/custody.ts) that never leaves Vault.
// AKAC_CHECKPOINT_SIGNER=extension (ADR-023): the signer (for example an HSM) comes from an extension build; the stock server has
// none and refuses to start rather than sign with a weaker key or not at all.
if (config.checkpointExtension) {
  logger.error('AKAC_CHECKPOINT_SIGNER=extension requires a checkpoint signer supplied by an extension; this server has none', { alg: config.checkpointExtension.alg });
  await store.close().catch(() => {}); process.exit(2);
}
const control = new ControlPlane(store, { onEvent: metrics.onControl, ...(config.checkpointVault ? { checkpoint: vaultSigner(config.checkpointVault) } : config.checkpointSigner ? { checkpoint: config.checkpointSigner } : config.checkpoint ? { checkpoint: config.checkpoint } : {}) });
const protection = config.protection;
const retrieval = config.retrieval ? configuredRetrieval(config.retrieval, store, control, metrics.onIngest, protection.anchors ? { ...protection.anchors, onCheck: metrics.onAnchorCheck } : undefined) : undefined;
// Rate windows, admin Idempotency-Key records and job locks (0.6, ADR-016): shared through PostgreSQL across
// instances, or per instance. One limiter serves every listener (scopes keep their windows apart).
const sharedUrl = config.sharedState.mode === 'postgres' ? requireConnectionUrl(process.env, 'DATABASE_URL')! : undefined;
const limiter: RateLimitStore = sharedUrl ? new PostgresRateLimits(sharedUrl, { max: 8 }) : new MemoryRateLimits();
// Release filters and derive sanitizers (0.6, ADR-020) come from an operator-supplied ES module; AKAC ships none.
let releaseFilters: ReleaseFilter[] = [], deriveSanitizers: DeriveSanitizer[] = [];
// External risk source (R152): the same module may export `risk`; the agent engine and the AuthZEN PDP both apply it.
let risk: RiskProvider | undefined;
if (protection.hooks.module) {
  try {
    const mod = await import(pathToFileURL(resolve(protection.hooks.module)).href) as { releaseFilters?: ReleaseFilter[]; deriveSanitizers?: DeriveSanitizer[]; risk?: RiskProvider };
    releaseFilters = mod.releaseFilters ?? []; deriveSanitizers = mod.deriveSanitizers ?? [];
    if (mod.risk !== undefined && (!mod.risk || typeof mod.risk.level !== 'function')) throw new Error('Invalid risk provider');
    risk = mod.risk;
  } catch (error) { logger.error('AKAC_HOOKS_MODULE could not be loaded', { error: error instanceof Error ? error.name : typeof error }); process.exit(2); }
}
const required = protection.hooks.requiredFilters;
const requiredFilters = Object.keys(required).length ? (_tenant: string, classification: Level) =>
  LEVELS.slice(0, LEVELS.indexOf(classification) + 1).flatMap(level => required[level] ?? []) : undefined;
const volume = protection.volume ? new VolumeBudget({ limiter, windowMs: protection.volume.windowSeconds * 1000, limits: protection.volume.limits, onExceed: protection.volume.onExceed }) : undefined;
const decisionCache = protection.decisionCache ? new DecisionCache(protection.decisionCache) : undefined;
// Model lineage (R191): the model this deployment's trusted runtime uses, recorded on derived content. Operator configuration only.
const model = process.env.AKAC_MODEL_ID !== undefined || process.env.AKAC_MODEL_VERSION !== undefined
  ? { id: process.env.AKAC_MODEL_ID ?? '', version: process.env.AKAC_MODEL_VERSION ?? '' } : undefined;
if (model && !validModel(model)) { logger.error('configuration error', { problem: 'AKAC_MODEL_ID and AKAC_MODEL_VERSION must both be identifiers' }); process.exit(2); }
let engine: Engine;
try {
  engine = new Engine(store, { policy, onEvent: metrics.onEvent, ...(retrieval ? { candidates: retrieval.candidates } : {}), releaseFilters, deriveSanitizers,
    hooks: { timeoutMs: protection.hooks.timeoutMs, failure: protection.hooks.failure }, ...(requiredFilters ? { requiredFilters } : {}), ...(volume ? { volume } : {}),
    ...(decisionCache ? { decisionCache } : {}), ...(model ? { model } : {}), ...(risk ? { risk } : {}),
    ...(protection.combinationWindowMs !== undefined ? { combinationWindowMs: protection.combinationWindowMs } : {}) });
} catch (error) { logger.error('invalid release or retrieval protection configuration', { error: error instanceof Error ? error.message : 'unknown' }); process.exit(2); }
// Embedding anchors: baseline at start-up, then periodic checks. A failed start leaves vector retrieval disabled (fail closed) until a check succeeds.
if (retrieval?.monitor && protection.anchors) {
  // Never an implicit baseline: without a stored one (or with an unreadable one) retrieval stays disabled until an administrator
  // re-baselines (POST /admin/v1/index/anchors/rebaseline) or the one-time AKAC_ANCHOR_BOOTSTRAP=true creates it.
  try {
    if (await retrieval.monitor.start() === 'pending') logger.warn('embedding anchor baseline missing or unreadable; vector retrieval stays disabled until an administrator re-baselines');
    else if (protection.anchors.bootstrap) logger.warn('AKAC_ANCHOR_BOOTSTRAP is set: remove it now that a baseline exists');
  } catch { logger.warn('embedding anchors could not be checked at start-up; vector retrieval stays disabled until they can'); }
  retrieval.monitor.schedule(protection.anchors.intervalSeconds * 1000);
}
const observability = { metrics, logger };
const idempotency: IdempotencyStore = sharedUrl ? new PostgresIdempotency(sharedUrl, { ttlMs: config.sharedState.idempotencyTtlSeconds * 1000 }) : new MemoryIdempotency();
const jobs: JobLock = sharedUrl ? new PostgresJobLock(sharedUrl) : new MemoryJobLock();
// Cascade sweeper (R193, R194): serialized per tenant by the same job lock; documents are re-checked against the index.
const sweeper = new Sweeper({ control, lock: jobs, ...(retrieval ? { reindex: (tenant: string, id: string) => retrieval.ingestor.relabel(tenant, id), reconcile: (tenant: string) => retrieval.ingestor.reconcile(tenant) } : {}) });
// DPoP replay cache: shared through PostgreSQL when configured (multiple instances), otherwise per instance.
const replay: DpopReplayCache | undefined = config.dpop ? config.dpop.replay === 'postgres' ? new PostgresReplayCache(requireConnectionUrl(process.env, 'DATABASE_URL')!) : new MemoryReplayCache() : undefined;
const dpopOptions = (l?: { dpop?: { mode: 'optional' | 'required'; publicUrl: string } }): { dpop?: DpopOptions } =>
  l?.dpop && config.dpop ? { dpop: { mode: l.dpop.mode, publicUrl: l.dpop.publicUrl, algorithms: config.dpop.algorithms, skewSeconds: config.dpop.skewSeconds, replay: replay! } } : {};
const listeners: { name: string; server: Server; host: string; port: number }[] = [
  { name: 'agent', server: createGateway(engine, config.agent.credentials, { ...observability, limiter, runtimeObligations: config.agent.runtimeObligations, denialHints: protection.denialHints,
      ...(protection.timing ? { timing: protection.timing } : {}), ...(protection.backoff ? { backoff: protection.backoff } : {}), ...(config.agent.jwt ? { authenticator: new JwtAuthenticator(config.agent.jwt) } : {}), ...dpopOptions(config.agent) }),
    host: config.agent.host, port: config.agent.port }
];
if (config.admin) listeners.push({ name: 'admin', host: config.admin.host, port: config.admin.port,
  server: createAdminGateway(control, { ...observability, limiter, idempotency, jobs, sweeper, ...(retrieval ? { ingestor: retrieval.ingestor } : {}), ...(retrieval?.monitor ? { anchors: retrieval.monitor } : {}), credentials: config.admin.credentials,
    ...(config.admin.jwt ? { authenticator: new AdminJwtAuthenticator(config.admin.jwt) } : {}), ...dpopOptions(config.admin) }) });
if (config.authzen) listeners.push({ name: 'authzen', host: config.authzen.host, port: config.authzen.port,
  server: createAuthzenGateway(store, { ...observability, limiter, ...(protection.timing ? { timing: protection.timing } : {}), ...(decisionCache ? { decisionCache } : {}), ...(policy ? { policy } : {}), ...(risk ? { risk } : {}), onEvent: metrics.onEvent, reasons: config.authzen.reasons,
    ...(config.authzen.publicUrl ? { publicUrl: config.authzen.publicUrl } : {}), credentials: config.authzen.credentials,
    ...(config.authzen.jwt ? { authenticator: new PepJwtAuthenticator(config.authzen.jwt) } : {}), ...dpopOptions(config.authzen) }) });
listeners.push({ name: 'metrics', server: createMetricsServer(metrics), host: config.metrics.host, port: config.metrics.port });

await Promise.all(listeners.map(l => new Promise<void>((resolve, reject) => {
  l.server.once('error', reject);
  l.server.listen(l.port, l.host, () => { logger.info('listening', { listener: l.name, host: l.host, port: l.port, policy: policy ? 'opa+core' : 'core', retrieval: config.retrieval ? `vector:${config.retrieval.backend}` : 'lexical', sharedState: config.sharedState.mode }); resolve(); });
})));

let stopping = false;
async function shutdown(signal: string) {
  if (stopping) return; stopping = true;
  logger.info('shutting down', { signal });
  // Stop accepting, let in-flight requests finish for up to 10 seconds, then cut the rest.
  const closed = Promise.all(listeners.map(l => new Promise<void>(resolve => { l.server.close(() => resolve()); l.server.closeIdleConnections(); })));
  const timer = setTimeout(() => { logger.warn('drain deadline reached; closing connections'); for (const l of listeners) l.server.closeAllConnections(); }, 10_000);
  try { await closed; clearTimeout(timer); await retrieval?.close(); await replay?.close?.(); await limiter.close?.(); await idempotency.close?.(); await jobs.close?.(); await store.close(); logger.info('stopped'); process.exit(0); }
  catch (error) { fatal('shutdown failed', error); }
}
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => { void shutdown(signal); });
