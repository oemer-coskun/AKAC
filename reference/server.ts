import type { Server } from 'node:http';
import { Engine } from './engine.ts';
import { ControlPlane } from './control.ts';
import { createGateway } from './http.ts';
import { createAdminGateway } from './admin.ts';
import { ConfigError, configuredRetrieval, configuredStore, loadConfig } from './config.ts';
import { createLogger } from './log.ts';
import { createMetricsServer, Metrics } from './metrics.ts';
import { OpaPolicy } from '../adapters/opa.ts';
import { AdminJwtAuthenticator, JwtAuthenticator } from '../adapters/jwt.ts';
import { PostgresStore } from '../adapters/postgres.ts';

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
if (store instanceof PostgresStore) {
  try { await store.verify(); }
  catch (error) { logger.error('store start-up check failed', { error: error instanceof Error ? error.message : 'unknown' }); await store.close().catch(() => {}); process.exit(2); }
}
const policy = config.opa ? new OpaPolicy(config.opa.url, config.opa.revision) : undefined;
const control = new ControlPlane(store);
const retrieval = config.retrieval ? configuredRetrieval(config.retrieval, store, control, metrics.onIngest) : undefined;
const engine = new Engine(store, { policy, onEvent: metrics.onEvent, ...(retrieval ? { candidates: retrieval.candidates } : {}) });
const observability = { metrics, logger };
const listeners: { name: string; server: Server; host: string; port: number }[] = [
  { name: 'agent', server: createGateway(engine, config.agent.credentials, { ...observability, ...(config.agent.jwt ? { authenticator: new JwtAuthenticator(config.agent.jwt) } : {}) }),
    host: config.agent.host, port: config.agent.port }
];
if (config.admin) listeners.push({ name: 'admin', host: config.admin.host, port: config.admin.port,
  server: createAdminGateway(control, { ...observability, ...(retrieval ? { ingestor: retrieval.ingestor } : {}), credentials: config.admin.credentials,
    ...(config.admin.jwt ? { authenticator: new AdminJwtAuthenticator(config.admin.jwt) } : {}) }) });
listeners.push({ name: 'metrics', server: createMetricsServer(metrics), host: config.metrics.host, port: config.metrics.port });

await Promise.all(listeners.map(l => new Promise<void>((resolve, reject) => {
  l.server.once('error', reject);
  l.server.listen(l.port, l.host, () => { logger.info('listening', { listener: l.name, host: l.host, port: l.port, policy: policy ? 'opa+core' : 'core', retrieval: config.retrieval ? `vector:${config.retrieval.backend}` : 'lexical' }); resolve(); });
})));

let stopping = false;
async function shutdown(signal: string) {
  if (stopping) return; stopping = true;
  logger.info('shutting down', { signal });
  // Stop accepting, let in-flight requests finish for up to 10 seconds, then cut the rest.
  const closed = Promise.all(listeners.map(l => new Promise<void>(resolve => { l.server.close(() => resolve()); l.server.closeIdleConnections(); })));
  const timer = setTimeout(() => { logger.warn('drain deadline reached; closing connections'); for (const l of listeners) l.server.closeAllConnections(); }, 10_000);
  try { await closed; clearTimeout(timer); await retrieval?.close(); await store.close(); logger.info('stopped'); process.exit(0); }
  catch (error) { fatal('shutdown failed', error); }
}
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => { void shutdown(signal); });
