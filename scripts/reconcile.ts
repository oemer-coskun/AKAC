import { ConfigError, configuredRetrieval, configuredStore, loadRetrievalConfig } from '../reference/config.ts';
import { ControlPlane } from '../reference/control.ts';
import { jobLock } from './job-lock.ts';
// Usage: node scripts/reconcile.ts <tenant> <admin-actor>
// Repairs drift between the authoritative store and the vector index for one tenant. The
// admin actor must hold kb-admin; the run is authorized and audited like the HTTP route.
// Runs are serialized per tenant across instances (job lock, ADR-016); a concurrent run is skipped.
const [tenant, admin] = process.argv.slice(2);
if (!tenant || !admin) { console.error('Usage: node scripts/reconcile.ts <tenant> <admin-actor>'); process.exit(2); }
let config;
try { config = loadRetrievalConfig(); } catch (error) {
  if (error instanceof ConfigError) { for (const p of error.problems) console.error(`configuration error: ${p}`); process.exit(2); }
  throw error;
}
if (!config) { console.error('configuration error: set AKAC_RETRIEVAL=vector'); process.exit(2); }
const store = configuredStore(), control = new ControlPlane(store), retrieval = configuredRetrieval(config, store, control);
let code = 0;
const lock = jobLock();
try {
  const allowed = await control.authorize(tenant, admin, 'kb-admin', 'index_reconcile');
  if (!allowed.ok) { console.error(JSON.stringify({ level: 'error', msg: 'not authorized' })); code = 3; }
  else {
    const outcome = await lock.run('reconcile', tenant, () => retrieval.ingestor.reconcile(tenant));
    if (!outcome.ran) console.log(JSON.stringify({ level: 'warn', time: new Date().toISOString(), msg: 'reconcile skipped: another run holds the job lock' }));
    else {
      console.log(JSON.stringify({ level: 'info', time: new Date().toISOString(), msg: 'reconcile complete', ...outcome.value }));
      if (outcome.value.failed) code = 1;
    }
  }
} finally { await lock.close?.(); await retrieval.close(); await store.close(); }
process.exit(code);
