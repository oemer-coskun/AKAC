import { ConfigError, configuredRetrieval, configuredStore, loadRetrievalConfig } from '../reference/config.ts';
import { ControlPlane } from '../reference/control.ts';
import { Sweeper } from '../reference/sweeper.ts';
import { validId } from '../reference/validation.ts';
import { jobLock } from './job-lock.ts';
// Usage: node scripts/sweep.ts <tenant> <admin-actor> [record-id ...]
// Knowledge hygiene job (0.6, R193, R194), suitable for a CronJob: runs every pending erasure that no
// legal hold blocks any more, then sweeps the lineage of each named record (quarantined, revoked, erased or
// relabelled). The admin actor must hold security-admin; every batch is audited. Runs are serialized per tenant
// across instances and CronJob pods by the job lock (ADR-016): a run that finds the lock held is skipped (exit 0,
// logged). Lazy denial stays authoritative whether or not this job runs.
const [tenant, admin, ...roots] = process.argv.slice(2);
if (!tenant || !admin || !roots.every(validId)) {
  console.error('Usage: node scripts/sweep.ts <tenant> <admin-actor> [record-id ...]'); process.exit(2);
}
let config;
try { config = loadRetrievalConfig(); } catch (error) {
  if (error instanceof ConfigError) { for (const p of error.problems) console.error(`configuration error: ${p}`); process.exit(2); }
  throw error;
}
const store = configuredStore(), control = new ControlPlane(store), lock = jobLock();
const retrieval = config ? configuredRetrieval(config, store, control) : undefined;
const sweeper = new Sweeper({ control, lock, ...(retrieval ? { reindex: (t: string, id: string) => retrieval.ingestor.relabel(t, id), reconcile: (t: string) => retrieval.ingestor.reconcile(t) } : {}) });
const log = (level: string, msg: string, extra: Record<string, unknown> = {}) => console.log(JSON.stringify({ level, time: new Date().toISOString(), msg, ...extra }));
let code = 0;
try {
  const erasures = await sweeper.applyPendingErasures(tenant, admin);
  if (!erasures.ran) log('warn', 'pending erasures skipped: another run holds the job lock');
  else if (erasures.refused) { log('error', 'pending erasures refused', { code: erasures.refused }); code = 3; }
  else { log('info', 'pending erasures complete', { erased: erasures.erased, held: erasures.held, deferred: erasures.deferred }); if (erasures.deferred) code = 1; }
  for (const id of roots) {
    const r = await sweeper.sweep(tenant, admin, id);
    if (!r.ran) { log('warn', 'sweep skipped: another run holds the job lock'); continue; }
    if (r.refused) { log('error', 'sweep refused', { code: r.refused }); code = 3; continue; }
    log(r.truncated || r.next ? 'warn' : 'info', 'sweep complete', { batches: r.batches, changed: r.changed, truncated: r.truncated, indexPending: r.indexPending, ...(r.next ? { next: r.next } : {}) });
    if (r.indexPending && !code) code = 1;
  }
} finally { await retrieval?.close(); await lock.close?.(); await store.close(); }
process.exit(code);
