import { ConfigError, configuredRetrieval, configuredStore, loadRetrievalConfig } from '../reference/config.ts';
import { ControlPlane } from '../reference/control.ts';
// Usage: node scripts/retention.ts <tenant> <admin-actor> [now-ms]
// Erases (with cascade) every record of the tenant whose retainUntil is at or before
// `now` and whose lineage carries no legal hold, in bounded batches until done. The
// admin actor must hold security-admin; every batch and every erasure is audited.
// With AKAC_RETRIEVAL=vector the vector index is reconciled afterwards, which drops
// the chunks of erased documents. Backups are NOT reached: see docs/RETENTION.md.
const [tenant, admin, at] = process.argv.slice(2);
if (!tenant || !admin || (at !== undefined && !/^\d{1,16}$/.test(at))) {
  console.error('Usage: node scripts/retention.ts <tenant> <admin-actor> [now-ms]'); process.exit(2);
}
let config;
try { config = loadRetrievalConfig(); } catch (error) {
  if (error instanceof ConfigError) { for (const p of error.problems) console.error(`configuration error: ${p}`); process.exit(2); }
  throw error;
}
const store = configuredStore(), control = new ControlPlane(store);
const now = at === undefined ? Date.now() : Number(at);
let code = 0;
const totals = { erased: 0, held: 0, deferred: 0, batches: 0 };
try {
  let after: string | undefined;
  do {
    const batch = await control.applyRetention(tenant, admin, now, after ? { after } : {});
    if (!batch.ok) { console.error(JSON.stringify({ level: 'error', msg: 'retention refused', code: batch.code, decisionId: batch.decisionId })); code = 3; break; }
    totals.erased += batch.value.erased; totals.held += batch.value.held; totals.deferred += batch.value.deferred; totals.batches++;
    after = batch.value.next;
  } while (after);
  if (!code && config) {
    const retrieval = configuredRetrieval(config, store, control);
    try { const result = await retrieval.ingestor.reconcile(tenant); if (result.failed) code = 1; }
    finally { await retrieval.close(); }
  }
  console.log(JSON.stringify({ level: code ? 'warn' : 'info', time: new Date().toISOString(), msg: 'retention complete', ...totals }));
  if (!code && totals.deferred) code = 1;
} finally { await store.close(); }
process.exit(code);
