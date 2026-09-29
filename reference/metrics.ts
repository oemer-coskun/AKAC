import { createServer } from 'node:http';
import type { Server } from 'node:http';
import type { EngineEvent } from './engine.ts';
import type { IngestEvent } from './ingest.ts';
import type { ControlEvent } from './control.ts';

/** Bounded series per metric: a runaway label value can never exhaust memory. Excess series are dropped. */
const MAX_SERIES = 512;
const escape = (v: string) => v.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
const fmt = (n: number) => Number.isInteger(n) ? String(n) : String(Number(n.toPrecision(12)));
const bounded = (v: string) => /^[a-zA-Z0-9_./:{}-]{1,64}$/.test(v) ? v : 'other';

type Kind = 'counter' | 'gauge' | 'histogram';
type Series = { labels: string[]; value: number; counts: number[]; sum: number; count: number };
class Metric {
  readonly name: string; readonly help: string; readonly kind: Kind; readonly labels: string[];
  readonly buckets: number[]; readonly series = new Map<string, Series>();
  dropped = 0;
  constructor(name: string, help: string, kind: Kind, labels: string[], buckets: number[] = []) {
    this.name = name; this.help = help; this.kind = kind; this.labels = labels; this.buckets = buckets;
  }
  private entry(values: string[]) {
    if (values.length !== this.labels.length) throw new Error(`Label mismatch for ${this.name}`);
    const clean = values.map(bounded), key = clean.join('\u0000');
    let e = this.series.get(key);
    if (!e) {
      if (this.series.size >= MAX_SERIES) { this.dropped++; return undefined; }
      e = { labels: clean, value: 0, counts: this.buckets.map(() => 0), sum: 0, count: 0 }; this.series.set(key, e);
    }
    return e;
  }
  inc(values: string[] = [], by = 1) { const e = this.entry(values); if (e && by >= 0) e.value += by; }
  set(values: string[], value: number) { const e = this.entry(values); if (e) e.value = value; }
  observe(values: string[], value: number) {
    const e = this.entry(values); if (!e || !Number.isFinite(value) || value < 0) return;
    e.sum += value; e.count++;
    this.buckets.forEach((b, i) => { if (value <= b) e.counts[i]!++; });
  }
  lines(): string[] {
    const out = [`# HELP ${this.name} ${this.help.replace(/\\/g, '\\\\').replace(/\n/g, '\\n')}`, `# TYPE ${this.name} ${this.kind}`];
    const label = (values: string[], extra?: string) => {
      const parts = this.labels.map((l, i) => `${l}="${escape(values[i]!)}"`); if (extra) parts.push(extra);
      return parts.length ? `{${parts.join(',')}}` : '';
    };
    // An unlabelled counter reads 0 before its first event, so rate() and absence alerts behave.
    if (!this.labels.length && this.kind !== 'histogram' && !this.series.size) out.push(`${this.name} 0`);
    for (const e of this.series.values()) {
      if (this.kind === 'histogram') {
        this.buckets.forEach((b, i) => out.push(`${this.name}_bucket${label(e.labels, `le="${fmt(b)}"`)} ${e.counts[i]}`));
        out.push(`${this.name}_bucket${label(e.labels, 'le="+Inf"')} ${e.count}`, `${this.name}_sum${label(e.labels)} ${fmt(e.sum)}`, `${this.name}_count${label(e.labels)} ${e.count}`);
      } else out.push(`${this.name}${label(e.labels)} ${fmt(e.value)}`);
    }
    return out;
  }
}
/** Minimal Prometheus registry: counters, gauges and fixed-bucket histograms; text exposition 0.0.4. */
export class Registry {
  private metrics: Metric[] = [];
  private make(name: string, help: string, kind: Kind, labels: string[], buckets?: number[]) {
    if (!/^[a-zA-Z_:][a-zA-Z0-9_:]*$/.test(name) || labels.some(l => !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(l) || l === 'le')
      || this.metrics.some(m => m.name === name)) throw new Error(`Invalid metric ${name}`);
    const m = new Metric(name, help, kind, labels, buckets); this.metrics.push(m); return m;
  }
  counter(name: string, help: string, labels: string[] = []) { return this.make(name, help, 'counter', labels); }
  gauge(name: string, help: string, labels: string[] = []) { return this.make(name, help, 'gauge', labels); }
  histogram(name: string, help: string, labels: string[], buckets: number[]) {
    if (!buckets.length || buckets.some((b, i) => !Number.isFinite(b) || (i > 0 && b <= buckets[i - 1]!))) throw new Error('Buckets must be ascending');
    return this.make(name, help, 'histogram', labels, buckets);
  }
  expose(): string { return this.metrics.flatMap(m => m.lines()).join('\n') + '\n'; }
}

const REASONS = ['AUTHORIZED', 'DENIED', 'DEFERRED'] as const;
const DECISION_OPERATIONS = ['read', 'retrieve', 'derive', 'share', 'export', 'delegate', 'write_memory', 'authzen_evaluate'];
/** Lifecycle administration (0.4); the admin operation label is a closed set as well. */
const LIFECYCLE_OPERATIONS = ['quarantine', 'release', 'lineage_read', 'revoke_lineage', 'legal_hold_set', 'legal_hold_lift', 'erase', 'retention_apply'];
const ADMIN_OPERATIONS = ['put_actor', 'assign_roles', 'put_role', 'put_group', 'put_constraint', 'put_container', 'put_knowledge', 'delete_knowledge', 'put_destination',
  'index_reconcile', 'index_rebaseline', 'issue_grant', 'revoke', 'audit_read', 'audit_export', 'audit_checkpoint', 'audit_proof', 'audit_consistency', 'unknown', ...LIFECYCLE_OPERATIONS,
  // Identity and authority (0.6, ADR-019).
  'grant_heartbeat', 'issue_break_glass', 'approval_list', 'approval_read', 'approval_grant', 'approval_reject', 'approval_execute', 'risk_signal', 'put_settings', 'read_settings'];
/** AKAC metrics. Labels are closed sets: no tenant, subject, resource, query or content values. */
export class Metrics {
  readonly registry = new Registry();
  private started = Date.now();
  readonly http = this.registry.counter('akac_http_requests_total', 'HTTP requests by listener, route template and status.', ['listener', 'route', 'status']);
  readonly duration = this.registry.histogram('akac_http_request_duration_seconds', 'HTTP request duration.', ['listener', 'route'], [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]);
  readonly decisions = this.registry.counter('akac_decisions_total', 'Authorization decisions by operation and reason class.', ['operation', 'allowed', 'reason_class']);
  readonly filterMismatch = this.registry.counter('akac_filter_mismatch_total', 'Retrieval candidates rejected by the authoritative policy check. Any value above 0 needs investigation.');
  readonly candidatesUnavailable = this.registry.counter('akac_candidates_unavailable_total', 'Retrieval candidate source failures (requests fail closed).');
  readonly adminOps = this.registry.counter('akac_admin_operations_total', 'Administrative operations by name and result.', ['operation', 'result']);
  readonly lifecycle = this.registry.counter('akac_lifecycle_operations_total', 'Knowledge lifecycle administration (quarantine, release, erasure, legal hold, retention) by operation and result.', ['operation', 'result']);
  readonly indexChunks = this.registry.counter('akac_index_chunks_written_total', 'Chunks written to the vector index.');
  readonly indexRemoved = this.registry.counter('akac_index_documents_removed_total', 'Documents removed from the vector index.');
  readonly indexPending = this.registry.counter('akac_index_pending_total', 'Documents left unindexed after an authoritative write; reconcile repairs them.', ['reason']);
  readonly indexReconciles = this.registry.counter('akac_index_reconcile_runs_total', 'Index reconciliation runs.');
  readonly indexRepairs = this.registry.counter('akac_index_reconcile_documents_total', 'Documents handled by reconciliation.', ['action']);
  readonly indexTruncated = this.registry.counter('akac_index_reconcile_truncated_total', 'Reconciliation runs that hit the per-tenant scan cap.');
  /** Shared-state and job metrics (0.6, ADR-016). */
  readonly rateLimits = this.registry.counter('akac_rate_limit_rejections_total', 'Requests refused by a rate limiter: limited (429), full (in-memory limiter at its bucket cap, 503) or unavailable (shared limiter store error, 503).', ['listener', 'reason']);
  readonly obligationDenials = this.registry.counter('akac_unsupported_obligation_denials_total', 'Denials because an allow would carry an obligation the caller cannot enforce (for example runtime_profile on the agent listener).', ['operation']);
  readonly idempotency = this.registry.counter('akac_idempotency_total', 'Admin Idempotency-Key outcomes.', ['outcome']);
  /** Identity and authority (0.6, ADR-019): alert on any break-glass issuance or use. */
  readonly breakGlassGrants = this.registry.counter('akac_break_glass_grants_total', 'Break-glass grants issued (after their approval quorum). Any increase needs review.');
  readonly breakGlassDecisions = this.registry.counter('akac_break_glass_decisions_total', 'Decisions taken under a break-glass grant.', ['allowed']);
  readonly approvals = this.registry.counter('akac_approvals_total', 'Approval workflow events by operation class and outcome.', ['class', 'outcome']);
  readonly jobs = this.registry.counter('akac_job_runs_total', 'Maintenance job runs through the job lock: ran, skipped (another instance holds the lock) or failed.', ['job', 'result']);
  /** Release and retrieval protection metrics (0.6, ADR-020). Closed label sets; no tenant, content or ids. */
  readonly hooks = this.registry.counter('akac_release_hook_outcomes_total', 'Release filter and derive sanitizer outcomes that changed or stopped an operation.', ['hook', 'outcome']);
  readonly volumeExceeded = this.registry.counter('akac_volume_budget_exceeded_total', 'Disclosures refused because a volume budget was exhausted, by classification.', ['classification']);
  readonly retrievalDisabled = this.registry.counter('akac_retrieval_disabled_total', 'Retrievals deferred because vector retrieval is disabled by embedding drift.');
  readonly anchorDrift = this.registry.gauge('akac_embedding_drift', '1 while embedding anchors report drift (or no baseline yet) and vector retrieval is disabled, else 0.');
  readonly anchorCosine = this.registry.gauge('akac_embedding_anchor_min_cosine', 'Lowest cosine of an embedding anchor against its baseline at the last check.');
  readonly anchorChecks = this.registry.counter('akac_embedding_anchor_checks_total', 'Embedding anchor checks by result: ok, drifted or failed (the embedder could not be reached).', ['result']);
  private uptime = this.registry.gauge('akac_process_uptime_seconds', 'Process uptime.');
  private heap = this.registry.gauge('akac_process_heap_used_bytes', 'V8 heap in use.');
  private rss = this.registry.gauge('akac_process_resident_memory_bytes', 'Resident set size.');
  readonly onEvent = (event: EngineEvent) => {
    if (event.type === 'decision') {
      const cls = REASONS.find(r => event.reason === r || event.reason.startsWith(`${r}:`)) ?? 'other';
      const operation = DECISION_OPERATIONS.includes(event.operation) ? event.operation : 'other';
      this.decisions.inc([operation, String(event.allowed), cls.toLowerCase()]);
      if (!event.allowed && (event.code === 'UNSUPPORTED_OBLIGATION' || event.reason.endsWith(':UNSUPPORTED_OBLIGATION'))) this.obligationDenials.inc([operation]);
      if (event.breakGlass) this.breakGlassDecisions.inc([String(event.allowed)]);
    } else if (event.type === 'filter_mismatch') this.filterMismatch.inc();
    else if (event.type === 'candidates_unavailable') this.candidatesUnavailable.inc();
    else if (event.type === 'hook') this.hooks.inc([event.hook, event.outcome]);
    else if (event.type === 'volume_exceeded') this.volumeExceeded.inc([event.classification]);
    else if (event.type === 'retrieval_disabled') this.retrievalDisabled.inc();
  };
  /** Anchor monitor results (reference/anchors.ts AnchorOptions.onCheck). */
  readonly onAnchorCheck = (r: { state: 'pending' | 'ok' | 'drifted'; minCosine?: number; failed?: boolean }) => {
    this.anchorDrift.set([], r.state === 'ok' ? 0 : 1);
    if (r.minCosine !== undefined) this.anchorCosine.set([], r.minCosine);
    this.anchorChecks.inc([r.failed ? 'failed' : r.state === 'ok' ? 'ok' : 'drifted']);
  };
  /** Control-plane events (0.6): break-glass issuance and approval outcomes, no identities. */
  readonly onControl = (event: ControlEvent) => {
    if (event.type === 'break_glass') this.breakGlassGrants.inc();
    else if (event.type === 'approval') this.approvals.inc([event.class, event.outcome]);
  };
  /** Ingest events carry counts only: no tenant, document ids or text. */
  readonly onIngest = (event: IngestEvent) => {
    if (event.type === 'indexed') this.indexChunks.inc([], event.chunks);
    else if (event.type === 'index_removed') this.indexRemoved.inc();
    else if (event.type === 'index_pending') this.indexPending.inc([event.reason]);
    else {
      this.indexReconciles.inc();
      this.indexRepairs.inc(['indexed'], event.indexed); this.indexRepairs.inc(['removed'], event.removed); this.indexRepairs.inc(['failed'], event.failed);
      if (event.truncated) this.indexTruncated.inc();
    }
  };
  request(listener: string, route: string, status: number, seconds: number) {
    this.http.inc([listener, route, String(status)]); this.duration.observe([listener, route], seconds);
  }
  rateLimited(listener: string, reason: 'limited' | 'full' | 'unavailable') {
    this.rateLimits.inc([['agent', 'admin', 'authzen'].includes(listener) ? listener : 'other', reason]);
  }
  idempotent(outcome: 'stored' | 'replayed' | 'reused' | 'in_flight' | 'unavailable') { this.idempotency.inc([outcome]); }
  job(job: string, result: 'ran' | 'skipped' | 'failed') { this.jobs.inc([['retention', 'reconcile', 'audit-verify'].includes(job) ? job : 'other', result]); }
  admin(operation: string, result: string) {
    const known = ADMIN_OPERATIONS.includes(operation) || operation.startsWith('scim_') ? operation : 'other';
    this.adminOps.inc([known, result]);
    if (LIFECYCLE_OPERATIONS.includes(operation)) this.lifecycle.inc([operation, result]);
  }
  expose(): string {
    const mem = process.memoryUsage();
    this.uptime.set([], (Date.now() - this.started) / 1000); this.heap.set([], mem.heapUsed); this.rss.set([], mem.rss);
    return this.registry.expose();
  }
}
/** Separate listener for scrapers. It exposes aggregate counters only, but should still be reachable from the monitoring network alone. */
export function createMetricsServer(metrics: Metrics): Server {
  const server = createServer((req, res) => {
    req.resume();
    const path = (req.url ?? '').split('?')[0];
    if (req.method === 'GET' && path === '/metrics') {
      res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
      res.end(metrics.expose());
    } else { res.writeHead(404, { 'content-type': 'text/plain', 'cache-control': 'no-store' }); res.end('not found\n'); }
  });
  server.requestTimeout = 5000; server.headersTimeout = 5000; server.timeout = 10000; server.maxHeadersCount = 32;
  return server;
}
