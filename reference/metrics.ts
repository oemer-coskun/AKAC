import { createServer } from 'node:http';
import type { Server } from 'node:http';
import type { EngineEvent } from './engine.ts';
import type { IngestEvent } from './ingest.ts';

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
const DECISION_OPERATIONS = ['read', 'retrieve', 'derive', 'share', 'export', 'delegate'];
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
  readonly indexChunks = this.registry.counter('akac_index_chunks_written_total', 'Chunks written to the vector index.');
  readonly indexRemoved = this.registry.counter('akac_index_documents_removed_total', 'Documents removed from the vector index.');
  readonly indexPending = this.registry.counter('akac_index_pending_total', 'Documents left unindexed after an authoritative write; reconcile repairs them.', ['reason']);
  readonly indexReconciles = this.registry.counter('akac_index_reconcile_runs_total', 'Index reconciliation runs.');
  readonly indexRepairs = this.registry.counter('akac_index_reconcile_documents_total', 'Documents handled by reconciliation.', ['action']);
  readonly indexTruncated = this.registry.counter('akac_index_reconcile_truncated_total', 'Reconciliation runs that hit the per-tenant scan cap.');
  private uptime = this.registry.gauge('akac_process_uptime_seconds', 'Process uptime.');
  private heap = this.registry.gauge('akac_process_heap_used_bytes', 'V8 heap in use.');
  private rss = this.registry.gauge('akac_process_resident_memory_bytes', 'Resident set size.');
  readonly onEvent = (event: EngineEvent) => {
    if (event.type === 'decision') {
      const cls = REASONS.find(r => event.reason === r || event.reason.startsWith(`${r}:`)) ?? 'other';
      this.decisions.inc([DECISION_OPERATIONS.includes(event.operation) ? event.operation : 'other', String(event.allowed), cls.toLowerCase()]);
    } else if (event.type === 'filter_mismatch') this.filterMismatch.inc();
    else if (event.type === 'candidates_unavailable') this.candidatesUnavailable.inc();
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
  admin(operation: string, result: string) { this.adminOps.inc([operation, result]); }
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
