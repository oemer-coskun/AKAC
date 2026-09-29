/**
 * Shared-state seams for running several gateway instances (0.6, ADR-016): fixed-window
 * rate limits, admin Idempotency-Key records and job locks. The in-memory
 * implementations here are per process (single node, tests); adapters/postgres-ha.ts
 * provides implementations shared through PostgreSQL. Every implementation fails
 * closed: a store error rejects, and the listener answers 503.
 */

/** `tenant` scopes the bucket (row-level security in the shared store); `key` is an opaque digest. */
export type RateVerdict = { ok: true } | { ok: false; status: 429 | 503; retryAfter: number; reason: 'limited' | 'full' };
export interface RateLimitStore {
  /** Adds `cost` (default 1) to the (tenant, scope, key) window and refuses once the window's total exceeds `limit`. */
  take(tenant: string, scope: string, key: string, limit: number, windowMs: number, cost?: number): Promise<RateVerdict>;
  readonly shared: boolean;
  close?(): Promise<void>;
}
const SCOPE = /^[a-z][a-z0-9_-]{0,31}$/;
export const validScope = (scope: unknown): scope is string => typeof scope === 'string' && SCOPE.test(scope);
const positive = (n: unknown) => Number.isSafeInteger(n) && (n as number) >= 1;

/**
 * Per-process fixed windows. At most `maxBuckets` windows are tracked per scope; when
 * full, a request that would need a new bucket is refused with 503 (fail closed)
 * rather than evicting another caller's counter.
 */
export class MemoryRateLimits implements RateLimitStore {
  readonly shared = false;
  private scopes = new Map<string, { buckets: Map<string, { window: number; count: number }>; swept: number }>();
  private maxBuckets: number; private clock: () => number;
  constructor(options: { maxBuckets?: number; clock?: () => number } = {}) {
    this.maxBuckets = options.maxBuckets ?? 10_000; this.clock = options.clock ?? Date.now;
    if (!positive(this.maxBuckets)) throw new Error('Invalid rate limit configuration');
  }
  async take(tenant: string, scope: string, key: string, limit: number, windowMs: number, cost = 1): Promise<RateVerdict> {
    return this.takeSync(tenant, scope, key, limit, windowMs, cost);
  }
  /** Synchronous form (the in-process listeners use it without an await). */
  takeSync(tenant: string, scope: string, key: string, limit: number, windowMs: number, cost = 1): RateVerdict {
    if (!validScope(scope) || !positive(limit) || !positive(windowMs) || !Number.isSafeInteger(cost) || cost < 0) throw new Error('Invalid rate limit request');
    const now = this.clock(), window = Math.floor(now / windowMs);
    const retryAfter = Math.max(1, Math.ceil(((window + 1) * windowMs - now) / 1000));
    let s = this.scopes.get(scope);
    if (!s) { s = { buckets: new Map(), swept: -1 }; this.scopes.set(scope, s); }
    if (window !== s.swept || s.buckets.size >= this.maxBuckets) {
      for (const [k, v] of s.buckets) if (v.window !== window) s.buckets.delete(k);
      s.swept = window;
    }
    const id = `${tenant}\u0000${key}`;
    let bucket = s.buckets.get(id);
    if (!bucket) {
      if (s.buckets.size >= this.maxBuckets) return { ok: false, status: 503, retryAfter, reason: 'full' };
      bucket = { window, count: 0 }; s.buckets.set(id, bucket);
    }
    bucket.count += cost;
    return bucket.count > limit ? { ok: false, status: 429, retryAfter, reason: 'limited' } : { ok: true };
  }
}

/** A remembered admin response: status and JSON body only (streamed responses are never remembered). */
export type StoredResponse = { status: number; body?: unknown };
export type IdempotencyClaim =
  | { state: 'new' }
  /** `response` absent: the first request is still in flight (or its instance died before completing). */
  | { state: 'seen'; fingerprint: string; response?: StoredResponse };
export interface IdempotencyStore {
  /** Atomically claims (tenant, owner, key) for a request with this fingerprint, or returns what is recorded. */
  claim(tenant: string, owner: string, key: string, fingerprint: string): Promise<IdempotencyClaim>;
  /** Records the response of a claimed key. */
  complete(tenant: string, owner: string, key: string, response: StoredResponse): Promise<void>;
  /** Forgets a claimed key (transient failure: the caller may retry with it). */
  release(tenant: string, owner: string, key: string): Promise<void>;
  readonly shared: boolean;
  close?(): Promise<void>;
}
export const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{1,128}$/;
/**
 * Per-process least-recently-used records: at most `keys` per owner and `owners`
 * owners; the oldest is evicted, so a retry after eviction is not deduplicated.
 */
export class MemoryIdempotency implements IdempotencyStore {
  readonly shared = false;
  private owners = new Map<string, Map<string, { fingerprint: string; response?: StoredResponse }>>();
  private keys: number; private maxOwners: number;
  constructor(options: { keys?: number; owners?: number } = {}) {
    this.keys = options.keys ?? 256; this.maxOwners = options.owners ?? 1024;
    if (!positive(this.keys) || !positive(this.maxOwners)) throw new Error('Invalid idempotency configuration');
  }
  private id(tenant: string, owner: string) { return `${tenant}\u0000${owner}`; }
  async claim(tenant: string, owner: string, key: string, fingerprint: string): Promise<IdempotencyClaim> {
    const id = this.id(tenant, owner);
    let mine = this.owners.get(id);
    if (!mine) {
      if (this.owners.size >= this.maxOwners) this.owners.delete(this.owners.keys().next().value!);
      mine = new Map(); this.owners.set(id, mine);
    }
    const seen = mine.get(key);
    if (seen) {
      mine.delete(key); mine.set(key, seen); // most recently used
      return { state: 'seen', fingerprint: seen.fingerprint, ...(seen.response ? { response: structuredClone(seen.response) } : {}) };
    }
    if (mine.size >= this.keys) mine.delete(mine.keys().next().value!);
    mine.set(key, { fingerprint });
    return { state: 'new' };
  }
  async complete(tenant: string, owner: string, key: string, response: StoredResponse): Promise<void> {
    const entry = this.owners.get(this.id(tenant, owner))?.get(key);
    if (entry) entry.response = structuredClone(response);
  }
  async release(tenant: string, owner: string, key: string): Promise<void> {
    this.owners.get(this.id(tenant, owner))?.delete(key);
  }
}

/**
 * Serializes maintenance jobs (retention, index reconciliation) per (job, tenant)
 * without a leader: `run` executes `fn` only when no other holder runs the same job
 * for the same tenant, otherwise it returns `{ ran: false }` at once. The PostgreSQL
 * implementation uses a session advisory lock, released when the job ends or its
 * connection closes (a crashed instance never leaves a stale lock behind).
 */
export interface JobLock {
  run<T>(job: string, tenant: string, fn: () => Promise<T>): Promise<{ ran: true; value: T } | { ran: false }>;
  readonly shared: boolean;
  close?(): Promise<void>;
}
/** `sweep` (0.6, R193) and `erasure` (pending erasures, R194) serialize the lineage sweeper and the pending-erasure job. */
export const JOBS = ['retention', 'reconcile', 'audit-verify', 'sweep', 'erasure'] as const;
export class MemoryJobLock implements JobLock {
  readonly shared = false;
  private held = new Set<string>();
  async run<T>(job: string, tenant: string, fn: () => Promise<T>): Promise<{ ran: true; value: T } | { ran: false }> {
    if (!(JOBS as readonly string[]).includes(job)) throw new Error('Unknown job');
    const id = `${job}\u0000${tenant}`;
    if (this.held.has(id)) return { ran: false };
    this.held.add(id);
    try { return { ran: true, value: await fn() }; } finally { this.held.delete(id); }
  }
}
