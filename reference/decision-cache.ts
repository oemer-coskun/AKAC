import { createHash } from 'node:crypto';
import type { Obligation } from './decision.ts';
import { canonicalize } from './jcs.ts';
import type { Action, Binding } from './types.ts';

/**
 * Optional in-process decision cache (0.6, ADR-020). Off unless the operator constructs one.
 * It caches only ALLOW verdicts of Engine.evaluate() (the read-only decision used by external
 * enforcement points); a denial is always recomputed, so a stale entry can never withhold a
 * decision that a later grant would allow, and nothing here can turn a deny into an allow.
 *
 * The key holds everything the verdict depends on that the engine can read without hydrating:
 * tenant, tenant epoch, policy digest (core version, state policy version, hook revision),
 * binding (subject, agent, grant), resource, action, purpose, destination, the audited
 * operation (so the evaluate and AuthZEN listeners never share entries, 0.6b) and, when a
 * RiskProvider is configured, the levels it reported for the user and the agent. Every
 * control-plane change that can withdraw access (revoke, deactivate, quarantine, role,
 * group and label changes) advances the tenant epoch, so an entry of an older epoch is never
 * found. An entry also expires at `ttlMs` (at most one context lifetime, 300 s) and at the
 * earliest grant, heartbeat, access or session-scope (ephemeral) expiry of what the verdict
 * read; closing a session evicts every entry of its run (evictRun). A supplemental policy whose
 * answers change without a new `revision` is bounded by the TTL only.
 *
 * Process-local: it is not shared between instances, it is not persisted and it holds no
 * content. Every cached decision is still audited when it is served.
 */
export type DecisionCacheOptions = { ttlMs: number; maxEntries?: number; clock?: () => number };
export const DECISION_CACHE = { maxTtlMs: 300_000, maxEntries: 10_000 } as const;
export type CacheKey = { tenant: string; epoch: number; policyDigest: string; binding: Binding; resource: string; action: Action; purpose: string; destination?: string;
  /** The audited operation (evaluate, authzen_evaluate): one listener never serves another's entries (0.6b). */
  operation?: string;
  /** RiskProvider levels of the user and the agent at decision time (0.6b); absent without a provider. */
  risk?: string };
type Entry = { obligations: Obligation[]; expiresAt: number; tenant: string; run: string };
export class DecisionCache {
  readonly ttlMs: number;
  private maxEntries: number; private clock: () => number;
  private entries = new Map<string, Entry>();
  private counters = { hits: 0, misses: 0 };
  constructor(o: DecisionCacheOptions) {
    this.ttlMs = o.ttlMs; this.maxEntries = o.maxEntries ?? DECISION_CACHE.maxEntries; this.clock = o.clock ?? Date.now;
    if (!Number.isSafeInteger(this.ttlMs) || this.ttlMs < 1 || this.ttlMs > DECISION_CACHE.maxTtlMs || !Number.isSafeInteger(this.maxEntries) || this.maxEntries < 1) throw new Error('Invalid decision cache configuration');
  }
  private id(k: CacheKey) {
    return createHash('sha256').update(canonicalize([k.tenant, k.epoch, k.policyDigest, k.binding.subject, k.binding.agent, k.binding.grant, k.resource, k.action, k.purpose, k.destination ?? null,
      k.operation ?? null, k.risk ?? null])).digest('hex');
  }
  /** The cached allow's obligations, or undefined (miss, expired). The returned list is a copy. */
  get(k: CacheKey): Obligation[] | undefined {
    const id = this.id(k), e = this.entries.get(id), now = this.clock();
    if (!e || now >= e.expiresAt) { if (e) this.entries.delete(id); this.counters.misses++; return undefined; }
    this.entries.delete(id); this.entries.set(id, e); // most recently used
    this.counters.hits++;
    return structuredClone(e.obligations);
  }
  /** Stores an allow until `min(now + ttlMs, notAfter)`; nothing is stored when that is not in the future. */
  set(k: CacheKey, obligations: readonly Obligation[], notAfter = Infinity): void {
    const now = this.clock(), expiresAt = Math.min(now + this.ttlMs, notAfter);
    if (!(expiresAt > now)) return;
    const id = this.id(k);
    this.entries.delete(id);
    if (this.entries.size >= this.maxEntries) this.entries.delete(this.entries.keys().next().value!);
    this.entries.set(id, { obligations: structuredClone([...obligations]), expiresAt, tenant: k.tenant, run: k.binding.grant });
  }
  /** Drops every entry of one run (grant) of a tenant, for example when one of its sessions closes (R190). */
  evictRun(tenant: string, run: string): void {
    for (const [id, e] of this.entries) if (e.tenant === tenant && e.run === run) this.entries.delete(id);
  }
  clear(): void { this.entries.clear(); }
  get size(): number { return this.entries.size; }
  stats() { return { ...this.counters, size: this.entries.size }; }
}
