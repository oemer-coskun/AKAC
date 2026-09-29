import { createHash, randomInt } from 'node:crypto';
import { LEVELS } from './types.ts';
import type { Action, Binding, Grant, Level, State } from './types.ts';
import type { DenialHint } from './decision.ts';
import { subset } from './policy.ts';
import type { RateLimitStore } from './limits.ts';

/**
 * Community-level release and retrieval protections (0.6, ADR-020, spec/AKAC-0.6.md):
 * response-time equalisation, denial hints, per-principal volume budgets and progressive
 * backoff. They are deliberately simple and deterministic. Adaptive throttling, anomaly
 * scoring and collusion detection are separate extensions that can only add restrictions.
 */

/** Response-time floor with jitter: every equalised response takes at least `minMs` plus a random 0..`jitterMs`. */
export type TimingOptions = { minMs: number; jitterMs?: number; now?: () => number; sleep?: (ms: number) => Promise<void> };
export const TIMING_LIMITS = { maxMinMs: 5000, maxJitterMs: 1000 } as const;
export class Equaliser {
  readonly minMs: number; readonly jitterMs: number;
  private now: () => number; private sleep: (ms: number) => Promise<void>;
  constructor(o: TimingOptions) {
    this.minMs = o.minMs; this.jitterMs = o.jitterMs ?? 0;
    if (!Number.isSafeInteger(this.minMs) || this.minMs < 0 || this.minMs > TIMING_LIMITS.maxMinMs
      || !Number.isSafeInteger(this.jitterMs) || this.jitterMs < 0 || this.jitterMs > TIMING_LIMITS.maxJitterMs) throw new Error('Invalid timing configuration');
    this.now = o.now ?? (() => performance.now()); this.sleep = o.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms)));
  }
  /** Timestamp to pass to pad() when the request handling starts. */
  start(): number { return this.now(); }
  /** Waits until the floor plus a fresh random jitter has elapsed since `startedAt`; resolves at once when it already has. */
  async pad(startedAt: number): Promise<void> {
    const target = this.minMs + (this.jitterMs ? randomInt(0, this.jitterMs + 1) : 0), wait = target - (this.now() - startedAt);
    if (wait > 0) await this.sleep(wait);
  }
}

/**
 * Denial hint from the caller's own grant, computed only from that grant (and its ancestors), the requested
 * action and purpose, and listener state; never from a resource, its existence, labels or ACL. A hint is
 * emitted only when the fact denies the request whatever the resource is:
 * - GRANT_EXPIRED: the grant, or an ancestor in its chain, has passed its expiry.
 * - PURPOSE_NOT_GRANTED: the grant does not list the requested purpose.
 * - ACTION_NOT_GRANTED: the grant does not list the requested action.
 * - RUNTIME_ENFORCER_REQUIRED: the listener has no runtime enforcer, and the tenant uses runtime containment policies.
 *   A property of the listener and the tenant configuration, not of any resource.
 * (RATE_LIMITED and APPROVAL_REQUIRED come from the caller's own rate and volume state.)
 */
export function grantHint(s: State, b: Binding, now: number, ask: { action?: Action; purpose?: string } = {}, listener: { noRuntimeEnforcer?: boolean } = {}): DenialHint | undefined {
  const own = Object.hasOwn(s.grants, b.grant) ? s.grants[b.grant] : undefined;
  if (!own || own.tenant !== b.tenant || own.subject !== b.subject || own.agent !== b.agent) return undefined;
  let g: Grant | undefined = own, n = 0;
  while (g && n++ < 32) {
    if (Number.isSafeInteger(g.expiresAt) && now >= g.expiresAt) return 'GRANT_EXPIRED';
    g = g.parent !== undefined && Object.hasOwn(s.grants, g.parent) ? s.grants[g.parent] : undefined;
  }
  if (ask.purpose !== undefined && Array.isArray(own.purposes) && !subset([ask.purpose], own.purposes)) return 'PURPOSE_NOT_GRANTED';
  if (ask.action !== undefined && Array.isArray(own.actions) && !own.actions.includes(ask.action)) return 'ACTION_NOT_GRANTED';
  if (listener.noRuntimeEnforcer && Object.values(s.runtimeProfiles ?? {}).some(p => !!p && p.tenant === b.tenant && p.active === true)) return 'RUNTIME_ENFORCER_REQUIRED';
  return undefined;
}

/**
 * Volume budgets (0.6, ADR-020): released content per (tenant, user, agent) and classification in one
 * window: bytes and documents. "Released" means what a read projection returns (retrieve, contexts) and what a
 * share/export outputs. The counters live in the RateLimitStore the listeners already use (shared through
 * PostgreSQL when configured), as fixed windows: a principal can spend up to twice a budget across a window
 * boundary; size the budget accordingly. A counter error is a denial (fail closed). Exceeding a budget denies
 * (`deny`) or defers to an approval (`approval`); it never allows.
 */
export type VolumeLimits = { bytes?: number; documents?: number };
export type VolumeOptions = { limiter: RateLimitStore; windowMs: number; limits: Partial<Record<Level, VolumeLimits>>; onExceed?: 'deny' | 'approval' };
export type VolumeVerdict = 'ok' | 'exceeded' | 'unavailable';
export const VOLUME_LIMITS = { maxWindowMs: 86_400_000, max: 2 ** 40 } as const;
export class VolumeBudget {
  readonly onExceed: 'deny' | 'approval';
  private limiter: RateLimitStore; private windowMs: number; private limits: Partial<Record<Level, VolumeLimits>>;
  constructor(o: VolumeOptions) {
    this.limiter = o.limiter; this.windowMs = o.windowMs; this.limits = o.limits; this.onExceed = o.onExceed ?? 'deny';
    const ok = (n: unknown) => n === undefined || (Number.isSafeInteger(n) && (n as number) >= 1 && (n as number) <= VOLUME_LIMITS.max);
    if (!this.limiter || !Number.isSafeInteger(this.windowMs) || this.windowMs < 1000 || this.windowMs > VOLUME_LIMITS.maxWindowMs || !this.limits || typeof this.limits !== 'object'
      || (this.onExceed !== 'deny' && this.onExceed !== 'approval') || Object.entries(this.limits).some(([level, l]) => !(LEVELS as readonly string[]).includes(level) || !l || !ok(l.bytes) || !ok(l.documents))) throw new Error('Invalid volume budget configuration');
  }
  /** Charges one disclosure to the principal's window for `level`; a level without a limit is unlimited. */
  async charge(b: Binding, level: Level, bytes: number, documents: number): Promise<VolumeVerdict> {
    const l = Object.hasOwn(this.limits, level) ? this.limits[level] : undefined;
    if (!l) return 'ok';
    const key = createHash('sha256').update(JSON.stringify([b.subject, b.agent])).digest('hex');
    try {
      if (l.bytes !== undefined) { const r = await this.limiter.take(b.tenant, `vol-b-${level}`, key, l.bytes, this.windowMs, bytes); if (!r.ok) return r.status === 429 ? 'exceeded' : 'unavailable'; }
      if (l.documents !== undefined) { const r = await this.limiter.take(b.tenant, `vol-d-${level}`, key, l.documents, this.windowMs, documents); if (!r.ok) return r.status === 429 ? 'exceeded' : 'unavailable'; }
      return 'ok';
    } catch { return 'unavailable'; }
  }
  /** True when the principal has already spent more than a budget of some classification in this window (a read of the counters; nothing is charged). */
  async exhausted(b: Binding): Promise<boolean> {
    const key = createHash('sha256').update(JSON.stringify([b.subject, b.agent])).digest('hex');
    for (const [level, l] of Object.entries(this.limits)) {
      if (l.bytes !== undefined && !(await this.limiter.take(b.tenant, `vol-b-${level}`, key, l.bytes, this.windowMs, 0)).ok) return true;
      if (l.documents !== undefined && !(await this.limiter.take(b.tenant, `vol-d-${level}`, key, l.documents, this.windowMs, 0)).ok) return true;
    }
    return false;
  }
}

/**
 * Progressive backoff (0.6, ADR-020): after `freeDenials` consecutive denials of one (tenant, user, agent)
 * within `resetSeconds`, every further denial doubles the time the principal is refused with 429 and
 * Retry-After, up to `maxSeconds`. A success resets the streak. Denials and no-match results count alike (they
 * are indistinguishable), so the streak reveals nothing about resources. State is per process: with several
 * instances each backs off separately; bounded to `maxPrincipals` entries (the oldest is dropped).
 */
export type BackoffOptions = { freeDenials?: number; baseSeconds?: number; maxSeconds?: number; resetSeconds?: number; maxPrincipals?: number; clock?: () => number };
export const BACKOFF = { freeDenials: 3, baseSeconds: 1, maxSeconds: 300, resetSeconds: 600, maxPrincipals: 10_000 } as const;
export class Backoff {
  private o: Required<Omit<BackoffOptions, 'clock'>>; private clock: () => number;
  private streaks = new Map<string, { count: number; last: number; until: number }>();
  constructor(o: BackoffOptions = {}) {
    this.o = { ...BACKOFF, ...Object.fromEntries(Object.entries(o).filter(([k, v]) => k !== 'clock' && v !== undefined)) } as Required<Omit<BackoffOptions, 'clock'>>;
    this.clock = o.clock ?? Date.now;
    const { freeDenials, baseSeconds, maxSeconds, resetSeconds, maxPrincipals } = this.o;
    if (![freeDenials, baseSeconds, maxSeconds, resetSeconds, maxPrincipals].every(n => Number.isSafeInteger(n) && n >= 1) || freeDenials > 1000 || maxSeconds < baseSeconds || maxSeconds > 86_400) throw new Error('Invalid backoff configuration');
  }
  private key(b: Binding) { return `${b.tenant}\u0000${b.subject}\u0000${b.agent}`; }
  /** Seconds the principal must still wait (0: not blocked). */
  blocked(b: Binding): number {
    const s = this.streaks.get(this.key(b)), now = this.clock();
    return s && s.until > now ? Math.ceil((s.until - now) / 1000) : 0;
  }
  /** Records a denial and returns the Retry-After it earned (0: still within the free denials). */
  denied(b: Binding): number {
    const k = this.key(b), now = this.clock();
    let s = this.streaks.get(k);
    if (s && now - s.last > this.o.resetSeconds * 1000) s = undefined;
    this.streaks.delete(k);
    const count = (s?.count ?? 0) + 1, over = count - this.o.freeDenials;
    const wait = over >= 1 ? Math.min(this.o.maxSeconds, this.o.baseSeconds * 2 ** Math.min(over - 1, 30)) : 0;
    this.streaks.set(k, { count, last: now, until: wait ? now + wait * 1000 : 0 });
    if (this.streaks.size > this.o.maxPrincipals) this.streaks.delete(this.streaks.keys().next().value!);
    return wait;
  }
  allowed(b: Binding) { this.streaks.delete(this.key(b)); }
}
