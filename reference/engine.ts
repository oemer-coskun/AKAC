import { canDelegate, contextFresh, decide, destinationGate, effectiveClearance, effectiveLabel, principalTokens, targetOf, transitiveClassification, visible } from './policy.ts';
import { randomUUID } from 'node:crypto';
import { appendAudit } from './audit.ts';
import { BudgetExceeded, hydrate } from './hydrate.ts';
import { ControlPlane } from './control.ts';
import { CORE_VERSION, LEVELS } from './types.ts';
import type { Action, Binding, Context, Decision, DestinationClass, Grant, Knowledge, Level, PolicyHook, Ref, State, Store, Tx } from './types.ts';
import { validId } from './validation.ts';
import { classify, merge, newDecisionId, parseObligations, policyDigest, traceOf } from './decision.ts';
import type { Call, Obligation, ReasonCode } from './decision.ts';
export { validId } from './validation.ts';
export { auditHash, verifyAudit } from './audit.ts';
export type { Call, Obligation } from './decision.ts';

/**
 * Every result carries the id of its decision (recorded in audit when the request
 * reached a tenant transaction). An allow carries the obligations the caller MUST
 * enforce; a caller that cannot enforce all of them MUST treat the result as a
 * deny. A denial carries nothing beyond NOT_AUTHORIZED and the decision id: its
 * reason code is recorded in audit only.
 */
export type Result<T> = { ok: true; value: T; decisionId: string; obligations: Obligation[] }
  | { ok: false; code: 'NOT_AUTHORIZED'; decisionId: string };
/** Read-only verdict of evaluate(): `code` is internal (audit, admin reason exposure). */
export type Verdict = { decision: boolean; decisionId: string; code: ReasonCode; obligations: Obligation[] };
/** The destination profile a release was authorized for (absent for unrestricted legacy releases). */
export type Released = { recipient: string; content: string; destination?: { id?: string; class: DestinationClass } };
export type Projection = { context: string; expiresAt: number; documents: { id: string; version: number; content: string }[] };
/**
 * Retrieval seam (for example a vector index partitioned per tenant and
 * classification). Results are untrusted hints: every candidate is re-checked by
 * decide() before disclosure, and failures are dropped and counted.
 */
export interface CandidateSource {
  candidates(input: { tenant: string; maxClassification: Level; tokens: string[]; query: string; limit: number }): Promise<string[]>;
}
export type EngineEvent =
  | { type: 'decision'; tenant: string; operation: string; allowed: boolean; reason: string; /** Always set by the engine. */ decisionId?: string; code?: ReasonCode }
  | { type: 'filter_mismatch'; tenant: string }
  | { type: 'candidates_unavailable'; tenant: string };
export type EngineOptions = {
  policy?: PolicyHook; clock?: () => number; candidates?: CandidateSource;
  /** Metrics hook. Events carry no content, query text or resource ids. */
  onEvent?: (event: EngineEvent) => void;
  /** Overrides RETRIEVAL.contentBytes (lexical fallback content budget, UTF-8 bytes). */
  contentBytes?: number;
  /**
   * Model-origin memory review (0.4, R-LIFE-7). 'quarantine': memory written by
   * derive() is stored quarantined until a security-admin releases it. A function
   * selects per tenant; any other result than 'none' quarantines (fail closed).
   * Default 'none' (0.3 behavior).
   */
  memoryReview?: MemoryReview | ((tenant: string) => MemoryReview);
};
export type MemoryReview = 'none' | 'quarantine';
/** An allow may name its audit reason (default AUTHORIZED) and carries its obligations. */
type Outcome<T> = { ok: true; value: T; obligations: Obligation[]; reason?: string } | { ok: false; reason: string };
/** One audited operation: its decision id and, when valid, the caller's trace id. */
type Op = { id: string; trace?: string };
const op = (call?: Call): Op => { const trace = traceOf(call); return { id: newDecisionId(), ...(trace ? { trace } : {}) }; };
const bad = <T>(o: Op): Result<T> => ({ ok: false, code: 'NOT_AUTHORIZED', decisionId: o.id });
const fail = <T>(reason: string): Outcome<T> => ({ ok: false, reason });
/** Internal audit reason; HTTP responses never carry it. */
const reasonOf = (d: Decision) => d.effect === 'allow' ? 'AUTHORIZED' : `${d.category === 'defer' ? 'DEFERRED' : 'DENIED'}:${d.code}`;
const same = (a: Binding, b: Binding) => a.tenant === b.tenant && a.subject === b.subject && a.agent === b.agent && a.grant === b.grant;
const bindingValid = (b: Binding) => !!b && typeof b === 'object' && [b.tenant, b.subject, b.agent, b.grant].every(validId);
/**
 * Adds the destination gate's restriction. The intersection with a policy's
 * destination_restricted may be empty: no destination can then receive the content,
 * so the release is denied rather than allowed with an unsatisfiable obligation.
 */
const restrictTo = (obligations: Obligation[], restrict?: string[]): Obligation[] | null => {
  if (!restrict) return obligations;
  const merged = merge(obligations, [{ type: 'destination_restricted', value: restrict }]);
  return unsatisfiable(merged) ? null : merged;
};
/** A merged destination_restricted with no destination left: no enforcement point can satisfy it (R37, R66). */
const unsatisfiable = (obligations: Obligation[]) => obligations.some(o => o.type === 'destination_restricted' && !o.value.length);
/**
 * R66: every destination_restricted obligation of a release must admit the actual
 * recipient, by the class or id of its profile, or `internal-user` for a user
 * without one. A recipient without a destination (R61 "none") admits nothing.
 */
const admits = (obligations: Obligation[], names: readonly string[]) =>
  obligations.every(o => o.type !== 'destination_restricted' || o.value.some(v => names.includes(v)));
/** A retrieval limit bounded by the run's result limit (grant.maxResults), when it has one. */
const capped = (s: State, b: Binding, limit: number) => {
  const cap = Object.hasOwn(s.grants, b.grant) ? s.grants[b.grant]!.maxResults : undefined;
  return Number.isSafeInteger(cap) && cap! >= 1 ? Math.min(limit, cap!) : limit;
};
const RANK = { confidential: LEVELS.indexOf('confidential'), restricted: LEVELS.indexOf('restricted') };
/** `contentBytes`: total content the lexical fallback may load (64 MiB); above it the retrieval is a deferred denial. */
export const RETRIEVAL = { corpus: 1000, candidates: 100, deadlineMs: 5000, contentBytes: 64 * 1024 * 1024 } as const;

export class Engine {
  private store: Store;
  private hook?: PolicyHook;
  private clock: () => number;
  private source?: CandidateSource;
  private emit: (event: EngineEvent) => void;
  private counters = { filterMismatches: 0, decisions: 0, denials: 0 };
  private contentBytes: number;
  private memoryReview: (tenant: string) => MemoryReview;
  constructor(store: Store, options: EngineOptions = {}) {
    if (options.policy && (!options.policy.revision || options.policy.revision.length > 128)) throw new Error('Policy revision required');
    this.contentBytes = options.contentBytes ?? RETRIEVAL.contentBytes;
    const review = options.memoryReview ?? 'none';
    if (typeof review !== 'function' && review !== 'none' && review !== 'quarantine') throw new Error('Invalid memory review mode');
    this.memoryReview = typeof review === 'function' ? tenant => { try { return review(tenant) === 'none' ? 'none' : 'quarantine'; } catch { return 'quarantine'; } } : () => review;
    if (!Number.isSafeInteger(this.contentBytes) || this.contentBytes < 0) throw new Error('Invalid content budget');
    this.store = store; this.hook = options.policy; this.clock = options.clock ?? Date.now; this.source = options.candidates;
    const listener = options.onEvent;
    this.emit = event => { try { listener?.(event); } catch { /* metrics never affect decisions */ } };
  }
  stats() { return { ...this.counters }; }
  private revision(s: State) { return `${CORE_VERSION}|${s.policyVersion}|${this.hook?.revision ?? 'core-only'}`; }
  /** Digest of the same material as revision(), over its JCS array form (unambiguous). */
  private digest(s: State) { return policyDigest([CORE_VERSION, s.policyVersion, this.hook?.revision ?? 'core-only']); }
  async ready(tenant?: string): Promise<boolean> {
    try { return await this.store.ready(tenant) && (!this.hook?.ready || await this.hook.ready()); }
    catch { return false; }
  }
  private audit(s: State, b: Binding, o: Op, operation: string, allowed: boolean, reason: string, obligations: Obligation[] = []) {
    const code = classify(reason);
    if (!code || !code.category !== allowed) throw new Error('Unclassified decision reason');
    appendAudit(s, { time: this.clock(), tenant: b.tenant, actor: b.subject, operation, decision: allowed ? 'allow' : 'deny',
      reason, policyVersion: this.revision(s), epoch: s.epochs[b.tenant] ?? 0, decisionId: o.id, reasonCode: code.code,
      policyDigest: this.digest(s), obligations: allowed ? obligations : [], runId: b.grant, ...(o.trace ? { traceId: o.trace } : {}) });
    this.counters.decisions++; if (!allowed) this.counters.denials++;
    this.emit({ type: 'decision', tenant: b.tenant, operation, allowed, reason, decisionId: o.id, code: code.code });
  }
  /**
   * One tenant transaction for one audited operation. An exceeded load budget is a
   * deferred denial audited in the same transaction (only reads preceded it). Any
   * other failure is audited best effort as DEFERRED:STORE_ERROR in a separate
   * transaction and rethrown unchanged.
   */
  private async run<T>(b: Binding, o: Op, operation: string, fn: (tx: Tx) => Promise<Result<T>>): Promise<Result<T>> {
    try {
      return await this.store.transaction(b.tenant, async tx => {
        try { return await fn(tx); }
        catch (error) {
          if (!(error instanceof BudgetExceeded)) throw error;
          await tx.load({ epoch: true, audit: true });
          return this.finish(tx.state, b, o, operation, fail('DEFERRED:BUDGET_EXCEEDED'));
        }
      });
    } catch (error) {
      try {
        await this.store.transaction(b.tenant, async tx => { await tx.load({ epoch: true, audit: true }); this.audit(tx.state, b, o, operation, false, 'DEFERRED:STORE_ERROR'); });
      } catch { /* best effort: the caller still receives the original failure */ }
      throw error;
    }
  }
  /**
   * decide(), then the supplemental policy. Obligations of the policy verdict are
   * validated strictly and appended to `sink` (the operation's obligations): an
   * unknown or malformed obligation is a definite UNSUPPORTED_OBLIGATION denial.
   */
  private async authorize(s: State, b: Binding, resource: string, action: Action, purpose: string, sink?: Obligation[]): Promise<Decision> {
    const decision = decide(s, { binding: b, resource, action, purpose, now: this.clock() });
    if (decision.effect !== 'allow' || !this.hook) return decision;
    // Supplemental policy sees the highest effective classification over the whole
    // source graph, not only the object's own container chain (R25).
    const classification = transitiveClassification(s, s.knowledge[resource]!);
    if (!classification) return { effect: 'deny', code: 'INVALID_CONTEXT', category: 'defer' };
    const input = { tenant: b.tenant, action, purpose, classification };
    let verdict: unknown;
    try { verdict = this.hook.verdict ? await this.hook.verdict(input) : { allow: await this.hook.check(input) }; }
    catch { return { effect: 'deny', code: 'POLICY_UNAVAILABLE', category: 'defer' }; }
    const v = verdict as { allow?: unknown; obligations?: unknown } | null;
    if (!v || typeof v !== 'object' || typeof v.allow !== 'boolean') return { effect: 'deny', code: 'POLICY_UNAVAILABLE', category: 'defer' };
    if (!v.allow) return { effect: 'deny', code: 'POLICY_DENIED', category: 'deny' };
    if (v.obligations !== undefined) {
      const obligations = parseObligations(v.obligations);
      if (!obligations) return { effect: 'deny', code: 'UNSUPPORTED_OBLIGATION', category: 'deny' };
      // Combined with what earlier records of the same operation required, the restriction must stay satisfiable.
      if (sink && unsatisfiable(merge(sink, obligations))) return { effect: 'deny', code: 'UNSUPPORTED_OBLIGATION', category: 'deny' };
      sink?.push(...obligations);
    }
    return decision;
  }
  /**
   * Core obligations of disclosing (or deriving from) these records, by the highest
   * transitive effective classification: full audit from confidential, no
   * persistence outside AKAC for restricted material, and the context lifetime
   * when given. Merged restrictively with the supplemental policy's obligations.
   */
  private obligations(s: State, ids: Iterable<string>, policy: Obligation[], ttl?: number): Obligation[] | null {
    const level = this.top(s, ids);
    if (!level) return null;
    const top = LEVELS.indexOf(level);
    const own: Obligation[] = [];
    if (top >= RANK.confidential) own.push({ type: 'audit_level', value: 'full' });
    if (top >= RANK.restricted) own.push({ type: 'no_persist' });
    if (ttl !== undefined) own.push({ type: 'max_context_ttl_ms', value: Math.max(1, ttl) });
    const merged = merge(own, policy);
    return unsatisfiable(merged) ? null : merged;
  }
  /** Highest transitive effective classification over these records (R25); null when it cannot be established. */
  private top(s: State, ids: Iterable<string>): Level | null {
    let top = 0;
    for (const id of ids) {
      const level = Object.hasOwn(s.knowledge, id) ? transitiveClassification(s, s.knowledge[id]!) : null;
      if (!level) return null;
      top = Math.max(top, LEVELS.indexOf(level));
    }
    return LEVELS[top]!;
  }
  /** Capture every read in this credential-bound run. A new run needs a new grant. */
  private async projection(s: State, b: Binding, ids: string[], purpose: string): Promise<Outcome<Projection>> {
    if (!ids.length || ids.length > 64) return fail('DEFERRED:INVALID_REQUEST');
    // Result limit of the run (ADR-008): one disclosure never returns more documents than the grant allows.
    const cap = s.grants[b.grant]?.maxResults;
    if (cap !== undefined && new Set(ids).size > cap) return fail('DENIED:OUT_OF_SCOPE');
    const existing = Object.values(s.contexts).filter(c => same(c, b));
    if (existing.some(c => !contextFresh(s, c, this.clock(), this.revision(s)))) return fail('DENIED:STALE_CONTEXT');
    const all = new Set(ids);
    for (const c of existing) for (const ref of c.sources) {
      if (s.knowledge[ref.id]?.version !== ref.version) return fail('DENIED:STALE_SOURCE');
      all.add(ref.id);
    }
    if (all.size > 128) return fail('DEFERRED:BUDGET_EXCEEDED');
    const policy: Obligation[] = [];
    for (const id of all) {
      const decision = await this.authorize(s, b, id, 'read', purpose, policy);
      if (decision.effect !== 'allow') return fail(reasonOf(decision));
    }
    const grant = s.grants[b.grant]!;
    const id = randomUUID();
    const context: Context = { ...b, id, purpose, sources: [...all].sort().map(key => ({ id: key, version: s.knowledge[key]!.version })),
      expiresAt: Math.min(grant.expiresAt, this.clock() + 300_000, ...existing.map(c => c.expiresAt)),
      epoch: s.epochs[b.tenant] ?? 0, policyVersion: this.revision(s), active: true };
    // OPA evaluation may have taken time; enforce freshness at the disclosure boundary.
    if (this.clock() >= context.expiresAt) return fail('DENIED:EXPIRED');
    for (const key of all) {
      const decision = decide(s, { binding: b, resource: key, action: 'read', purpose, now: this.clock() });
      if (decision.effect !== 'allow') return fail(reasonOf(decision));
    }
    const obligations = this.obligations(s, all, policy, context.expiresAt - this.clock());
    if (!obligations) return fail('DEFERRED:INVALID_CONTEXT');
    s.contexts[id] = context;
    return { ok: true, obligations, value: { context: id, expiresAt: context.expiresAt,
      documents: [...new Set(ids)].map(key => { const r = s.knowledge[key]!; return { id: r.id, version: r.version, content: r.content }; }) } };
  }
  private finish<T>(s: State, b: Binding, o: Op, operation: string, outcome: Outcome<T>): Result<T> {
    this.audit(s, b, o, operation, outcome.ok, outcome.ok ? outcome.reason ?? 'AUTHORIZED' : outcome.reason, outcome.ok ? outcome.obligations : []);
    return outcome.ok ? { ok: true, value: outcome.value, decisionId: o.id, obligations: outcome.obligations } : bad(o);
  }
  async openContext(b: Binding, ids: string[], purpose: string, call?: Call): Promise<Result<Projection>> {
    const o = op(call);
    if (!bindingValid(b) || !Array.isArray(ids) || ids.length > 64 || !ids.every(validId)) return bad(o);
    return this.run(b, o, 'read', async tx => {
      await hydrate(tx, { bindings: [b], knowledge: ids });
      return this.finish(tx.state, b, o, 'read', await this.projection(tx.state, b, ids, purpose));
    });
  }
  async retrieve(b: Binding, query: string, purpose: string, limit = 5, call?: Call): Promise<Result<Projection>> {
    const o = op(call);
    if (!bindingValid(b)) return bad(o);
    const valid = typeof query === 'string' && !!query.trim() && query.length <= 4096 && Number.isInteger(limit) && limit >= 1 && limit <= 20;
    return this.source ? this.indexed(b, o, valid ? query : '', purpose, limit) : this.lexical(b, o, valid ? query : '', purpose, limit);
  }
  /**
   * Bounded fallback: authorize every tenant record first; unauthorized records never
   * enter scoring. Record count and total content bytes are both bounded.
   */
  private async lexical(b: Binding, o: Op, query: string, purpose: string, limit: number): Promise<Result<Projection>> {
    return this.run(b, o, 'retrieve', async tx => {
      await hydrate(tx, { bindings: [b] });
      const s = tx.state;
      if (!query) return this.finish(s, b, o, 'retrieve', fail('DEFERRED:INVALID_REQUEST'));
      limit = capped(s, b, limit);
      await tx.load({ corpus: RETRIEVAL.corpus + 1, corpusBytes: this.contentBytes });
      const candidates = Object.values(s.knowledge).filter(r => r.tenant === b.tenant);
      if (candidates.length > RETRIEVAL.corpus) return this.finish(s, b, o, 'retrieve', fail('DEFERRED:BUDGET_EXCEEDED'));
      let bytes = 0;
      for (const r of candidates) bytes += typeof r.content === 'string' ? Buffer.byteLength(r.content, 'utf8') : 0;
      if (bytes > this.contentBytes) return this.finish(s, b, o, 'retrieve', fail('DEFERRED:BUDGET_EXCEEDED'));
      await hydrate(tx, { bindings: [b], knowledge: candidates.map(r => r.id) });
      const eligible: Knowledge[] = [];
      const deadline = performance.now() + RETRIEVAL.deadlineMs;
      for (const r of candidates) {
        if (performance.now() >= deadline) return this.finish(s, b, o, 'retrieve', fail('DEFERRED:BUDGET_EXCEEDED'));
        if ((await this.authorize(s, b, r.id, 'read', purpose)).effect === 'allow') eligible.push(r);
      }
      if (performance.now() >= deadline) return this.finish(s, b, o, 'retrieve', fail('DEFERRED:BUDGET_EXCEEDED'));
      // No global document statistics. Unauthorized records never enter scoring.
      const terms = [...new Set(query.toLocaleLowerCase('en').split(/\s+/).filter(Boolean))];
      const ids = eligible.map(r => ({ r, score: terms.reduce((n, t) => n + Number(r.content.toLocaleLowerCase('en').includes(t)), 0) }))
        .filter(x => x.score > 0).sort((x, y) => y.score - x.score || x.r.id.localeCompare(y.r.id)).slice(0, limit).map(x => x.r.id);
      // An empty search deliberately does not distinguish no match from no authority.
      return this.finish(s, b, o, 'retrieve', await this.projection(s, b, ids, purpose));
    });
  }
  /** Candidate-source retrieval: pre-filter outside the tenant lock, re-check everything inside it. */
  private async indexed(b: Binding, o: Op, query: string, purpose: string, limit: number): Promise<Result<Projection>> {
    const probe = query ? await this.store.transaction(b.tenant, async tx => {
      // An over-budget probe yields no candidates; the audited transaction below denies.
      try { await hydrate(tx, { bindings: [b] }); } catch (error) { if (error instanceof BudgetExceeded) return null; throw error; }
      const s = tx.state, user = s.actors[b.subject], agent = s.actors[b.agent], grant = s.grants[b.grant];
      if (!user || !agent || !grant || user.tenant !== b.tenant || agent.tenant !== b.tenant) return null;
      const tokens = principalTokens(s, user, grant.activeRoles), maxClassification = effectiveClearance(user, agent);
      return tokens && maxClassification ? { tokens, maxClassification } : null;
    }) : null;
    let ids: string[] = [], unavailable = false;
    if (probe) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const deadline = new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error('deadline')), RETRIEVAL.deadlineMs); });
        const found = await Promise.race([this.source!.candidates({ tenant: b.tenant, ...probe, query,
          limit: Math.min(RETRIEVAL.candidates, limit * 4) }), deadline]);
        if (!Array.isArray(found)) throw new Error('shape');
        ids = [...new Set(found.filter(validId))].slice(0, RETRIEVAL.candidates);
      } catch { unavailable = true; this.emit({ type: 'candidates_unavailable', tenant: b.tenant }); }
      finally { if (timer) clearTimeout(timer); }
    }
    return this.run(b, o, 'retrieve', async tx => {
      await hydrate(tx, { bindings: [b], knowledge: ids });
      const s = tx.state;
      if (!query) return this.finish(s, b, o, 'retrieve', fail('DEFERRED:INVALID_REQUEST'));
      if (unavailable) return this.finish(s, b, o, 'retrieve', fail('DEFERRED:CANDIDATES_UNAVAILABLE'));
      limit = capped(s, b, limit);
      const eligible: string[] = [];
      for (const id of ids) {
        if (eligible.length >= limit) break;
        if ((await this.authorize(s, b, id, 'read', purpose)).effect === 'allow') eligible.push(id);
        else { this.counters.filterMismatches++; this.emit({ type: 'filter_mismatch', tenant: b.tenant }); }
      }
      return this.finish(s, b, o, 'retrieve', await this.projection(s, b, eligible, purpose));
    });
  }
  private async contextSources(s: State, b: Binding, contextId: string, action: Action): Promise<Outcome<Ref[]>> {
    if (!validId(contextId)) return fail('DEFERRED:INVALID_REQUEST');
    const selected = Object.hasOwn(s.contexts, contextId) ? s.contexts[contextId] : undefined;
    if (!selected || !same(selected, b)) return fail('DEFERRED:NOT_AUTHORIZED');
    const refs = new Map<string, Ref>(), policy: Obligation[] = [];
    for (const c of Object.values(s.contexts).filter(c => same(c, b))) {
      if (!contextFresh(s, c, this.clock(), this.revision(s)) || c.purpose !== selected.purpose) return fail('DENIED:STALE_CONTEXT');
      for (const ref of c.sources) {
        if (s.knowledge[ref.id]?.version !== ref.version) return fail('DENIED:STALE_SOURCE');
        const decision = await this.authorize(s, b, ref.id, action, selected.purpose, policy);
        if (decision.effect !== 'allow') return fail(reasonOf(decision));
        refs.set(ref.id, ref);
      }
    }
    if (!refs.size || selected.expiresAt <= this.clock()) return fail('DENIED:EXPIRED');
    for (const ref of refs.values()) {
      const decision = decide(s, { binding: b, resource: ref.id, action, purpose: selected.purpose, now: this.clock() });
      if (decision.effect !== 'allow') return fail(reasonOf(decision));
    }
    const obligations = this.obligations(s, refs.keys(), policy);
    if (!obligations) return fail('DEFERRED:INVALID_CONTEXT');
    return { ok: true, value: [...refs.values()].sort((x, y) => x.id.localeCompare(y.id)), obligations };
  }
  async derive(b: Binding, contextId: string, content: string, kind: 'memory' | 'artifact' = 'artifact', call?: Call): Promise<Result<{ id: string; classification: string; quarantined?: true }>> {
    const o = op(call);
    if (!bindingValid(b)) return bad(o);
    return this.run(b, o, 'derive', async tx => {
      await hydrate(tx, { bindings: [b], contexts: validId(contextId) ? [contextId] : [] });
      const s = tx.state;
      if (!content || content.length > 100_000 || !['memory', 'artifact'].includes(kind)) return this.finish(s, b, o, 'derive', fail('DEFERRED:INVALID_REQUEST'));
      const refs = await this.contextSources(s, b, contextId, 'derive');
      if (!refs.ok) return this.finish(s, b, o, 'derive', refs);
      let obligations = refs.obligations;
      if (kind === 'memory') {
        const memory = await this.contextSources(s, b, contextId, 'write_memory');
        if (!memory.ok) return this.finish(s, b, o, 'derive', memory);
        obligations = merge(obligations, memory.obligations);
        if (unsatisfiable(obligations)) return this.finish(s, b, o, 'derive', fail('DENIED:UNSUPPORTED_OBLIGATION'));
      }
      const labels = refs.value.map(r => ({ source: s.knowledge[r.id]!, label: effectiveLabel(s, s.knowledge[r.id]!), top: transitiveClassification(s, s.knowledge[r.id]!) }));
      if (labels.some(x => !x.label || !x.top)) return this.finish(s, b, o, 'derive', fail('DEFERRED:INVALID_CONTEXT'));
      const id = randomUUID();
      // Effective labels include container floors and every transitive source: derivation never lowers a classification.
      const classification = LEVELS[Math.max(...labels.map(x => LEVELS.indexOf(x.top!)))]!;
      s.knowledge[id] = { id, tenant: b.tenant, version: 1, kind, origin: 'model', content, classification,
        projects: [...new Set(labels.flatMap(x => x.label!.projects))].sort(),
        // This local ACL cannot override the transitive source and container ACL conjunction.
        readerRoles: [...new Set(labels.flatMap(x => x.source.readerRoles))],
        readers: [...new Set(labels.flatMap(x => x.source.readers))], sources: refs.value, active: true };
      // Derived content inherits the earliest retention deadline of its sources (R-LIFE-12).
      const retain = labels.map(x => x.source.retainUntil).filter((t): t is number => Number.isSafeInteger(t));
      if (retain.length) s.knowledge[id]!.retainUntil = Math.min(...retain);
      const quarantined = kind === 'memory' && this.memoryReview(b.tenant) !== 'none';
      if (quarantined) Object.assign(s.knowledge[id]!, { lifecycle: 'quarantined', lifecycleAt: this.clock(), quarantineReason: 'memory_review' });
      return this.finish(s, b, o, 'derive', { ok: true, value: { id, classification, ...(quarantined ? { quarantined: true } : {}) }, obligations, reason: 'PROTECTED_DERIVATION' });
    });
  }
  /**
   * Release a generated response to a named recipient. Actual transport is an
   * integration responsibility. Beyond the recipient's own visibility, the
   * recipient's destination profile and the run's destination restriction apply
   * (ADR-008, R-DEST-3..7); an allow bound to a destination carries
   * destination_restricted and names the destination in the result.
   */
  async release(b: Binding, contextId: string, recipientId: string, content: string, action: 'share' | 'export' = 'share', call?: Call): Promise<Result<Released>> {
    const o = op(call);
    if (!bindingValid(b)) return bad(o);
    return this.run(b, o, action === 'export' ? 'export' : 'share', async tx => {
      await hydrate(tx, { bindings: [b], contexts: validId(contextId) ? [contextId] : [], actors: validId(recipientId) ? [recipientId] : [] });
      const s = tx.state;
      const recipient = validId(recipientId) && Object.hasOwn(s.actors, recipientId) ? s.actors[recipientId] : undefined;
      const refs = await this.contextSources(s, b, contextId, action);
      if (!refs.ok) return this.finish(s, b, o, action, refs);
      if (!content || content.length > 100_000 || !recipient || recipient.tenant !== b.tenant
        || refs.value.some(ref => !visible(s, recipient, s.knowledge[ref.id]!, this.clock()))) {
        return this.finish(s, b, o, action, fail('DENIED:RECIPIENT'));
      }
      // Destination gate (ADR-008): everything released, with its transitive sources, against the recipient's profile and the run.
      const target = targetOf(recipient);
      const gate = destinationGate(s, s.grants[b.grant]!, target, b.tenant, this.top(s, refs.value.map(r => r.id)), s.contexts[contextId]!.purpose);
      if (!gate.ok) return this.finish(s, b, o, action, fail('DENIED:RECIPIENT'));
      const obligations = restrictTo(refs.obligations, gate.restrict);
      // A supplemental policy may restrict destinations even when the run and the recipient do not (R66):
      // the actual recipient must be admitted by every restriction, whatever its origin.
      const destination = gate.destination ?? (target.kind === 'implicit-user' ? { class: 'internal-user' as const } : undefined);
      const names = destination ? [destination.class, ...(destination.id !== undefined ? [destination.id] : [])] : [];
      if (!obligations || !admits(obligations, names)) return this.finish(s, b, o, action, fail('DENIED:RECIPIENT'));
      const restricted = obligations.some(x => x.type === 'destination_restricted');
      return this.finish(s, b, o, action, { ok: true, value: { recipient: recipientId, content, ...(destination && (gate.destination || restricted) ? { destination } : {}) },
        obligations, reason: 'AUTHORIZED_RECIPIENT' });
    });
  }
  /**
   * Read-only, audited decision for an external enforcement point (AuthZEN, egress
   * proxies): hydrate, decide(), the supplemental policy and the core obligations,
   * exactly as the gates above apply them, without creating a context or disclosing
   * content. For share/export, `destination` names the Destination profile the
   * enforcement point will send to; the destination gate then applies (an unknown
   * or inactive profile denies). Without it, a run restricted to destinations is
   * allowed only with destination_restricted naming the run's destinations.
   */
  async evaluate(b: Binding, resource: string, action: Action, purpose: string, options: { destination?: string; operation?: string } = {}, call?: Call): Promise<Verdict> {
    const o = op(call), operation = options.operation ?? 'evaluate';
    if (!bindingValid(b)) return { decision: false, decisionId: o.id, code: 'INVALID_REQUEST', obligations: [] };
    let reason: string | undefined;
    const result = await this.run<true>(b, o, operation, async tx => {
      await hydrate(tx, { bindings: [b], knowledge: validId(resource) ? [resource] : [], destinations: validId(options.destination) ? [options.destination] : [] });
      const s = tx.state, outcome = await this.evaluation(s, b, resource, action, purpose, options.destination);
      reason = outcome.ok ? 'AUTHORIZED' : outcome.reason;
      return this.finish(s, b, o, operation, outcome);
    });
    // Only an exceeded load budget returns a denial without passing through evaluation().
    const code = classify(result.ok ? 'AUTHORIZED' : reason ?? 'DEFERRED:BUDGET_EXCEEDED')!.code;
    return { decision: result.ok, decisionId: result.decisionId, code, obligations: result.ok ? result.obligations : [] };
  }
  private async evaluation(s: State, b: Binding, resource: string, action: Action, purpose: string, destination?: string): Promise<Outcome<true>> {
    if (destination !== undefined && !validId(destination)) return fail('DEFERRED:INVALID_REQUEST');
    const policy: Obligation[] = [];
    const decision = await this.authorize(s, b, resource, action, purpose, policy);
    if (decision.effect !== 'allow') return fail(reasonOf(decision));
    const obligations = this.obligations(s, [resource], policy);
    if (!obligations) return fail('DEFERRED:INVALID_CONTEXT');
    if (action !== 'share' && action !== 'export' && destination === undefined) return { ok: true, value: true, obligations };
    const gate = destinationGate(s, s.grants[b.grant]!, destination !== undefined ? { kind: 'profile', id: destination } : { kind: 'unspecified' },
      b.tenant, this.top(s, [resource]), purpose);
    const restricted = gate.ok && restrictTo(obligations, gate.restrict);
    return restricted ? { ok: true, value: true, obligations: restricted } : fail('DENIED:RECIPIENT');
  }
  async delegate(b: Binding, child: Grant, call?: Call): Promise<Result<{ id: string }>> {
    const o = op(call);
    if (!bindingValid(b) || !child || typeof child !== 'object' || !validId(child.id)) return bad(o);
    return this.run(b, o, 'delegate', async tx => {
      await hydrate(tx, { bindings: [b], grants: [child.id], actors: validId(child.agent) ? [child.agent] : [] });
      const s = tx.state;
      const parent = s.grants[b.grant];
      const user = s.actors[b.subject], agent = s.actors[b.agent];
      if (Object.hasOwn(s.grants, child.id) || !parent || parent.subject !== b.subject
        || parent.agent !== b.agent || parent.tenant !== b.tenant || !user?.active || !agent?.active
        || !canDelegate(s, parent, child, this.clock())) {
        return this.finish(s, b, o, 'delegate', fail('DENIED:INVALID_DELEGATION'));
      }
      s.grants[child.id] = structuredClone(child);
      return this.finish(s, b, o, 'delegate', { ok: true, value: { id: child.id }, obligations: [], reason: 'ATTENUATED' });
    });
  }
  /** Privileged control-plane operation; NOT exposed through the agent API. Advances only this tenant's epoch. */
  async revoke(tenant: string, adminId: string, type: 'grant' | 'knowledge' | 'actor', id: string, call?: Call): Promise<Result<{ epoch: number }>> {
    const result = await new ControlPlane(this.store, { clock: this.clock }).traced(call?.trace).revoke(tenant, adminId, type, id);
    return result.ok ? { ok: true, value: result.value, decisionId: result.decisionId, obligations: [] }
      : { ok: false, code: 'NOT_AUTHORIZED', decisionId: result.decisionId };
  }
}
