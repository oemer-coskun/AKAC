import { randomUUID } from 'node:crypto';
import { canDelegate, contextFresh, decide, effectiveClearance, effectiveLabel, principalTokens, transitiveClassification, visible } from './policy.ts';
import { appendAudit } from './audit.ts';
import { BudgetExceeded, hydrate } from './hydrate.ts';
import { ControlPlane } from './control.ts';
import { CORE_VERSION, LEVELS } from './types.ts';
import type { Action, Binding, Context, Decision, Grant, Knowledge, Level, PolicyHook, Ref, State, Store, Tx } from './types.ts';
import { validId } from './validation.ts';
export { validId } from './validation.ts';
export { auditHash, verifyAudit } from './audit.ts';

export type Result<T> = { ok: true; value: T } | { ok: false; code: 'NOT_AUTHORIZED' };
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
  | { type: 'decision'; tenant: string; operation: string; allowed: boolean; reason: string }
  | { type: 'filter_mismatch'; tenant: string }
  | { type: 'candidates_unavailable'; tenant: string };
export type EngineOptions = {
  policy?: PolicyHook; clock?: () => number; candidates?: CandidateSource;
  /** Metrics hook. Events carry no content, query text or resource ids. */
  onEvent?: (event: EngineEvent) => void;
  /** Overrides RETRIEVAL.contentBytes (lexical fallback content budget, UTF-8 bytes). */
  contentBytes?: number;
};
type Outcome<T> = { ok: true; value: T } | { ok: false; reason: string };
const good = <T>(value: T): Result<T> => ({ ok: true, value });
const bad = <T>(): Result<T> => ({ ok: false, code: 'NOT_AUTHORIZED' });
const fail = <T>(reason: string): Outcome<T> => ({ ok: false, reason });
/** Internal audit reason; HTTP responses never carry it. */
const reasonOf = (d: Decision) => d.effect === 'allow' ? 'AUTHORIZED' : `${d.category === 'defer' ? 'DEFERRED' : 'DENIED'}:${d.code}`;
const same = (a: Binding, b: Binding) => a.tenant === b.tenant && a.subject === b.subject && a.agent === b.agent && a.grant === b.grant;
const bindingValid = (b: Binding) => !!b && typeof b === 'object' && [b.tenant, b.subject, b.agent, b.grant].every(validId);
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
  constructor(store: Store, options: EngineOptions = {}) {
    if (options.policy && (!options.policy.revision || options.policy.revision.length > 128)) throw new Error('Policy revision required');
    this.contentBytes = options.contentBytes ?? RETRIEVAL.contentBytes;
    if (!Number.isSafeInteger(this.contentBytes) || this.contentBytes < 0) throw new Error('Invalid content budget');
    this.store = store; this.hook = options.policy; this.clock = options.clock ?? Date.now; this.source = options.candidates;
    const listener = options.onEvent;
    this.emit = event => { try { listener?.(event); } catch { /* metrics never affect decisions */ } };
  }
  stats() { return { ...this.counters }; }
  private revision(s: State) { return `${CORE_VERSION}|${s.policyVersion}|${this.hook?.revision ?? 'core-only'}`; }
  async ready(tenant?: string): Promise<boolean> {
    try { return await this.store.ready(tenant) && (!this.hook?.ready || await this.hook.ready()); }
    catch { return false; }
  }
  private audit(s: State, b: Binding, operation: string, allowed: boolean, reason: string) {
    appendAudit(s, { time: this.clock(), tenant: b.tenant, actor: b.subject, operation, decision: allowed ? 'allow' : 'deny',
      reason, policyVersion: this.revision(s), epoch: s.epochs[b.tenant] ?? 0 });
    this.counters.decisions++; if (!allowed) this.counters.denials++;
    this.emit({ type: 'decision', tenant: b.tenant, operation, allowed, reason });
  }
  /**
   * One tenant transaction for one audited operation. An exceeded load budget is a
   * deferred denial audited in the same transaction (only reads preceded it). Any
   * other failure is audited best effort as DEFERRED:STORE_ERROR in a separate
   * transaction and rethrown unchanged.
   */
  private async run<T>(b: Binding, operation: string, fn: (tx: Tx) => Promise<Result<T>>): Promise<Result<T>> {
    try {
      return await this.store.transaction(b.tenant, async tx => {
        try { return await fn(tx); }
        catch (error) {
          if (!(error instanceof BudgetExceeded)) throw error;
          await tx.load({ epoch: true, audit: true });
          return this.finish(tx.state, b, operation, fail('DEFERRED:BUDGET_EXCEEDED'));
        }
      });
    } catch (error) {
      try {
        await this.store.transaction(b.tenant, async tx => { await tx.load({ epoch: true, audit: true }); this.audit(tx.state, b, operation, false, 'DEFERRED:STORE_ERROR'); });
      } catch { /* best effort: the caller still receives the original failure */ }
      throw error;
    }
  }
  private async authorize(s: State, b: Binding, resource: string, action: Action, purpose: string): Promise<Decision> {
    const decision = decide(s, { binding: b, resource, action, purpose, now: this.clock() });
    if (decision.effect !== 'allow' || !this.hook) return decision;
    // Supplemental policy sees the highest effective classification over the whole
    // source graph, not only the object's own container chain (R25).
    const classification = transitiveClassification(s, s.knowledge[resource]!);
    if (!classification) return { effect: 'deny', code: 'INVALID_CONTEXT', category: 'defer' };
    try {
      return await this.hook.check({ tenant: b.tenant, action, purpose, classification })
        ? decision : { effect: 'deny', code: 'POLICY_DENIED', category: 'deny' };
    } catch { return { effect: 'deny', code: 'POLICY_UNAVAILABLE', category: 'defer' }; }
  }
  /** Capture every read in this credential-bound run. A new run needs a new grant. */
  private async projection(s: State, b: Binding, ids: string[], purpose: string): Promise<Outcome<Projection>> {
    if (!ids.length || ids.length > 64) return fail('DEFERRED:INVALID_REQUEST');
    const existing = Object.values(s.contexts).filter(c => same(c, b));
    if (existing.some(c => !contextFresh(s, c, this.clock(), this.revision(s)))) return fail('DENIED:STALE_CONTEXT');
    const all = new Set(ids);
    for (const c of existing) for (const ref of c.sources) {
      if (s.knowledge[ref.id]?.version !== ref.version) return fail('DENIED:STALE_SOURCE');
      all.add(ref.id);
    }
    if (all.size > 128) return fail('DEFERRED:BUDGET_EXCEEDED');
    for (const id of all) {
      const decision = await this.authorize(s, b, id, 'read', purpose);
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
    s.contexts[id] = context;
    return { ok: true, value: { context: id, expiresAt: context.expiresAt,
      documents: [...new Set(ids)].map(key => { const r = s.knowledge[key]!; return { id: r.id, version: r.version, content: r.content }; }) } };
  }
  private finish<T>(s: State, b: Binding, operation: string, outcome: Outcome<T>): Result<T> {
    this.audit(s, b, operation, outcome.ok, outcome.ok ? 'AUTHORIZED' : outcome.reason);
    return outcome.ok ? good(outcome.value) : bad();
  }
  async openContext(b: Binding, ids: string[], purpose: string): Promise<Result<Projection>> {
    if (!bindingValid(b) || !Array.isArray(ids) || ids.length > 64 || !ids.every(validId)) return bad();
    return this.run(b, 'read', async tx => {
      await hydrate(tx, { bindings: [b], knowledge: ids });
      return this.finish(tx.state, b, 'read', await this.projection(tx.state, b, ids, purpose));
    });
  }
  async retrieve(b: Binding, query: string, purpose: string, limit = 5): Promise<Result<Projection>> {
    if (!bindingValid(b)) return bad();
    const valid = typeof query === 'string' && !!query.trim() && query.length <= 4096 && Number.isInteger(limit) && limit >= 1 && limit <= 20;
    return this.source ? this.indexed(b, valid ? query : '', purpose, limit) : this.lexical(b, valid ? query : '', purpose, limit);
  }
  /**
   * Bounded fallback: authorize every tenant record first; unauthorized records never
   * enter scoring. Record count and total content bytes are both bounded.
   */
  private async lexical(b: Binding, query: string, purpose: string, limit: number): Promise<Result<Projection>> {
    return this.run(b, 'retrieve', async tx => {
      await hydrate(tx, { bindings: [b] });
      const s = tx.state;
      if (!query) return this.finish(s, b, 'retrieve', fail('DEFERRED:INVALID_REQUEST'));
      await tx.load({ corpus: RETRIEVAL.corpus + 1, corpusBytes: this.contentBytes });
      const candidates = Object.values(s.knowledge).filter(r => r.tenant === b.tenant);
      if (candidates.length > RETRIEVAL.corpus) return this.finish(s, b, 'retrieve', fail('DEFERRED:BUDGET_EXCEEDED'));
      let bytes = 0;
      for (const r of candidates) bytes += typeof r.content === 'string' ? Buffer.byteLength(r.content, 'utf8') : 0;
      if (bytes > this.contentBytes) return this.finish(s, b, 'retrieve', fail('DEFERRED:BUDGET_EXCEEDED'));
      await hydrate(tx, { bindings: [b], knowledge: candidates.map(r => r.id) });
      const eligible: Knowledge[] = [];
      const deadline = performance.now() + RETRIEVAL.deadlineMs;
      for (const r of candidates) {
        if (performance.now() >= deadline) return this.finish(s, b, 'retrieve', fail('DEFERRED:BUDGET_EXCEEDED'));
        if ((await this.authorize(s, b, r.id, 'read', purpose)).effect === 'allow') eligible.push(r);
      }
      if (performance.now() >= deadline) return this.finish(s, b, 'retrieve', fail('DEFERRED:BUDGET_EXCEEDED'));
      // No global document statistics. Unauthorized records never enter scoring.
      const terms = [...new Set(query.toLocaleLowerCase('en').split(/\s+/).filter(Boolean))];
      const ids = eligible.map(r => ({ r, score: terms.reduce((n, t) => n + Number(r.content.toLocaleLowerCase('en').includes(t)), 0) }))
        .filter(x => x.score > 0).sort((x, y) => y.score - x.score || x.r.id.localeCompare(y.r.id)).slice(0, limit).map(x => x.r.id);
      // An empty search deliberately does not distinguish no match from no authority.
      return this.finish(s, b, 'retrieve', await this.projection(s, b, ids, purpose));
    });
  }
  /** Candidate-source retrieval: pre-filter outside the tenant lock, re-check everything inside it. */
  private async indexed(b: Binding, query: string, purpose: string, limit: number): Promise<Result<Projection>> {
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
    return this.run(b, 'retrieve', async tx => {
      await hydrate(tx, { bindings: [b], knowledge: ids });
      const s = tx.state;
      if (!query) return this.finish(s, b, 'retrieve', fail('DEFERRED:INVALID_REQUEST'));
      if (unavailable) return this.finish(s, b, 'retrieve', fail('DEFERRED:CANDIDATES_UNAVAILABLE'));
      const eligible: string[] = [];
      for (const id of ids) {
        if (eligible.length >= limit) break;
        if ((await this.authorize(s, b, id, 'read', purpose)).effect === 'allow') eligible.push(id);
        else { this.counters.filterMismatches++; this.emit({ type: 'filter_mismatch', tenant: b.tenant }); }
      }
      return this.finish(s, b, 'retrieve', await this.projection(s, b, eligible, purpose));
    });
  }
  private async contextSources(s: State, b: Binding, contextId: string, action: Action): Promise<Outcome<Ref[]>> {
    if (!validId(contextId)) return fail('DEFERRED:INVALID_REQUEST');
    const selected = Object.hasOwn(s.contexts, contextId) ? s.contexts[contextId] : undefined;
    if (!selected || !same(selected, b)) return fail('DEFERRED:NOT_AUTHORIZED');
    const refs = new Map<string, Ref>();
    for (const c of Object.values(s.contexts).filter(c => same(c, b))) {
      if (!contextFresh(s, c, this.clock(), this.revision(s)) || c.purpose !== selected.purpose) return fail('DENIED:STALE_CONTEXT');
      for (const ref of c.sources) {
        if (s.knowledge[ref.id]?.version !== ref.version) return fail('DENIED:STALE_SOURCE');
        const decision = await this.authorize(s, b, ref.id, action, selected.purpose);
        if (decision.effect !== 'allow') return fail(reasonOf(decision));
        refs.set(ref.id, ref);
      }
    }
    if (!refs.size || selected.expiresAt <= this.clock()) return fail('DENIED:EXPIRED');
    for (const ref of refs.values()) {
      const decision = decide(s, { binding: b, resource: ref.id, action, purpose: selected.purpose, now: this.clock() });
      if (decision.effect !== 'allow') return fail(reasonOf(decision));
    }
    return { ok: true, value: [...refs.values()].sort((x, y) => x.id.localeCompare(y.id)) };
  }
  async derive(b: Binding, contextId: string, content: string, kind: 'memory' | 'artifact' = 'artifact'): Promise<Result<{ id: string; classification: string }>> {
    if (!bindingValid(b)) return bad();
    return this.run(b, 'derive', async tx => {
      await hydrate(tx, { bindings: [b], contexts: validId(contextId) ? [contextId] : [] });
      const s = tx.state;
      if (!content || content.length > 100_000 || !['memory', 'artifact'].includes(kind)) return this.finish(s, b, 'derive', fail('DEFERRED:INVALID_REQUEST'));
      const refs = await this.contextSources(s, b, contextId, 'derive');
      if (!refs.ok) return this.finish(s, b, 'derive', refs);
      if (kind === 'memory') {
        const memory = await this.contextSources(s, b, contextId, 'write_memory');
        if (!memory.ok) return this.finish(s, b, 'derive', memory);
      }
      const labels = refs.value.map(r => ({ source: s.knowledge[r.id]!, label: effectiveLabel(s, s.knowledge[r.id]!), top: transitiveClassification(s, s.knowledge[r.id]!) }));
      if (labels.some(x => !x.label || !x.top)) return this.finish(s, b, 'derive', fail('DEFERRED:INVALID_CONTEXT'));
      const id = randomUUID();
      // Effective labels include container floors and every transitive source: derivation never lowers a classification.
      const classification = LEVELS[Math.max(...labels.map(x => LEVELS.indexOf(x.top!)))]!;
      s.knowledge[id] = { id, tenant: b.tenant, version: 1, kind, origin: 'model', content, classification,
        projects: [...new Set(labels.flatMap(x => x.label!.projects))].sort(),
        // This local ACL cannot override the transitive source and container ACL conjunction.
        readerRoles: [...new Set(labels.flatMap(x => x.source.readerRoles))],
        readers: [...new Set(labels.flatMap(x => x.source.readers))], sources: refs.value, active: true };
      this.audit(s, b, 'derive', true, 'PROTECTED_DERIVATION'); return good({ id, classification });
    });
  }
  /** Release a generated response to a named recipient. Actual transport is an integration responsibility. */
  async release(b: Binding, contextId: string, recipientId: string, content: string, action: 'share' | 'export' = 'share'): Promise<Result<{ recipient: string; content: string }>> {
    if (!bindingValid(b)) return bad();
    return this.run(b, action === 'export' ? 'export' : 'share', async tx => {
      await hydrate(tx, { bindings: [b], contexts: validId(contextId) ? [contextId] : [], actors: validId(recipientId) ? [recipientId] : [] });
      const s = tx.state;
      const recipient = validId(recipientId) && Object.hasOwn(s.actors, recipientId) ? s.actors[recipientId] : undefined;
      const refs = await this.contextSources(s, b, contextId, action);
      if (!refs.ok) return this.finish(s, b, action, refs);
      if (!content || content.length > 100_000 || !recipient || recipient.tenant !== b.tenant
        || refs.value.some(ref => !visible(s, recipient, s.knowledge[ref.id]!, this.clock()))) {
        return this.finish(s, b, action, fail('DENIED:RECIPIENT'));
      }
      this.audit(s, b, action, true, 'AUTHORIZED_RECIPIENT'); return good({ recipient: recipientId, content });
    });
  }
  async delegate(b: Binding, child: Grant): Promise<Result<{ id: string }>> {
    if (!bindingValid(b) || !child || typeof child !== 'object' || !validId(child.id)) return bad();
    return this.run(b, 'delegate', async tx => {
      await hydrate(tx, { bindings: [b], grants: [child.id], actors: validId(child.agent) ? [child.agent] : [] });
      const s = tx.state;
      const parent = s.grants[b.grant];
      const user = s.actors[b.subject], agent = s.actors[b.agent];
      if (Object.hasOwn(s.grants, child.id) || !parent || parent.subject !== b.subject
        || parent.agent !== b.agent || parent.tenant !== b.tenant || !user?.active || !agent?.active
        || !canDelegate(s, parent, child, this.clock())) {
        return this.finish(s, b, 'delegate', fail('DENIED:INVALID_DELEGATION'));
      }
      s.grants[child.id] = structuredClone(child);
      this.audit(s, b, 'delegate', true, 'ATTENUATED'); return good({ id: child.id });
    });
  }
  /** Privileged control-plane operation; NOT exposed through the agent API. Advances only this tenant's epoch. */
  async revoke(tenant: string, adminId: string, type: 'grant' | 'knowledge' | 'actor', id: string): Promise<Result<{ epoch: number }>> {
    const result = await new ControlPlane(this.store, { clock: this.clock }).revoke(tenant, adminId, type, id);
    return result.ok ? result : bad();
  }
}
