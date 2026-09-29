import { canDelegate, contextFresh, decide, destinationGate, effectiveClearance, evaluationTargetNamed, effectiveLabel, principalTokens, targetOf, transitiveClassification, visible } from './policy.ts';
import { randomUUID } from 'node:crypto';
import { appendAudit } from './audit.ts';
import { BudgetExceeded, hydrate } from './hydrate.ts';
import { ControlPlane } from './control.ts';
import { CORE_VERSION, DESTINATION_CLASSES, LEVELS } from './types.ts';
import type { Action, Binding, Context, Decision, DestinationClass, Grant, Knowledge, Level, PolicyHook, Ref, State, Store, Tx } from './types.ts';
import { validId } from './validation.ts';
import { classify, executionOf, merge, newDecisionId, parseObligations, policyDigest, runtimeRevisionOf, traceOf, unenforceableOf, unsatisfiable } from './decision.ts';
import { containment, containmentAcross, runtimeSetDigest } from './containment.ts';
import type { Call, DenialHint, Obligation, ObligationType, ReasonCode } from './decision.ts';
import { validFindings } from './decision.ts';
import { checkHookOptions, checkHooks, runReleaseFilters, runSanitizers } from './hooks.ts';
import type { DeriveSanitizer, HookOptions, ReleaseFilter } from './hooks.ts';
import { grantHint } from './protection.ts';
import type { VolumeBudget } from './protection.ts';
import { DecisionCache } from './decision-cache.ts';
import { actorChainOf } from './delegation.ts';
import { withRisk } from './risk.ts';
import type { RiskProvider } from './risk.ts';
import { RISK_LEVELS } from './types.ts';
import type { RiskLevel } from './types.ts';
import type { CacheKey } from './decision-cache.ts';
import { RetrievalDisabled } from './anchors.ts';
import { COMBINATION_WINDOW, combination, factsOf, lineageDepthOf, placementAllowed, residencyAdmits, sessionOf, sortedResidency, sortedTags, validModality, validModel } from './knowledge.ts';
import { withEphemeral } from './ephemeral.ts';
import type { EphemeralStore } from './ephemeral.ts';
import { containerChain, subset } from './policy.ts';
import { KNOWLEDGE } from './types.ts';
import type { Modality, ModelRef } from './types.ts';
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
  | { ok: false; code: 'NOT_AUTHORIZED'; decisionId: string; /** Opt-in (Call.hints): a closed hint from the caller's own grant, credential or budget state, never from the resource. */ hint?: DenialHint };
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
  /**
   * `tokens` are the user's pre-filter tokens; `agent` (0.6, ADR-020) holds the agent's. A document is a candidate only when
   * BOTH audiences admit it (decide() requires the user and the agent to see it), so a source should pre-filter on both.
   */
  candidates(input: { tenant: string; maxClassification: Level; tokens: string[]; agent?: { tokens: string[] }; query: string; limit: number }): Promise<string[]>;
}
export type EngineEvent =
  | { type: 'decision'; tenant: string; operation: string; allowed: boolean; reason: string; /** Always set by the engine. */ decisionId?: string; code?: ReasonCode;
    /** The decision was taken under a break-glass grant (0.6, R150). */ breakGlass?: true }
  | { type: 'filter_mismatch'; tenant: string }
  | { type: 'candidates_unavailable'; tenant: string }
  /** Release filter or derive sanitizer outcome (ADR-020); no content, no ids of resources. */
  | { type: 'hook'; tenant: string; hook: 'release_filter' | 'derive_sanitizer'; outcome: 'redact' | 'clean' | 'deny' | 'error' }
  | { type: 'volume_exceeded'; tenant: string; classification: Level }
  | { type: 'retrieval_disabled'; tenant: string };
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
  /**
   * External risk source (0.6, R152): consulted after decide() allows; its level for
   * the user and the agent can only lower their clearance (policy.ts riskLimit). A
   * failure or an unknown level denies (POLICY_UNAVAILABLE).
   */
  risk?: RiskProvider;
  /**
   * Release filters and derive sanitizers (0.6, ADR-020), in order. They run after the operation was authorized and can only
   * narrow: redact/clean or deny. `hooks.failure` 'deny' (default) makes an error, timeout or malformed result a denial.
   */
  releaseFilters?: ReleaseFilter[]; deriveSanitizers?: DeriveSanitizer[]; hooks?: HookOptions;
  /**
   * Filter ids every release of this tenant and highest classification must pass, in addition to the release_filter
   * obligations of the supplemental policy. A required filter that is not configured denies the release.
   */
  requiredFilters?: (tenant: string, classification: Level) => readonly string[];
  /** Volume budgets per (tenant, user, agent) and classification (0.6, ADR-020). Off unless given. */
  volume?: VolumeBudget;
  /** In-process cache of allow verdicts of evaluate() (0.6, ADR-020). Off unless given. */
  decisionCache?: DecisionCache;
  /**
   * Model identity recorded on derived content (0.6, R191): the model this gateway's
   * trusted runtime uses, per tenant. Operator configuration, never request data; a
   * trusted in-process caller may name the model per derivation (derive() `trusted`).
   */
  model?: ModelRef | ((tenant: string) => ModelRef | undefined);
  /**
   * Combination window (0.6b, R188), ms: a disclosure is checked against the combination rules together with
   * everything the same user and agent read under ANY grant in contexts alive during the last `combinationWindowMs`,
   * so splitting a forbidden combination across grants or credentials does not bypass a rule. Default and minimum:
   * the maximum context lifetime (300 000 ms); at most 30 days.
   */
  combinationWindowMs?: number;
};
/**
 * Caller options of derive() (0.6, ADR-022). `modality`: descriptive (R183). `session`:
 * keep the result in the gateway's memory only, for this run's session (R190).
 * `container`: place the result into a knowledge base or folder (R192, no write-down).
 */
export type DeriveOptions = { modality?: Modality; session?: { id: string; ttlMs?: number }; container?: string };
export type MemoryReview = 'none' | 'quarantine';
/** An allow may name its audit reason (default AUTHORIZED) and carries its obligations. */
/** `recorded`: the obligations the audit entry records when they differ from those returned (an enforced release_filter is recorded, not returned). */
type Outcome<T> = { ok: true; value: T; obligations: Obligation[]; reason?: string; recorded?: Obligation[] } | { ok: false; reason: string };
/** One audited operation: its decision id and, when valid, the caller's correlation fields (never authority). */
/** `contained`: the tenant's runtime profile policies were loaded for this operation (their active set enters the policy digest). */
/** `unenforceable`: obligation types the caller cannot enforce (null: malformed, every allow is refused; R123). */
/** `hints`: the caller asked for a denial hint; `ask` is what it asked for (action, purpose); `findings`: closed audit findings of hooks and budgets; `require`: filter ids the caller requires. */
type Op = { id: string; trace?: string; execution?: string; runtime?: string; contained?: boolean; unenforceable?: readonly ObligationType[] | null;
  hints?: true; ask?: { action?: Action; purpose?: string }; findings?: string[]; require?: string[]; spent?: true };
const op = (call?: Call): Op => {
  const trace = traceOf(call), execution = executionOf(call), runtime = runtimeRevisionOf(call), unenforceable = unenforceableOf(call);
  const require = Array.isArray(call?.requireFilters) ? call!.requireFilters!.filter(validId) : [];
  return { id: newDecisionId(), ...(trace ? { trace } : {}), ...(execution ? { execution } : {}), ...(runtime ? { runtime } : {}),
    ...(unenforceable === null || unenforceable.length ? { unenforceable } : {}), ...(call?.hints === true ? { hints: true as const } : {}), ...(require.length ? { require } : {}) };
};
/** Thrown by finish() when the caller cannot enforce an obligation of an allow: the transaction rolls back, run() audits the denial. */
class Refused extends Error {}
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
  private store: EphemeralStore;
  private hook?: PolicyHook;
  private model?: EngineOptions['model'];
  private clock: () => number;
  private source?: CandidateSource;
  private emit: (event: EngineEvent) => void;
  private counters = { filterMismatches: 0, decisions: 0, denials: 0 };
  private contentBytes: number;
  private memoryReview: (tenant: string) => MemoryReview;
  private filters: ReleaseFilter[]; private sanitizers: DeriveSanitizer[]; private hookOptions: ReturnType<typeof checkHookOptions>;
  private requiredFilters?: EngineOptions['requiredFilters']; private volume?: VolumeBudget; private cache?: DecisionCache;
  private risk?: RiskProvider;
  private combinationWindowMs: number;
  /** RiskProvider answers per transaction snapshot and principal (one external call per principal and operation). */
  private risks = new WeakMap<State, Map<string, Promise<RiskLevel | null>>>();
  constructor(store: Store, options: EngineOptions = {}) {
    if (options.policy && (!options.policy.revision || options.policy.revision.length > 128)) throw new Error('Policy revision required');
    this.contentBytes = options.contentBytes ?? RETRIEVAL.contentBytes;
    const review = options.memoryReview ?? 'none';
    if (typeof review !== 'function' && review !== 'none' && review !== 'quarantine') throw new Error('Invalid memory review mode');
    this.memoryReview = typeof review === 'function' ? tenant => { try { return review(tenant) === 'none' ? 'none' : 'quarantine'; } catch { return 'quarantine'; } } : () => review;
    if (!Number.isSafeInteger(this.contentBytes) || this.contentBytes < 0) throw new Error('Invalid content budget');
    this.combinationWindowMs = options.combinationWindowMs ?? COMBINATION_WINDOW.defaultMs;
    if (!Number.isSafeInteger(this.combinationWindowMs) || this.combinationWindowMs < COMBINATION_WINDOW.defaultMs || this.combinationWindowMs > COMBINATION_WINDOW.maxMs) throw new Error('Invalid combination window');
    checkHooks(options.releaseFilters, 'release filter'); checkHooks(options.deriveSanitizers, 'derive sanitizer');
    if (options.requiredFilters !== undefined && typeof options.requiredFilters !== 'function') throw new Error('Invalid required filters');
    if (options.decisionCache !== undefined && !(options.decisionCache instanceof DecisionCache)) throw new Error('Invalid decision cache');
    this.filters = [...(options.releaseFilters ?? [])]; this.sanitizers = [...(options.deriveSanitizers ?? [])]; this.hookOptions = checkHookOptions(options.hooks ?? {});
    this.requiredFilters = options.requiredFilters; this.volume = options.volume; this.cache = options.decisionCache;
    this.hook = options.policy; this.clock = options.clock ?? Date.now; this.source = options.candidates; this.risk = options.risk;
    // Session-scoped records (R190) live in this engine's in-memory partition, never in `store`.
    this.store = withEphemeral(store, this.clock); this.model = options.model;
    const listener = options.onEvent;
    this.emit = event => { try { listener?.(event); } catch { /* metrics never affect decisions */ } };
  }
  stats() { return { ...this.counters }; }
  private revision(s: State) { return `${CORE_VERSION}|${s.policyVersion}|${this.hook?.revision ?? 'core-only'}`; }
  /**
   * Digest of the same material as revision(), over its JCS array form (unambiguous);
   * for an operation that loaded the tenant's runtime profile policies, also of its
   * active set (runtimeSetDigest; absent when there is none, so 0.4 digests are unchanged).
   */
  private digest(s: State, tenant: string, o: Op) {
    const parts = [CORE_VERSION, s.policyVersion, this.hook?.revision ?? 'core-only'];
    const runtime = o.contained ? runtimeSetDigest(s, tenant) : undefined;
    return policyDigest(runtime ? [...parts, runtime] : parts);
  }
  async ready(tenant?: string): Promise<boolean> {
    try { return await this.store.ready(tenant) && (!this.hook?.ready || await this.hook.ready()); }
    catch { return false; }
  }
  private audit(s: State, b: Binding, o: Op, operation: string, allowed: boolean, reason: string, obligations: Obligation[] = []) {
    const code = classify(reason);
    const chain = actorChainOf(b), breakGlass = Object.hasOwn(s.grants, b.grant) && s.grants[b.grant]!.breakGlass === true ? true as const : undefined;
    if (!code || !code.category !== allowed) throw new Error('Unclassified decision reason');
    appendAudit(s, { time: this.clock(), tenant: b.tenant, actor: b.subject, operation, decision: allowed ? 'allow' : 'deny',
      reason, policyVersion: this.revision(s), epoch: s.epochs[b.tenant] ?? 0, decisionId: o.id, reasonCode: code.code,
      policyDigest: this.digest(s, b.tenant, o), obligations: allowed ? obligations : [], runId: b.grant, ...(o.trace ? { traceId: o.trace } : {}),
      ...(o.execution ? { executionId: o.execution } : {}), ...(o.runtime ? { runtimeRevision: o.runtime } : {}),
      ...(o.findings?.length && validFindings(o.findings) ? { findings: [...o.findings] } : {}),
      // R145, R150: the verified RFC 8693 actor chain of the credential, and the break-glass flag of the run.
      ...(chain ? { actorChain: chain } : {}), ...(breakGlass ? { breakGlass } : {}) });
    this.counters.decisions++; if (!allowed) this.counters.denials++;
    this.emit({ type: 'decision', tenant: b.tenant, operation, allowed, reason, decisionId: o.id, code: code.code, ...(breakGlass ? { breakGlass } : {}) });
  }
  /**
   * One tenant transaction for one audited operation. An exceeded load budget is a
   * deferred denial audited in the same transaction (only reads preceded it). Any
   * other failure is audited best effort as DEFERRED:STORE_ERROR in a separate
   * transaction and rethrown unchanged.
   */
  private async run<T>(b: Binding, o: Op, operation: string, fn: (tx: Tx) => Promise<Result<T>>): Promise<Result<T>> {
    try {
      return await this.attempt(b, o, operation, fn);
    } catch (error) {
      if (!(error instanceof Refused)) throw error;
      // R123: nothing of the refused operation persists (its transaction rolled back); the denial is audited
      // in its own transaction, under the same runtime policy digest input.
      return this.attempt(b, o, operation, async tx => {
        // With hints the caller's grant state is needed too, so that a refused disclosure carries the same hints as any other denial.
        if (o.hints) await hydrate(tx, { bindings: [b], runtimeProfiles: true }); else await tx.load({ epoch: true, audit: true, ...(o.contained ? { runtimeProfiles: true } : {}) });
        return this.finish(tx.state, b, o, operation, fail('DENIED:UNSUPPORTED_OBLIGATION'));
      });
    }
  }
  private async attempt<T>(b: Binding, o: Op, operation: string, fn: (tx: Tx) => Promise<Result<T>>): Promise<Result<T>> {
    try {
      return await this.store.transaction(b.tenant, async tx => {
        try {
          const result = await fn(tx);
          if (!result.ok && o.hints) { const hint = await this.hint(tx.state, b, o); if (hint) result.hint = hint; }
          return result;
        }
        catch (error) {
          if (!(error instanceof BudgetExceeded)) throw error;
          await tx.load({ epoch: true, audit: true });
          return this.finish(tx.state, b, o, operation, fail('DEFERRED:BUDGET_EXCEEDED'));
        }
      });
    } catch (error) {
      if (error instanceof Refused) throw error;
      try {
        await this.store.transaction(b.tenant, async tx => { await tx.load({ epoch: true, audit: true }); this.audit(tx.state, b, o, operation, false, 'DEFERRED:STORE_ERROR'); });
      } catch { /* best effort: the caller still receives the original failure */ }
      throw error;
    }
  }
  /**
   * Denial hint (ADR-020): a fact about the caller's own grant, listener and volume budget, never about a resource, so
   * it is the same whether the requested resource exists or not.
   */
  private async hint(s: State, b: Binding, o: Op): Promise<DenialHint | undefined> {
    try {
      const own = grantHint(s, b, this.clock(), o.ask, { noRuntimeEnforcer: Array.isArray(o.unenforceable) && o.unenforceable.includes('runtime_profile') });
      if (own) return own;
      // Not when this very operation charged the budget: that the budget ran out now would show that a resource matched.
      if (this.volume && !o.spent && await this.volume.exhausted(b)) return this.volume.onExceed === 'approval' ? 'APPROVAL_REQUIRED' : 'RATE_LIMITED';
    } catch { /* a hint is optional */ }
    return undefined;
  }
  /**
   * Charges what a disclosure returns to the principal's volume budgets, per classification. A denial is audited with
   * the closed finding `volume:<classification>`; a budget store error defers (fail closed).
   */
  private async spend<T>(b: Binding, o: Op, charges: Map<Level, { bytes: number; documents: number }>): Promise<Outcome<T> | undefined> {
    if (!this.volume) return undefined;
    if (charges.size) o.spent = true;
    for (const [level, c] of charges) {
      const verdict = await this.volume.charge(b, level, c.bytes, c.documents);
      if (verdict === 'ok') continue;
      if (verdict === 'unavailable') return fail('DEFERRED:STORE_ERROR');
      o.findings = [`volume:${level}`]; this.emit({ type: 'volume_exceeded', tenant: b.tenant, classification: level });
      return fail(this.volume.onExceed === 'approval' ? 'DEFERRED:APPROVAL_REQUIRED' : 'DENIED:VOLUME_EXCEEDED');
    }
    return undefined;
  }
  /**
   * decide(), then the supplemental policy. Obligations of the policy verdict are
   * validated strictly and appended to `sink` (the operation's obligations): an
   * unknown or malformed obligation is a definite UNSUPPORTED_OBLIGATION denial.
   */
  /** The RiskProvider's levels of the user and the agent as one cache-key string, or null when it did not answer (0.6b). */
  private async riskLevels(s: State, b: Binding): Promise<string | null> {
    const [user, agent] = await this.levels(s, b);
    return user && agent ? `${user}|${agent}` : null;
  }
  private levels(s: State, b: Binding): Promise<[RiskLevel | null, RiskLevel | null]> {
    let memo = this.risks.get(s);
    if (!memo) { memo = new Map(); this.risks.set(s, memo); }
    const ask = (principal: string, kind: 'user' | 'agent') => {
      let p = memo!.get(principal);
      if (!p) {
        p = (async () => { try { const l = await this.risk!.level({ tenant: b.tenant, principal, kind }); return RISK_LEVELS.includes(l) ? l : null; } catch { return null; } })();
        memo!.set(principal, p);
      }
      return p;
    };
    return Promise.all([ask(b.subject, 'user'), ask(b.agent, 'agent')]);
  }
  /**
   * decide() again with the RiskProvider's levels of the user and the agent added as
   * transient signals (risk.ts withRisk): it can only turn an allow into a denial.
   */
  private async risky(s: State, b: Binding, input: Parameters<typeof decide>[1]): Promise<Decision> {
    const [user, agent] = await this.levels(s, b);
    if (!user || !agent) return { effect: 'deny', code: 'POLICY_UNAVAILABLE', category: 'defer' };
    if (user === 'none' && agent === 'none') return decide(s, input);
    return decide(withRisk(s, b.tenant, input.now, [{ principal: b.subject, level: user }, { principal: b.agent, level: agent }]), input);
  }
  private async authorize(s: State, b: Binding, resource: string, action: Action, purpose: string, sink?: Obligation[], run?: Iterable<string>): Promise<Decision> {
    // 0.6b (R195): a record whose content could not be opened is a deferred denial (decide() hides it as well).
    if (Object.hasOwn(s.knowledge, resource) && s.knowledge[resource]!.unreadable !== undefined) return { effect: 'deny', code: 'STORE_ERROR', category: 'defer' };
    let decision = decide(s, { binding: b, resource, action, purpose, now: this.clock() });
    if (decision.effect === 'allow' && this.risk) decision = await this.risky(s, b, { binding: b, resource, action, purpose, now: this.clock() });
    if (decision.effect !== 'allow' || !this.hook) return decision;
    // Supplemental policy sees the highest effective classification over the whole
    // source graph, not only the object's own container chain (R25).
    const classification = transitiveClassification(s, s.knowledge[resource]!);
    if (!classification) return { effect: 'deny', code: 'INVALID_CONTEXT', category: 'defer' };
    // R189: the effective tags and residency and the run's source set reach the supplemental policy (it can only narrow).
    const facts = factsOf(s, [resource]);
    if (!facts) return { effect: 'deny', code: 'INVALID_CONTEXT', category: 'defer' };
    const residency = sortedResidency(facts.residency);
    const input = { tenant: b.tenant, action, purpose, classification, tags: sortedTags(facts.tags), ...(residency ? { residency } : {}), sources: [...new Set([resource, ...(run ?? [])])].sort() };
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
  /**
   * Adds the runtime containment obligations (0.5, ADR-012) of these records
   * for a decision towards `destination`: a class, none (read, derive), or a list
   * of the classes a share/export of unknown destination may reach (merged,
   * containmentAcross). A conflict between runtime profiles, from the tenant's
   * policies or together with the supplemental policy's obligations, denies with
   * UNSUPPORTED_OBLIGATION.
   */
  private contain(s: State, tenant: string, ids: Iterable<string>, obligations: Obligation[], destination?: DestinationClass | readonly DestinationClass[]): Outcome<Obligation[]> {
    const level = this.top(s, ids);
    const c = Array.isArray(destination) ? containmentAcross(s, tenant, level, destination) : containment(s, tenant, level, destination as DestinationClass | undefined);
    if (!c.ok) return fail(c.reason);
    const merged = merge(obligations, c.obligations);
    return unsatisfiable(merged) ? fail('DENIED:UNSUPPORTED_OBLIGATION') : { ok: true, value: merged, obligations: merged };
  }
  /**
   * Destination classes a share/export may reach when its destination is not known
   * (R109): the run's restriction resolved to classes (a Destination id by its
   * active profile of this tenant; an id that resolves to nothing can receive
   * nothing), or every class for an unrestricted run. An empty result denies
   * (containmentAcross, R122): it never falls back to ignoring destination classes.
   */
  private reachable(s: State, b: Binding): DestinationClass[] {
    const restrict = s.grants[b.grant]?.destinations;
    if (restrict === undefined) return [...DESTINATION_CLASSES];
    const classes = new Set<DestinationClass>();
    for (const v of restrict) {
      if ((DESTINATION_CLASSES as readonly string[]).includes(v)) { classes.add(v as DestinationClass); continue; }
      const d = s.destinations && Object.hasOwn(s.destinations, v) ? s.destinations[v] : undefined;
      if (d && d.id === v && d.tenant === b.tenant && d.active === true && DESTINATION_CLASSES.includes(d.class)) classes.add(d.class);
    }
    return [...classes];
  }
  /**
   * Filter ids this release must pass (ADR-020): release_filter obligations of the decision, the operator's per-classification list
   * (an error there denies: null) and the ids the caller requires (Call.requireFilters).
   */
  private required(tenant: string, top: Level, obligations: readonly Obligation[], o: Op): Set<string> | null {
    const ids = new Set<string>(o.require ?? []);
    for (const x of obligations) if (x.type === 'release_filter') for (const id of x.value) ids.add(id);
    if (this.requiredFilters) {
      try {
        const listed = this.requiredFilters(tenant, top);
        if (!Array.isArray(listed) || !listed.every(validId)) return null;
        for (const id of listed) ids.add(id);
      } catch { return null; }
    }
    return ids;
  }
  /** Capture every read in this credential-bound run. A new run needs a new grant. */
  private async projection(s: State, b: Binding, o: Op, ids: string[], purpose: string): Promise<Outcome<Projection>> {
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
      const decision = await this.authorize(s, b, id, 'read', purpose, policy, all);
      if (decision.effect !== 'allow') return fail(reasonOf(decision));
    }
    // Combination rules (R188) over everything the run has read, this disclosure included, and (0.6b) everything the
    // same user and agent read under any other grant within the combination window (a forbidden pair split across runs).
    const across = new Set(all), since = this.clock() - this.combinationWindowMs;
    for (const c of Object.values(s.contexts)) {
      if (c.tenant !== b.tenant || c.subject !== b.subject || c.agent !== b.agent || c.grant === b.grant || !(c.expiresAt > since) || !Array.isArray(c.sources)) continue;
      for (const ref of c.sources) if (validId(ref?.id) && Object.hasOwn(s.knowledge, ref.id)) across.add(ref.id);
    }
    const combined = this.combined(s, b, across);
    if (combined) return combined;
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
    const core = this.obligations(s, all, policy, context.expiresAt - this.clock());
    if (!core) return fail('DEFERRED:INVALID_CONTEXT');
    const contained = this.contain(s, b.tenant, all, core);
    if (!contained.ok) return fail(contained.reason);
    const obligations = contained.value;
    // Volume budgets (ADR-020): what the read projection returns counts, per effective classification of each document.
    const charges = new Map<Level, { bytes: number; documents: number }>();
    if (this.volume) for (const key of new Set(ids)) {
      const level = this.top(s, [key]);
      if (!level) return fail('DEFERRED:INVALID_CONTEXT');
      const c = charges.get(level) ?? { bytes: 0, documents: 0 };
      c.bytes += Buffer.byteLength(s.knowledge[key]!.content, 'utf8'); c.documents++; charges.set(level, c);
    }
    const over = await this.spend<Projection>(b, o, charges);
    if (over) return over;
    s.contexts[id] = context;
    return { ok: true, obligations, value: { context: id, expiresAt: context.expiresAt,
      documents: [...new Set(ids)].map(key => { const r = s.knowledge[key]!; return { id: r.id, version: r.version, content: r.content }; }) } };
  }
  /** The (user, agent) pair of a run and the start of its combination window, for hydration (0.6b). */
  private pairs(b: Binding) { return [{ subject: b.subject, agent: b.agent, since: this.clock() - this.combinationWindowMs }]; }
  private finish<T>(s: State, b: Binding, o: Op, operation: string, outcome: Outcome<T>): Result<T> {
    if (outcome.ok && o.unenforceable !== undefined && (o.unenforceable === null || (outcome.obligations ?? []).some(x => o.unenforceable!.includes(x.type)))) throw new Refused();
    this.audit(s, b, o, operation, outcome.ok, outcome.ok ? outcome.reason ?? 'AUTHORIZED' : outcome.reason, outcome.ok ? outcome.recorded ?? outcome.obligations : []);
    return outcome.ok ? { ok: true, value: outcome.value, decisionId: o.id, obligations: outcome.obligations } : bad(o);
  }
  async openContext(b: Binding, ids: string[], purpose: string, call?: Call): Promise<Result<Projection>> {
    const o = op(call); o.ask = { action: 'read', purpose };
    if (!bindingValid(b) || !Array.isArray(ids) || ids.length > 64 || !ids.every(validId)) return bad(o);
    return this.run(b, o, 'read', async tx => {
      await hydrate(tx, { bindings: [b], knowledge: ids, runtimeProfiles: true, pairs: this.pairs(b) }); o.contained = true;
      return this.finish(tx.state, b, o, 'read', await this.projection(tx.state, b, o, ids, purpose));
    });
  }
  async retrieve(b: Binding, query: string, purpose: string, limit = 5, call?: Call): Promise<Result<Projection>> {
    const o = op(call); o.ask = { action: 'read', purpose };
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
      await hydrate(tx, { bindings: [b], runtimeProfiles: true, pairs: this.pairs(b) }); o.contained = true;
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
      return this.finish(s, b, o, 'retrieve', await this.projection(s, b, o, ids, purpose));
    });
  }
  /** Candidate-source retrieval: pre-filter outside the tenant lock, re-check everything inside it. */
  private async indexed(b: Binding, o: Op, query: string, purpose: string, limit: number): Promise<Result<Projection>> {
    const probe = query ? await this.store.transaction(b.tenant, async tx => {
      // An over-budget probe yields no candidates; the audited transaction below denies.
      try { await hydrate(tx, { bindings: [b] }); } catch (error) { if (error instanceof BudgetExceeded) return null; throw error; }
      const s = tx.state, user = s.actors[b.subject], agent = s.actors[b.agent], grant = s.grants[b.grant];
      if (!user || !agent || !grant || user.tenant !== b.tenant || agent.tenant !== b.tenant) return null;
      // Both audiences must admit a document (decide() checks the user and the agent), so the index pre-filters on both: candidates
      // the agent cannot see are never fetched, and never crowd out visible ones (recall). The authoritative re-check below stays.
      const tokens = principalTokens(s, user, grant.activeRoles), agentTokens = principalTokens(s, agent), maxClassification = effectiveClearance(user, agent);
      return tokens && agentTokens && maxClassification ? { tokens, agent: { tokens: agentTokens }, maxClassification } : null;
    }) : null;
    let ids: string[] = [], unavailable = false, disabled = false;
    if (probe) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const deadline = new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error('deadline')), RETRIEVAL.deadlineMs); });
        const found = await Promise.race([this.source!.candidates({ tenant: b.tenant, ...probe, query,
          limit: Math.min(RETRIEVAL.candidates, limit * 4) }), deadline]);
        if (!Array.isArray(found)) throw new Error('shape');
        ids = [...new Set(found.filter(validId))].slice(0, RETRIEVAL.candidates);
      } catch (error) {
        unavailable = true;
        if (error instanceof RetrievalDisabled) { disabled = true; this.emit({ type: 'retrieval_disabled', tenant: b.tenant }); }
        else this.emit({ type: 'candidates_unavailable', tenant: b.tenant });
      }
      finally { if (timer) clearTimeout(timer); }
    }
    return this.run(b, o, 'retrieve', async tx => {
      await hydrate(tx, { bindings: [b], knowledge: ids, runtimeProfiles: true, pairs: this.pairs(b) }); o.contained = true;
      const s = tx.state;
      if (!query) return this.finish(s, b, o, 'retrieve', fail('DEFERRED:INVALID_REQUEST'));
      if (disabled) return this.finish(s, b, o, 'retrieve', fail('DEFERRED:RETRIEVAL_DISABLED'));
      if (unavailable) return this.finish(s, b, o, 'retrieve', fail('DEFERRED:CANDIDATES_UNAVAILABLE'));
      limit = capped(s, b, limit);
      const eligible: string[] = [];
      for (const id of ids) {
        if (eligible.length >= limit) break;
        if ((await this.authorize(s, b, id, 'read', purpose)).effect === 'allow') eligible.push(id);
        else { this.counters.filterMismatches++; this.emit({ type: 'filter_mismatch', tenant: b.tenant }); }
      }
      return this.finish(s, b, o, 'retrieve', await this.projection(s, b, o, eligible, purpose));
    });
  }
  private async contextSources(s: State, b: Binding, contextId: string, action: Action): Promise<Outcome<Ref[]>> {
    if (!validId(contextId)) return fail('DEFERRED:INVALID_REQUEST');
    const selected = Object.hasOwn(s.contexts, contextId) ? s.contexts[contextId] : undefined;
    if (!selected || !same(selected, b)) return fail('DEFERRED:NOT_AUTHORIZED');
    const refs = new Map<string, Ref>(), policy: Obligation[] = [];
    const run = new Set(Object.values(s.contexts).filter(c => same(c, b)).flatMap(c => Array.isArray(c.sources) ? c.sources.map(r => r.id) : []));
    for (const c of Object.values(s.contexts).filter(c => same(c, b))) {
      if (!contextFresh(s, c, this.clock(), this.revision(s)) || c.purpose !== selected.purpose) return fail('DENIED:STALE_CONTEXT');
      for (const ref of c.sources) {
        if (s.knowledge[ref.id]?.version !== ref.version) return fail('DENIED:STALE_SOURCE');
        const decision = await this.authorize(s, b, ref.id, action, selected.purpose, policy, run);
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
  /**
   * `options` (0.6, ADR-022) are caller choices that can only narrow: a modality label, a
   * session scope, a target container. `trusted` is for in-process trusted runtimes only
   * (never reachable from the agent API): the model that produced the content (R191).
   */
  async derive(b: Binding, contextId: string, content: string, kind: 'memory' | 'artifact' = 'artifact', call?: Call, options: DeriveOptions = {},
    trusted?: { model?: ModelRef }): Promise<Result<{ id: string; classification: string; quarantined?: true; ephemeral?: { sessionId: string; expiresAt: number } }>> {
    const o = op(call);
    if (!bindingValid(b)) return bad(o);
    return this.run(b, o, 'derive', async tx => {
      await hydrate(tx, { bindings: [b], contexts: validId(contextId) ? [contextId] : [], containers: validId(options?.container) ? [options.container] : [], runtimeProfiles: true }); o.contained = true;
      const s = tx.state;
      o.ask = { action: 'derive', ...(validId(contextId) && Object.hasOwn(s.contexts, contextId) && same(s.contexts[contextId]!, b) ? { purpose: s.contexts[contextId]!.purpose } : {}) };
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
      const contained = this.contain(s, b.tenant, refs.value.map(r => r.id), obligations);
      if (!contained.ok) return this.finish(s, b, o, 'derive', fail(contained.reason));
      obligations = contained.value;
      const labels = refs.value.map(r => ({ source: s.knowledge[r.id]!, label: effectiveLabel(s, s.knowledge[r.id]!), top: transitiveClassification(s, s.knowledge[r.id]!) }));
      if (labels.some(x => !x.label || !x.top)) return this.finish(s, b, o, 'derive', fail('DEFERRED:INVALID_CONTEXT'));
      // Knowledge semantics (R182..R192): depth, combination, inherited attributes, session scope, placement.
      const own = { readers: [...new Set(labels.flatMap(x => x.source.readers))], readerRoles: [...new Set(labels.flatMap(x => x.source.readerRoles))],
        projects: [...new Set(labels.flatMap(x => x.label!.projects))] };
      const extra = this.semantics(s, b, refs.value.map(r => r.id), own, options, trusted);
      if (!extra.ok) return this.finish(s, b, o, 'derive', extra);
      // Derive sanitizers (ADR-020) see the content about to be stored, after every check above; they clean it or deny.
      if (this.sanitizers.length) {
        const cleaned = await runSanitizers(this.sanitizers, { tenant: b.tenant, content, kind }, this.hookOptions);
        o.findings = cleaned.findings;
        if (!cleaned.ok) { this.emit({ type: 'hook', tenant: b.tenant, hook: 'derive_sanitizer', outcome: cleaned.findings.some(f => f.endsWith(':deny')) ? 'deny' : 'error' }); return this.finish(s, b, o, 'derive', fail('DENIED:SANITIZER')); }
        if (cleaned.content !== content) this.emit({ type: 'hook', tenant: b.tenant, hook: 'derive_sanitizer', outcome: 'clean' });
        content = cleaned.content;
      }
      const id = randomUUID();
      // Effective labels include container floors and every transitive source: derivation never lowers a classification.
      // A combination uplift (R188) only raises it.
      const classification = LEVELS[Math.max(extra.value.level, ...labels.map(x => LEVELS.indexOf(x.top!)))]!;
      s.knowledge[id] = { id, tenant: b.tenant, version: 1, kind, origin: 'model', content, classification,
        projects: [...new Set(labels.flatMap(x => x.label!.projects))].sort(),
        // This local ACL cannot override the transitive source and container ACL conjunction.
        readerRoles: [...new Set(labels.flatMap(x => x.source.readerRoles))],
        readers: [...new Set(labels.flatMap(x => x.source.readers))], sources: refs.value, active: true, ...extra.value.fields };
      // Derived content inherits the earliest retention deadline of its sources (R-LIFE-12).
      const retain = labels.map(x => x.source.retainUntil).filter((t): t is number => Number.isSafeInteger(t));
      if (retain.length) s.knowledge[id]!.retainUntil = Math.min(...retain);
      const quarantined = kind === 'memory' && this.memoryReview(b.tenant) !== 'none';
      if (quarantined) Object.assign(s.knowledge[id]!, { lifecycle: 'quarantined', lifecycleAt: this.clock(), quarantineReason: 'memory_review' });
      const session = extra.value.fields.ephemeral;
      return this.finish(s, b, o, 'derive', { ok: true, value: { id, classification, ...(quarantined ? { quarantined: true } : {}),
        ...(session ? { ephemeral: { sessionId: session.sessionId, expiresAt: session.expiresAt } } : {}) }, obligations, reason: 'PROTECTED_DERIVATION' });
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
      await hydrate(tx, { bindings: [b], contexts: validId(contextId) ? [contextId] : [], actors: validId(recipientId) ? [recipientId] : [], runtimeProfiles: true, grantDestinations: true }); o.contained = true;
      const s = tx.state;
      o.ask = { action, ...(validId(contextId) && Object.hasOwn(s.contexts, contextId) && same(s.contexts[contextId]!, b) ? { purpose: s.contexts[contextId]!.purpose } : {}) };
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
      // Residency (R187): content whose effective residency is set leaves only to a destination whose region is in it.
      const scope = factsOf(s, refs.value.map(r => r.id));
      if (!scope) return this.finish(s, b, o, action, fail('DEFERRED:INVALID_CONTEXT'));
      if (!residencyAdmits(s, target, b.tenant, scope.residency)) return this.finish(s, b, o, action, fail('DENIED:RESIDENCY'));
      const obligations = restrictTo(refs.obligations, gate.restrict);
      // A supplemental policy may restrict destinations even when the run and the recipient do not (R66):
      // the actual recipient must be admitted by every restriction, whatever its origin.
      const destination = gate.destination ?? (target.kind === 'implicit-user' ? { class: 'internal-user' as const } : undefined);
      const names = destination ? [destination.class, ...(destination.id !== undefined ? [destination.id] : [])] : [];
      if (!obligations || !admits(obligations, names)) return this.finish(s, b, o, action, fail('DENIED:RECIPIENT'));
      const restricted = obligations.some(x => x.type === 'destination_restricted');
      // Runtime profiles narrowed to a destination class apply to the class this release goes to: the
      // recipient's Destination, internal-user for a user without one (R109). A principal without a
      // Destination profile may forward to any class the run allows: never weaker than any of them.
      const contained = this.contain(s, b.tenant, refs.value.map(r => r.id), obligations, destination?.class ?? this.reachable(s, b));
      if (!contained.ok) return this.finish(s, b, o, action, fail(contained.reason));
      // Release filters and the volume budget (ADR-020) run last: only a release that is otherwise allowed reaches them, so they can only narrow.
      const top = this.top(s, refs.value.map(r => r.id));
      if (!top) return this.finish(s, b, o, action, fail('DEFERRED:INVALID_CONTEXT'));
      const required = this.required(b.tenant, top, contained.value, o);
      if (!required) return this.finish(s, b, o, action, fail('DENIED:RELEASE_FILTER'));
      const missing = [...required].filter(id => !this.filters.some(f => f.id === id));
      if (missing.length) { o.findings = missing.map(id => `required:${id}:missing`.slice(0, 128)); this.emit({ type: 'hook', tenant: b.tenant, hook: 'release_filter', outcome: 'deny' }); return this.finish(s, b, o, action, fail('DENIED:RELEASE_FILTER')); }
      let released = content;
      if (this.filters.length) {
        const filtered = await runReleaseFilters(this.filters, { tenant: b.tenant, content, classification: top, recipient: recipientId, purpose: s.contexts[contextId]!.purpose }, this.hookOptions, required);
        o.findings = filtered.findings;
        if (!filtered.ok) { this.emit({ type: 'hook', tenant: b.tenant, hook: 'release_filter', outcome: filtered.findings.some(f => f.endsWith(':deny')) ? 'deny' : 'error' }); return this.finish(s, b, o, action, fail('DENIED:RELEASE_FILTER')); }
        if (filtered.content !== content) this.emit({ type: 'hook', tenant: b.tenant, hook: 'release_filter', outcome: 'redact' });
        released = filtered.content;
      }
      const over = await this.spend<Released>(b, o, new Map([[top, { bytes: Buffer.byteLength(released, 'utf8'), documents: 1 }]]));
      if (over) return this.finish(s, b, o, action, over);
      // A release_filter obligation is enforced here (every listed filter ran), so it is not passed on to the caller.
      const remaining = contained.value.filter(x => x.type !== 'release_filter');
      return this.finish(s, b, o, action, { ok: true, value: { recipient: recipientId, content: released, ...(destination && (gate.destination || restricted) ? { destination } : {}) },
        obligations: remaining, recorded: contained.value, reason: 'AUTHORIZED_RECIPIENT' });
    });
  }
  /**
   * Read-only, audited decision for an external enforcement point (AuthZEN, egress
   * proxies): hydrate, decide(), the supplemental policy and the core obligations,
   * exactly as the gates above apply them, without creating a context or disclosing
   * content. For share/export, `destination` names the Destination profile the
   * enforcement point will send to; the destination gate then applies (an unknown
   * or inactive profile denies). A share/export that names no destination is denied
   * (RECIPIENT, 0.6 R121): unlike release(), a read-only evaluation has no
   * recipient whose visibility of the sources could be checked.
   */
  async evaluate(b: Binding, resource: string, action: Action, purpose: string, options: { destination?: string; operation?: string } = {}, call?: Call): Promise<Verdict> {
    const o = op(call), operation = options.operation ?? 'evaluate';
    if (!bindingValid(b)) return { decision: false, decisionId: o.id, code: 'INVALID_REQUEST', obligations: [] };
    let reason: string | undefined;
    o.ask = { action, purpose };
    const result = await this.run<true>(b, o, operation, async tx => {
      // Decision cache (ADR-020): the epoch is read in this same transaction, so an entry of an older epoch is never found.
      let key: CacheKey | undefined;
      if (this.cache) {
        await tx.load({ epoch: true, audit: true, runtimeProfiles: true }); o.contained = true;
        // 0.6b: the operation (listener) and the RiskProvider's current levels are part of the key; an unanswered provider bypasses the cache.
        const risk = this.risk ? await this.riskLevels(tx.state, b) : undefined;
        if (risk !== null) {
          key = { tenant: b.tenant, epoch: tx.state.epochs[b.tenant] ?? 0, policyDigest: this.digest(tx.state, b.tenant, o), binding: b, resource, action, purpose,
            operation, ...(options.destination !== undefined ? { destination: options.destination } : {}), ...(risk !== undefined ? { risk } : {}) };
        }
        const hit = key ? this.cache.get(key) : undefined;
        if (hit) { reason = 'AUTHORIZED'; return this.finish(tx.state, b, o, operation, { ok: true, value: true, obligations: hit }); }
      }
      await hydrate(tx, { bindings: [b], knowledge: validId(resource) ? [resource] : [], destinations: validId(options.destination) ? [options.destination] : [], runtimeProfiles: true, grantDestinations: true }); o.contained = true;
      const s = tx.state, outcome = await this.evaluation(s, b, resource, action, purpose, options.destination);
      reason = outcome.ok ? 'AUTHORIZED' : outcome.reason;
      // Only an allow is cached, until the earliest grant or access expiry of everything it read.
      if (key && outcome.ok) {
        const expiries = [...Object.values(s.grants).map(g => g.expiresAt), ...Object.values(s.knowledge).map(k => k.accessExpiresAt),
          // R147: a heartbeat-bound run lapses without an epoch change, so its heartbeat deadline bounds the entry too.
          ...Object.values(s.grants).map(g => g.heartbeatTtlMs !== undefined ? (g.lastHeartbeatAt ?? 0) + g.heartbeatTtlMs : undefined),
          // R190 (0.6b): a session-scoped record is gone at its expiry without an epoch change.
          ...Object.values(s.knowledge).map(k => k.ephemeral?.expiresAt)].filter((t): t is number => Number.isSafeInteger(t));
        this.cache!.set({ ...key, epoch: s.epochs[b.tenant] ?? 0, policyDigest: this.digest(s, b.tenant, o) }, outcome.obligations, Math.min(Infinity, ...expiries));
      }
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
    // R188: a single record whose own closure combines excluded tag sets is refused like a context over it.
    const combined = this.combined(s, b, [resource]);
    if (combined) return combined;
    const obligations = this.obligations(s, [resource], policy);
    if (!obligations) return fail('DEFERRED:INVALID_CONTEXT');
    if (action !== 'share' && action !== 'export' && destination === undefined) {
      const contained = this.contain(s, b.tenant, [resource], obligations);
      return contained.ok ? { ok: true, value: true, obligations: contained.value } : fail(contained.reason);
    }
    // R121: a share/export evaluation must name the Destination the enforcement point sends to.
    if (!evaluationTargetNamed(action, destination) || destination === undefined) return fail('DENIED:RECIPIENT');
    const gate = destinationGate(s, s.grants[b.grant]!, { kind: 'profile', id: destination }, b.tenant, this.top(s, [resource]), purpose);
    const restricted = gate.ok && gate.destination ? restrictTo(obligations, gate.restrict) : null;
    if (!restricted || !gate.ok || !gate.destination) return fail('DENIED:RECIPIENT');
    // Residency (R187) against the named destination.
    const scope = factsOf(s, [resource]);
    if (!scope) return fail('DEFERRED:INVALID_CONTEXT');
    if (!residencyAdmits(s, { kind: 'profile', id: destination }, b.tenant, scope.residency)) return fail('DENIED:RESIDENCY');
    const contained = this.contain(s, b.tenant, [resource], restricted, gate.destination.class);
    return contained.ok ? { ok: true, value: true, obligations: contained.value } : fail(contained.reason);
  }
  /**
   * Audits that a trusted in-process enforcement point withheld the result of an
   * allowed release (`operation`: its action, R124): for example ProtectedRuntime when the runtime
   * revision changed between its last check and the final release. Records a
   * denial (UNSUPPORTED_OBLIGATION) with the call's correlation; it never allows
   * anything and is not exposed over HTTP.
   */
  async withhold(b: Binding, operation: 'share' | 'export', call?: Call): Promise<Result<never>> {
    const o = op(call);
    if (!bindingValid(b) || (operation !== 'share' && operation !== 'export')) return bad(o);
    return this.run<never>(b, o, operation, async tx => {
      await tx.load({ epoch: true, audit: true });
      return this.finish(tx.state, b, o, operation, fail('DENIED:UNSUPPORTED_OBLIGATION'));
    });
  }
  /** R188: a denial when a deny combination rule matches the tags of these records (undefined: none matches). */
  private combined(s: State, b: Binding, ids: Iterable<string>): { ok: false; reason: string } | undefined {
    const facts = factsOf(s, ids);
    const verdict = facts ? combination(s, b.tenant, facts.tags, facts.level) : null;
    if (!verdict) return { ok: false, reason: 'DEFERRED:INVALID_CONTEXT' };
    return verdict.deny ? { ok: false, reason: 'DENIED:COMBINATION' } : undefined;
  }
  private modelOf(tenant: string): ModelRef | undefined | null {
    try { return typeof this.model === 'function' ? this.model(tenant) : this.model; } catch { return null; }
  }
  /**
   * Knowledge semantics of a derivation (ADR-022) over the run's sources `ids`: the
   * generation limit (R182), combination rules (R188), inherited tags and
   * residency (R186, R187), modality (R183), the trusted model (R191),
   * the session scope (R190) and the placement rule (R192). Returns the level the
   * result must at least carry and the fields it inherits.
   */
  private semantics(s: State, b: Binding, ids: string[], own: { readers: string[]; readerRoles: string[]; projects: string[] }, options: DeriveOptions,
    trusted?: { model?: ModelRef }): Outcome<{ level: number; fields: Partial<Knowledge> }> {
    if (!options || typeof options !== 'object' || (options.modality !== undefined && !validModality(options.modality))
      || (options.container !== undefined && !validId(options.container))
      || (options.session !== undefined && (!options.session || typeof options.session !== 'object'))) return fail('DEFERRED:INVALID_REQUEST');
    const facts = factsOf(s, ids), depth = lineageDepthOf(s, b.tenant);
    if (!facts || depth === null) return fail('DEFERRED:INVALID_CONTEXT');
    if (facts.generation + 1 > depth) return fail('DENIED:LINEAGE_DEPTH');
    const combo = combination(s, b.tenant, facts.tags, facts.level);
    if (!combo) return fail('DEFERRED:INVALID_CONTEXT');
    if (combo.deny) return fail('DENIED:COMBINATION');
    if (facts.tags.size > KNOWLEDGE.tags || (facts.residency?.size ?? 0) > KNOWLEDGE.residency) return fail('DEFERRED:BUDGET_EXCEEDED');
    const model = trusted?.model ?? this.modelOf(b.tenant);
    if (model === null || (model !== undefined && !validModel(model))) return fail('DEFERRED:INVALID_CONTEXT');
    const grant = s.grants[b.grant]!, now = this.clock();
    const session = sessionOf(facts, b.grant, now, grant.expiresAt, options.session ? { sessionId: options.session.id, ...(options.session.ttlMs !== undefined ? { ttlMs: options.session.ttlMs } : {}) } : undefined);
    if (!session.ok) return fail(session.reason);
    if (session.ephemeral) {
      this.store.partition.purge(b.tenant, now);
      if (!this.store.partition.room(b.tenant, b.grant, session.ephemeral.sessionId)) return fail('DEFERRED:BUDGET_EXCEEDED');
    }
    if (options.container !== undefined) {
      const chain = containerChain(s, { tenant: b.tenant, container: options.container });
      if (!chain) return fail('DEFERRED:INVALID_REQUEST');
      // Placement is a write into the container: the run must name it (or '*') and every level must be active.
      if (!subset([options.container], grant.resources) || chain.some(c => c.active !== true)) return fail('DENIED:OUT_OF_SCOPE');
      if (!placementAllowed(s, b.tenant, ids.map(id => s.knowledge[id]!), own, LEVELS[combo.level]!, options.container)) return fail('DENIED:WRITE_DOWN');
    }
    const residency = sortedResidency(facts.residency);
    return { ok: true, obligations: [], value: { level: combo.level, fields: {
      ...(facts.tags.size ? { tags: sortedTags(facts.tags) } : {}), ...(residency ? { residency } : {}),
      ...(options.modality !== undefined ? { modality: options.modality } : {}), ...(model ? { model: { id: model.id, version: model.version } } : {}),
      ...(session.ephemeral ? { ephemeral: session.ephemeral } : {}), ...(options.container !== undefined ? { container: options.container } : {}) } } };
  }
  /**
   * Closes a session of the caller's run (0.6, R190): every session-scoped record of
   * this run and session is removed from the gateway's memory at once. Audited
   * (`session_close`); closing an unknown or already closed session is allowed and removes nothing.
   */
  async closeSession(b: Binding, sessionId: string, call?: Call): Promise<Result<{ closed: number }>> {
    const o = op(call);
    if (!bindingValid(b)) return bad(o);
    return this.run(b, o, 'session_close', async tx => {
      await tx.load({ epoch: true, audit: true });
      if (!validId(sessionId)) return this.finish(tx.state, b, o, 'session_close', fail('DEFERRED:INVALID_REQUEST'));
      // Removal only narrows: it happens at once, whatever becomes of this audit transaction.
      const closed = this.store.partition.closeSession(b.tenant, b.grant, sessionId);
      // 0.6b: cached allows of this run may rest on the closed records.
      this.cache?.evictRun(b.tenant, b.grant);
      for (const [id, k] of Object.entries(tx.state.knowledge)) if (k?.ephemeral?.run === b.grant && k.ephemeral.sessionId === sessionId) delete tx.state.knowledge[id];
      return this.finish(tx.state, b, o, 'session_close', { ok: true, value: { closed }, obligations: [] });
    });
  }
  async delegate(b: Binding, child: Grant, call?: Call): Promise<Result<{ id: string }>> {
    const o = op(call);
    if (!bindingValid(b) || !child || typeof child !== 'object' || !validId(child.id)) return bad(o);
    return this.run(b, o, 'delegate', async tx => {
      await hydrate(tx, { bindings: [b], grants: [child.id], actors: validId(child.agent) ? [child.agent] : [] });
      const s = tx.state;
      const parent = s.grants[b.grant];
      const user = s.actors[b.subject], agent = s.actors[b.agent];
      // R147: a heartbeat-bound child starts alive at delegation; a caller-supplied heartbeat time is never kept.
      const next: Grant = child.heartbeatTtlMs !== undefined ? { ...child, lastHeartbeatAt: this.clock() } : child;
      if (Object.hasOwn(s.grants, child.id) || !parent || parent.subject !== b.subject
        || parent.agent !== b.agent || parent.tenant !== b.tenant || !user?.active || !agent?.active
        || !canDelegate(s, parent, next, this.clock())) {
        return this.finish(s, b, o, 'delegate', fail('DENIED:INVALID_DELEGATION'));
      }
      s.grants[child.id] = structuredClone(next);
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
