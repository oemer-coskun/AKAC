import { randomUUID } from 'node:crypto';
import { Engine } from './engine.ts';
import { LEVELS } from './types.ts';
import type { Binding } from './types.ts';
import type { Released, Result } from './engine.ts';
import { enforceable, executionOf, merge, newDecisionId, unsatisfiable } from './decision.ts';
import type { Call, Obligation, ObligationType, RuntimeDomain } from './decision.ts';
import { validId } from './validation.ts';

export interface StatelessProvider {
  /** Trusted configured service identity, not a model-supplied value. */
  readonly principal: string;
  generate(request: { instruction: string; documents: { id: string; version: number; content: string }[]; signal: AbortSignal }): Promise<string>;
}
/** One runtime profile to apply: an operator-reviewed template id for one containment domain (0.5, ADR-012). */
export type RuntimeProfileRef = { domain: RuntimeDomain; profile: string };
/**
 * What an enforcer applied for one execution: the applied runtime policy revision
 * (an AKAC identifier, at most 128 characters) and an optional `release()` that
 * ends the execution's hold on the runtime (for example restores the sandbox's
 * idle policy or destroys a per-execution sandbox). A rejecting or late release()
 * turns an allowed answer into a deny.
 */
export type RuntimeLease = { runtimeRevision: string; release?: () => Promise<void> };
/**
 * Isolation of an enforcer's runtime (R112):
 * - 'sandbox-wide' (the default when absent): one runtime policy is in force for
 *   everything the runtime holds (for example one sandbox policy).
 *   ProtectedRuntime serializes every execution through such an enforcer: apply,
 *   provider call, revision check, final release and lease release of one
 *   execution complete before the next execution's apply().
 * - 'per-execution': every execution gets its own runtime (one sandbox per
 *   execution id), so executions may run concurrently. The operator guarantees
 *   that the policy applied for one execution id never governs another.
 */
export type RuntimeIsolation = 'sandbox-wide' | 'per-execution';
/**
 * Runtime enforcer (0.5, ADR-012, R112): the out-of-band component that confines
 * the runtime holding released content (network, filesystem, tool and credential
 * access), for example a sandbox runtime driven by operator-reviewed templates.
 * Vendor-neutral; AKAC names profile ids only and never emits runtime policy.
 * The contract is execution-scoped:
 * - supports(): true only when the enforcer has an operator-reviewed template for
 *   that profile id in that domain. Must not throw; a throw counts as false.
 * - apply(profiles, { executionId }): applies exactly these profiles (at most one
 *   per domain) for this execution before anything protected happens, and
 *   resolves with a RuntimeLease. A rejection, a malformed lease or revision or a
 *   timeout is a deny.
 * - current(executionId): the revision in force for this execution now (undefined
 *   when none). Checked after the provider call and before the answer is
 *   released; anything but the applied revision is a deny.
 */
export interface RuntimeEnforcer {
  readonly isolation?: RuntimeIsolation;
  supports(domain: RuntimeDomain, profile: string): boolean;
  apply(profiles: readonly RuntimeProfileRef[], execution: { executionId: string }): Promise<RuntimeLease>;
  current(executionId: string): Promise<string | undefined> | string | undefined;
}
/** `enforcerDeadlineMs`: how long each enforcer step (apply, current, release) may take (1..5000, default 5000); later is a deny. */
export type RuntimeOptions = { enforcer?: RuntimeEnforcer; enforcerDeadlineMs?: number };
/**
 * Obligations this runtime enforces. audit_level full: every step is an audited
 * engine decision and the final result carries its decision id. max_context_ttl_ms:
 * the provider call is aborted when the context lifetime ends. no_persist: the
 * runtime persists nothing and passes the obligation on to its caller.
 * destination_restricted (ADR-008): the runtime sends content only to the
 * destination the engine authorized for the provider gate (and the answer only to
 * the subject); every such obligation of the context, of the provider gate and of
 * the answer must name that destination's class or id, or the runtime fails closed
 * before the provider (or the caller) receives anything.
 *
 * This 0.4 list is kept unchanged for runtimes that reuse it (for example a passage-level runtime): they do not enforce the 0.5 containment obligations, so they
 * deny decisions that carry them (fail closed).
 */
export const RUNTIME_OBLIGATIONS: readonly ObligationType[] = ['audit_level', 'max_context_ttl_ms', 'no_persist', 'destination_restricted'];
/**
 * What ProtectedRuntime enforces (0.5, ADR-012), in addition to RUNTIME_OBLIGATIONS:
 * runtime_profile: the configured RuntimeEnforcer must support every governing
 * profile of the provider hop and apply them before the provider is called, and
 * still report the applied revision for the execution before the answer is
 * released; without an enforcer, or with an unsupported or conflicting profile,
 * the runtime fails closed before the provider receives anything. The governing
 * profiles are the provider gate's, and the context's for domains the gate names
 * none for (R112: the gate is derived over at least the context's material and a
 * superset of its applicable policies, so its winner is never of a lower tier).
 * The answer's own profiles bind the caller that receives it.
 * max_output_classification: passed on with the answer (the highest of the context,
 * provider gate and answer values); the caller must label the output with it.
 * release_filter (0.6, ADR-020): every release this runtime performs (the provider gate and
 * the final answer) is called with the release_filter ids of the context as required, so
 * the engine runs those filters or denies when one is not configured.
 * approval_required is deliberately not listed: the runtime has no approval workflow, so a
 * decision that carries it is denied.
 */
export const PROTECTED_RUNTIME_OBLIGATIONS: readonly ObligationType[] = [...RUNTIME_OBLIGATIONS, 'runtime_profile', 'max_output_classification', 'release_filter'];
/** True when every destination_restricted obligation admits the destination the content goes to. */
const reaches = (obligations: readonly Obligation[], to: Released['destination']) => obligations.every(o => o.type !== 'destination_restricted'
  || (!!to && (o.value.includes(to.class) || (to.id !== undefined && o.value.includes(to.id)))));
const profilesOf = (obligations: readonly Obligation[]): RuntimeProfileRef[] =>
  obligations.flatMap(o => o.type === 'runtime_profile' ? [{ domain: o.domain, profile: o.profile }] : []);
/** Every profile is supported by the enforcer (a throwing enforcer supports nothing). */
const supported = (enforcer: RuntimeEnforcer | undefined, profiles: readonly RuntimeProfileRef[]) => {
  if (!profiles.length) return true;
  if (!enforcer || typeof enforcer.apply !== 'function' || typeof enforcer.current !== 'function') return false;
  try { return profiles.every(p => enforcer.supports(p.domain, p.profile) === true); } catch { return false; }
};
const PROVIDER_DEADLINE_MS = 5000;
/** Tail of the per-enforcer queue of sandbox-wide executions (R112). */
const queues = new WeakMap<RuntimeEnforcer, Promise<void>>();
/** Execution ids in flight per enforcer. */
const inflight = new WeakMap<RuntimeEnforcer, Set<string>>();
/** Waits until every earlier execution through this enforcer has finished; resolves with the unlock function. */
async function exclusive(enforcer: RuntimeEnforcer): Promise<() => void> {
  const prior = queues.get(enforcer) ?? Promise.resolve();
  let unlock!: () => void;
  const mine = new Promise<void>(resolve => { unlock = resolve; });
  const tail = prior.then(() => mine);
  queues.set(enforcer, tail);
  await prior;
  return () => { unlock(); if (queues.get(enforcer) === tail) queues.delete(enforcer); };
}
const label = (obligations: readonly Obligation[]) => {
  const o = obligations.find((x): x is Extract<Obligation, { type: 'max_output_classification' }> => x.type === 'max_output_classification');
  return o ? LEVELS.indexOf(o.value) : -1;
};
type Documents = { id: string; version: number; content: string }[];
/** Bounds an enforcer step; a timeout rejects. */
async function bounded<T>(work: () => Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([Promise.resolve().then(work), new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Enforcer deadline')), ms); })]);
  } finally { if (timer) clearTimeout(timer); }
}

/**
 * Mediates both model input and output. Provider isolation is still a deployment
 * obligation. As a policy enforcement point it enforces every obligation of every
 * decision it acts on, or fails closed (R-DE-7, R112, R113).
 */
export class ProtectedRuntime {
  private engine: Engine;
  private provider: StatelessProvider;
  private enforcer?: RuntimeEnforcer;
  private enforcerDeadline: number;
  constructor(engine: Engine, provider: StatelessProvider, options: RuntimeOptions = {}) {
    const deadline = options.enforcerDeadlineMs ?? PROVIDER_DEADLINE_MS;
    if (!Number.isSafeInteger(deadline) || deadline < 1 || deadline > PROVIDER_DEADLINE_MS) throw new Error('Invalid enforcer deadline');
    this.engine = engine; this.provider = provider; this.enforcer = options.enforcer; this.enforcerDeadline = deadline;
  }
  async answer(binding: Binding, resourceIds: string[], purpose: string, instruction: string, call?: Call): Promise<Result<{ content: string }>> {
    if (!instruction || instruction.length > 4096) return { ok: false, code: 'NOT_AUTHORIZED', decisionId: newDecisionId() };
    // Correlation only: a caller never supplies the runtime revision; only the enforcer's result is recorded (R117).
    // Every answer has an execution id, the caller's or a fresh one; the enforcer scopes what it applies to it (R112).
    const { runtimeRevision: _ignored, ...given } = call?.trace ?? {};
    const executionId = executionOf(call) ?? `exec-${randomUUID()}`;
    const trace = { ...given, executionId };
    const context = await this.engine.openContext(binding, resourceIds, purpose, { trace });
    if (!context.ok) return context;
    if (!enforceable(context.obligations, PROTECTED_RUNTIME_OBLIGATIONS)) return { ok: false, code: 'NOT_AUTHORIZED', decisionId: context.decisionId };
    // Release filters the context requires apply to every release below (ADR-020); a filter that is not configured denies there.
    const requireFilters = context.obligations.flatMap(o => o.type === 'release_filter' ? o.value : []);
    const traced: Call = { trace, ...(requireFilters.length ? { requireFilters } : {}) };
    const prompt = JSON.stringify({ instruction, documents: context.value.documents });
    const providerGate = await this.engine.release(binding, context.value.context, this.provider.principal, prompt, 'share', traced);
    if (!providerGate.ok) return providerGate;
    const deny = { ok: false as const, code: 'NOT_AUTHORIZED' as const, decisionId: providerGate.decisionId };
    // The provider gate is the decision for the hop the content takes: its profile supersedes the context's
    // for each domain it names (R112). It never carries a lower output label than the context.
    const hop = profilesOf(providerGate.obligations);
    if (label(providerGate.obligations) < label(context.obligations)) return deny;
    const inherited = context.obligations.filter(o => o.type !== 'runtime_profile' || !hop.some(p => p.domain === o.domain));
    const governing = merge(inherited, providerGate.obligations);
    const profiles = profilesOf(governing);
    // No runtime obligation may disappear: an unsupported, conflicting or unapplied profile stops before the provider (R112, R113).
    if (!enforceable(providerGate.obligations, PROTECTED_RUNTIME_OBLIGATIONS) || unsatisfiable(governing) || !supported(this.enforcer, profiles)
      || !reaches([...context.obligations, ...providerGate.obligations], providerGate.value.destination)) return deny;
    // Construct from the authorized payload; caller/model cannot choose a different destination.
    // A release filter may have redacted the prompt; the payload must still be the same shape (fail closed otherwise).
    let approved: { instruction: string; documents: Documents };
    try {
      const parsed = JSON.parse(providerGate.value.content) as { instruction?: unknown; documents?: unknown };
      if (!parsed || typeof parsed.instruction !== 'string' || !Array.isArray(parsed.documents)) return deny;
      approved = parsed as { instruction: string; documents: Documents };
    } catch { return deny; }
    if (!profiles.length) return this.generate(binding, context.value.context, approved, governing, trace, providerGate.decisionId, undefined, requireFilters);
    const enforcer = this.enforcer!;
    // A sandbox-wide runtime holds one policy at a time: executions through it never overlap (R112).
    const unlock = enforcer.isolation === 'per-execution' ? undefined : await exclusive(enforcer);
    const running = inflight.get(enforcer) ?? new Set<string>();
    inflight.set(enforcer, running);
    if (running.has(executionId)) { unlock?.(); return deny; }
    running.add(executionId);
    let lease: RuntimeLease | undefined, result: Result<{ content: string }> = deny;
    try {
      try {
        const applied = await bounded(() => enforcer.apply(profiles.map(p => ({ ...p })), { executionId }), this.enforcerDeadline);
        if (applied && typeof applied === 'object' && validId(applied.runtimeRevision) && (applied.release === undefined || typeof applied.release === 'function')) lease = applied;
      } catch { lease = undefined; }
      if (!lease) return deny;
      const runtimeRevision = lease.runtimeRevision;
      // Before anything is released, the revision applied for this execution must still be the one in force.
      const verify = async () => {
        try { return await bounded(async () => enforcer.current(executionId), this.enforcerDeadline) === runtimeRevision; } catch { return false; }
      };
      result = await this.generate(binding, context.value.context, approved, governing, trace, providerGate.decisionId, { runtimeRevision, verify }, requireFilters);
    } finally {
      if (lease?.release) {
        const held = lease, release = lease.release;
        try { await bounded(() => release.call(held), this.enforcerDeadline); }
        catch { if (result.ok) result = { ok: false, code: 'NOT_AUTHORIZED', decisionId: result.decisionId }; }
      }
      running.delete(executionId);
      unlock?.();
    }
    return result;
  }
  /**
   * Provider call and final release; under a lease the revision is verified before the final release, recorded on it
   * (R117, R112) and verified again after it (R124): a change in between withholds the answer, audited as a denial.
   */
  private async generate(binding: Binding, contextId: string, approved: { instruction: string; documents: Documents }, governing: Obligation[],
    trace: NonNullable<Call['trace']>, gateDecision: string, runtime?: { runtimeRevision: string; verify: () => Promise<boolean> }, requireFilters?: readonly string[]): Promise<Result<{ content: string }>> {
    const deny = { ok: false as const, code: 'NOT_AUTHORIZED' as const, decisionId: gateDecision };
    const ttl = governing.find((o): o is Extract<Obligation, { type: 'max_context_ttl_ms' }> => o.type === 'max_context_ttl_ms');
    const deadline = Math.min(PROVIDER_DEADLINE_MS, ttl?.value ?? PROVIDER_DEADLINE_MS);
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timedOut = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error('Provider deadline')); }, deadline);
      });
      const text = await Promise.race([this.provider.generate({ ...approved, signal: controller.signal }), timedOut]);
      // Output produced at or after the deadline (for example in reaction to the abort) is never released.
      if (controller.signal.aborted || typeof text !== 'string' || !text || text.length > 100000) return deny;
      if (runtime && !await runtime.verify()) return deny;
      // Re-evaluate after inference: revoked/expired context never produces a released answer.
      // The applied runtime revision is recorded in this decision's audit entry (R117).
      const result = await this.engine.release(binding, contextId, binding.subject, text, 'share',
        { trace: { ...trace, ...(runtime ? { runtimeRevision: runtime.runtimeRevision } : {}) }, ...(requireFilters?.length ? { requireFilters } : {}) });
      if (!result.ok) return result;
      // R124: the runtime may change between the check above and the final release; check again before
      // returning. A changed revision withholds the answer and audits the denial (the release entry stays).
      if (runtime && !await runtime.verify()) {
        try { return await this.engine.withhold(binding, 'share', { trace: { ...trace, runtimeRevision: runtime.runtimeRevision } }); }
        catch { return { ok: false, code: 'NOT_AUTHORIZED', decisionId: result.decisionId }; }
      }
      if (!enforceable(result.obligations, PROTECTED_RUNTIME_OBLIGATIONS) || !reaches(result.obligations, result.value.destination)) return { ok: false, code: 'NOT_AUTHORIZED', decisionId: result.decisionId };
      // The answer's own obligations (for example no_persist, runtime_profile) bind the caller that receives it;
      // its output label is never lower than that of the context or the provider gate.
      const obligations = merge(result.obligations, governing.filter(o => o.type === 'max_output_classification'));
      return { ok: true, value: { content: result.value.content }, decisionId: result.decisionId, obligations };
    } catch { return deny; }
    finally { if (timer) clearTimeout(timer); controller.abort(); }
  }
}
