import { Engine } from './engine.ts';
import type { Binding } from './types.ts';
import type { Released, Result } from './engine.ts';
import { enforceable, merge, newDecisionId } from './decision.ts';
import type { Call, Obligation, ObligationType } from './decision.ts';

export interface StatelessProvider {
  /** Trusted configured service identity, not a model-supplied value. */
  readonly principal: string;
  generate(request: { instruction: string; documents: { id: string; version: number; content: string }[]; signal: AbortSignal }): Promise<string>;
}
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
 */
export const RUNTIME_OBLIGATIONS: readonly ObligationType[] = ['audit_level', 'max_context_ttl_ms', 'no_persist', 'destination_restricted'];
/** True when every destination_restricted obligation admits the destination the content goes to. */
const reaches = (obligations: readonly Obligation[], to: Released['destination']) => obligations.every(o => o.type !== 'destination_restricted'
  || (!!to && (o.value.includes(to.class) || (to.id !== undefined && o.value.includes(to.id)))));
const PROVIDER_DEADLINE_MS = 5000;

/**
 * Mediates both model input and output. Provider isolation is still a deployment
 * obligation. As a policy enforcement point it enforces every obligation of every
 * decision it acts on, or fails closed (R-DE-7).
 */
export class ProtectedRuntime {
  private engine: Engine;
  private provider: StatelessProvider;
  constructor(engine: Engine, provider: StatelessProvider) { this.engine = engine; this.provider = provider; }
  async answer(binding: Binding, resourceIds: string[], purpose: string, instruction: string, call?: Call): Promise<Result<{ content: string }>> {
    if (!instruction || instruction.length > 4096) return { ok: false, code: 'NOT_AUTHORIZED', decisionId: newDecisionId() };
    const context = await this.engine.openContext(binding, resourceIds, purpose, call);
    if (!context.ok) return context;
    if (!enforceable(context.obligations, RUNTIME_OBLIGATIONS)) return { ok: false, code: 'NOT_AUTHORIZED', decisionId: context.decisionId };
    const prompt = JSON.stringify({ instruction, documents: context.value.documents });
    const providerGate = await this.engine.release(binding, context.value.context, this.provider.principal, prompt, 'share', call);
    if (!providerGate.ok) return providerGate;
    if (!enforceable(providerGate.obligations, RUNTIME_OBLIGATIONS)
      || !reaches([...context.obligations, ...providerGate.obligations], providerGate.value.destination)) return { ok: false, code: 'NOT_AUTHORIZED', decisionId: providerGate.decisionId };
    // Construct from the authorized payload; caller/model cannot choose a different destination.
    const approved = JSON.parse(providerGate.value.content) as { instruction: string; documents: typeof context.value.documents };
    const ttl = merge(context.obligations, providerGate.obligations).find((o): o is Extract<Obligation, { type: 'max_context_ttl_ms' }> => o.type === 'max_context_ttl_ms');
    const deadline = Math.min(PROVIDER_DEADLINE_MS, ttl?.value ?? PROVIDER_DEADLINE_MS);
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timedOut = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error('Provider deadline')); }, deadline);
      });
      const text = await Promise.race([this.provider.generate({ ...approved, signal: controller.signal }), timedOut]);
      // Output produced at or after the deadline (for example in reaction to the abort) is never released.
      if (controller.signal.aborted || typeof text !== 'string' || !text || text.length > 100000) return { ok: false, code: 'NOT_AUTHORIZED', decisionId: providerGate.decisionId };
      // Re-evaluate after inference: revoked/expired context never produces a released answer.
      const result = await this.engine.release(binding, context.value.context, binding.subject, text, 'share', call);
      if (!result.ok) return result;
      if (!enforceable(result.obligations, RUNTIME_OBLIGATIONS) || !reaches(result.obligations, result.value.destination)) return { ok: false, code: 'NOT_AUTHORIZED', decisionId: result.decisionId };
      // The answer's own obligations (for example no_persist) bind the caller that receives it.
      return { ok: true, value: { content: result.value.content }, decisionId: result.decisionId, obligations: result.obligations };
    } catch { return { ok: false, code: 'NOT_AUTHORIZED', decisionId: providerGate.decisionId }; }
    finally { if (timer) clearTimeout(timer); controller.abort(); }
  }
}
