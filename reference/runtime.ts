import { Engine } from './engine.ts';
import type { Binding } from './types.ts';
import type { Result } from './engine.ts';

export interface StatelessProvider {
  /** Trusted configured service identity, not a model-supplied value. */
  readonly principal: string;
  generate(request: { instruction: string; documents: { id: string; version: number; content: string }[]; signal: AbortSignal }): Promise<string>;
}

/** Mediates both model input and output. Provider isolation is still a deployment obligation. */
export class ProtectedRuntime {
  private engine: Engine;
  private provider: StatelessProvider;
  constructor(engine: Engine, provider: StatelessProvider) { this.engine = engine; this.provider = provider; }
  async answer(binding: Binding, resourceIds: string[], purpose: string, instruction: string): Promise<Result<{ content: string }>> {
    if (!instruction || instruction.length > 4096) return { ok: false, code: 'NOT_AUTHORIZED' };
    const context = await this.engine.openContext(binding, resourceIds, purpose);
    if (!context.ok) return context;
    const prompt = JSON.stringify({ instruction, documents: context.value.documents });
    const providerGate = await this.engine.release(binding, context.value.context, this.provider.principal, prompt);
    if (!providerGate.ok) return providerGate;
    // Construct from the authorized payload; caller/model cannot choose a different destination.
    const approved = JSON.parse(providerGate.value.content) as { instruction: string; documents: typeof context.value.documents };
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timedOut = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error('Provider deadline')); }, 5000);
      });
      const text = await Promise.race([this.provider.generate({ ...approved, signal: controller.signal }), timedOut]);
      if (typeof text !== 'string' || !text || text.length > 100000) return { ok: false, code: 'NOT_AUTHORIZED' };
      // Re-evaluate after inference: revoked/expired context never produces a released answer.
      const result = await this.engine.release(binding, context.value.context, binding.subject, text);
      return result.ok ? { ok: true, value: { content: result.value.content } } : result;
    } catch { return { ok: false, code: 'NOT_AUTHORIZED' }; }
    finally { if (timer) clearTimeout(timer); controller.abort(); }
  }
}
