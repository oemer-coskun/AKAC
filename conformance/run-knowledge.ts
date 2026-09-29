import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { decide } from '../reference/policy.ts';
import { kbFixture, bindings } from '../examples/fixture.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryStore } from '../reference/store.ts';
import { EphemeralPartition, EphemeralStore } from '../reference/ephemeral.ts';
import type { Action, Binding, Knowledge, ModelRef } from '../reference/types.ts';
import { apply } from './patch.ts';
import type { Patch } from './patch.ts';
import { outcomeOf } from './outcome.ts';
import type { Row } from './outcome.ts';

/**
 * Knowledge semantics vectors (0.6, ADR-022, spec/AKAC-0.6.md, profile
 * AKAC-Knowledge/0.6-draft), over kbFixture(clock) with patches (whole records:
 * [collection, id, record]; the settings and combinationRules collections start empty).
 * - decision: decide() of one request; expected {effect, code}.
 * - steps: gateway operations in order through the engine (session-scoped records held in
 *   its in-memory partition). Each step names its binding (`as`) and expects {effect,
 *   code}; a derive step may also expect `record` fields of the stored result
 *   (`ephemeral: true` means the record is session-scoped). `$name` refers to the context
 *   or record id saved by an earlier step. The last step decides the vector's outcome.
 *   `model` configures the engine's trusted model identity (R191).
 */
type Expected = { effect: 'allow' | 'deny'; code?: string; record?: Record<string, unknown> };
type Step = { op: 'open' | 'derive' | 'release' | 'evaluate' | 'close'; as: keyof typeof bindings | Binding; resources?: string[]; purpose?: string; context?: string;
  content?: string; kind?: 'memory' | 'artifact'; modality?: string; session?: { id: string; ttlMs?: number }; container?: string; recipient?: string;
  action?: string; resource?: string; destination?: string; save?: string; expected: Expected };
type Vector = { id: string; kind: 'decision' | 'steps'; description?: string; patch: Patch[]; tags?: string[]; model?: ModelRef;
  binding?: keyof typeof bindings; grant?: string; resource?: string; action?: Action; purpose?: string; steps?: Step[]; expected?: Expected };
export const KNOWLEDGE_VECTORS = './vectors-0.6-knowledge.json';
const RECORD_FIELDS = ['classification', 'tags', 'residency', 'modality', 'model', 'container', 'kind', 'origin'];

/** The effect, audited code and (for derive) the stored record of each step, stopping at the first thrown error. */
export async function runKnowledgeSteps(clock: number, v: Pick<Vector, 'patch' | 'model' | 'steps'>): Promise<{ effect: string; code?: string; record?: Record<string, unknown> }[]> {
  const state = kbFixture(clock); state.settings ??= {}; state.combinationRules ??= {};
  apply(state, v.patch);
  const partition = new EphemeralPartition(() => clock);
  const store = new EphemeralStore(new MemoryStore(state), partition, () => clock);
  const engine = new Engine(store, { clock: () => clock, ...(v.model ? { model: v.model } : {}) });
  const saved = new Map<string, string>();
  const sub = (x: string | undefined) => x !== undefined && x.startsWith('$') ? saved.get(x.slice(1)) ?? x : x;
  const out: { effect: string; code?: string; record?: Record<string, unknown> }[] = [];
  for (const step of v.steps ?? []) {
    const b: Binding = typeof step.as === 'string' ? bindings[step.as] : step.as;
    const before = (await store.auditLog(b.tenant)).length;
    let r: { ok: boolean; value?: unknown };
    switch (step.op) {
      case 'open': r = await engine.openContext(b, (step.resources ?? []).map(x => sub(x)!), step.purpose ?? 'work'); break;
      case 'derive': r = await engine.derive(b, sub(step.context)!, step.content ?? 'Synthetic derived note.', step.kind ?? 'artifact', undefined, {
        ...(step.modality !== undefined ? { modality: step.modality as Knowledge['modality'] } : {}), ...(step.session ? { session: step.session } : {}),
        ...(step.container !== undefined ? { container: step.container } : {}) }); break;
      case 'release': r = await engine.release(b, sub(step.context)!, step.recipient!, step.content ?? 'Synthetic answer.', (step.action ?? 'share') as 'share' | 'export'); break;
      case 'evaluate': { const e = await engine.evaluate(b, sub(step.resource)!, step.action as Action, step.purpose ?? 'work', step.destination !== undefined ? { destination: step.destination } : {});
        r = { ok: e.decision }; break; }
      case 'close': r = await engine.closeSession(b, step.session!.id); break;
      default: throw new Error('unknown step');
    }
    const log = await store.auditLog(b.tenant);
    const result: { effect: string; code?: string; record?: Record<string, unknown> } = { effect: r.ok ? 'allow' : 'deny', ...(log.length > before ? { code: log.at(-1)!.reasonCode! } : {}) };
    if (r.ok && step.op === 'derive' && step.expected.record) {
      const id = (r.value as { id: string }).id;
      const record = await store.transaction(b.tenant, async tx => structuredClone(tx.state.knowledge[id]));
      result.record = Object.fromEntries(Object.keys(step.expected.record).map(k => [k, k === 'ephemeral' ? record?.ephemeral !== undefined
        : RECORD_FIELDS.includes(k) ? (record as Record<string, unknown> | undefined)?.[k] : undefined]));
    }
    if (r.ok && step.save) saved.set(step.save, step.op === 'open' ? (r.value as { context: string }).context : (r.value as { id: string }).id);
    out.push(result);
  }
  return out;
}
const matches = (actual: { effect: string; code?: string; record?: Record<string, unknown> }, expected: Expected) =>
  actual.effect === expected.effect && (expected.code === undefined || actual.code === expected.code)
  && (expected.record === undefined || isDeepStrictEqual(actual.record, expected.record));

export async function runKnowledgeVectors(hooks: { decide?: typeof decide } = {}): Promise<Row[]> {
  const decideFn = hooks.decide ?? decide;
  const data = JSON.parse(readFileSync(new URL(KNOWLEDGE_VECTORS, import.meta.url), 'utf8')) as { clock: number; cases: Vector[] };
  const rows: Row[] = [];
  for (const v of data.cases) {
    let pass = false, got = false, want = false;
    try {
      if (v.kind === 'decision') {
        const state = kbFixture(data.clock); state.settings ??= {}; state.combinationRules ??= {};
        apply(state, v.patch);
        const binding = { ...bindings[v.binding!], ...(v.grant ? { grant: v.grant } : {}) };
        const d = decideFn(state, { binding, resource: v.resource!, action: v.action!, purpose: v.purpose ?? 'work', now: data.clock });
        want = v.expected!.effect === 'allow'; got = d.effect === 'allow';
        pass = matches({ effect: d.effect, code: d.code }, v.expected!);
      } else if (v.kind === 'steps') {
        const results = await runKnowledgeSteps(data.clock, v);
        const steps = v.steps!;
        want = steps.at(-1)!.expected.effect === 'allow'; got = results.at(-1)?.effect === 'allow';
        pass = results.length === steps.length && steps.every((s, i) => matches(results[i]!, s.expected));
      } else throw new Error('unknown vector kind');
    } catch { pass = false; }
    rows.push({ id: v.id, kind: `knowledge-${v.kind}`, expected: want ? 'allow' : 'deny', actual: got ? 'allow' : 'deny', pass, outcome: outcomeOf(want, got, pass), ...(v.tags ? { tags: v.tags } : {}) });
  }
  return rows;
}
