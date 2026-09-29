import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { kbFixture, bindings } from '../examples/fixture.ts';
import { transitiveClassification } from '../reference/policy.ts';
import { containment, containmentAcross } from '../reference/containment.ts';
import { Engine } from '../reference/engine.ts';
import { ProtectedRuntime } from '../reference/runtime.ts';
import type { RuntimeEnforcer } from '../reference/runtime.ts';
import { MemoryStore } from '../reference/store.ts';
import { LEVELS } from '../reference/types.ts';
import type { Action, DestinationClass, Level } from '../reference/types.ts';
import type { Obligation, RuntimeDomain } from '../reference/decision.ts';
import { apply } from './patch.ts';
import type { Patch } from './patch.ts';
import { outcomeOf } from './outcome.ts';
import type { Outcome, Row } from './outcome.ts';

/**
 * Runtime containment vectors (AKAC 0.5 draft, ADR-012, profile AKAC-RuntimeContainment/0.5-draft).
 * - profiles: the pure derivation (reference/containment.ts containment()) over
 *   kbFixture(clock) with patches, for the highest transitive classification of
 *   `sources` and an optional `destinationClass` (or, with `destinationClasses`, the merged
 *   containmentAcross() over those classes); expected {ok, obligations} or {ok: false, reason}.
 * - engine: the same through Engine (openContext, release after openContext, evaluate,
 *   derive after openContext); only the runtime obligations (runtime_profile,
 *   max_output_classification) are compared; expected {effect, obligations?, code?}.
 * - enforcer: ProtectedRuntime.answer with a scripted RuntimeEnforcer (or none);
 *   expected {effect, providerCalled, runtimeRevision?, applied?} where runtimeRevision is the
 *   value recorded on the answer's audit entry (absent: none recorded) and applied the
 *   profiles passed to apply(). The scripted enforcer is execution-scoped (R112):
 *   `fail: 'drift'` reports another revision for the execution after the provider
 *   call, `fail: 'late-drift'` only after the final release (R124), `fail: 'release'`
 *   rejects the lease release; all must deny the answer.
 *
 * Outcomes: an allow that lacks an expected runtime profile, names a different one,
 * or carries a lower max_output_classification is UNSAFE_SUCCESS (containment would
 * silently disappear); so is a provider call where the vector requires a denial
 * before the provider.
 */
type Enforcer = null | { supports: string[]; revision?: string; fail?: 'reject' | 'throw-supports' | 'drift' | 'late-drift' | 'release' };
type Vector = { id: string; kind: 'profiles' | 'engine' | 'enforcer'; description?: string; patch: Patch[]; tags?: string[];
  sources?: string[]; destinationClass?: DestinationClass; destinationClasses?: DestinationClass[];
  binding?: keyof typeof bindings; operation?: 'openContext' | 'release' | 'evaluate' | 'derive'; resources?: string[]; recipient?: string;
  action?: Action; destination?: string; purpose?: string; enforcer?: Enforcer; callRevision?: string;
  expected: { ok?: boolean; reason?: string; obligations?: Obligation[]; effect?: 'allow' | 'deny'; code?: string; providerCalled?: boolean; runtimeRevision?: string; applied?: { domain: RuntimeDomain; profile: string }[] } };
export type RuntimeHooks = { containment?: typeof containment; runtime?: typeof ProtectedRuntime };
const runtimeOnly = (obligations: readonly Obligation[]) => obligations.filter(o => o.type === 'runtime_profile' || o.type === 'max_output_classification');
/** True when `actual` drops, changes or lowers a runtime obligation of `expected` (the containment would disappear). */
function weaker(expected: readonly Obligation[], actual: readonly Obligation[]): boolean {
  return expected.some(e => {
    if (e.type === 'runtime_profile') return !actual.some(a => a.type === 'runtime_profile' && a.domain === e.domain && a.profile === e.profile)
      || actual.some(a => a.type === 'runtime_profile' && a.domain === e.domain && a.profile !== e.profile);
    if (e.type === 'max_output_classification') {
      const got = actual.find(a => a.type === 'max_output_classification');
      return !got || got.type !== 'max_output_classification' || LEVELS.indexOf(got.value) < LEVELS.indexOf(e.value);
    }
    return false;
  });
}
function classify(v: Vector, allowed: boolean, pass: boolean, obligations: readonly Obligation[] | undefined): Outcome {
  const expectAllow = v.expected.ok ?? v.expected.effect === 'allow';
  if (expectAllow && allowed && v.expected.obligations && weaker(v.expected.obligations, obligations ?? [])) return 'UNSAFE_SUCCESS';
  return outcomeOf(expectAllow, allowed, pass);
}
function scripted(spec: Enforcer, applied: { domain: RuntimeDomain; profile: string }[][]): RuntimeEnforcer | undefined {
  if (!spec) return undefined;
  const current = new Map<string, string>();
  let checks = 0;
  return {
    supports: (domain: RuntimeDomain, profile: string) => { if (spec.fail === 'throw-supports') throw new Error('enforcer unavailable'); return spec.supports.includes(`${domain}/${profile}`); },
    apply: async (profiles, { executionId }) => {
      if (spec.fail === 'reject') throw new Error('apply failed');
      applied.push(profiles.map(p => ({ domain: p.domain, profile: p.profile })));
      const runtimeRevision = spec.revision ?? 'rev';
      current.set(executionId, runtimeRevision);
      return { runtimeRevision, release: async () => { current.delete(executionId); if (spec.fail === 'release') throw new Error('release failed'); } };
    },
    // 'late-drift': the applied revision is in force at the first check, another one at every later check.
    current: executionId => spec.fail === 'drift' || (spec.fail === 'late-drift' && checks++ > 0) ? 'other-rev' : current.get(executionId)
  };
}

export async function runRuntimeVectors(hooks: RuntimeHooks = {}): Promise<Row[]> {
  const derive = hooks.containment ?? containment, Runtime = hooks.runtime ?? ProtectedRuntime;
  const data = JSON.parse(readFileSync(new URL('./vectors-runtime.json', import.meta.url), 'utf8')) as { clock: number; cases: Vector[] };
  const rows: Row[] = [];
  for (const v of data.cases) {
    let actual: unknown, allowed = false, obligations: Obligation[] | undefined;
    try {
      const state = kbFixture(data.clock); state.destinations ??= {}; state.runtimeProfiles ??= {};
      apply(state, v.patch);
      if (v.kind === 'profiles') {
        const levels = v.sources!.map(id => Object.hasOwn(state.knowledge, id) ? transitiveClassification(state, state.knowledge[id]!) : null);
        const top = levels.some(l => !l) ? null : LEVELS[Math.max(...levels.map(l => LEVELS.indexOf(l!)))]! as Level;
        const c = v.destinationClasses !== undefined ? containmentAcross(state, 'acme', top, v.destinationClasses) : derive(state, 'acme', top, v.destinationClass);
        actual = c.ok ? { ok: true, obligations: c.obligations } : { ok: false, reason: c.reason };
        allowed = c.ok; obligations = c.ok ? c.obligations : undefined;
      } else {
        const store = new MemoryStore(state), engine = new Engine(store, { clock: () => data.clock });
        const b = bindings[v.binding!], purpose = v.purpose ?? 'work';
        const code = async () => (await store.auditLog('acme')).at(-1)?.reasonCode;
        if (v.kind === 'engine') {
          let result: { ok: boolean; obligations?: Obligation[] };
          if (v.operation === 'evaluate') {
            const r = await engine.evaluate(b, v.resources![0]!, v.action!, purpose, v.destination !== undefined ? { destination: v.destination } : {});
            result = { ok: r.decision, obligations: r.obligations };
          } else {
            const context = await engine.openContext(b, v.resources!, purpose);
            result = context;
            if (context.ok && v.operation === 'release') result = await engine.release(b, context.value.context, v.recipient!, 'Synthetic answer', 'share');
            if (context.ok && v.operation === 'derive') result = await engine.derive(b, context.value.context, 'Synthetic note', 'artifact');
          }
          allowed = result.ok; obligations = result.ok ? runtimeOnly(result.obligations ?? []) : undefined;
          actual = { effect: result.ok ? 'allow' : 'deny', ...(result.ok ? { obligations } : {}), ...(v.expected.code !== undefined ? { code: await code() } : {}) };
        } else {
          let called = false;
          const applied: { domain: RuntimeDomain; profile: string }[][] = [];
          const enforcer = scripted(v.enforcer ?? null, applied);
          const runtime = new Runtime(engine, { principal: 'provider', generate: async () => { called = true; return 'Synthetic answer'; } },
            { ...(enforcer ? { enforcer } : {}) });
          const r = await runtime.answer(b, v.resources!, purpose, 'Summarize', v.callRevision ? { trace: { runtimeRevision: v.callRevision } } : undefined);
          const entry = (await store.auditLog('acme')).at(-1);
          // A provider call where the vector requires a denial before the provider counts as an allow.
          allowed = r.ok || (called && v.expected.providerCalled === false);
          actual = { effect: r.ok ? 'allow' : 'deny', providerCalled: called, ...(r.ok && entry?.runtimeRevision !== undefined ? { runtimeRevision: entry.runtimeRevision } : {}),
            ...(v.expected.applied ? { applied: applied[0] ?? [] } : {}) };
        }
      }
    } catch (error) { actual = `error: ${(error as Error).message}`; allowed = false; }
    const pass = isDeepStrictEqual(actual, v.expected);
    const expectAllow = v.expected.ok ?? v.expected.effect === 'allow';
    rows.push({ id: v.id, kind: `runtime-${v.kind}`, expected: expectAllow ? 'allow' : 'deny', actual: allowed ? 'allow' : 'deny', pass,
      outcome: classify(v, allowed, pass, obligations), ...(v.tags ? { tags: v.tags } : {}) });
  }
  return rows;
}
