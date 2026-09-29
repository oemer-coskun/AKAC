import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { decide, destinationGate, targetOf, transitiveClassification } from '../reference/policy.ts';
import { kbFixture, bindings } from '../examples/fixture.ts';
import { LEVELS } from '../reference/types.ts';
import type { Action } from '../reference/types.ts';
import { apply } from './patch.ts';
import type { Patch } from './patch.ts';
import { outcomeOf } from './outcome.ts';
import type { Row } from './outcome.ts';

/**
 * Destination profile vectors (0.4, ADR-008, profile AKAC-Destinations/0.4-draft).
 * - decision: decide() over kbFixture(clock) with patches; expected {effect, code}
 *   (grant attenuation of destinations and maxResults).
 * - destination: the pure destination gate (reference/policy.ts destinationGate) for
 *   the binding's grant, the recipient's target (targetOf(actor), or
 *   {kind:'unspecified'} when recipient is null), the highest transitive effective
 *   classification of `sources`, and `purpose`; expected {ok, restrict?}.
 */
type Vector = { id: string; kind: 'decision' | 'destination'; binding: keyof typeof bindings; grant?: string; patch: Patch[]; purpose: string;
  resource?: string; action?: Action; recipient?: string | null; sources?: string[]; expected: { effect?: string; code?: string; ok?: boolean; restrict?: string[] }; tags?: string[] };
export function runDestinationVectors(): Row[] {
  const data = JSON.parse(readFileSync(new URL('./vectors-destinations.json', import.meta.url), 'utf8')) as { clock: number; cases: Vector[] };
  return data.cases.map(v => {
    let actual: unknown;
    try {
      const state = kbFixture(data.clock); state.destinations ??= {};
      apply(state, v.patch);
      const binding = { ...bindings[v.binding], ...(v.grant ? { grant: v.grant } : {}) };
      if (v.kind === 'decision') {
        const d = decide(state, { binding, resource: v.resource!, action: v.action!, purpose: v.purpose, now: data.clock });
        actual = { effect: d.effect, code: d.code };
      } else if (v.kind === 'destination') {
        const levels = v.sources!.map(id => Object.hasOwn(state.knowledge, id) ? transitiveClassification(state, state.knowledge[id]!) : null);
        const top = levels.some(l => !l) ? null : LEVELS[Math.max(...levels.map(l => LEVELS.indexOf(l!)))]!;
        const target = v.recipient === null ? { kind: 'unspecified' as const } : targetOf(state.actors[v.recipient!]!);
        const g = destinationGate(state, state.grants[binding.grant]!, target, binding.tenant, top, v.purpose);
        actual = g.ok ? { ok: true, ...(g.restrict ? { restrict: g.restrict } : {}) } : { ok: false };
      } else actual = 'unknown vector kind';
    } catch (error) { actual = `error: ${(error as Error).message}`; }
    const pass = isDeepStrictEqual(actual, v.expected);
    const want = v.kind === 'decision' ? v.expected.effect === 'allow' : v.expected.ok === true;
    const got = v.kind === 'decision' ? (actual as { effect?: string })?.effect === 'allow' : (actual as { ok?: boolean })?.ok === true;
    return { id: v.id, kind: `destination-${v.kind}`, expected: want ? 'allow' : 'deny', actual: got ? 'allow' : 'deny', pass, outcome: outcomeOf(want, got, pass), ...(v.tags ? { tags: v.tags } : {}) };
  });
}
