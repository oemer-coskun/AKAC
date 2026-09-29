import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { decide } from '../reference/policy.ts';
import { kbFixture, bindings } from '../examples/fixture.ts';
import type { Action } from '../reference/types.ts';
import { apply } from './patch.ts';
import type { Patch } from './patch.ts';
import { outcomeOf } from './outcome.ts';
import type { Row } from './outcome.ts';

/**
 * Identity and authority vectors (0.6, ADR-019, profile AKAC-Identity/0.6-draft):
 * decide() over kbFixture(clock) with patches; the riskSignals and settings
 * collections start empty. Heartbeat-bound grants, break-glass grants, risk caps.
 */
type Vector = { id: string; kind: 'decision'; binding: keyof typeof bindings; grant?: string; patch: Patch[]; purpose: string;
  resource: string; action: Action; expected: { effect: string; code: string }; tags?: string[] };
export function runIdentityVectors(hooks: { decide?: typeof decide } = {}): Row[] {
  const decideFn = hooks.decide ?? decide;
  const data = JSON.parse(readFileSync(new URL('./vectors-0.6-identity.json', import.meta.url), 'utf8')) as { clock: number; cases: Vector[] };
  return data.cases.map(v => {
    let actual: unknown;
    try {
      const state = kbFixture(data.clock); state.riskSignals ??= {}; state.settings ??= {};
      apply(state, v.patch);
      if (v.kind !== 'decision') throw new Error('unknown vector kind');
      const binding = { ...bindings[v.binding], ...(v.grant ? { grant: v.grant } : {}) };
      const d = decideFn(state, { binding, resource: v.resource, action: v.action, purpose: v.purpose, now: data.clock });
      actual = { effect: d.effect, code: d.code };
    } catch (error) { actual = `error: ${(error as Error).message}`; }
    const pass = isDeepStrictEqual(actual, v.expected);
    const got = (actual as { effect?: string })?.effect === 'allow';
    return { id: v.id, kind: 'identity-decision', expected: v.expected.effect, actual: got ? 'allow' : 'deny', pass,
      outcome: outcomeOf(v.expected.effect === 'allow', got, pass), ...(v.tags ? { tags: v.tags } : {}) };
  });
}
