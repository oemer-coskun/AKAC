import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { mapEvaluation } from '../reference/authzen.ts';
import { decide } from '../reference/policy.ts';
import { outcomeOf } from './outcome.ts';
import type { Row } from './outcome.ts';
import { kbFixture } from '../examples/fixture.ts';

type Case = { id: string; tenant: string; request: unknown; expected: 'allow' | 'deny' | 'malformed' | 'unsupported'; code?: string; binding?: unknown; tags?: string[] };
/**
 * AuthZEN mapping vectors: each request is mapped for its credential tenant and, when the mapping succeeds,
 * evaluated with the pure decide() over the fixture. Only the mapping and decide() are exercised (no listener).
 */
export function runAuthzenVectors(hooks: { decide?: typeof decide } = {}): Row[] {
  const decideFn = hooks.decide ?? decide;
  const data = JSON.parse(readFileSync(new URL('./vectors-authzen.json', import.meta.url), 'utf8')) as { clock: number; cases: Case[] };
  return data.cases.map(v => {
    const mapped = mapEvaluation(v.tenant, v.request);
    let actual: string, code: string | undefined;
    if (!mapped.ok) actual = mapped.kind;
    else {
      const d = decideFn(kbFixture(data.clock), { binding: mapped.binding, resource: mapped.resource, action: mapped.action, purpose: mapped.purpose, now: data.clock });
      actual = d.effect; code = d.code;
    }
    const pass = actual === v.expected && (v.code === undefined || code === v.code)
      && (v.binding === undefined || (mapped.ok && isDeepStrictEqual(mapped.binding, v.binding)));
    // Only an allow grants access: malformed and unsupported requests MUST NOT be allowed.
    return { id: v.id, kind: 'authzen', expected: v.expected, actual, pass, outcome: outcomeOf(v.expected === 'allow', actual === 'allow', pass), ...(v.tags ? { tags: v.tags } : {}) };
  });
}
