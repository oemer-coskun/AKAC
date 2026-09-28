import { readFileSync } from 'node:fs';
import { contextFresh, decide } from '../reference/policy.ts';
import { fixture, kbFixture, bindings } from '../examples/fixture.ts';
import type { Action, Context, PolicyInput, State } from '../reference/types.ts';
/**
 * Patch entries: [collection, id, field, value] sets a field (existing, or one
 * of the optional fields below); [collection, id, record] inserts or replaces a
 * whole record; ['epochs', tenant, n] sets a tenant epoch.
 */
type Patch = [string, string, string, unknown] | [string, string, unknown];
type Decision = { id: string; kind?: 'decision'; binding: keyof typeof bindings; grant?: string; resource: string; action: Action; purpose: string;
  patch: Patch[]; expected: 'allow' | 'deny'; code?: string };
type Freshness = { id: string; kind: 'context'; context: Context; revision: string; patch: Patch[]; expected: 'valid' | 'invalid' };
const OPTIONAL = ['container', 'activeRoles', 'parent', 'accessExpiresAt'];
const FILES = ['./vectors.json', './vectors-0.3.json'];

function apply(state: State, patch: Patch[]) {
  for (const entry of patch) {
    const collections = state as unknown as Record<string, Record<string, unknown>>;
    if (entry.length === 3) {
      const [collection, id, value] = entry;
      if (!collections[collection] || typeof collections[collection] !== 'object' || Array.isArray(collections[collection])) throw new Error('Invalid trusted test vector');
      collections[collection]![id] = structuredClone(value); continue;
    }
    const [collection, id, field, value] = entry;
    const target = collections[collection]?.[id] as Record<string, unknown> | undefined;
    if (!target || (!Object.hasOwn(target, field) && !OPTIONAL.includes(field))) throw new Error('Invalid trusted test vector');
    target[field] = structuredClone(value);
  }
}
/** Decision vectors as portable {state, request} cases, for differential runs against other evaluators. */
export function vectorCases(): { id: string; state: State; request: PolicyInput }[] {
  return FILES.flatMap(file => {
    const data = JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8')) as { clock: number; fixture?: 'kbFixture'; cases: (Decision | Freshness)[] };
    return data.cases.filter((v): v is Decision => v.kind !== 'context').map(vector => {
      const state = data.fixture === 'kbFixture' ? kbFixture(data.clock) : fixture(data.clock);
      apply(state, vector.patch);
      const binding = { ...bindings[vector.binding], ...(vector.grant ? { grant: vector.grant } : {}) };
      return { id: vector.id, state, request: { binding, action: vector.action, resource: vector.resource, purpose: vector.purpose, now: data.clock } };
    });
  });
}
export function runVectors() {
  return FILES.flatMap(file => {
    const data = JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8')) as { clock: number; fixture?: 'kbFixture'; cases: (Decision | Freshness)[] };
    return data.cases.map(vector => {
      const state = data.fixture === 'kbFixture' ? kbFixture(data.clock) : fixture(data.clock);
      apply(state, vector.patch);
      if (vector.kind === 'context') {
        const actual = contextFresh(state, vector.context, data.clock, vector.revision) ? 'valid' : 'invalid';
        return { id: vector.id, expected: vector.expected, actual, pass: actual === vector.expected };
      }
      const binding = { ...bindings[vector.binding], ...(vector.grant ? { grant: vector.grant } : {}) };
      const result = decide(state, { binding, action: vector.action, resource: vector.resource, purpose: vector.purpose, now: data.clock });
      const pass = result.effect === vector.expected && (vector.code === undefined || result.code === vector.code);
      return { id: vector.id, expected: vector.expected, actual: result.effect, ...(vector.code ? { code: result.code } : {}), pass };
    });
  });
}
if (/[\\/]conformance[\\/]run\.ts$/.test(process.argv[1] ?? '')) {
  const results = runVectors();
  console.log(JSON.stringify({ profiles: ['AKAC-Core/0.1-draft', 'AKAC-KB/0.3-draft'], independentCertification: false, results }, null, 2));
  if (results.some(r => !r.pass)) process.exitCode = 1;
}
