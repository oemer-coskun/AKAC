import { readFileSync } from 'node:fs';
import { decide } from '../reference/policy.ts';
import { fixture, bindings } from '../examples/fixture.ts';
import type { Action } from '../reference/types.ts';
type Vector = { id: string; binding: keyof typeof bindings; resource: string; action: Action; purpose: string;
  patch: [string, string, string, unknown][]; expected: 'allow' | 'deny' };
export function runVectors() {
  const data = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8')) as { clock: number; cases: Vector[] };
  return data.cases.map(vector => {
    const state = fixture(data.clock);
    for (const [collection, id, field, value] of vector.patch) {
      const target = (state as unknown as Record<string, Record<string, Record<string, unknown>>>)[collection]?.[id];
      if (!target || !Object.hasOwn(target, field)) throw new Error('Invalid trusted test vector');
      target[field] = value;
    }
    const result = decide(state, { binding: bindings[vector.binding], action: vector.action, resource: vector.resource, purpose: vector.purpose, now: data.clock });
    return { id: vector.id, expected: vector.expected, actual: result.effect, pass: result.effect === vector.expected };
  });
}
if (/[\\/]conformance[\\/]run\.ts$/.test(process.argv[1] ?? '')) {
  const results = runVectors();
  console.log(JSON.stringify({ profile: 'AKAC-Core/0.1-draft', independentCertification: false, results }, null, 2));
  if (results.some(r => !r.pass)) process.exitCode = 1;
}
