// Negative-space differential fuzzing (ADR-014): random tenants, role graphs, groups, SoD
// constraints, container chains, derivation DAGs, delegation chains, lifecycle states,
// destinations and runtime profile policies, plus malformed members (tests/differential-generators.ts).
// Each generated world is decided by the TypeScript reference and by the Python implementation (one
// long-lived `python -m akac serve` process); any disagreement fails with fast-check's minimized
// counterexample. AKAC_FUZZ_RUNS and AKAC_FUZZ_SEED widen or vary the run locally.
import test from 'node:test';
import assert from 'node:assert/strict';
import { isDeepStrictEqual } from 'node:util';
import fc from 'fast-check';
import { PythonWorker, evaluateTs, firstDifference, skipReason } from './differential-harness.ts';
import type { J } from './differential-harness.ts';
import { casesOf, worldArb } from './differential-generators.ts';

const RUNS = Number(process.env.AKAC_FUZZ_RUNS ?? 2000);
const SEED = Number(process.env.AKAC_FUZZ_SEED ?? 20260929);

test(`${RUNS} generated worlds: the TypeScript reference and the Python implementation decide identically`, { skip: skipReason, timeout: 600_000 }, async t => {
  const worker = new PythonWorker();
  const codes = new Map<string, number>(), obligations = new Set<string>();
  let allows = 0, compared = 0;
  const note = (r: J) => {
    for (const x of Array.isArray(r) ? r : [r]) {
      if (!x || typeof x !== 'object' || !x.code) continue;
      codes.set(x.code, (codes.get(x.code) ?? 0) + 1);
      if (x.effect === 'allow') allows++;
      for (const o of x.obligations ?? []) obligations.add(o.type);
    }
  };
  try {
    await fc.assert(fc.asyncProperty(worldArb, async w => {
      for (const c of casesOf(w)) {
        const expected = await evaluateTs(c), actual = await worker.call(c);
        compared++;
        if (!isDeepStrictEqual(expected, actual)) throw new Error(`${c.op}: ${firstDifference(expected, actual)}
minimal case (runner contract JSON): ${JSON.stringify(c)}`);
        note(expected);
      }
    }), { seed: SEED, numRuns: RUNS, endOnFailure: false });
  } finally { worker.close(); }
  t.diagnostic(`${compared} cases compared (seed ${SEED}); ${allows} allows; codes: ${[...codes].map(([c, n]) => `${c}=${n}`).join(' ')}`);
  t.diagnostic(`obligation types seen: ${[...obligations].sort().join(' ')}`);
  // The generator must reach both effects and the interesting rules; an all-deny agreement proves nothing.
  assert.ok(compared >= 3 * RUNS && allows > RUNS / 10, `too few allows: ${allows}`);
  for (const code of ['AUTHORIZED', 'KNOWLEDGE_BOUNDARY', 'INVALID_DELEGATION', 'SOD_VIOLATION', 'INVALID_CONTEXT', 'OUT_OF_SCOPE', 'IDENTITY_BOUNDARY',
    'NOT_AUTHORIZED', 'RECIPIENT', 'UNSUPPORTED_OBLIGATION', 'PROTECTED_DERIVATION', 'AUTHORIZED_RECIPIENT', 'ATTENUATED', 'INVALID_REQUEST']) {
    assert.ok(codes.has(code), `generator never produced ${code}`);
  }
  for (const type of ['audit_level', 'no_persist', 'max_context_ttl_ms', 'destination_restricted', 'runtime_profile', 'max_output_classification']) {
    assert.ok(obligations.has(type), `generator never produced obligation ${type}`);
  }
});
