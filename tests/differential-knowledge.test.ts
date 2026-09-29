// Knowledge semantics differential fuzzing (0.6, ADR-022): random tags, residency, regions, combination
// rules, depth limits, derivation chains, session scopes and placements over the kbFixture company. Each
// gateway sequence is run by the TypeScript reference and by the Python implementation; any disagreement
// fails with fast-check's minimized counterexample.
import test from 'node:test';
import assert from 'node:assert/strict';
import { isDeepStrictEqual } from 'node:util';
import fc from 'fast-check';
import { PythonWorker, evaluateTs, firstDifference, skipReason } from './differential-harness.ts';
import type { J } from './differential-harness.ts';
import { caseOf, world } from './knowledge-generators.ts';

const RUNS = Number(process.env.AKAC_FUZZ_RUNS ?? 600);
const SEED = Number(process.env.AKAC_FUZZ_SEED ?? 20260929);
test(`${RUNS} knowledge worlds: the TypeScript reference and the Python implementation agree on depth, combination, residency, placement and sessions`,
  { skip: skipReason, timeout: 600_000 }, async t => {
    const worker = new PythonWorker();
    const seen = new Map<string, number>();
    try {
      await fc.assert(fc.asyncProperty(world, async w => {
        const c = caseOf(w);
        const expected = await evaluateTs(c), actual = await worker.call(c);
        if (!isDeepStrictEqual(expected, actual)) throw new Error(`${firstDifference(expected, actual)}\nminimal case: ${JSON.stringify(c)}`);
        for (const r of expected as J[]) if (r?.code) seen.set(r.code, (seen.get(r.code) ?? 0) + 1);
      }), { seed: SEED, numRuns: RUNS, endOnFailure: false });
    } finally { worker.close(); }
    t.diagnostic(`codes: ${[...seen].map(([c, n]) => `${c}=${n}`).join(' ')}`);
    for (const code of ['PROTECTED_DERIVATION', 'AUTHORIZED_RECIPIENT', 'LINEAGE_DEPTH', 'COMBINATION', 'RESIDENCY', 'WRITE_DOWN', 'INVALID_CONTEXT'])
      assert.ok(seen.has(code), `generator never produced ${code}`);
  });
