import test from 'node:test';
import assert from 'node:assert/strict';
import { runAuthzenVectors } from '../conformance/run-authzen.ts';

test('AuthZEN mapping vectors pass', () => {
  const results = runAuthzenVectors();
  assert.ok(results.length >= 20);
  for (const r of results) assert.equal(r.pass, true, r.id);
  assert.deepEqual([...new Set(results.map(r => r.expected))].sort(), ['allow', 'deny', 'malformed', 'unsupported']);
});

test('broken oracle: an evaluator that allows share/export without a destination is UNSAFE_SUCCESS (R121)', () => {
  const results = runAuthzenVectors({ targetNamed: () => true });
  const unsafe = results.filter(r => r.outcome === 'UNSAFE_SUCCESS').map(r => r.id);
  assert.deepEqual(unsafe, ['Z21', 'Z22']);
});
