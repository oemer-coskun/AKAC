import assert from 'node:assert/strict';
/**
 * A result without its per-decision evidence (0.4): `decisionId`, when present,
 * must be a non-empty string; `obligations`, when present, an array. Tests that
 * compare whole results use it; evidence itself is tested in evidence.test.ts
 * and decisions.test.ts.
 */
export function bare<T>(result: T): T {
  if (!result || typeof result !== 'object') return result;
  const { decisionId, obligations, ...rest } = result as Record<string, unknown>;
  if (decisionId !== undefined) assert.ok(typeof decisionId === 'string' && decisionId.length > 0, 'decisionId');
  if (obligations !== undefined) assert.ok(Array.isArray(obligations), 'obligations');
  return rest as T;
}
