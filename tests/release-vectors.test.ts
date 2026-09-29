import test from 'node:test';
import assert from 'node:assert/strict';
import { runReleaseVectors } from '../conformance/run-release.ts';

test('release and retrieval protection vectors pass (conformance/vectors-0.6-release.json)', async () => {
  const rows = await runReleaseVectors();
  assert.ok(rows.length >= 45);
  for (const r of rows) assert.equal(r.pass, true, `${r.id}: expected ${JSON.stringify(r.expected)}, got ${JSON.stringify(r.actual)}`);
  assert.equal(rows.filter(r => r.outcome === 'UNSAFE_SUCCESS' || r.outcome === 'FAILURE').length, 0);
  assert.ok(new Set(rows.map(r => r.kind)).size >= 7);
});
test('broken oracle: an engine that ignores required filters or the volume budget is UNSAFE_SUCCESS', async () => {
  const ignoreFilters = (await runReleaseVectors('ignore-required-filters')).filter(r => r.outcome === 'UNSAFE_SUCCESS').map(r => r.id);
  assert.deepEqual(ignoreFilters, ['REL-R08', 'REL-R10', 'REL-R13']);
  const ignoreVolume = (await runReleaseVectors('ignore-volume')).filter(r => r.outcome === 'UNSAFE_SUCCESS').map(r => r.id);
  assert.deepEqual(ignoreVolume, ['REL-V01', 'REL-V02', 'REL-V04']);
});
