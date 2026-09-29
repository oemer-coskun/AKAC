import test from 'node:test';
import assert from 'node:assert/strict';
import { runBench } from '../bench/run.ts';
import { toMarkdown } from '../bench/render.ts';
import { generate, SCALES } from '../bench/data.ts';
import { LIMITS } from '../reference/policy.ts';

const tiny = { ...SCALES.tiny!, iterations: 12 };

test('bench: synthetic data is deterministic and respects the documented bounds', () => {
  const a = generate(tiny, 7, 1_800_000_000_000), b = generate(tiny, 7, 1_800_000_000_000);
  assert.deepEqual([...a.states.entries()], [...b.states.entries()]);
  assert.equal(a.tenants.length, tiny.tenants);
  for (const state of a.states.values()) {
    for (const k of Object.values(state.knowledge)) assert.ok(k.sources.length <= 2);
    assert.ok(Object.keys(state.roles).length <= tiny.roles);
  }
  assert.ok(tiny.roleDepth <= LIMITS.roleDepth && tiny.containerDepth <= LIMITS.containerDepth && tiny.dagDepth <= LIMITS.path);
});

test('bench: harness runs at tiny scale on MemoryStore, authorized workloads allow, bounds fail closed', async () => {
  const r = await runBench({ scale: tiny, backends: ['memory'], concurrency: [1, 2] });
  const rows = r.backends[0]!.rows;
  assert.ok(rows.length >= 10);
  for (const row of rows) {
    assert.equal(row.errors, 0, row.workload);
    assert.equal(row.filterMismatches, 0, row.workload);
    assert.ok(row.p50 <= row.p95 && row.p95 <= row.p99 && row.p99 <= row.max, row.workload);
    if (row.workload.includes('authorized') || row.workload.startsWith('evaluate derived')) assert.deepEqual(Object.keys(row.outcomes), ['allow'], row.workload);
  }
  for (const c of r.curves) {
    const last = c.points.at(-1)!, atBound = c.points.find(p => p.parameter === c.bound)!;
    assert.equal(last.parameter, c.bound + 1);
    assert.notEqual(last.effect, 'allow', `${c.name} past its bound must not allow`);
    assert.equal(atBound.effect, 'allow', `${c.name} at its bound is still decidable`);
  }
  const md = toMarkdown(r);
  assert.match(md, /## AKAC benchmark: scale `tiny`/);
  assert.match(md, /\| Workload \| Callers \|/);
  assert.ok(r.machine.node.startsWith('v'));
});

const url = process.env.AKAC_TEST_DATABASE_URL;
test('bench: harness runs at tiny scale on PostgreSQL with a non-bypass runtime role', { skip: !url && 'AKAC_TEST_DATABASE_URL not set' }, async () => {
  const r = await runBench({ scale: { ...tiny, iterations: 6 }, backends: ['postgres'], concurrency: [1], curves: false, databaseUrl: url! });
  const rows = r.backends[0]!.rows;
  assert.ok(r.machine.postgres && r.machine.pgvector);
  for (const row of rows) {
    assert.equal(row.errors, 0, row.workload);
    assert.equal(row.filterMismatches, 0, row.workload);
    if (row.workload.includes('authorized')) assert.deepEqual(Object.keys(row.outcomes), ['allow'], row.workload);
  }
});
