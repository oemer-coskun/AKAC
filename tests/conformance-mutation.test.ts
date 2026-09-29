import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { decide } from '../reference/policy.ts';
import { LEVELS } from '../reference/types.ts';
import type { Decision, State } from '../reference/types.ts';
import { Engine } from '../reference/engine.ts';
import { exitCode, summarize } from '../conformance/outcome.ts';
import { manifest, report, runAll } from '../conformance/run.ts';
import type { Hooks } from '../conformance/run.ts';
import type { Mutant } from '../conformance/scenarios.ts';

/**
 * "Broken oracle" meta-tests: the conformance suite is only evidence if it can see a leak. Each
 * deliberately permissive implementation below MUST make the runner report UNSAFE_SUCCESS and a
 * non-zero exit code; the unmodified implementation MUST NOT.
 */
const allow: Decision = { effect: 'allow', code: 'AUTHORIZED', category: 'allow' } as unknown as Decision;
const via = (mutate: (state: State) => void): typeof decide => (state, input) => { const copy = structuredClone(state); try { mutate(copy); } catch { /* keep going */ } return decide(copy, input); };
const decideMutants: Record<string, Hooks> = {
  'decide always allows': { decide: () => allow },
  'decide ignores tenant': { decide: (state, input) => {
    const copy = structuredClone(state) as unknown as Record<string, Record<string, { tenant?: string }>>;
    for (const c of ['actors', 'grants', 'knowledge', 'roles', 'groups', 'constraints', 'containers']) for (const r of Object.values(copy[c] ?? {})) r.tenant = input.binding.tenant;
    return decide(copy as unknown as State, input);
  } },
  'decide ignores classification': { decide: via(state => {
    for (const a of Object.values(state.actors)) a.clearance = LEVELS[LEVELS.length - 1]!;
    for (const k of Object.values(state.knowledge)) k.classification = 'public';
    for (const c of Object.values(state.containers)) c.classification = 'public';
  }) },
  'decide ignores quarantine lifecycle': { decide: via(state => { for (const k of Object.values(state.knowledge)) { delete k.lifecycle; delete k.quarantineReason; } }) },
};
const scenarioMutants: Mutant[] = [
  { name: 'ignores quarantine lifecycle', state: s => { for (const k of Object.values(s.knowledge)) { delete k.lifecycle; delete k.quarantineReason; } } },
  { name: 'ignores classification and audience', state: s => { for (const k of Object.values(s.knowledge)) { k.classification = 'public'; k.readerRoles = ['staff']; k.projects = []; k.readers = []; delete k.container; } } },
  { name: 'ignores tenant epoch', state: s => { for (const c of Object.values(s.contexts)) c.epoch = s.epochs[c.tenant] ?? 0; } },
  { name: 'derives with a lowered label and no provenance', engine: (engine, store) => {
    const derive = engine.derive.bind(engine);
    engine.derive = async (...args: Parameters<Engine['derive']>) => {
      const r = await derive(...args);
      if (r.ok) await store.transaction(args[0].tenant, async tx => { const k = tx.state.knowledge[r.value.id]!; k.classification = 'public'; k.readerRoles = ['staff']; k.projects = []; k.readers = []; k.sources = []; });
      return r;
    };
  } },
  { name: 'delegates without attenuation checks', engine: (engine, store) => {
    engine.delegate = async (b, child) => {
      await store.transaction(b.tenant, async tx => { tx.state.grants[child.id] = structuredClone(child); });
      return { ok: true, value: { id: child.id }, decisionId: 'mutant', obligations: [] };
    };
  } },
];

test('the unmodified implementation has no failure and no unsafe success, and covers every red-team class', async () => {
  const results = await runAll(), summary = summarize(results);
  assert.equal(summary.UNSAFE_SUCCESS, 0); assert.equal(summary.FAILURE, 0);
  assert.ok(summary.gates.pass); assert.equal(exitCode(summary), 0);
  assert.ok(summary.cross_tenant.vectors >= 6);
  assert.ok(summary.SUCCESS > 0 && summary.SAFE_BLOCK > 0);
  const tags = new Set(results.flatMap(r => r.tags ?? []));
  for (const t of ['trust-laundering', 'delayed-memory-injection', 'child-grant-escalation', 'subagent', 'lexical-bypass', 'stale-context', 'cross-tenant']) assert.ok(tags.has(t), t);
  // Every attack class keeps at least one allow control, so a blanket deny cannot pass unnoticed.
  for (const t of ['trust-laundering', 'child-grant-escalation', 'subagent', 'lexical-bypass', 'stale-context']) assert.ok(results.some(r => r.tags?.includes(t) && r.tags.includes('control') && r.outcome === 'SUCCESS'), `control ${t}`);
});
for (const [name, hooks] of Object.entries(decideMutants)) test(`broken oracle detected: ${name}`, async () => {
  const summary = summarize(await runAll({ hooks }));
  assert.ok(summary.UNSAFE_SUCCESS > 0, 'UNSAFE_SUCCESS reported');
  assert.equal(summary.gates.unsafe_success_zero, false);
  assert.equal(exitCode(summary), 1);
});
test('broken oracle detected: decide ignores tenant trips the cross-tenant gate', async () => {
  const summary = summarize(await runAll({ hooks: decideMutants['decide ignores tenant']! }));
  assert.ok(summary.cross_tenant.leaks > 0); assert.equal(summary.gates.cross_tenant_leaks_zero, false);
});
for (const mutant of scenarioMutants) test(`broken engine detected: ${mutant.name}`, async () => {
  const summary = summarize(await runAll({ mutant }));
  assert.ok(summary.UNSAFE_SUCCESS > 0, 'UNSAFE_SUCCESS reported');
  assert.equal(exitCode(summary), 1);
});
test('a blanket-deny implementation is reported as FAILURE, not as safe', async () => {
  const deny = { effect: 'deny', code: 'KNOWLEDGE_BOUNDARY', category: 'deny' } as unknown as Decision;
  const summary = summarize(await runAll({ hooks: { decide: () => deny, contextFresh: () => false } }));
  assert.equal(summary.UNSAFE_SUCCESS, 0); assert.ok(summary.FAILURE > 0); assert.equal(exitCode(summary), 1);
});
test('a suite without cross-tenant vectors cannot pass the tenant gate', () => {
  const summary = summarize([{ id: 'X', expected: 'deny', actual: 'deny', pass: true, outcome: 'SAFE_BLOCK' }]);
  assert.equal(summary.gates.cross_tenant_leaks_zero, false); assert.equal(exitCode(summary), 1);
});
test('an id that merely names a tenant does not count for the tenant gate; only the cross-tenant tag does', () => {
  const own = summarize([{ id: 'KB-032-own-tenant-revocation', expected: 'deny', actual: 'deny', pass: true, outcome: 'SAFE_BLOCK' }]);
  assert.equal(own.cross_tenant.vectors, 0); assert.equal(own.gates.cross_tenant_leaks_zero, false);
  const tagged = summarize([{ id: 'X', expected: 'deny', actual: 'deny', pass: true, outcome: 'SAFE_BLOCK', tags: ['cross-tenant'] }]);
  assert.equal(tagged.cross_tenant.vectors, 1); assert.equal(tagged.gates.pass, true);
});
test('the AuthZEN tenant-pinning vectors are tagged cross-tenant', async () => {
  const rows = await runAll();
  for (const id of ['Z05', 'Z06', 'AKAC-004-tenant', 'RT-060-cross-tenant-open', 'DST-G07']) assert.ok(rows.find(r => r.id === id)?.tags?.includes('cross-tenant'), id);
  assert.ok(!rows.find(r => r.id === 'KB-032-own-tenant-revocation')?.tags?.includes('cross-tenant'));
});
for (const [name, hooks] of Object.entries({
  'inclusion verifier always accepts': { verifyInclusion: () => true },
  'consistency verifier always accepts': { verifyConsistency: () => true },
  'checkpoint v2 verifier always accepts': { verifyCheckpointV2: () => true },
} satisfies Record<string, Hooks>)) test(`broken verifier detected: ${name}`, async () => {
  const summary = summarize(await runAll({ hooks }));
  assert.ok(summary.UNSAFE_SUCCESS > 0, 'forged evidence accepted is reported as UNSAFE_SUCCESS');
  assert.equal(exitCode(summary), 1);
});
test('a verifier that rejects everything is reported as FAILURE', async () => {
  const summary = summarize(await runAll({ hooks: { verifyInclusion: () => false, verifyConsistency: () => false, verifyCheckpointV2: () => false } }));
  assert.equal(summary.UNSAFE_SUCCESS, 0); assert.ok(summary.FAILURE > 0); assert.equal(exitCode(summary), 1);
});
test('machine-readable summary carries a reproducibility manifest', async () => {
  const { out } = report(await runAll());
  const m = out.manifest;
  assert.match(m.packageLock, /^[0-9a-f]{64}$/); assert.equal(m.node, process.version); assert.match(m.runner, /^akac-conformance-runner\//);
  assert.ok(Object.keys(m.spec).includes('spec/CONFORMANCE.md') && Object.keys(m.spec).includes('spec/AKAC-0.3.md'));
  for (const f of ['vectors.json', 'vectors-0.3.json', 'vectors-0.4.json', 'vectors-authzen.json', 'vectors-redteam.json']) assert.match(m.vectors[`conformance/${f}`] ?? '', /^[0-9a-f]{64}$/, f);
  assert.deepEqual(m, manifest());
  assert.ok(!JSON.stringify(out).includes(process.cwd().replaceAll('\\', '/')) && !JSON.stringify(out).includes(process.cwd()), 'no host paths');
  assert.equal(out.summary.gates.pass, true); assert.equal(out.independentCertification, false);
});
test('CLI exits zero and writes the JSON summary', () => {
  const file = new URL(`../.conformance-${process.pid}.json`, import.meta.url);
  try {
    const run = spawnSync(process.execPath, ['conformance/run.ts', `--json=${file.pathname.replace(/^\/([A-Za-z]:)/, '$1')}`], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stdout, /conformance\s+PASS/);
    assert.equal(JSON.parse(readFileSync(file, 'utf8')).summary.gates.pass, true);
  } finally { try { execFileSync(process.execPath, ['-e', `require('node:fs').rmSync(${JSON.stringify(file.pathname.replace(/^\/([A-Za-z]:)/, '$1'))},{force:true})`]); } catch { /* ignore */ } }
});
