// Differential conformance (ADR-014): every shared vector file, evaluated by the TypeScript
// reference and by the Python implementation from the same JSON, must give identical results:
// effect, reason code, category and obligations (and, for operations, disclosed ids,
// derived labels and destinations). A vector that has no decision form is counted and named.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { bindings, fixture, kbFixture } from '../examples/fixture.ts';
import { apply } from '../conformance/patch.ts';
import type { Patch } from '../conformance/patch.ts';
import { CORE_VERSION } from '../reference/types.ts';
import type { State } from '../reference/types.ts';
import { evalPython, evaluateTs, firstDifference, json, python, pythonCrypto, skipReason } from './differential-harness.ts';
import type { J } from './differential-harness.ts';

const read = (name: string): J => JSON.parse(readFileSync(new URL(`../conformance/${name}`, import.meta.url), 'utf8'));
type Case = { file: string; id: string; case: J };
const binding = (name: keyof typeof bindings, grant?: string) => ({ ...bindings[name], ...(grant ? { grant } : {}) });
const world = (name: 'fixture' | 'kbFixture' | undefined, clock: number, patch: Patch[] = []): State => {
  const s = (name === 'kbFixture' ? kbFixture : fixture)(clock);
  s.destinations ??= {}; s.runtimeProfiles ??= {};
  apply(s, patch); return s;
};
const request = (v: J, clock: number) => ({ binding: binding(v.binding, v.grant), action: v.action, resource: v.resource, purpose: v.purpose, now: clock });

/** Every vector as runner-contract cases, plus the vectors that have no decision form (with the reason). */
function cases(): { list: Case[]; notApplicable: { file: string; id: string; reason: string }[] } {
  const list: Case[] = [], notApplicable: { file: string; id: string; reason: string }[] = [];
  const add = (file: string, id: string, c: J) => list.push({ file, id, case: json(c) });
  for (const file of ['vectors.json', 'vectors-0.3.json']) {
    const data = read(file);
    for (const v of data.cases) {
      const state = world(data.fixture, data.clock, v.patch);
      if (v.kind === 'context') { add(file, v.id, { op: 'fresh', state, context: v.context, now: data.clock, revision: v.revision }); continue; }
      add(file, v.id, { op: 'decide', state, request: request(v, data.clock) });
      add(file, `${v.id}/evaluate`, { op: 'evaluate', state, request: request(v, data.clock) });
    }
  }
  {
    const file = 'vectors-0.4.json', data = read(file);
    const ops: Record<string, string> = { 'merkle-root': 'merkleRoot', inclusion: 'inclusionProof', consistency: 'consistencyProof', jcs: 'jcs',
      'audit-hash': 'auditHash', 'audit-leaf': 'auditLeaf', 'audit-chain': 'auditChain', obligations: 'obligations', reason: 'reason',
      'verify-inclusion': 'verifyInclusion', 'verify-consistency': 'verifyConsistency', 'checkpoint-v2': 'checkpointV2' };
    for (const v of data.cases) {
      if (v.kind === 'decision') {
        const state = world('kbFixture', v.clock, v.patch);
        add(file, v.id, { op: 'decide', state, request: request(v, v.clock) });
        add(file, `${v.id}/evaluate`, { op: 'evaluate', state, request: request(v, v.clock) });
      } else if (v.kind === 'checkpoint-v2' && !pythonCrypto) notApplicable.push({ file, id: v.id, reason: 'Python: optional dependency cryptography not installed' });
      else add(file, v.id, { ...v, op: ops[v.kind] });
    }
  }
  {
    const file = 'vectors-authzen.json', data = read(file);
    for (const v of data.cases) add(file, v.id, { op: 'authzen', state: world('kbFixture', data.clock), tenant: v.tenant, request: v.request, now: data.clock });
  }
  {
    const file = 'vectors-destinations.json', data = read(file);
    for (const v of data.cases) {
      const state = world('kbFixture', data.clock, v.patch), b = binding(v.binding, v.grant);
      if (v.kind === 'decision') {
        add(file, v.id, { op: 'decide', state, request: request(v, data.clock) });
        add(file, `${v.id}/evaluate`, { op: 'evaluate', state, request: request(v, data.clock) });
        continue;
      }
      add(file, v.id, { op: 'gate', state, binding: b, recipient: v.recipient, sources: v.sources, purpose: v.purpose });
      // The same release through the gateway operations: open the sources, then release to the recipient.
      if (v.recipient !== null) add(file, `${v.id}/release`, { op: 'steps', state, now: data.clock, steps: [
        { op: 'open', binding: b, resources: v.sources, purpose: v.purpose, save: 'c' },
        { op: 'release', binding: b, context: '$c', recipient: v.recipient, content: 'Synthetic answer', action: 'share' },
        { op: 'release', binding: b, context: '$c', recipient: v.recipient, content: 'Synthetic answer', action: 'export' }] });
      const profile = v.recipient !== null ? state.actors[v.recipient]?.destination : undefined;
      if (profile !== undefined) add(file, `${v.id}/evaluate`, { op: 'evaluate', state, request: { binding: b, action: 'share', resource: v.sources[0], purpose: v.purpose, now: data.clock }, destination: profile });
    }
  }
  {
    const file = 'vectors-runtime.json', data = read(file);
    for (const v of data.cases) {
      const state = world('kbFixture', data.clock, v.patch);
      if (v.kind === 'profiles') {
        add(file, v.id, { op: 'containment', state, tenant: 'acme', sources: v.sources,
          ...(v.destinationClasses !== undefined ? { classes: v.destinationClasses } : v.destinationClass !== undefined ? { destinationClass: v.destinationClass } : {}) });
      } else if (v.kind === 'engine') {
        const b = binding(v.binding), purpose = v.purpose ?? 'work';
        if (v.operation === 'evaluate') add(file, v.id, { op: 'evaluate', state, request: { binding: b, action: v.action, resource: v.resources[0], purpose, now: data.clock },
          ...(v.destination !== undefined ? { destination: v.destination } : {}) });
        else add(file, v.id, { op: 'steps', state, now: data.clock, steps: [{ op: 'open', binding: b, resources: v.resources, purpose, save: 'c' },
          ...(v.operation === 'release' ? [{ op: 'release', binding: b, context: '$c', recipient: v.recipient, content: 'Synthetic answer', action: 'share' }] : []),
          ...(v.operation === 'derive' ? [{ op: 'derive', binding: b, context: '$c', content: 'Synthetic note', kind: 'artifact' }] : [])] });
      } else notApplicable.push({ file, id: v.id, reason: 'runtime enforcer protocol (ProtectedRuntime), not a decision' });
    }
  }
  {
    const file = 'vectors-redteam.json', data = read(file);
    for (const v of data.cases) add(file, v.id, { op: 'scenario', scenario: v });
  }
  return { list, notApplicable };
}

test('every shared vector file: the TypeScript reference and the Python implementation agree', { skip: skipReason }, async t => {
  const { list, notApplicable } = cases();
  const expected: J[] = [];
  for (const c of list) expected.push(await evaluateTs(c.case));
  const actual = evalPython(list.map(c => c.case));
  assert.equal(actual.length, list.length);
  const perFile = new Map<string, { compared: number; agreed: number }>();
  const differences: string[] = [];
  list.forEach((c, i) => {
    const row = perFile.get(c.file) ?? { compared: 0, agreed: 0 };
    row.compared++;
    if (isDeepStrictEqual(expected[i], actual[i])) row.agreed++;
    else differences.push(`${c.file} ${c.id}: ${firstDifference(expected[i], actual[i])}`);
    perFile.set(c.file, row);
  });
  for (const [file, row] of perFile) t.diagnostic(`${file}: ${row.agreed}/${row.compared} cases identical`);
  for (const n of notApplicable) t.diagnostic(`not compared: ${n.file} ${n.id} (${n.reason})`);
  assert.deepEqual(differences, [], `TypeScript and Python disagree on ${differences.length} case(s)`);
  // Every vector file took part, and the comparison saw both effects.
  assert.equal(perFile.size, 7);
  assert.ok(expected.some(r => r?.effect === 'allow') && expected.some(r => r?.effect === 'deny'));
  assert.ok(CORE_VERSION.startsWith('akac-reference/'));
});

test('the Python implementation runs the shared vectors on its own (python -m akac conformance)', { skip: skipReason }, async () => {
  const { spawnSync } = await import('node:child_process');
  const { PYTHON_DIR } = await import('./differential-harness.ts');
  const r = spawnSync(python!, ['-m', 'akac', 'conformance', '--json'], { cwd: PYTHON_DIR, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 300_000 });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout) as J;
  assert.equal(report.summary.UNSAFE_SUCCESS, 0);
  assert.equal(report.summary.FAILURE, 0);
  assert.equal(report.summary.gates.pass, true);
  assert.equal(report.independentCertification, false);
  // Only the runtime enforcer protocol (and checkpoint signatures without the optional dependency) is not applicable.
  for (const row of report.results.filter((x: J) => x.outcome === 'NOT_APPLICABLE')) {
    // 0.6 crypto vectors: an algorithm the installed cryptography package lacks (SLH-DSA always; ML-DSA and the hybrid on older releases) is never a pass.
    // 0.6 release vectors: the engine-level kinds (filters, sanitizers, hints, volume budgets, decision cache) need the TypeScript engine hooks.
    assert.ok(row.kind === 'runtime-enforcer' || String(row.kind).startsWith('release-') || (row.kind === 'checkpoint-v2' && !pythonCrypto) || ((row.kind === 'checkpoint-v3' || row.kind === 'checkpoint-history') && row.pass === false), row.id);
  }
});

test('integral JSON numbers (1.0, 1e0) are integers in both implementations (review finding 14)', { skip: skipReason }, async () => {
  const { spawnSync } = await import('node:child_process');
  const { PYTHON_DIR } = await import('./differential-harness.ts');
  const clock = 1_800_000_000_000;
  const state = kbFixture(clock);
  const request = { binding: bindings.chief, action: 'read', resource: 'strategy', purpose: 'work', now: clock };
  // The same document as text, with integral numbers written as fractions and exponents.
  const text = JSON.stringify({ cases: [{ op: 'decide', state, request }, { op: 'evaluate', state, request }, { op: 'jcs', input: { a: 1, b: [2, -0] } }] })
    .replace(/"version":1([,}])/g, '"version":1.0$1').replace(`"now":${clock}`, '"now":1.8e12').replace('"a":1', '"a":1.0').replace('-0]', '-0.0]');
  assert.ok(text.includes('"version":1.0') && text.includes('"now":1.8e12'));
  const parsed = JSON.parse(text) as { cases: J[] };
  const expected: J[] = [];
  for (const c of parsed.cases) expected.push(await evaluateTs(c));
  const r = spawnSync(python!, ['-m', 'akac', 'eval'], { cwd: PYTHON_DIR, input: text, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), expected);
  assert.equal(expected[0].effect, 'allow');
  assert.equal(expected[2], '{"a":1,"b":[2,0]}');
  // NaN and Infinity are not JSON: the Python reader rejects them like JSON.parse does.
  const bad = spawnSync(python!, ['-m', 'akac', 'eval'], { cwd: PYTHON_DIR, input: '{"cases":[{"op":"jcs","input":NaN}]}', encoding: 'utf8', timeout: 60_000 });
  assert.notEqual(bad.status, 0);
  assert.throws(() => JSON.parse('{"x":NaN}'));
});

test('the fixture is data: examples/fixture.json validates against schemas/fixture.json and loads into valid records', async () => {
  const { Ajv2020 } = await import('ajv/dist/2020.js');
  const schema = (name: string) => JSON.parse(readFileSync(new URL(`../schemas/${name}.json`, import.meta.url), 'utf8'));
  const ajv = new Ajv2020();
  for (const name of ['binding', 'principal', 'knowledge', 'context', 'role', 'group', 'container', 'constraint', 'destination', 'runtime-profile', 'grant', 'obligation']) ajv.addSchema(schema(name));
  const validate = ajv.compile(schema('fixture'));
  const data = JSON.parse(readFileSync(new URL('../examples/fixture.json', import.meta.url), 'utf8')) as Record<string, unknown>;
  assert.ok(validate(data), JSON.stringify(validate.errors));
  assert.equal(validate({ ...data, extra: true }), false);
  assert.equal(validate({ ...data, clockRelative: [['nowhere', 'x']] }), false);
  // After the clock is applied, every grant is a valid grant record.
  const grant = ajv.getSchema('https://github.com/oemer-coskun/AKAC/schemas/grant.json')!;
  for (const g of Object.values(kbFixture(1_800_000_000_000).grants)) assert.ok(grant(g), JSON.stringify(grant.errors));
  assert.deepEqual(Object.keys(fixture(0).knowledge), ['handbook', 'strategy', 'project-alpha']);
});
