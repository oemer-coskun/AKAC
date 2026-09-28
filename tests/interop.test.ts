import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fc from 'fast-check';
import { decide } from '../reference/policy.ts';
import { fixture, kbFixture, bindings } from '../examples/fixture.ts';
import { vectorCases } from '../conformance/run.ts';
import { LEVELS } from '../reference/types.ts';
import type { Origin, PolicyInput, State } from '../reference/types.ts';

const now = 1800000000000;
const python = (cases: { state: State; request: PolicyInput }[]) => {
  const result = spawnSync('python3', ['implementations/python/akac.py'], { input: JSON.stringify({ cases }), encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 30000 });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  return JSON.parse(result.stdout) as unknown[];
};

test('two language implementations agree on 1000 generated 0.2 authorization cases', () => {
  const samples = fc.sample(fc.record({ user: fc.constantFrom(...LEVELS), agent: fc.constantFrom(...LEVELS),
    resource: fc.constantFrom(...LEVELS), active: fc.boolean(), role: fc.boolean(), project: fc.boolean(),
    expired: fc.boolean(), otherTenant: fc.boolean(), revokedSource: fc.boolean(), sourceVersion: fc.integer({ min: 1, max: 2 }) }),
    { seed: 20260928, numRuns: 1000 });
  const cases: { state: State; request: PolicyInput }[] = samples.map(sample => {
    const state = fixture(now);
    state.actors.chief!.clearance = sample.user; state.actors['chief-agent']!.clearance = sample.agent;
    state.actors.chief!.active = sample.active;
    state.knowledge.strategy!.classification = sample.resource;
    if (!sample.role) state.actors.chief!.roles = ['staff'];
    if (!sample.project) state.knowledge.strategy!.projects = ['missing-project'];
    if (sample.expired) state.grants['chief-run']!.expiresAt = now;
    if (sample.otherTenant) state.knowledge.strategy!.tenant = 'other';
    state.knowledge.strategy!.sources = [{ id: 'handbook', version: sample.sourceVersion }];
    state.knowledge.handbook!.active = !sample.revokedSource;
    return { state, request: { binding: bindings.chief, action: 'read', resource: 'strategy', purpose: 'work', now } };
  });
  // Include unequivocal positive controls: all-deny agreement is insufficient.
  cases.push({ state: fixture(now), request: { binding: bindings.chief, action: 'read', resource: 'strategy', purpose: 'work', now } });
  const expected = cases.map(c => decide(c.state, c.request));
  assert.ok(expected.some(d => d.effect === 'allow'));
  assert.ok(expected.some(d => d.effect === 'deny'));
  assert.deepEqual(python(cases), expected);
});

test('two language implementations agree on 1500 generated hierarchy, SoD and container cases', () => {
  const roleSets = [['staff', 'executive'], ['board'], ['staff'], ['board', 'requester', 'approver'], ['executive', 'project', 'auditor-role'], ['auditor-role', 'executive']];
  const samples = fc.sample(fc.record({
    roles: fc.constantFrom(...roleSets), agentRoles: fc.constantFrom(...roleSets),
    boardActive: fc.boolean(), cycle: fc.boolean(), crossTenantRole: fc.boolean(),
    group: fc.constantFrom('none', 'active', 'inactive', 'other-tenant'), groupRoles: fc.constantFrom(['board'], ['approver'], ['project']),
    activeRoles: fc.option(fc.subarray(['staff', 'executive', 'board', 'project', 'auditor-role', 'missing']), { nil: undefined }),
    parentActive: fc.option(fc.subarray(['staff', 'executive', 'board']), { nil: undefined }), useChild: fc.boolean(),
    resource: fc.constantFrom('strategy', 'board-notes', 'vault-memo', 'staff-faq', 'handbook'),
    container: fc.constantFrom('keep', 'none', 'kb-corporate', 'f-executive', 'f-vault', 'missing'),
    folderActive: fc.boolean(), folderLevel: fc.constantFrom(...LEVELS), folderRoles: fc.constantFrom(['executive'], ['staff'], []),
    folderReader: fc.boolean(), folderCycle: fc.boolean(), folderOtherTenant: fc.boolean(), folderProject: fc.boolean(),
    origin: fc.constantFrom<Origin | 'bogus' | undefined>('system', 'human', 'model', 'bogus', undefined),
    sourceInFolder: fc.boolean(), clearance: fc.constantFrom(...LEVELS), sodCardinality: fc.integer({ min: 1, max: 3 })
  }), { seed: 20260929, numRuns: 1500 });
  const cases: { state: State; request: PolicyInput }[] = samples.map(x => {
    const s = kbFixture(now);
    s.actors.chief!.roles = [...x.roles]; s.actors['chief-agent']!.roles = [...x.agentRoles];
    s.actors['chief-agent']!.clearance = x.clearance;
    s.roles.board!.active = x.boardActive;
    if (x.cycle) s.roles.staff!.inherits = ['board'];
    if (x.crossTenantRole) s.roles.executive!.tenant = 'other';
    if (x.group !== 'none') s.groups.leadership = { id: 'leadership', tenant: x.group === 'other-tenant' ? 'other' : 'acme',
      members: ['chief', 'chief-agent'], roles: [...x.groupRoles], active: x.group !== 'inactive' };
    s.constraints['ssd-payments']!.cardinality = x.sodCardinality;
    let grant = 'chief-run';
    if (x.parentActive) s.grants['chief-run']!.activeRoles = [...x.parentActive];
    if (x.useChild) {
      grant = 'chief-child';
      s.grants[grant] = { ...structuredClone(s.grants['chief-run']!), id: grant, parent: 'chief-run', actions: ['read'] };
      delete s.grants[grant]!.activeRoles;
    }
    if (x.activeRoles) s.grants[grant]!.activeRoles = [...x.activeRoles];
    const folder = s.containers['f-executive']!;
    folder.active = x.folderActive; folder.classification = x.folderLevel; folder.readerRoles = [...x.folderRoles];
    folder.readers = x.folderReader ? ['chief', 'chief-agent'] : [];
    if (x.folderProject) folder.projects = ['alpha'];
    if (x.folderCycle) folder.parent = 'f-vault';
    if (x.folderOtherTenant) folder.tenant = 'other';
    const target = s.knowledge[x.resource]!;
    if (x.container === 'none') delete target.container; else if (x.container !== 'keep') target.container = x.container;
    if (x.origin === undefined) delete (target as Partial<typeof target>).origin; else target.origin = x.origin as Origin;
    if (x.sourceInFolder && x.resource !== 'board-notes') target.sources = [{ id: 'board-notes', version: 1 }];
    return { state: s, request: { binding: { ...bindings.chief, grant }, action: 'read', resource: x.resource, purpose: 'work', now } };
  });
  const expected = cases.map(c => decide(c.state, c.request));
  const codes = new Set(expected.map(d => d.code));
  for (const code of ['AUTHORIZED', 'KNOWLEDGE_BOUNDARY', 'SOD_VIOLATION', 'INVALID_CONTEXT', 'INVALID_DELEGATION']) assert.ok(codes.has(code), `generator never produced ${code}`);
  assert.deepEqual(python(cases), expected);
});

test('the Python evaluator reproduces every portable decision vector', () => {
  const cases = vectorCases();
  assert.deepEqual(python(cases.map(({ state, request }) => ({ state, request }))), cases.map(c => decide(c.state, c.request)));
});

test('reducing clearance never creates an authorization', () => {
  fc.assert(fc.property(fc.integer({ min: 0, max: 3 }), fc.integer({ min: 0, max: 3 }), (initial, lower) => {
    const state = fixture(now);
    state.knowledge.strategy!.classification = LEVELS[initial]!;
    const request: PolicyInput = { binding: bindings.chief, action: 'read', resource: 'strategy', purpose: 'work', now };
    state.actors.chief!.clearance = LEVELS[lower]!;
    const before = decide(state, request).effect;
    state.actors.chief!.clearance = LEVELS[Math.max(0, lower - 1)]!;
    if (before === 'deny') assert.equal(decide(state, request).effect, 'deny');
  }), { seed: 20260928, numRuns: 500 });
});
