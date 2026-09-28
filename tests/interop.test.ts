import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fc from 'fast-check';
import { decide } from '../reference/policy.ts';
import { fixture, bindings } from '../examples/fixture.ts';
import { LEVELS } from '../reference/types.ts';
import type { PolicyInput, State } from '../reference/types.ts';

test('two language implementations agree on 1000 generated authorization cases', () => {
  const samples = fc.sample(fc.record({ user: fc.constantFrom(...LEVELS), agent: fc.constantFrom(...LEVELS),
    resource: fc.constantFrom(...LEVELS), active: fc.boolean(), role: fc.boolean(), project: fc.boolean(),
    expired: fc.boolean(), otherTenant: fc.boolean(), revokedSource: fc.boolean(), sourceVersion: fc.integer({ min: 1, max: 2 }) }),
    { seed: 20260928, numRuns: 1000 });
  const cases: { state: State; request: PolicyInput }[] = samples.map(sample => {
    const now = 1800000000000, state = fixture(now);
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
  cases.push({ state: fixture(1800000000000), request: { binding: bindings.chief, action: 'read', resource: 'strategy', purpose: 'work', now: 1800000000000 } });
  const result = spawnSync('python3', ['implementations/python/akac.py'], { input: JSON.stringify({ cases }), encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, timeout: 20000 });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  const expected = cases.map(c => decide(c.state, c.request));
  assert.ok(expected.some(d => d.effect === 'allow'));
  assert.ok(expected.some(d => d.effect === 'deny'));
  assert.deepEqual(JSON.parse(result.stdout), expected);
});

test('reducing clearance never creates an authorization', () => {
  fc.assert(fc.property(fc.integer({ min: 0, max: 3 }), fc.integer({ min: 0, max: 3 }), (initial, lower) => {
    const now = 1800000000000, state = fixture(now);
    state.knowledge.strategy!.classification = LEVELS[initial]!;
    const request: PolicyInput = { binding: bindings.chief, action: 'read', resource: 'strategy', purpose: 'work', now };
    state.actors.chief!.clearance = LEVELS[lower]!;
    const before = decide(state, request).effect;
    state.actors.chief!.clearance = LEVELS[Math.max(0, lower - 1)]!;
    if (before === 'deny') assert.equal(decide(state, request).effect, 'deny');
  }), { seed: 20260928, numRuns: 500 });
});
