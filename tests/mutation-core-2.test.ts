// Second pass over the survivors of the first full mutation run: boundaries of the 0.6 identity rules (risk caps,
// heartbeat-bound and break-glass grants), malformed configuration, ordering and load behaviour. See
// docs/CONFORMANCE-COVERAGE.md; tests/mutation-core.test.ts holds the first pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import { bindings, kbFixture } from '../examples/fixture.ts';
import { canDelegate, decide, destinationGate, effectiveRoles, ephemeralLive, lineageLive, riskLimit, transitiveClassification, validGrantChain, visible } from '../reference/policy.ts';
import { lineage, LIFECYCLE, materialize, retentionDue, tombstone } from '../reference/lifecycle.ts';
import { FINDINGS_LIMIT, merge, unenforceableOf, validFindings, validObligation } from '../reference/decision.ts';
import { BREAK_GLASS, HEARTBEAT, LEVELS } from '../reference/types.ts';
import type { Destination, Grant, Knowledge, State, Tx } from '../reference/types.ts';

const NOW = 1800000000000;
const world = (change?: (s: State) => void) => { const s = kbFixture(NOW); change?.(s); return s; };
const doc = (id: string, sources: { id: string; version: number }[] = [], extra: Partial<Knowledge> = {}): Knowledge =>
  ({ id, tenant: 'acme', version: 1, kind: 'document', origin: 'system', content: 'c', classification: 'public', readerRoles: ['staff'], projects: [], readers: [], sources, active: true, ...extra });
const ref = (id: string, version = 1) => ({ id, version });
const complete = (knowledge: Record<string, Knowledge>): Tx => ({ complete: true, state: { knowledge } as State, load: async () => {} }) as unknown as Tx;

const read = (s: State, over: Record<string, unknown> = {}) => decide(s, { binding: bindings.chief, resource: 'strategy', action: 'read', purpose: 'work', now: NOW, ...over } as never);
const ok = { effect: 'allow', code: 'AUTHORIZED' };
const rejected = (code: string) => ({ effect: 'deny', code, category: 'deny' });
const signal = (over: Record<string, unknown> = {}) => ({ id: 's1', tenant: 'acme', principal: 'chief', level: 'high', source: 'sec', issuedAt: NOW - 10, expiresAt: NOW + 1000, ...over }) as never;
const withSignals = (signals: unknown[], settings?: unknown) => world((w) => {
  w.riskSignals = Object.fromEntries(signals.map((x, i) => [`s${i}`, x])) as never;
  if (settings !== undefined) w.settings = { acme: settings } as never;
});
const kid = (over: Partial<Grant> = {}): Grant => ({ id: 'chief-child', tenant: 'acme', subject: 'chief', agent: 'chief-agent', actions: ['read'], resources: ['*'], purposes: ['work'],
  notBefore: NOW - 1000, expiresAt: NOW + 3600000, active: true, parent: 'chief-run', ...over });
const asKid = { ...bindings.chief, grant: 'chief-child' };

test('riskLimit: the highest live signal of the principal selects the cap, and a higher risk never widens', () => {
  const chief = { id: 'chief', tenant: 'acme' };
  const cap = (s: State, at = NOW) => riskLimit(s, chief, at);
  assert.equal(cap(world()), LEVELS.length - 1, 'no signals: the clearance is not capped');
  for (const [level, limit] of [['none', 3], ['low', 3], ['medium', 2], ['high', 1], ['critical', -1]] as const) assert.equal(cap(withSignals([signal({ level })])), limit, level);
  assert.equal(cap(withSignals([signal({ level: 'medium' }), signal({ id: 's2', level: 'high' }), signal({ id: 's3', level: 'low' })])), 1, 'the highest level counts');
  assert.equal(cap(withSignals([signal({ principal: 'lead', level: 'critical' })])), 3, 'the signal of another principal does not apply');
  assert.equal(cap(withSignals([signal({ tenant: 'other', level: 'critical' })])), 3, 'nor does one of another tenant');
  assert.equal(cap(withSignals([signal({ principal: 'lead', level: 'extreme' })])), 3, 'a malformed signal of another principal is not read');
  assert.equal(cap(withSignals([signal({ expiresAt: NOW })])), 3, 'a signal is live only before it expires');
  assert.equal(cap(withSignals([signal({ expiresAt: NOW + 1 })])), 1);
  assert.equal(cap(withSignals([signal({ expiresAt: NOW })]), NOW - 1), 1);
  const caps = (riskCaps: unknown, level = 'high') => withSignals([signal({ level })], { id: 'acme', tenant: 'acme', riskCaps });
  assert.equal(cap(caps({ medium: 'public' }, 'medium')), 0, 'a tenant may lower a cap');
  assert.equal(cap(caps({ high: 'restricted' })), 2, 'but never above the cap of a lower level (medium: confidential)');
  assert.equal(cap(caps({ low: 'public' })), 0, 'a lower level caps the higher one');
  assert.equal(cap(caps({ medium: 'deny' }, 'medium')), -1);
  assert.equal(cap(caps({ critical: 'restricted' }, 'critical')), -1, 'critical always denies');
  assert.equal(cap(withSignals([signal()], { id: 'other', tenant: 'other', riskCaps: { high: 'public' } })), 1, 'settings of another tenant do not apply');
  assert.equal(cap(withSignals([signal()], { id: 'acme', tenant: 'other', riskCaps: { high: 'public' } })), 1);
  assert.equal(cap(caps({ none: 'public' }, 'none')), 3, 'level none is no signal');
  for (const bad of [{ level: 'extreme' }, { expiresAt: 'soon' }, { expiresAt: -1 }, { expiresAt: 1.5 }]) assert.throws(() => cap(withSignals([signal(bad)])), /risk/, JSON.stringify(bad));
  for (const malformed of [[], null, 'restricted', { high: 'secret' }]) assert.throws(() => cap(caps(malformed)), /risk/, JSON.stringify(malformed));
  assert.doesNotThrow(() => cap(withSignals([], { id: 'acme', tenant: 'acme', riskCaps: [] })), 'malformed caps are read only when a signal applies');
});

test('risk caps in decide(): a cap lowers the clearance of the user or the agent, and only a cap can be the reason', () => {
  const at = (level: string, principal = 'chief', settings?: unknown) => withSignals([signal({ level, principal })], settings);
  assert.deepEqual(read(at('high'), { resource: 'handbook' }), ok);
  assert.deepEqual(read(at('high')), rejected('RISK_CAP'), 'restricted material above the cap of the risk level');
  assert.deepEqual(read(at('high', 'chief-agent')), rejected('RISK_CAP'), 'the agent is capped as well');
  assert.deepEqual(read(at('critical')), rejected('RISK_CAP'));
  assert.deepEqual(read(at('critical', 'chief-agent'), { resource: 'handbook' }), rejected('RISK_CAP'), 'critical denies everything, for the user or for the agent alone');
  assert.deepEqual(read(at('critical'), { resource: 'handbook' }), rejected('RISK_CAP'));
  const publicOnly = { id: 'acme', tenant: 'acme', riskCaps: { high: 'public' } };
  assert.deepEqual(read(at('high', 'chief', publicOnly), { resource: 'handbook' }), ok, 'a cap of public still reads public material');
  assert.deepEqual(read(at('high', 'chief', publicOnly), { resource: 'project-alpha' }), rejected('RISK_CAP'));
  assert.deepEqual(read(at('high', 'chief-agent', publicOnly), { resource: 'handbook' }), ok);
  assert.deepEqual(read(at('low')), ok, 'a low risk keeps the full clearance');
  assert.deepEqual(read(withSignals([signal({ level: 'high', principal: 'intern' })])), ok, 'the signal of another principal is not this one');
  assert.deepEqual(read(at('high', 'intern'), { binding: bindings.intern }), rejected('KNOWLEDGE_BOUNDARY'), 'a denial that the cap did not cause keeps its own reason');
  assert.deepEqual(read(world(), { binding: bindings.intern }), rejected('KNOWLEDGE_BOUNDARY'));
  const broken = withSignals([signal({ level: 'extreme' })]);
  assert.deepEqual(read(broken), { effect: 'deny', code: 'INVALID_CONTEXT', category: 'defer' }, 'a malformed signal defers');
  assert.equal(visible(broken, broken.actors.chief!, broken.knowledge.handbook!, NOW), false, 'and never admits when read directly');
});

test('visible: an inactive or foreign actor and an unresolved role set admit nothing', () => {
  const s = world();
  const handbook = s.knowledge.handbook!;
  assert.equal(visible(s, s.actors.chief!, handbook, NOW), true);
  assert.equal(visible(s, { ...s.actors.chief!, active: false }, handbook, NOW), false);
  assert.equal(visible(s, s.actors.outsider!, handbook, NOW), false, 'another tenant');
  assert.equal(visible(s, { ...s.actors.chief!, tenant: 'other' }, handbook, NOW), false);
  assert.equal(visible(s, { ...s.actors.chief!, clearance: 'secret' as never }, handbook, NOW), false);
  const violating = world((w) => { w.actors.chief!.roles = ['requester', 'approver']; });
  assert.equal(visible(violating, violating.actors.chief!, violating.knowledge.handbook!, NOW), false, 'a static violation leaves no standing roles');
  assert.equal(visible(s, s.actors.chief!, { ...handbook, sources: 'x' as never }, NOW), false);
});

test('heartbeat-bound grants are valid only inside their TTL bounds and while the heartbeat is fresh', () => {
  const grant = (over: Partial<Grant>) => world((w) => { Object.assign(w.grants['chief-run']!, over); });
  const H = HEARTBEAT;
  assert.deepEqual(read(grant({})), ok, 'no TTL, no condition');
  assert.deepEqual(read(grant({ heartbeatTtlMs: H.minTtlMs, lastHeartbeatAt: NOW - H.minTtlMs + 1 })), ok);
  assert.deepEqual(read(grant({ heartbeatTtlMs: H.minTtlMs, lastHeartbeatAt: NOW - H.minTtlMs })), rejected('INVALID_DELEGATION'), 'the heartbeat must be younger than the TTL');
  assert.deepEqual(read(grant({ heartbeatTtlMs: H.minTtlMs - 1, lastHeartbeatAt: NOW })), rejected('INVALID_DELEGATION'), 'below the smallest TTL');
  assert.deepEqual(read(grant({ heartbeatTtlMs: H.maxTtlMs, lastHeartbeatAt: NOW })), ok);
  assert.deepEqual(read(grant({ heartbeatTtlMs: H.maxTtlMs + 1, lastHeartbeatAt: NOW })), rejected('INVALID_DELEGATION'), 'above the largest TTL');
  assert.deepEqual(read(grant({ heartbeatTtlMs: 5000.5, lastHeartbeatAt: NOW })), rejected('INVALID_DELEGATION'));
  assert.deepEqual(read(grant({ heartbeatTtlMs: 5000 })), rejected('INVALID_DELEGATION'), 'a bound run that never reported');
  assert.deepEqual(read(grant({ heartbeatTtlMs: 5000, lastHeartbeatAt: NOW + 1 })), rejected('INVALID_DELEGATION'), 'a heartbeat from the future');
  assert.deepEqual(read(grant({ heartbeatTtlMs: 5000, lastHeartbeatAt: NOW })), ok);
  assert.deepEqual(read(grant({ heartbeatTtlMs: 5000, lastHeartbeatAt: 1.5 })), rejected('INVALID_DELEGATION'));
  // a child of a bound parent needs a TTL of its own that is no longer than the parent's
  const child = (parent: Partial<Grant>, own: Partial<Grant>) => world((w) => { Object.assign(w.grants['chief-run']!, parent); w.grants['chief-child'] = kid(own); });
  const beat = (heartbeatTtlMs: number, lastHeartbeatAt = NOW) => ({ heartbeatTtlMs, lastHeartbeatAt });
  const asChild = (s: State) => read(s, { binding: asKid });
  assert.deepEqual(asChild(child(beat(5000), beat(5000))), ok, 'the same TTL');
  assert.deepEqual(asChild(child(beat(5000), beat(4000))), ok, 'a shorter TTL');
  assert.deepEqual(asChild(child(beat(5000), beat(5001))), rejected('INVALID_DELEGATION'), 'a longer one');
  assert.deepEqual(asChild(child(beat(5000), {})), rejected('INVALID_DELEGATION'), 'none at all');
  assert.deepEqual(asChild(child({}, beat(5000))), ok, 'a bound child of an unbound parent');
  assert.deepEqual(asChild(child(beat(5000, NOW - 5000), beat(4000))), rejected('INVALID_DELEGATION'), 'a lapsed parent invalidates its descendants');
});

test('break-glass grants: read only, named resources, a bounded lifetime and never delegated', () => {
  const B = BREAK_GLASS;
  const glass = (over: Partial<Grant>) => world((w) => { Object.assign(w.grants['chief-run']!, { breakGlass: true, actions: ['read'], resources: ['strategy'], ...over }); });
  assert.deepEqual(read(glass({})), ok);
  const names = (n: number) => ['strategy', ...Array.from({ length: n - 1 }, (_, i) => `named-${i}`)];
  assert.deepEqual(read(glass({ resources: names(B.resources) })), ok, 'the largest set of named resources');
  assert.deepEqual(read(glass({ resources: names(B.resources + 1) })), rejected('INVALID_DELEGATION'));
  assert.deepEqual(read(glass({ resources: ['strategy', 'bad id'] })), rejected('INVALID_DELEGATION'), 'every name must be an identifier');
  assert.deepEqual(read(glass({ resources: [] })), rejected('INVALID_DELEGATION'));
  assert.deepEqual(read(glass({ resources: '*' as never })), rejected('INVALID_DELEGATION'));
  assert.deepEqual(read(glass({ resources: ['*'] })), rejected('INVALID_DELEGATION'), 'a wildcard is not a name');
  assert.deepEqual(read(glass({ actions: ['read', 'derive'] })), rejected('INVALID_DELEGATION'));
  assert.deepEqual(read(glass({ actions: ['derive'] }), { action: 'derive' }), rejected('INVALID_DELEGATION'), 'read is the only action');
  assert.deepEqual(read(glass({ breakGlass: false as never })), rejected('INVALID_DELEGATION'), 'the flag is exactly true or absent');
  assert.deepEqual(read(glass({ notBefore: NOW - 1000, expiresAt: NOW - 1000 + B.maxTtlMs })), ok, 'a lifetime of exactly the maximum');
  assert.deepEqual(read(glass({ notBefore: NOW - 1000, expiresAt: NOW - 1000 + B.maxTtlMs + 1 })), rejected('INVALID_DELEGATION'));
  const delegated = world((w) => { Object.assign(w.grants['chief-run']!, { breakGlass: true, actions: ['read'], resources: ['strategy'] }); w.grants['chief-child'] = kid({ resources: ['strategy'] }); });
  assert.deepEqual(read(delegated, { binding: asKid }), rejected('INVALID_DELEGATION'), 'never delegated');
  const flagged = world((w) => { w.grants['chief-child'] = kid({ resources: ['strategy'], breakGlass: true }); });
  assert.deepEqual(read(flagged, { binding: asKid }), rejected('INVALID_DELEGATION'), 'a break-glass grant cannot have a parent');
  // it lifts the audience clauses, never the clearance
  const outside = (grant: Partial<Grant>) => world((w) => { Object.assign(w.grants['intern-run']!, grant); w.knowledge.handbook!.readerRoles = ['nobody']; });
  assert.deepEqual(read(outside({}), { binding: bindings.intern, resource: 'handbook' }), rejected('KNOWLEDGE_BOUNDARY'));
  assert.deepEqual(read(outside({ breakGlass: true, actions: ['read'], resources: ['handbook'] }), { binding: bindings.intern, resource: 'handbook' }), ok, 'named material outside the audience');
  const above = world((w) => { Object.assign(w.grants['intern-run']!, { breakGlass: true, actions: ['read'], resources: ['strategy'] }); });
  assert.deepEqual(read(above, { binding: bindings.intern }), rejected('KNOWLEDGE_BOUNDARY'), 'clearance still applies');
});

test('canDelegate needs the parent named by the child, and a destination list is checked as a whole', () => {
  const s = world((w) => { w.grants.second = { ...w.grants['chief-run']!, id: 'second' }; });
  const child = { id: 'kid', tenant: 'acme', subject: 'chief', agent: 'chief-agent', actions: ['read'], resources: ['handbook'], purposes: ['work'], notBefore: s.grants['chief-run']!.notBefore, expiresAt: s.grants['chief-run']!.expiresAt, active: true } as Grant;
  assert.equal(canDelegate(s, s.grants['chief-run']!, { ...child, parent: 'chief-run' }, NOW), true);
  assert.equal(canDelegate(s, s.grants['chief-run']!, { ...child, parent: 'second' }, NOW), false, 'a valid grant that is not the parent');
  const dest: Destination = { id: 'llm-eu', tenant: 'acme', class: 'model-provider', maxClassification: 'confidential', purposes: ['work'], active: true };
  const gated = world((w) => { w.destinations = { 'llm-eu': dest }; });
  const restricted = (destinations: string[]) => ({ ...gated.grants['chief-run']!, destinations }) as Grant;
  assert.deepEqual(destinationGate(gated, restricted(['internal-user', 'internal-user']), { kind: 'implicit-user' }, 'acme', 'public', 'work'), { ok: false }, 'a list with a duplicate is malformed');
  assert.deepEqual(destinationGate(gated, restricted(['internal-user', 'bad id']), { kind: 'implicit-user' }, 'acme', 'public', 'work'), { ok: false });
  assert.deepEqual(destinationGate(gated, restricted(['llm-eu', 'llm-eu']), { kind: 'profile', id: 'llm-eu' }, 'acme', 'public', 'work'), { ok: false });
});

test('tombstone and lineage: an empty live record is still erased fully; ordering, bounds and loads are exact', async () => {
  const empty = doc('e', [], { content: '', readers: ['chief'], readerRoles: ['staff'] });
  assert.equal(tombstone(empty, 42), true);
  assert.deepEqual([empty.active, empty.lifecycle, empty.lifecycleAt, empty.readers, empty.readerRoles], [false, 'erased', 42, [], []], 'an empty record that is not erased yet becomes a tombstone');
  const unsorted = complete({ r: doc('r'), z: doc('z', [ref('r')]), a: doc('a', [ref('r')]), m: doc('m', [ref('r')]), q: doc('q', [ref('r')]) });
  assert.deepEqual((await lineage(unsorted, 'acme', ['r'], 10)).records.map(k => k.id), ['a', 'm', 'q', 'z']);
  const partial = { complete: false, state: {} as State, load: async () => {}, descendants: async () => ({ records: [doc('z'), doc('a'), doc('m'), doc('q')], truncated: false }) } as unknown as Tx;
  assert.deepEqual((await lineage(partial, 'acme', ['r'], 10)).records.map(k => k.id), ['a', 'm', 'q', 'z']);
  await assert.rejects(() => lineage(unsorted, 'acme', ['r', 'bad id'], 10), /Invalid lineage request/, 'every root must be an identifier');
  const fan = (n: number) => complete({ r: doc('r'), ...Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, doc(`k${i}`, [ref('r')])])) });
  const rows = await lineage(fan(LIFECYCLE.rows), 'acme', ['r'], 100000);
  assert.equal(rows.truncated, false, 'exactly the row bound is not truncation');
  assert.equal(rows.records.length, LIFECYCLE.rows);
  assert.equal((await lineage(fan(LIFECYCLE.rows + 1), 'acme', ['r'], 100000)).truncated, true);
  const loads: unknown[] = [];
  await materialize({ complete: true, state: {} as State, load: async (n: unknown) => { loads.push(n); } } as unknown as Tx, ['a', 'b']);
  assert.deepEqual(loads, [], 'a complete snapshot loads nothing');
  const shuffled = complete({ d: doc('d', [], { retainUntil: 1 }), b: doc('b', [], { retainUntil: 1 }), c: doc('c', [], { retainUntil: 1 }), a: doc('a', [], { retainUntil: 1 }) });
  assert.deepEqual(await retentionDue(shuffled, 'acme', NOW, '', 3), ['a', 'b', 'c'], 'id order, then the batch bound');
});

test('obligations: release filters, findings and unenforceable lists are validated and merged exactly', () => {
  const filters = (...value: unknown[]) => ({ type: 'release_filter', value }) as never;
  assert.equal(validObligation(filters('f', 'bad id')), false);
  assert.equal(validObligation({ type: 'release_filter', value: 'f' } as never), false);
  assert.equal(validObligation(filters('f', 'g')), true);
  assert.deepEqual(merge([{ type: 'release_filter', value: ['b', 'c'] }], [{ type: 'release_filter', value: ['a', 'c'] }]), [{ type: 'release_filter', value: ['a', 'b', 'c'] }], 'the union, sorted');
  assert.deepEqual(merge([{ type: 'release_filter', value: ['z', 'a', 'm'] }]), [{ type: 'release_filter', value: ['a', 'm', 'z'] }]);
  assert.equal(validFindings([]), true);
  assert.equal(validFindings(['a.b:c-d_e']), true);
  assert.equal(validFindings(Array.from({ length: FINDINGS_LIMIT }, () => 'f')), true);
  assert.equal(validFindings(Array.from({ length: FINDINGS_LIMIT + 1 }, () => 'f')), false);
  assert.equal(validFindings(['ok', 'not ok']), false);
  assert.equal(validFindings(['ok', 7 as never]), false);
  assert.equal(validFindings(['']), false);
  assert.equal(validFindings(['x'.repeat(128)]), true);
  assert.equal(validFindings(['x'.repeat(129)]), false);
  assert.equal(validFindings(['ok\nx']), false, 'the pattern is anchored at both ends');
  assert.equal(validFindings([' ok']), false);
  assert.equal(validFindings('ok' as never), false);
  const holes = ['a'] as string[]; holes[2] = 'b';
  assert.equal(validFindings(holes), false);
  assert.deepEqual(unenforceableOf(undefined), []);
  assert.deepEqual(unenforceableOf({}), []);
  assert.deepEqual(unenforceableOf({ unenforceable: [] }), []);
  assert.deepEqual(unenforceableOf({ unenforceable: ['runtime_profile'] }), ['runtime_profile']);
  assert.deepEqual(unenforceableOf({ unenforceable: ['runtime_profile', 'no_persist'] }), ['runtime_profile', 'no_persist']);
  assert.equal(unenforceableOf({ unenforceable: ['runtime_profile', 'bogus'] as never }), null, 'every entry must be a known type');
  assert.equal(unenforceableOf({ unenforceable: 'runtime_profile' as never }), null);
});

test('every traversal fails closed with the exact failure value when the snapshot itself misbehaves', () => {
  const boom = (state: State, key: string) => Object.defineProperty(state, key, { get() { throw new Error('unreadable'); } });
  // a snapshot whose records cannot be read: null and false, never undefined
  const unreadable = (key: string) => boom(world(), key);
  const chief = world().actors.chief!;
  assert.equal(effectiveRoles(unreadable('groups'), chief), null, 'groups that cannot be read');
  assert.equal(effectiveRoles(world((w) => { w.groups.g = { id: 'g', tenant: 'acme', members: 'chief' as never, roles: [], active: true }; }), chief), null, 'a group with malformed members');
  const cyclic = world((w) => { w.roles.a = { id: 'a', tenant: 'acme', inherits: ['b'], active: true }; w.roles.b = { id: 'b', tenant: 'acme', inherits: ['a'], active: true }; });
  assert.equal(effectiveRoles(cyclic, { ...cyclic.actors.chief!, roles: ['a'] }), null, 'a cycle of roles');
  assert.equal(effectiveRoles(world(), { ...chief, roles: 'x' as never }), null);
  assert.equal(effectiveRoles(world((w) => { w.roles.a = { id: 'a', tenant: 'acme', inherits: 'b' as never, active: true }; }), { ...chief, roles: ['a'] }), null, 'juniors that are not a list');
  assert.equal(visible(unreadable('knowledge'), chief, doc('x', [ref('handbook')]), NOW), false, 'a source that cannot be read');
  assert.equal(visible(world(), chief, { ...world().knowledge.handbook!, sources: 5 as never }, NOW), false, 'sources that cannot be iterated');
  const hidden = world();
  assert.equal(lineageLive(unreadable('knowledge'), doc('x', [ref('handbook')]), NOW), false);
  assert.equal(lineageLive(hidden, hidden.knowledge.handbook!, NOW), true);
  assert.equal(transitiveClassification(unreadable('knowledge'), doc('x', [ref('handbook')])), null);
  const gated = world();
  Object.defineProperty(gated, 'destinations', { get() { throw new Error('unreadable'); } });
  assert.deepEqual(destinationGate(gated, world().grants['chief-run']!, { kind: 'profile', id: 'llm-eu' }, 'acme', 'public', 'work'), { ok: false }, 'an unreadable destination set denies');
  assert.equal(validGrantChain(unreadable('actors'), world().grants['chief-run']!, NOW), false);
});

test('ephemeralLive: a session-scoped record is live while well formed, before its expiry and for its own run', () => {
  const rec = (over: Record<string, unknown> = {}) => ({ ephemeral: { sessionId: 's1', run: 'run-1', expiresAt: NOW + 1, ...over } }) as never;
  assert.equal(ephemeralLive({} as never, NOW), true, 'a record without the member is unaffected');
  assert.equal(ephemeralLive({ ephemeral: undefined } as never, NOW, 'run-9'), true);
  assert.equal(ephemeralLive(rec(), NOW), true);
  assert.equal(ephemeralLive(rec(), NOW + 1), false, 'expiry is exclusive');
  assert.equal(ephemeralLive(rec(), NOW, 'run-1'), true);
  assert.equal(ephemeralLive(rec(), NOW, 'run-2'), false, 'only for the run that wrote it');
  for (const [name, over] of [['extra member', { note: 'x' }], ['bad session id', { sessionId: 'bad id' }], ['empty session id', { sessionId: '' }], ['bad run id', { run: 'bad id' }],
    ['missing run', { run: undefined }], ['negative expiry', { expiresAt: -1 }], ['fractional expiry', { expiresAt: 1.5 }], ['text expiry', { expiresAt: 'soon' }]] as const) {
    const record = rec(over) as { ephemeral: Record<string, unknown> };
    if (over && 'run' in over && over.run === undefined) delete record.ephemeral.run;
    assert.equal(ephemeralLive(record as never, NOW), false, name);
  }
  const missingSession = rec() as { ephemeral: Record<string, unknown> }; delete missingSession.ephemeral.sessionId;
  assert.equal(ephemeralLive(missingSession as never, NOW), false, 'missing session id');
  const missingExpiry = rec() as { ephemeral: Record<string, unknown> }; delete missingExpiry.ephemeral.expiresAt;
  assert.equal(ephemeralLive(missingExpiry as never, NOW), false, 'missing expiry');
  assert.equal(ephemeralLive(rec(), -1), false, 'a clock that is not a safe non-negative integer');
  assert.equal(ephemeralLive(rec(), 1.5), false);
  assert.equal(ephemeralLive({ ephemeral: 'x' } as never, NOW), false);
  assert.equal(ephemeralLive({ ephemeral: null } as never, NOW), false);
});

test('riskLimit skips a null signal entry instead of failing on it', () => {
  const s = world((w) => { w.riskSignals = { gone: null as never, mine: signal({ level: 'high' }) } as never; });
  assert.equal(riskLimit(s, { id: 'chief', tenant: 'acme' }, NOW), 1);
  assert.equal(riskLimit(s, { id: 'lead', tenant: 'acme' }, NOW), LEVELS.length - 1, 'a null entry and the signal of another principal leave the cap alone');
});

test('an unreadable record (R195) is neither visible nor live, alone or as a source', () => {
  const s = world((w) => { w.knowledge.sealed = doc('sealed', [], { unreadable: true }); w.knowledge.viaSealed = doc('viaSealed', [ref('sealed')]); });
  assert.equal(visible(s, s.actors.chief!, s.knowledge.sealed!, NOW), false);
  assert.equal(visible(s, s.actors.chief!, s.knowledge.viaSealed!, NOW), false);
  assert.equal(lineageLive(s, s.knowledge.sealed!, NOW), false);
  assert.equal(lineageLive(s, s.knowledge.viaSealed!, NOW), false);
  assert.equal(lineageLive(s, s.knowledge.handbook!, NOW), true);
});
