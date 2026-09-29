// Exact-behaviour tests for the pure helpers of the decision core that no portable vector reaches through decide():
// they were written from the survivors of the mutation run (docs/CONFORMANCE-COVERAGE.md) and pin values, not just
// allow/deny, so that a changed operator, bound or literal is noticed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { bindings, kbFixture } from '../examples/fixture.ts';
import { canDelegate, containerChain, contextFresh, countSodHolders, decide, destinationGate, effectiveClearance, effectiveLabel, effectiveRoles, evaluationTargetNamed, lineageLive,
  LIMITS, principalTokens, sessionRoles, sodViolated, standingRoles, subset, targetOf, transitiveClassification, validGrantChain, visible } from '../reference/policy.ts';
import { held, lineage, lineageRecord, LIFECYCLE, materialize, retentionDue, tombstone } from '../reference/lifecycle.ts';
import { containment, containmentAcross, runtimeSetDigest, validRuntimeProfile } from '../reference/containment.ts';
import { createHash } from 'node:crypto';
import { canonicalize } from '../reference/jcs.ts';
import { classify, enforceable, executionOf, merge, parseObligations, policyDigest, runtimeRevisionOf, traceOf, unsatisfiable, validDecisionId, validObligation, validTraceId } from '../reference/decision.ts';
import type { Context, Destination, Grant, Knowledge, State, Tx } from '../reference/types.ts';

const NOW = 1800000000000;
const world = (change?: (s: State) => void) => { const s = kbFixture(NOW); change?.(s); return s; };
const doc = (id: string, sources: { id: string; version: number }[] = [], extra: Partial<Knowledge> = {}): Knowledge =>
  ({ id, tenant: 'acme', version: 1, kind: 'document', origin: 'system', content: 'c', classification: 'public', readerRoles: ['staff'], projects: [], readers: [], sources, active: true, ...extra });
const ref = (id: string, version = 1) => ({ id, version });

test('subset: a wildcard in the larger set admits anything, one in the smaller set admits nothing', () => {
  assert.equal(subset([], []), true);
  assert.equal(subset(['a'], ['a', 'b']), true);
  assert.equal(subset(['c'], ['a', 'b']), false);
  assert.equal(subset(['a', 'c'], ['a', 'b']), false);
  assert.equal(subset(['a', 'b'], ['*']), true);
  assert.equal(subset(['*'], ['a', 'b']), false);
});

test('effectiveClearance is the lower of user and agent, and null for an unknown level', () => {
  const s = world();
  const { chief, 'chief-agent': agent, intern, 'intern-agent': internAgent } = s.actors;
  assert.equal(effectiveClearance(chief!, internAgent!), 'internal');
  assert.equal(effectiveClearance(intern!, agent!), 'internal');
  assert.equal(effectiveClearance(chief!, agent!), 'restricted');
  assert.equal(effectiveClearance({ ...chief!, clearance: 'public' }, agent!), 'public', 'the lowest level is a level, not an absence');
  assert.equal(effectiveClearance({ ...chief!, clearance: 'secret' as never }, agent!), null);
  assert.equal(effectiveClearance(chief!, { ...agent!, clearance: 'secret' as never }), null);
});

test('contextFresh needs an active context of the current epoch and revision that has not expired', () => {
  const s = world();
  const c: Context = { id: 'x', tenant: 'acme', subject: 'chief', agent: 'chief-agent', grant: 'chief-run', purpose: 'work', sources: [], expiresAt: NOW + 1, policyVersion: 'rev', epoch: 0, active: true };
  assert.equal(contextFresh(s, c, NOW, 'rev'), true);
  assert.equal(contextFresh(s, { ...c, expiresAt: NOW }, NOW, 'rev'), false, 'expiry is exclusive');
  assert.equal(contextFresh(s, { ...c, active: false }, NOW, 'rev'), false);
  assert.equal(contextFresh(s, { ...c, epoch: 1 }, NOW, 'rev'), false);
  assert.equal(contextFresh(s, c, NOW, 'other'), false);
  assert.equal(contextFresh(s, { ...c, policyVersion: 'other' }, NOW, 'rev'), false);
  assert.equal(contextFresh(s, c, -1, 'rev'), false, 'a clock that is not a safe non-negative integer never validates');
  assert.equal(contextFresh(s, c, 1.5, 'rev'), false);
  s.epochs.acme = 1;
  assert.equal(contextFresh(s, { ...c, epoch: 1 }, NOW, 'rev'), true);
  assert.equal(contextFresh(s, c, NOW, 'rev'), false);
});

test('roles: closure, session roles and separation of duty give exact sets', () => {
  const s = world((w) => { w.actors.chief!.roles = ['board']; });
  assert.deepEqual([...effectiveRoles(s, s.actors.chief!)!].sort(), ['board', 'executive', 'staff']);
  assert.deepEqual([...standingRoles(s, s.actors.chief!)!].sort(), ['board', 'executive', 'staff']);
  const held = effectiveRoles(s, s.actors.chief!)!;
  const grant = (activeRoles?: unknown) => ({ ...s.grants['chief-run']!, ...(activeRoles === undefined ? {} : { activeRoles }) }) as Grant;
  assert.deepEqual([...sessionRoles(s, s.actors.chief!, held, grant())!].sort(), ['board', 'executive', 'staff']);
  assert.deepEqual([...sessionRoles(s, s.actors.chief!, held, grant(['executive']))!].sort(), ['executive', 'staff'], 'an activated role brings its juniors');
  assert.equal(sessionRoles(s, s.actors.chief!, held, grant(['executive', 'ghost'])), null, 'every activated role must be held');
  assert.equal(sessionRoles(s, s.actors.chief!, held, grant('executive')), null);
  assert.equal(sessionRoles(s, s.actors.chief!, held, grant([7])), null);
  // a group of the same tenant adds roles while it is active
  s.groups.leadership!.active = true; s.groups.leadership!.members = ['chief']; s.groups.leadership!.roles = ['requester'];
  assert.ok(effectiveRoles(s, s.actors.chief!)!.has('requester'));
  s.groups.leadership!.members = ['someone-else'];
  assert.ok(!effectiveRoles(s, s.actors.chief!)!.has('requester'));
  // separation of duty: static constraints deny the principal, dynamic ones only the session
  const roles = new Set(['requester', 'approver']);
  assert.equal(sodViolated(s, 'acme', 'static', roles), true);
  assert.equal(sodViolated(s, 'acme', 'dynamic', roles), false, 'a static constraint is not a dynamic one');
  assert.equal(sodViolated(s, 'other', 'static', roles), false, 'constraints of another tenant do not apply');
  assert.equal(sodViolated(s, 'acme', 'static', new Set(['requester'])), false);
  s.actors.chief!.roles = ['requester', 'approver'];
  assert.equal(standingRoles(s, s.actors.chief!), null, 'a static violation leaves no standing roles');
  assert.equal(effectiveRoles(s, s.actors.chief!)!.size, 2);
});

test('countSodHolders counts active same-tenant principals that meet a constraint, with an optional candidate role', () => {
  const s = world((w) => {
    w.actors.chief!.roles = ['requester', 'approver'];
    w.actors.lead!.roles = ['requester'];
    w.actors.intern!.roles = ['requester', 'approver']; w.actors.intern!.active = false;
    w.actors.outsider!.roles = ['requester', 'approver'];
  });
  const q = { constraints: [{ roles: ['requester', 'approver'], cardinality: 2 }] };
  assert.equal(countSodHolders(s, 'acme', q), 1, 'an inactive principal and another tenant do not count');
  assert.equal(countSodHolders(s, 'other', q), 1);
  assert.equal(countSodHolders(s, 'acme', { constraints: [{ roles: ['requester', 'approver'], cardinality: 3 }] }), 0);
  assert.equal(countSodHolders(s, 'acme', { constraints: [{ roles: ['requester', 'approver'], cardinality: 1 }] }), 2, 'the leads requester role and the chiefs');
  assert.equal(countSodHolders(s, 'acme', { constraints: [] }), 0);
  assert.equal(countSodHolders(s, 'acme', { constraints: [{ roles: ['approver', 'x'], cardinality: 2 }, { roles: ['requester', 'approver'], cardinality: 2 }] }), 1, 'a principal is counted once');
  // the candidate role replaces the stored one before the closure is taken
  s.actors.lead!.roles = ['staff', 'supervisor'];
  const widened = { constraints: [{ roles: ['supervisor', 'approver'], cardinality: 2 }], role: { id: 'supervisor', tenant: 'acme', inherits: ['approver'], active: true } };
  assert.equal(countSodHolders(s, 'acme', widened), 1, 'lead holds supervisor and, through the candidate role, approver; chief lacks supervisor');
  assert.equal(countSodHolders(s, 'acme', { constraints: widened.constraints }), 0);
  s.actors.chief!.roles = ['loop-a']; s.roles['loop-a'] = { id: 'loop-a', tenant: 'acme', inherits: ['loop-a'], active: true };
  assert.equal(countSodHolders(s, 'acme', q), 'unknown', 'a closure that cannot be established is unknown, not zero');
});

test('containerChain returns the ancestors nearest first, and null for anything it cannot establish', () => {
  const s = world();
  assert.deepEqual(containerChain(s, s.knowledge['vault-memo']!)!.map(c => c.id), ['f-vault', 'f-executive', 'kb-corporate']);
  assert.deepEqual(containerChain(s, s.knowledge.handbook!), []);
  assert.equal(containerChain(s, { tenant: 'acme', container: 'ghost' }), null);
  assert.equal(containerChain(s, { tenant: 'other', container: 'kb-corporate' }), null);
  s.containers['f-vault']!.id = 'other-id';
  assert.equal(containerChain(s, s.knowledge['vault-memo']!), null);
});

test('effectiveLabel is the conjunctive label: highest classification, union of projects, every audience clause', () => {
  const s = world((w) => {
    w.containers['f-executive']!.projects = ['beta', 'alpha'];
    w.containers['kb-corporate']!.projects = ['alpha'];
    w.knowledge['vault-memo']!.projects = ['gamma'];
    w.knowledge['vault-memo']!.readers = ['chief'];
  });
  const label = effectiveLabel(s, s.knowledge['vault-memo']!)!;
  assert.equal(label.classification, 'restricted', 'the folder floor above the public document');
  assert.deepEqual(label.projects, ['alpha', 'beta', 'gamma'], 'sorted union without duplicates');
  assert.deepEqual(label.containers, ['f-vault', 'f-executive', 'kb-corporate']);
  assert.deepEqual(label.audiences, [
    { readers: ['chief'], readerRoles: ['staff'] }, { readers: [], readerRoles: ['executive'] }, { readers: [], readerRoles: ['executive'] }, { readers: [], readerRoles: ['staff'] }]);
  const copy = effectiveLabel(s, s.knowledge['vault-memo']!)!;
  copy.audiences[0]!.readers.push('x'); assert.deepEqual(s.knowledge['vault-memo']!.readers, ['chief'], 'the label is a copy');
  assert.equal(effectiveLabel(s, s.knowledge.handbook!)!.classification, 'public');
  assert.deepEqual(effectiveLabel(s, s.knowledge.handbook!)!.containers, []);
  assert.equal(effectiveLabel(s, { ...s.knowledge.handbook!, origin: 'robot' as never }), null);
  assert.equal(effectiveLabel(s, { ...s.knowledge.handbook!, classification: 'secret' as never }), null);
  s.containers['f-executive']!.classification = 'secret' as never;
  assert.equal(effectiveLabel(s, s.knowledge['vault-memo']!), null, 'an unknown level anywhere in the chain');
  assert.equal(effectiveLabel(world(), { ...world().knowledge['vault-memo']!, container: 'ghost' }), null);
});

test('transitiveClassification is the highest classification over the object and every source, within the budgets', () => {
  const s = world((w) => {
    w.knowledge.a = doc('a', [ref('b'), ref('handbook')]); w.knowledge.b = doc('b', [ref('strategy')]);
  });
  assert.equal(transitiveClassification(s, s.knowledge.a!), 'restricted');
  assert.equal(transitiveClassification(s, s.knowledge.handbook!), 'public');
  assert.equal(transitiveClassification(s, s.knowledge['vault-memo']!), 'restricted', 'container floors count');
  const bad = (change: (w: State) => void) => { const w = world((x) => { x.knowledge.a = doc('a', [ref('handbook')]); }); change(w); return transitiveClassification(w, w.knowledge.a!); };
  assert.equal(bad(() => {}), 'public');
  assert.equal(bad((w) => { w.knowledge.a!.sources = [ref('ghost')]; }), null, 'a missing source');
  assert.equal(bad((w) => { w.knowledge.a!.sources = [ref('handbook', 2)]; }), null, 'a stale version');
  assert.equal(bad((w) => { w.knowledge.handbook!.tenant = 'other'; }), null, 'a source of another tenant');
  assert.equal(bad((w) => { w.knowledge.a!.sources = [ref('a')]; }), null, 'a cycle');
  assert.equal(bad((w) => { w.knowledge.a!.sources = [{ id: 'bad id', version: 1 }]; }), null);
  assert.equal(bad((w) => { w.knowledge.a!.sources = 'x' as never; }), null);
  assert.equal(bad((w) => { w.knowledge.a!.origin = 'robot' as never; }), null);
  // budgets: 4096 edges, 1024 nodes, path 128
  const edges = (n: number) => { const w = world((x) => { x.knowledge.a = doc('a', Array.from({ length: n }, () => ref('handbook'))); }); return transitiveClassification(w, w.knowledge.a!); };
  assert.equal(edges(LIMITS.edges), 'public');
  assert.equal(edges(LIMITS.edges + 1), null);
  const nodes = (n: number) => { const w = world((x) => { x.knowledge.a = doc('a', Array.from({ length: n - 1 }, (_, i) => ref(`w${i}`))); for (let i = 0; i < n - 1; i++) x.knowledge[`w${i}`] = doc(`w${i}`); }); return transitiveClassification(w, w.knowledge.a!); };
  assert.equal(nodes(LIMITS.nodes), 'public');
  assert.equal(nodes(LIMITS.nodes + 1), null);
  const chain = (n: number) => { const w = world((x) => { for (let i = 1; i <= n; i++) x.knowledge[`c${i}`] = doc(`c${i}`, i < n ? [ref(`c${i + 1}`)] : []); }); return transitiveClassification(w, w.knowledge.c1!); };
  assert.equal(chain(LIMITS.path), 'public');
  assert.equal(chain(LIMITS.path + 1), null);
});

test('principalTokens name the user, the effective roles and the projects, sorted', () => {
  const s = world((w) => { w.actors.chief!.roles = ['board']; w.actors.chief!.projects = ['zeta', 'alpha']; });
  assert.deepEqual(principalTokens(s, s.actors.chief!), ['user:chief', 'role:board', 'role:executive', 'role:staff', 'project:alpha', 'project:zeta']);
  assert.deepEqual(principalTokens(s, s.actors.chief!, ['executive']), ['user:chief', 'role:executive', 'role:staff', 'project:alpha', 'project:zeta']);
  assert.equal(principalTokens(s, s.actors.chief!, ['ghost']), null, 'an activated role must be held');
  assert.equal(principalTokens(s, s.actors.chief!, ['board', 'ghost']), null);
  s.actors.chief!.roles = ['staff', 'board'];
  assert.deepEqual(principalTokens(s, s.actors.chief!), ['user:chief', 'role:board', 'role:executive', 'role:staff', 'project:alpha', 'project:zeta'], 'sorted whatever the order of discovery');
  s.actors.chief!.roles = ['requester', 'approver'];
  assert.equal(principalTokens(s, s.actors.chief!), null, 'a static violation gives no tokens');
  s.actors.chief!.roles = ['staff']; s.actors.chief!.projects = [];
  assert.deepEqual(principalTokens(s, s.actors.chief!), ['user:chief', 'role:staff']);
  s.actors.chief!.roles = 'staff' as never;
  assert.equal(principalTokens(s, s.actors.chief!), null);
});

test('lineageLive: a record and every source are active, unrestricted by lifecycle, unexpired and resolvable, within the budgets', () => {
  const setup = (change?: (w: State) => void) => world((w) => { w.knowledge.a = doc('a', [ref('b')]); w.knowledge.b = doc('b', [ref('handbook')]); change?.(w); });
  const live = (change?: (w: State) => void, at = NOW) => { const w = setup(change); return lineageLive(w, w.knowledge.a!, at); };
  assert.equal(live(), true);
  assert.equal(live((w) => { w.knowledge.b!.active = false; }), false);
  assert.equal(live((w) => { w.knowledge.a!.active = false; }), false);
  assert.equal(live((w) => { w.knowledge.a!.lifecycle = 'quarantined'; }), false);
  assert.equal(live((w) => { w.knowledge.handbook!.lifecycle = 'erased'; }), false, 'a lifecycle state deep in the lineage');
  assert.equal(live((w) => { w.knowledge.b!.accessExpiresAt = NOW; }), false, 'expiry is at or after now');
  assert.equal(live((w) => { w.knowledge.b!.accessExpiresAt = NOW + 1; }), true);
  assert.equal(live((w) => { w.knowledge.b!.accessExpiresAt = NOW - 1; }, NOW - 5), true, 'and only from then on');
  assert.equal(live((w) => { w.knowledge.b!.accessExpiresAt = 'soon' as never; }), false);
  assert.equal(live((w) => { w.knowledge.a!.sources = [ref('ghost')]; }), false);
  assert.equal(live((w) => { w.knowledge.a!.sources = [ref('b', 2)]; }), false);
  assert.equal(live((w) => { w.knowledge.b!.tenant = 'other'; }), false);
  assert.equal(live((w) => { w.knowledge.a!.sources = [{ id: 'bad id', version: 1 }]; }), false);
  assert.equal(live((w) => { w.knowledge.a!.sources = 'x' as never; }), false);
  assert.equal(live((w) => { w.knowledge.b!.sources = [ref('a')]; }), false, 'a cycle');
  assert.equal(live(undefined, -1), false);
  assert.equal(live(undefined, 1.5), false);
  const shared = (n: number) => { const w = world((x) => { x.knowledge.a = doc('a', [ref('m'), ref('m')]); x.knowledge.m = doc('m', n > 1 ? [ref('handbook')] : []); }); return lineageLive(w, w.knowledge.a!, NOW); };
  assert.equal(shared(1), true, 'a shared source is visited once');
  const chain = (n: number) => { const w = world((x) => { for (let i = 1; i <= n; i++) x.knowledge[`c${i}`] = doc(`c${i}`, i < n ? [ref(`c${i + 1}`)] : []); }); return lineageLive(w, w.knowledge.c1!, NOW); };
  assert.equal(chain(LIMITS.path), true);
  assert.equal(chain(LIMITS.path + 1), false);
  const wide = (n: number) => { const w = world((x) => { x.knowledge.a = doc('a', Array.from({ length: n - 1 }, (_, i) => ref(`w${i}`))); for (let i = 0; i < n - 1; i++) x.knowledge[`w${i}`] = doc(`w${i}`); }); return lineageLive(w, w.knowledge.a!, NOW); };
  assert.equal(wide(LIMITS.nodes), true);
  assert.equal(wide(LIMITS.nodes + 1), false);
});

test('visible: the same traversal budgets as decide(), with an explicit role set', () => {
  const s = world((w) => { for (let i = 1; i <= LIMITS.path; i++) w.knowledge[`c${i}`] = doc(`c${i}`, i < LIMITS.path ? [ref(`c${i + 1}`)] : []); });
  assert.equal(visible(s, s.actors.chief!, s.knowledge.c1!, NOW), true);
  assert.equal(visible(s, s.actors.chief!, s.knowledge.c1!, NOW, new Set()), false, 'no roles, no audience');
  assert.equal(visible(s, s.actors.chief!, s.knowledge.c1!, NOW, new Set(['staff'])), true);
  assert.equal(visible(s, s.actors.chief!, s.knowledge.c1!, 1.5), false);
  const edges = (n: number) => { const w = world((x) => { x.knowledge.a = doc('a', Array.from({ length: n }, () => ref('handbook'))); }); return visible(w, w.actors.chief!, w.knowledge.a!, NOW); };
  assert.equal(edges(LIMITS.edges), true);
  assert.equal(edges(LIMITS.edges + 1), false);
  const wide = (n: number) => { const w = world((x) => { x.knowledge.a = doc('a', Array.from({ length: n - 1 }, (_, i) => ref(`w${i}`))); for (let i = 0; i < n - 1; i++) x.knowledge[`w${i}`] = doc(`w${i}`); }); return visible(w, w.actors.chief!, w.knowledge.a!, NOW); };
  assert.equal(wide(LIMITS.nodes), true);
  assert.equal(wide(LIMITS.nodes + 1), false);
  const cyc = world((w) => { w.knowledge.a = doc('a', [ref('b')]); w.knowledge.b = doc('b', [ref('a')]); });
  assert.equal(visible(cyc, cyc.actors.chief!, cyc.knowledge.a!, NOW), false);
});

test('canDelegate and validGrantChain accept a narrowing child of an active parent only', () => {
  const s = world();
  const parent = s.grants['chief-run']!;
  const child = (over: Partial<Grant> = {}): Grant => ({ id: 'kid', tenant: 'acme', subject: 'chief', agent: 'chief-agent', actions: ['read'], resources: ['handbook'], purposes: ['work'],
    notBefore: parent.notBefore, expiresAt: parent.expiresAt, active: true, parent: 'chief-run', ...over });
  assert.equal(canDelegate(s, parent, child(), NOW), true);
  assert.equal(validGrantChain({ ...s, grants: { ...s.grants, kid: child() } }, child(), NOW), true);
  assert.equal(canDelegate(s, parent, child({ id: 'chief-run' }), NOW), false, 'a grant cannot delegate to itself');
  assert.equal(canDelegate(s, parent, child({ parent: 'other' }), NOW), false);
  assert.equal(canDelegate(s, parent, child({ tenant: 'other' }), NOW), false);
  assert.equal(canDelegate(s, parent, child({ subject: 'lead' }), NOW), false);
  assert.equal(canDelegate(s, parent, child({ agent: 'ghost' }), NOW), false, 'the agent must exist');
  assert.equal(canDelegate(s, parent, child({ agent: 'lead' }), NOW), false, 'the delegate must be an agent');
  assert.equal(canDelegate(s, parent, child({ agent: 'chief' }), NOW), false);
  s.actors['lead-agent']!.active = false;
  assert.equal(canDelegate(s, parent, child({ agent: 'lead-agent' }), NOW), false, 'and an active one');
  assert.equal(canDelegate(s, parent, child({ actions: ['read', 'derive', 'declassify'] }), NOW), false);
  assert.equal(canDelegate(world(), parent, child({ expiresAt: parent.expiresAt + 1 }), NOW), false);
  assert.equal(validGrantChain(s, { ...child(), parent: 'chief-run', actions: 'read' as never }, NOW), false, 'a malformed grant is false, not a throw');
  assert.equal(validGrantChain(s, null as never, NOW), false);
});

test('targetOf and evaluationTargetNamed', () => {
  const s = world();
  assert.deepEqual(targetOf({ ...s.actors.chief!, destination: 'llm-eu' }), { kind: 'profile', id: 'llm-eu' });
  assert.deepEqual(targetOf(s.actors.chief!), { kind: 'implicit-user' });
  assert.deepEqual(targetOf(s.actors['chief-agent']!), { kind: 'none' });
  assert.deepEqual(targetOf({ ...s.actors['chief-agent']!, destination: 'x' }), { kind: 'profile', id: 'x' });
  assert.equal(evaluationTargetNamed('read', undefined), true);
  assert.equal(evaluationTargetNamed('derive', undefined), true);
  assert.equal(evaluationTargetNamed('share', undefined), false);
  assert.equal(evaluationTargetNamed('export', undefined), false);
  assert.equal(evaluationTargetNamed('share', 'llm-eu'), true);
  assert.equal(evaluationTargetNamed('export', 'llm-eu'), true);
});

test('destinationGate returns exactly the verdict of each branch', () => {
  const dest: Destination = { id: 'llm-eu', tenant: 'acme', class: 'model-provider', maxClassification: 'confidential', purposes: ['work'], active: true };
  const s = world((w) => { w.destinations = { 'llm-eu': dest }; });
  const g = (over: Partial<Grant> = {}) => ({ ...s.grants['chief-run']!, ...over }) as Grant;
  const profile = { kind: 'profile', id: 'llm-eu' } as const;
  assert.deepEqual(destinationGate(s, g(), profile, 'acme', 'confidential', 'work'), { ok: true, restrict: ['model-provider', 'llm-eu'], destination: { id: 'llm-eu', class: 'model-provider' } });
  assert.deepEqual(destinationGate(s, g(), profile, 'acme', 'public', 'work'), { ok: true, restrict: ['model-provider', 'llm-eu'], destination: { id: 'llm-eu', class: 'model-provider' } });
  for (const [why, verdict] of [
    ['above the profile', destinationGate(s, g(), profile, 'acme', 'restricted', 'work')],
    ['purpose', destinationGate(s, g(), profile, 'acme', 'confidential', 'other')],
    ['no classification', destinationGate(s, g(), profile, 'acme', null, 'work')],
    ['unknown classification', destinationGate(s, g(), profile, 'acme', 'secret' as never, 'work')],
    ['other tenant', destinationGate(s, g(), profile, 'other', 'public', 'work')],
    ['unknown profile', destinationGate(s, g(), { kind: 'profile', id: 'ghost' }, 'acme', 'public', 'work')],
    ['class name as id', destinationGate(s, g(), { kind: 'profile', id: 'model-provider' }, 'acme', 'public', 'work')],
    ['run restriction', destinationGate(s, g({ destinations: ['internal-user'] }), profile, 'acme', 'public', 'work')],
    ['malformed restriction', destinationGate(s, g({ destinations: [] }), { kind: 'none' }, 'acme', 'public', 'work')],
    ['restricted run, no recipient', destinationGate(s, g({ destinations: ['internal-user'] }), { kind: 'none' }, 'acme', 'public', 'work')],
    ['implicit user outside the restriction', destinationGate(s, g({ destinations: ['llm-eu'] }), { kind: 'implicit-user' }, 'acme', 'public', 'work')],
    ['unknown target', destinationGate(s, g(), { kind: 'moon' } as never, 'acme', 'public', 'work')]] as const) assert.deepEqual(verdict, { ok: false }, why);
  s.destinations!['llm-eu'] = { ...dest, active: false };
  assert.deepEqual(destinationGate(s, g(), profile, 'acme', 'public', 'work'), { ok: false });
  s.destinations!['llm-eu'] = { ...dest, purposes: 'work' as never };
  assert.deepEqual(destinationGate(s, g(), profile, 'acme', 'public', 'work'), { ok: false });
  s.destinations!['llm-eu'] = { ...dest, maxClassification: 'secret' as never };
  assert.deepEqual(destinationGate(s, g(), profile, 'acme', 'public', 'work'), { ok: false });
  s.destinations!['llm-eu'] = { ...dest, class: 'moon' as never };
  assert.deepEqual(destinationGate(s, g(), profile, 'acme', 'public', 'work'), { ok: false });
  s.destinations!['llm-eu'] = { ...dest, id: 'other' };
  assert.deepEqual(destinationGate(s, g(), profile, 'acme', 'public', 'work'), { ok: false });
  s.destinations!['llm-eu'] = dest;
  assert.deepEqual(destinationGate(s, g(), { kind: 'implicit-user' }, 'acme', 'public', 'work'), { ok: true });
  assert.deepEqual(destinationGate(s, g(), { kind: 'none' }, 'acme', 'public', 'work'), { ok: true });
  assert.deepEqual(destinationGate(s, g(), { kind: 'unspecified' }, 'acme', 'public', 'work'), { ok: true });
  assert.deepEqual(destinationGate(s, g({ destinations: ['internal-user'] }), { kind: 'implicit-user' }, 'acme', 'public', 'work'), { ok: true, restrict: ['internal-user'], destination: { class: 'internal-user' } });
  const unspecified = destinationGate(s, g({ destinations: ['internal-user', 'llm-eu'] }), { kind: 'unspecified' }, 'acme', 'public', 'work');
  assert.deepEqual(unspecified, { ok: true, restrict: ['internal-user', 'llm-eu'] });
  assert.notEqual((unspecified as { restrict: string[] }).restrict, s.grants['chief-run']!.destinations, 'the restriction is a copy');
  assert.deepEqual(destinationGate(s, g({ destinations: ['model-provider'] }), profile, 'acme', 'public', 'work'), { ok: true, restrict: ['model-provider', 'llm-eu'], destination: { id: 'llm-eu', class: 'model-provider' } }, 'restricted by class');
  assert.deepEqual(destinationGate(s, g({ destinations: ['llm-eu'] }), profile, 'acme', 'public', 'work'), { ok: true, restrict: ['model-provider', 'llm-eu'], destination: { id: 'llm-eu', class: 'model-provider' } }, 'restricted by id');
  assert.deepEqual(destinationGate(s, g({ destinations: ['internal-user'] }), { kind: 'none' }, 'acme', 'public', 'work'), { ok: false });
});

test('lifecycle: lineageRecord, held and tombstone', () => {
  const k = doc('x', [], { lifecycle: 'quarantined' });
  assert.deepEqual(lineageRecord(k), { id: 'x', version: 1, kind: 'document', classification: 'public', active: true, lifecycle: 'quarantined' });
  assert.deepEqual(lineageRecord(doc('y')), { id: 'y', version: 1, kind: 'document', classification: 'public', active: true });
  assert.equal(Object.hasOwn(lineageRecord(doc('y')), 'lifecycle'), false);
  assert.equal(held({}), false);
  assert.equal(held({ legalHolds: [] }), false);
  assert.equal(held({ legalHolds: ['h1'] }), true);
  assert.equal(held({ legalHolds: 'h1' as never }), true, 'a malformed hold list counts as held');
  const t = doc('t', [ref('handbook')], { readers: ['chief'], readerRoles: ['executive'], projects: ['alpha'], quarantineReason: 'incident', retainUntil: 5, legalHolds: ['h'], lifecycle: 'quarantined' });
  assert.equal(tombstone(t, 77), true);
  assert.deepEqual({ ...t }, { id: 't', tenant: 'acme', version: 1, kind: 'document', origin: 'system', content: '', classification: 'public', readerRoles: [], projects: ['alpha'], readers: [],
    sources: [ref('handbook')], active: false, lifecycle: 'erased', lifecycleAt: 77 });
  assert.equal(tombstone(t, 99), false, 'idempotent, and the erasure time stays');
  assert.equal(t.lifecycleAt, 77);
  t.readerRoles = ['staff']; t.readers = ['chief'];
  assert.equal(tombstone(t, 99), true, 'a tombstone that still names an audience is cleaned');
  assert.deepEqual([t.readers, t.readerRoles, t.lifecycleAt], [[], [], 77]);
  t.readerRoles = ['staff'];
  assert.equal(tombstone(t, 99), true);
  t.readers = ['chief'];
  assert.equal(tombstone(t, 99), true);
  const noContent = doc('u', [], { content: 'still here', lifecycle: 'erased' });
  assert.equal(tombstone(noContent, 5), true, 'erased with content is not yet a tombstone');
  assert.equal(noContent.content, '');
});

const complete = (knowledge: Record<string, Knowledge>): Tx => ({ complete: true, state: { knowledge } as State, load: async () => {} }) as unknown as Tx;
test('lineage over a complete snapshot: descendants at any version, tenant-scoped, sorted, bounded', async () => {
  const tx = complete({ r: doc('r'), a: doc('a', [ref('r')]), b: doc('b', [ref('a', 7)]), c: doc('c', [ref('a'), ref('b')]), d: doc('d', [ref('r')], { tenant: 'other' }), e: doc('e'),
    f: doc('f', [{ id: 'bad id', version: 1 }]), g: doc('g', 'x' as never) });
  const all = await lineage(tx, 'acme', ['r'], 10);
  assert.deepEqual(all.records.map(k => k.id), ['a', 'b', 'c']);
  assert.equal(all.truncated, false);
  assert.ok(all.records.every(k => !('content' in k)), 'metadata only');
  const two = await lineage(tx, 'acme', ['r'], 2);
  assert.deepEqual(two.records.map(k => k.id), ['a', 'b']);
  assert.equal(two.truncated, true);
  const exact = await lineage(tx, 'acme', ['r'], 3);
  assert.equal(exact.truncated, false, 'exactly limit descendants is not truncation');
  assert.deepEqual((await lineage(tx, 'acme', ['a', 'b'], 10)).records.map(k => k.id), ['c']);
  assert.deepEqual((await lineage(tx, 'other', ['r'], 10)).records.map(k => k.id), ['d']);
  assert.deepEqual((await lineage(tx, 'acme', ['e'], 10)).records, []);
  const holes = complete({ r: doc('r'), n: doc('n', [null as never, ref('r')]) });
  assert.deepEqual((await lineage(holes, 'acme', ['r'], 10)).records.map(k => k.id), ['n'], 'a malformed source reference is skipped, not fatal');
  await assert.rejects(() => lineage(tx, 'acme', ['bad id'], 10), /Invalid lineage request/);
  await assert.rejects(() => lineage(tx, 'acme', ['r'], -1), /Invalid lineage request/);
  await assert.rejects(() => lineage(tx, 'acme', ['r'], 1.5), /Invalid lineage request/);
  assert.deepEqual((await lineage(tx, 'acme', ['r'], 0)).records, []);
  assert.equal((await lineage(tx, 'acme', ['r'], 0)).truncated, true);
  const chain = (n: number) => complete(Object.fromEntries(Array.from({ length: n + 1 }, (_, i) => [`k${i}`, doc(`k${i}`, i > 0 ? [ref(`k${i - 1}`)] : [])])));
  const deep = await lineage(chain(LIMITS.path - 1), 'acme', ['k0'], 1000);
  assert.equal(deep.records.length, LIMITS.path - 1);
  assert.equal(deep.truncated, false);
  const deeper = await lineage(chain(LIMITS.path), 'acme', ['k0'], 1000);
  assert.equal(deeper.truncated, true, 'the depth bound is reported (conservatively: one level early)');
  const wide = Object.fromEntries(Array.from({ length: LIFECYCLE.rows / 2 + 1 }, (_, i) => [`w${i}`, doc(`w${i}`, [ref('r'), ref('r')])]));
  assert.equal((await lineage(complete({ r: doc('r'), ...wide }), 'acme', ['r'], 100000)).truncated, true, 'the visited-edge bound is reported');
});

test('lineage over a partial store delegates to it and never trusts another tenant', async () => {
  const records = [doc('b'), doc('a'), doc('z', [], { tenant: 'other' }), doc('r')];
  const tx = { complete: false, state: {} as State, load: async () => {}, descendants: async (roots: string[], limit: number) => { assert.deepEqual(roots, ['r']); assert.equal(limit, 2); return { records, truncated: false }; } } as unknown as Tx;
  const got = await lineage(tx, 'acme', ['r'], 2);
  assert.deepEqual(got.records.map(k => k.id), ['a', 'b'], 'sorted; the root and the other tenant are dropped');
  assert.equal(got.truncated, false);
  const more = await lineage({ ...tx, descendants: async () => ({ records: [doc('a'), doc('b'), doc('c')], truncated: false }) } as unknown as Tx, 'acme', ['r'], 2);
  assert.deepEqual([more.records.length, more.truncated], [2, true]);
  const flagged = await lineage({ ...tx, descendants: async () => ({ records: [doc('a')], truncated: true }) } as unknown as Tx, 'acme', ['r'], 2);
  assert.equal(flagged.truncated, true);
  await assert.rejects(() => lineage({ complete: false, state: {} as State, load: async () => {} } as unknown as Tx, 'acme', ['r'], 1), /cannot traverse provenance/);
});

test('materialize loads a partial snapshot in chunks and does nothing for a complete one', async () => {
  const calls: string[][] = [];
  const partial = { complete: false, state: {} as State, load: async (need: { knowledge?: string[] }) => { calls.push(need.knowledge!); } } as unknown as Tx;
  const ids = Array.from({ length: LIFECYCLE.loadChunk * 2 + 1 }, (_, i) => `k${i}`);
  await materialize(partial, ids);
  assert.deepEqual(calls.map(c => c.length), [LIFECYCLE.loadChunk, LIFECYCLE.loadChunk, 1]);
  assert.deepEqual(calls.flat(), ids);
  calls.length = 0;
  await materialize(complete({}), ids);
  await materialize(partial, []);
  assert.deepEqual(calls, []);
});

test('retentionDue lists due, unheld, not yet erased records of the tenant after a cursor, in id order', async () => {
  const tx = complete({
    a: doc('a', [], { retainUntil: NOW }), b: doc('b', [], { retainUntil: NOW + 1 }), c: doc('c', [], { retainUntil: NOW - 1 }), d: doc('d', [], { retainUntil: 1, legalHolds: ['h'] }),
    e: doc('e', [], { retainUntil: 1, lifecycle: 'erased' }), f: doc('f', [], { retainUntil: 1, tenant: 'other' }), g: doc('g'), h: doc('h', [], { retainUntil: 'soon' as never }),
    i: doc('i', [], { retainUntil: 1, lifecycle: 'quarantined' }), j: doc('j', [], { retainUntil: 2 })
  });
  assert.deepEqual(await retentionDue(tx, 'acme', NOW, '', 100), ['a', 'c', 'i', 'j']);
  assert.deepEqual(await retentionDue(tx, 'acme', NOW, 'a', 100), ['c', 'i', 'j'], 'strictly after the cursor');
  assert.deepEqual(await retentionDue(tx, 'acme', NOW, '', 2), ['a', 'c']);
  assert.deepEqual(await retentionDue(tx, 'acme', 0, '', 100), [], 'nothing is due before the earliest deadline');
  assert.deepEqual(await retentionDue(tx, 'acme', 1, '', 100), ['i'], 'a deadline equal to now is due');
  assert.deepEqual(await retentionDue(tx, 'acme', 2, '', 100), ['i', 'j']);
  await assert.rejects(() => retentionDue(tx, 'acme', -1, '', 1), /Invalid retention request/);
  await assert.rejects(() => retentionDue(tx, 'acme', 1.5, '', 1), /Invalid retention request/);
  await assert.rejects(() => retentionDue(tx, 'acme', NOW, '', 0), /Invalid retention request/);
  await assert.rejects(() => retentionDue(tx, 'acme', NOW, '', 1.5), /Invalid retention request/);
  const partial = { complete: false, state: {} as State, load: async () => {}, retentionDue: async (now: number, after: string, limit: number) => { assert.deepEqual([now, after, limit], [NOW, 'x', 2]); return ['a', 'bad id', 'b', 'c']; } } as unknown as Tx;
  assert.deepEqual(await retentionDue(partial, 'acme', NOW, 'x', 2), ['a', 'b']);
  await assert.rejects(() => retentionDue({ complete: false, state: {} as State, load: async () => {} } as unknown as Tx, 'acme', NOW, '', 1), /cannot list retention/);
});

test('containment: a policy applies at or below the material level, the higher tier wins, and a bigger tier beats narrowing', () => {
  const s = world((w) => {
    const p = (id: string, classification: string, profiles: object, extra: object = {}) => { w.runtimeProfiles = { ...w.runtimeProfiles, [id]: { id, tenant: 'acme', classification, profiles, active: true, ...extra } as never }; };
    p('narrow', 'confidential', { network: 'model-only' }, { destinationClass: 'model-provider' });
    p('restricted', 'restricted', { network: 'deny-all' });
  });
  const net = (level: 'public' | 'confidential' | 'restricted', d?: 'model-provider' | 'internal-user') => containment(s, 'acme', level, d);
  assert.deepEqual(net('restricted', 'model-provider'), { ok: true, obligations: [{ type: 'runtime_profile', domain: 'network', profile: 'deny-all' }, { type: 'max_output_classification', value: 'restricted' }] });
  assert.deepEqual(net('confidential', 'model-provider'), { ok: true, obligations: [{ type: 'runtime_profile', domain: 'network', profile: 'model-only' }, { type: 'max_output_classification', value: 'confidential' }] });
  assert.deepEqual(net('confidential', 'internal-user'), { ok: true, obligations: [{ type: 'max_output_classification', value: 'confidential' }] }, 'narrowed to another class: does not apply');
  assert.deepEqual(net('public', 'model-provider'), { ok: true, obligations: [{ type: 'max_output_classification', value: 'public' }] }, 'a policy above the material level does not apply');
  assert.deepEqual(containment(s, 'acme', null), { ok: false, reason: 'DEFERRED:INVALID_CONTEXT' });
  assert.deepEqual(containment(s, 'acme', 'secret' as never), { ok: false, reason: 'DEFERRED:INVALID_CONTEXT' });
  assert.deepEqual(containment(s, 'other', 'restricted'), { ok: true, obligations: [] });
  assert.deepEqual(containment(world(), 'acme', null), { ok: true, obligations: [] }, 'no policy, no requirement and no need for a level');
  // conflicts at equal rank deny; a repeated profile is no conflict
  const conflict = world((w) => { w.runtimeProfiles = {
    a: { id: 'a', tenant: 'acme', classification: 'public', profiles: { network: 'deny-all' }, active: true },
    b: { id: 'b', tenant: 'acme', classification: 'public', profiles: { network: 'internal-only' }, active: true } }; });
  assert.deepEqual(containment(conflict, 'acme', 'public'), { ok: false, reason: 'DENIED:UNSUPPORTED_OBLIGATION' });
  conflict.runtimeProfiles!.b!.profiles = { network: 'deny-all' };
  assert.equal(containment(conflict, 'acme', 'public').ok, true);
  // A conflict at a lower rank than the winner is irrelevant
  conflict.runtimeProfiles!.b!.profiles = { network: 'internal-only' };
  conflict.runtimeProfiles!.c = { id: 'c', tenant: 'acme', classification: 'confidential', profiles: { network: 'x-tier' }, active: true };
  assert.deepEqual(containment(conflict, 'acme', 'confidential'), { ok: true, obligations: [{ type: 'runtime_profile', domain: 'network', profile: 'x-tier' }, { type: 'max_output_classification', value: 'confidential' }] });
  // a bound on the number of records of the tenant
  const many = (n: number) => world((w) => { w.runtimeProfiles = Object.fromEntries(Array.from({ length: n }, (_, i) => [`p${i}`, { id: `p${i}`, tenant: 'acme', classification: 'public', profiles: { tool: 'read-only-http' }, active: false }])) as never; });
  assert.deepEqual(containment(many(256), 'acme', 'public'), { ok: true, obligations: [] });
  assert.deepEqual(containment(many(257), 'acme', 'public'), { ok: false, reason: 'DEFERRED:BUDGET_EXCEEDED' });
  const odd = world((w) => { w.runtimeProfiles = { a: null as never, b: 'x' as never, c: { id: 'c', tenant: 'acme', classification: 'public', profiles: { tool: 'read-only-http' }, active: true } }; });
  assert.equal(containment(odd, 'acme', 'public').ok, true, 'records that are not objects of the tenant are not the tenant records');
});

test('containment ignores the records of other tenants, however malformed, and counts only its own toward the bound', () => {
  const foreign = world((w) => { w.runtimeProfiles = { junk: { tenant: 'other', garbage: 1 } as never, more: 'text' as never, nothing: null as never }; });
  assert.deepEqual(containment(foreign, 'acme', 'public'), { ok: true, obligations: [] });
  assert.deepEqual(containment(foreign, 'other', 'public'), { ok: false, reason: 'DEFERRED:INVALID_CONTEXT' }, 'the owner tenant sees its malformed record');
  const crowd = world((w) => { w.runtimeProfiles = Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`p${i}`, { id: `p${i}`, tenant: 'other', classification: 'public', profiles: { tool: 'read-only-http' }, active: false }])) as never; });
  assert.deepEqual(containment(crowd, 'acme', 'public'), { ok: true, obligations: [] }, 'records of another tenant do not count toward the bound');
});

test('containmentAcross merges the derivation over every reachable class', () => {
  const s = world((w) => { w.runtimeProfiles = {
    a: { id: 'a', tenant: 'acme', classification: 'public', profiles: { network: 'deny-all', tool: 'read-only-http' }, active: true },
    m: { id: 'm', tenant: 'acme', classification: 'public', destinationClass: 'model-provider', profiles: { tool: 'read-only-http' }, active: true } }; });
  assert.deepEqual(containmentAcross(s, 'acme', 'public', ['internal-user', 'model-provider']), { ok: true, obligations: [
    { type: 'runtime_profile', domain: 'network', profile: 'deny-all' }, { type: 'runtime_profile', domain: 'tool', profile: 'read-only-http' }, { type: 'max_output_classification', value: 'public' }] });
  assert.deepEqual(containmentAcross(s, 'acme', 'public', []), { ok: false, reason: 'DENIED:RECIPIENT' });
  assert.deepEqual(containmentAcross(s, 'acme', 'public', 'x' as never), { ok: false, reason: 'DENIED:RECIPIENT' });
  assert.deepEqual(containmentAcross(s, 'acme', null, ['internal-user']), { ok: false, reason: 'DEFERRED:INVALID_CONTEXT' });
  s.runtimeProfiles!.m!.profiles = { tool: 'other-http' };
  assert.deepEqual(containmentAcross(s, 'acme', 'public', ['internal-user', 'model-provider']), { ok: false, reason: 'DENIED:UNSUPPORTED_OBLIGATION' });
  assert.deepEqual(containmentAcross(s, 'acme', 'public', ['model-provider']), { ok: true, obligations: [
    { type: 'runtime_profile', domain: 'network', profile: 'deny-all' }, { type: 'runtime_profile', domain: 'tool', profile: 'other-http' }, { type: 'max_output_classification', value: 'public' }] });
  assert.deepEqual(containmentAcross(world(), 'acme', 'public', ['internal-user']), { ok: true, obligations: [] });
});

test('runtimeSetDigest covers the valid active policies of the tenant in id order, and only those', () => {
  const p = (id: string, extra: object = {}) => ({ id, tenant: 'acme', classification: 'public', profiles: { network: 'deny-all' }, active: true, ...extra }) as never;
  const s = world((w) => { w.runtimeProfiles = { b: p('b'), a: p('a'), off: p('off', { active: false }), foreign: p('foreign', { tenant: 'other' }), broken: p('broken', { profiles: {} }) }; });
  const digest = runtimeSetDigest(s, 'acme')!;
  assert.match(digest, /^runtime-profiles:[0-9a-f]{64}$/);
  const same = world((w) => { w.runtimeProfiles = { a: p('a'), b: p('b') }; });
  assert.equal(runtimeSetDigest(same, 'acme'), digest, 'inactive, foreign and malformed records are not covered, and order does not matter');
  const changed = world((w) => { w.runtimeProfiles = { a: p('a', { profiles: { network: 'internal-only' } }), b: p('b') }; });
  assert.notEqual(runtimeSetDigest(changed, 'acme'), digest);
  const trio = (order: string[]) => world((w) => { w.runtimeProfiles = Object.fromEntries(order.map(id => [id, p(id)])) as never; });
  const expected = 'runtime-profiles:' + createHash('sha256').update(canonicalize(['a', 'b', 'c'].map(id => p(id)))).digest('hex');
  for (const order of [['c', 'a', 'b'], ['a', 'b', 'c'], ['b', 'c', 'a'], ['c', 'b', 'a']]) assert.equal(runtimeSetDigest(trio(order), 'acme'), expected, order.join());
  assert.equal(runtimeSetDigest(world(), 'acme'), undefined);
  assert.equal(runtimeSetDigest(s, 'nobody'), undefined);
  assert.equal(runtimeSetDigest(world((w) => { w.runtimeProfiles = { off: p('off', { active: false }) }; }), 'acme'), undefined);
  assert.equal(validRuntimeProfile(p('x')), true);
  assert.equal(validRuntimeProfile(p('x', { active: 'yes' })), false);
  assert.equal(validRuntimeProfile(p('x', { destinationClass: 'model-provider' })), true);
  assert.equal(validRuntimeProfile(p('x', { destinationClass: 'moon' })), false);
  assert.equal(validRuntimeProfile(p('x', { profiles: { network: 'ok', tool: 'bad id' } })), false);
  assert.equal(validRuntimeProfile(p('bad id')), false);
  assert.equal(validRuntimeProfile(p('x', { tenant: 'bad id' })), false);
  assert.equal(validRuntimeProfile(p('x', { classification: 'secret' })), false);
  assert.equal(validRuntimeProfile(p('x', { extra: 1 })), false);
  assert.equal(validRuntimeProfile(null), false);
});

test('decision helpers: identifiers, trace correlation, digests and reason codes are exact', () => {
  assert.equal(validDecisionId('123e4567-e89b-42d3-a456-426614174000'), true);
  assert.equal(validDecisionId('123e4567-e89b-12d3-a456-426614174000'), false, 'version 4 only');
  assert.equal(validDecisionId('123e4567-e89b-42d3-c456-426614174000'), false, 'RFC 4122 variant only');
  assert.equal(validDecisionId('x123e4567-e89b-42d3-a456-426614174000'), false);
  assert.equal(validDecisionId('123e4567-e89b-42d3-a456-426614174000x'), false);
  assert.equal(validDecisionId('123E4567-E89B-42D3-A456-426614174000'), false, 'lowercase only');
  assert.equal(validDecisionId(7), false);
  assert.equal(validTraceId('0af7651916cd43dd8448eb211c80319c'), true);
  assert.equal(validTraceId('0'.repeat(32)), false);
  assert.equal(validTraceId('0'.repeat(31) + '1'), true);
  assert.equal(validTraceId('1' + '0'.repeat(31)), true, 'zeros at the end are not all zeros');
  assert.equal(validTraceId('0af7651916cd43dd8448eb211c80319'), false);
  assert.equal(validTraceId('x0af7651916cd43dd8448eb211c80319c'), false);
  assert.equal(validTraceId('0af7651916cd43dd8448eb211c80319cx'), false);
  assert.equal(validTraceId('0AF7651916CD43DD8448EB211C80319C'), false);
  assert.equal(validTraceId(1), false);
  const trace = '0af7651916cd43dd8448eb211c80319c';
  assert.equal(traceOf({ trace: { traceId: trace } }), trace);
  assert.equal(traceOf({ trace: { traceId: 'x' } }), undefined);
  assert.equal(traceOf(undefined), undefined);
  assert.equal(traceOf({}), undefined);
  assert.equal(executionOf({ trace: { executionId: 'run-1' } }), 'run-1');
  assert.equal(executionOf({ trace: { executionId: 'bad id' } }), undefined);
  assert.equal(executionOf(undefined), undefined);
  assert.equal(runtimeRevisionOf({ trace: { runtimeRevision: 'rev-7' } }), 'rev-7');
  assert.equal(runtimeRevisionOf({ trace: { runtimeRevision: 'bad id' } }), undefined);
  assert.equal(runtimeRevisionOf({}), undefined);
  assert.equal(runtimeRevisionOf(undefined), undefined);
  assert.match(policyDigest(['a', 'b']), /^[0-9a-f]{64}$/);
  assert.notEqual(policyDigest(['a', 'b']), policyDigest(['b', 'a']));
  assert.notEqual(policyDigest(['a']), policyDigest([]));
  assert.match(policyDigest([]), /^[0-9a-f]{64}$/);
  assert.equal(policyDigest(['ab']) === policyDigest(['a', 'b']), false);
  assert.deepEqual(classify('AUTHORIZED'), { code: 'AUTHORIZED' });
  assert.deepEqual(classify('DENIED:SOD_VIOLATION'), { code: 'SOD_VIOLATION', category: 'deny' });
  assert.deepEqual(classify('DEFERRED:BUDGET_EXCEEDED'), { code: 'BUDGET_EXCEEDED', category: 'defer' });
  assert.equal(classify('xDENIED:SOD_VIOLATION'), null);
  assert.equal(classify('DENIED:SOD_VIOLATION '), null);
  assert.equal(classify('DENIED:sod_violation'), null);
  assert.equal(classify('DENIED:'), null);
});

test('obligations: validation, satisfiability and the exact merged form', () => {
  const ok = (x: unknown) => assert.equal(validObligation(x), true, JSON.stringify(x));
  const no = (x: unknown) => assert.equal(validObligation(x), false, JSON.stringify(x));
  ok({ type: 'audit_level', value: 'full' }); no({ type: 'audit_level', value: 'low' }); no({ type: 'audit_level' }); no({ type: 'audit_level', value: 'full', x: 1 });
  ok({ type: 'no_persist' }); no({ type: 'no_persist', value: true });
  ok({ type: 'max_context_ttl_ms', value: 1 }); no({ type: 'max_context_ttl_ms', value: 0 }); no({ type: 'max_context_ttl_ms' }); no({ type: 'max_context_ttl_ms', value: 1, x: 1 });
  ok({ type: 'destination_restricted', value: ['a'] }); no({ type: 'destination_restricted', value: [] }); no({ type: 'destination_restricted', value: 'a' });
  no({ type: 'destination_restricted', value: ['a'], x: 1 }); no({ type: 'destination_restricted', value: ['a', 'a'] }); no({ type: 'destination_restricted', value: ['a', 'bad id'] });
  no({ type: 'destination_restricted', value: Array.from({ length: 65 }, (_, i) => `d${i}`) }); ok({ type: 'destination_restricted', value: Array.from({ length: 64 }, (_, i) => `d${i}`) });
  const sparse = [] as string[]; sparse[1] = 'a'; no({ type: 'destination_restricted', value: sparse });
  ok({ type: 'runtime_profile', domain: 'tool', profile: 'p' }); no({ type: 'runtime_profile', domain: 'gpu', profile: 'p' }); no({ type: 'runtime_profile', domain: 'tool' }); no({ type: 'runtime_profile', domain: 'tool', profile: 'p', x: 1 });
  ok({ type: 'max_output_classification', value: 'internal' }); no({ type: 'max_output_classification', value: 'secret' }); no({ type: 'max_output_classification' });
  ok({ type: 'release_filter', value: ['f'] }); no({ type: 'release_filter', value: [] }); no({ type: 'release_filter', value: ['f', 'f'] }); no({ type: 'release_filter', value: Array.from({ length: 17 }, (_, i) => `f${i}`) });
  ok({ type: 'release_filter', value: Array.from({ length: 16 }, (_, i) => `f${i}`) });
  ok({ type: 'approval_required', value: 'ticket-1' }); no({ type: 'approval_required', value: 'bad id' }); no({ type: 'approval_required' });
  no({ type: 'unknown' }); no(null); no([]); no('x'); no({}); no({ type: 'no_persist', 0: 1 } as never);
  assert.equal(unsatisfiable([{ type: 'destination_restricted', value: [] }]), true);
  assert.equal(unsatisfiable([{ type: 'destination_restricted', value: ['a'] }]), false);
  assert.equal(unsatisfiable([{ type: 'release_filter', value: Array.from({ length: 17 }, (_, i) => `f${i}`) }]), true);
  assert.equal(unsatisfiable([{ type: 'release_filter', value: Array.from({ length: 16 }, (_, i) => `f${i}`) }]), false);
  assert.equal(unsatisfiable([{ type: 'runtime_profile', domain: 'tool', profile: 'a' }, { type: 'runtime_profile', domain: 'network', profile: 'b' }]), false);
  assert.equal(unsatisfiable([{ type: 'runtime_profile', domain: 'tool', profile: 'a' }, { type: 'runtime_profile', domain: 'tool', profile: 'a' }]), false);
  assert.equal(unsatisfiable([{ type: 'runtime_profile', domain: 'tool', profile: 'a' }, { type: 'runtime_profile', domain: 'tool', profile: 'b' }]), true);
  assert.deepEqual(merge([{ type: 'max_context_ttl_ms', value: 9 }], [{ type: 'max_context_ttl_ms', value: 3 }], [{ type: 'max_context_ttl_ms', value: 5 }]), [{ type: 'max_context_ttl_ms', value: 3 }]);
  assert.deepEqual(merge([{ type: 'max_context_ttl_ms', value: 3 }], [{ type: 'max_context_ttl_ms', value: 9 }]), [{ type: 'max_context_ttl_ms', value: 3 }]);
  assert.deepEqual(merge([{ type: 'destination_restricted', value: ['a', 'b', 'c'] }], [{ type: 'destination_restricted', value: ['c', 'a', 'x'] }]), [{ type: 'destination_restricted', value: ['a', 'c'] }]);
  assert.deepEqual(merge([{ type: 'max_output_classification', value: 'public' }], [{ type: 'max_output_classification', value: 'restricted' }], [{ type: 'max_output_classification', value: 'internal' }]), [{ type: 'max_output_classification', value: 'restricted' }]);
  assert.deepEqual(merge([{ type: 'max_output_classification', value: 'internal' }], [{ type: 'max_output_classification', value: 'internal' }]), [{ type: 'max_output_classification', value: 'internal' }]);
  assert.deepEqual(merge([{ type: 'runtime_profile', domain: 'tool', profile: 'a' }, { type: 'runtime_profile', domain: 'tool', profile: 'a' }, { type: 'runtime_profile', domain: 'tool', profile: 'b' }]),
    [{ type: 'runtime_profile', domain: 'tool', profile: 'a' }, { type: 'runtime_profile', domain: 'tool', profile: 'b' }], 'a conflicting pair is kept for the satisfiability check');
  assert.deepEqual(merge([{ type: 'no_persist' }, { type: 'audit_level', value: 'full' }]), [{ type: 'audit_level', value: 'full' }, { type: 'no_persist' }], 'canonical order');
  const input = [{ type: 'destination_restricted', value: ['a', 'b'] }];
  parseObligations(input); assert.deepEqual(input, [{ type: 'destination_restricted', value: ['a', 'b'] }], 'parsing does not change its input');
  assert.equal(parseObligations([{ type: 'no_persist' }, undefined]), null);
  const sparseList = [{ type: 'no_persist' }] as unknown[]; sparseList[2] = { type: 'no_persist' };
  assert.equal(parseObligations(sparseList), null, 'a list with a hole');
  assert.equal(enforceable([{ type: 'audit_level', value: 'full' }], ['audit_level']), true);
  assert.equal(enforceable([{ type: 'audit_level', value: 'full' }], ['no_persist']), false);
  assert.equal(enforceable([{ type: 'audit_level', value: 'full' }, { type: 'no_persist' }], ['audit_level']), false, 'every obligation must be supported');
  assert.equal(enforceable([], []), true);
  assert.equal(enforceable('x' as never, ['audit_level']), false);
  assert.equal(enforceable([{ type: 'audit_level', value: 'nope' }], ['audit_level']), false);
  assert.equal(enforceable([{ type: 'runtime_profile', domain: 'tool', profile: 'a' }, { type: 'runtime_profile', domain: 'tool', profile: 'b' }], ['runtime_profile']), false);
  assert.equal(enforceable([{ type: 'audit_level', value: 'full' }, { type: 'audit_level', value: 'nope' }], ['audit_level']), false);
});

test('bindings used by these tests exist in the shared fixture', () => {
  assert.deepEqual(Object.keys(bindings).sort(), ['chief', 'intern', 'lead']);
});

test('decide returns the exact decision of every branch: effect, code and category', () => {
  const s = world();
  const req = (over: Record<string, unknown> = {}) => ({ binding: bindings.chief, resource: 'strategy', action: 'read', purpose: 'work', now: NOW, ...over }) as never;
  const denied = (code: string, category: 'deny' | 'defer') => ({ effect: 'deny', code, category });
  assert.deepEqual(decide(s, req()), { effect: 'allow', code: 'AUTHORIZED' });
  // an absent record is an unestablished authority (defer), never a definite denial
  for (const over of [{ binding: { ...bindings.chief, subject: 'ghost' } }, { binding: { ...bindings.chief, agent: 'ghost' } }, { binding: { ...bindings.chief, grant: 'ghost' } }, { resource: 'ghost' }])
    assert.deepEqual(decide(s, req(over)), denied('NOT_AUTHORIZED', 'defer'), JSON.stringify(over));
  // a request that is not exactly the closed shape is malformed (defer)
  const malformed: Record<string, unknown>[] = [{ extra: 1 }, { binding: { ...bindings.chief, extra: 1 } }, { binding: { tenant: 'acme', subject: 'chief', agent: 'chief-agent' } },
    { binding: { ...bindings.chief, agent: 'bad id' } }, { binding: { ...bindings.chief, tenant: 7 } }, { resource: 'bad id' }, { resource: 7 }, { action: 'delete' }, { purpose: '' }, { purpose: 'p'.repeat(129) },
    { purpose: 7 }, { now: -1 }, { now: 1.5 }, { now: '1' }];
  for (const over of malformed) assert.deepEqual(decide(s, req(over)), denied('INVALID_REQUEST', 'defer'), JSON.stringify(over));
  const noKey = { ...(req() as Record<string, unknown>) }; delete noKey.purpose;
  assert.deepEqual(decide(s, noKey as never), denied('INVALID_REQUEST', 'defer'));
  assert.deepEqual(decide(s, null as never), denied('INVALID_CONTEXT', 'defer'), 'a throw is a deferred denial');
  assert.deepEqual(decide(s, { ...(req() as Record<string, unknown>), binding: null } as never), denied('INVALID_REQUEST', 'defer'));
  const boundary = (change: (w: State) => void, over: Record<string, unknown> = {}) => { const w = world(change); return decide(w, req(over)); };
  assert.deepEqual(boundary((w) => { w.actors.chief!.tenant = 'other'; }), denied('IDENTITY_BOUNDARY', 'deny'));
  assert.deepEqual(boundary((w) => { w.actors['chief-agent']!.kind = 'user'; }), denied('IDENTITY_BOUNDARY', 'deny'));
  assert.deepEqual(boundary((w) => { w.grants['chief-run']!.active = false; }), denied('INVALID_DELEGATION', 'deny'));
  assert.deepEqual(boundary((w) => { w.grants['chief-run']!.subject = 'lead'; }), denied('INVALID_DELEGATION', 'deny'));
  assert.deepEqual(boundary((w) => { w.grants['chief-run']!.agent = 'lead-agent'; }), denied('INVALID_DELEGATION', 'deny'));
  assert.deepEqual(boundary((w) => { w.grants['chief-run']!.purposes = ['other']; }), denied('OUT_OF_SCOPE', 'deny'));
  assert.deepEqual(boundary((w) => { w.grants['chief-run']!.actions = ['read', 'declassify']; }, { action: 'declassify' }), denied('UNSUPPORTED_OBLIGATION', 'deny'));
  assert.deepEqual(boundary((w) => { w.actors.chief!.roles = 'x' as never; }), denied('INVALID_CONTEXT', 'defer'));
  assert.deepEqual(boundary((w) => { w.actors['chief-agent']!.roles = 'x' as never; }), denied('INVALID_CONTEXT', 'defer'));
  assert.deepEqual(boundary((w) => { w.actors['chief-agent']!.roles = ['requester', 'approver']; }), denied('SOD_VIOLATION', 'deny'), 'the agent is bound by static separation of duty too');
  assert.deepEqual(boundary((w) => { w.actors.chief!.roles = ['requester', 'approver']; }), denied('SOD_VIOLATION', 'deny'));
  assert.deepEqual(boundary((w) => { w.grants['chief-run']!.activeRoles = ['auditor-role', 'project']; w.actors.chief!.roles = ['auditor-role', 'project', 'executive']; }), denied('SOD_VIOLATION', 'deny'), 'dynamic separation of duty applies to the activated set');
  assert.deepEqual(boundary((w) => { w.knowledge.strategy!.origin = 'robot' as never; }), denied('INVALID_CONTEXT', 'defer'));
  assert.deepEqual(boundary((w) => { w.knowledge.strategy!.container = 'ghost'; }), denied('INVALID_CONTEXT', 'defer'));
  assert.deepEqual(boundary((w) => { w.actors.intern!.clearance = 'public'; }, { binding: bindings.intern }), denied('KNOWLEDGE_BOUNDARY', 'deny'));
  assert.deepEqual(boundary(() => {}, { binding: bindings.intern }), denied('KNOWLEDGE_BOUNDARY', 'deny'));
  assert.deepEqual(boundary(() => {}, { binding: bindings.intern, resource: 'handbook' }), { effect: 'allow', code: 'AUTHORIZED' });
});

