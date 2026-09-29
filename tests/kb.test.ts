import { bare } from './bare.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Engine, verifyAudit } from '../reference/engine.ts';
import type { CandidateSource, EngineEvent } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { MemoryStore, SqliteStore } from '../reference/store.ts';
import { decide, effectiveClearance, effectiveLabel, effectiveRoles, principalTokens, visible } from '../reference/policy.ts';
import { verifyLegacyAudit } from '../reference/audit.ts';
import { kbFixture, bindings } from '../examples/fixture.ts';
import { LEVELS, upgradeState } from '../reference/types.ts';
import type { Binding, Decision, Knowledge, PolicyInput, State } from '../reference/types.ts';

const now = 1800000000000;
const other: Binding = { tenant: 'other', subject: 'o-user', agent: 'o-agent', grant: 'o-run' };
function world(change?: (s: State) => void): State {
  const s = kbFixture(now);
  s.actors.admin!.roles = ['security-admin', 'kb-admin', 'auditor'];
  s.actors['kb-admin'] = { ...s.actors.admin!, id: 'kb-admin', roles: ['kb-admin'] };
  s.actors['o-user'] = { id: 'o-user', tenant: 'other', kind: 'user', roles: ['staff'], projects: [], clearance: 'restricted', active: true };
  s.actors['o-agent'] = { ...s.actors['o-user']!, id: 'o-agent', kind: 'agent' };
  s.actors['o-admin'] = { ...s.actors.admin!, id: 'o-admin', tenant: 'other' };
  s.grants['o-run'] = { ...s.grants['chief-run']!, id: 'o-run', tenant: 'other', subject: 'o-user', agent: 'o-agent' };
  s.knowledge['o-doc'] = { ...s.knowledge.handbook!, id: 'o-doc', tenant: 'other', content: 'Other tenant product notes.' };
  change?.(s); return s;
}
function setup(change?: (s: State) => void, options: ConstructorParameters<typeof Engine>[1] = {}) {
  const store = new MemoryStore(world(change));
  return { store, engine: new Engine(store, { clock: () => now, ...options }), control: new ControlPlane(store, { clock: () => now }) };
}
const read = (engine: Engine, b: Binding, id: string) => engine.openContext(b, [id], 'work').then(r => r.ok);
const lastReason = (store: MemoryStore, tenant = 'acme') => store.auditLog(tenant).then(log => log.at(-1)?.reason);
const board = (s: State) => { s.actors.chief!.roles = ['board']; s.actors['chief-agent']!.roles = ['board']; };

test('positive controls: hierarchy, group roles, folders and flat 0.2 roles', async () => {
  const { engine } = setup(s => { board(s); s.groups.leadership!.active = true; });
  assert.ok(await read(engine, bindings.chief, 'vault-memo'));
  assert.ok(await read(engine, bindings.lead, 'board-notes'));
  assert.ok(await read(engine, bindings.intern, 'staff-faq'));
  assert.ok(await read(engine, bindings.lead, 'project-alpha'));
});

const attacks: Record<string, [Binding, string, (s: State) => void]> = {
  'role hierarchy cycle': [bindings.chief, 'vault-memo', s => { board(s); s.roles.staff!.inherits = ['board']; }],
  'self-inheriting role': [bindings.chief, 'vault-memo', s => { board(s); s.roles.board!.inherits = ['board', 'executive']; }],
  'role hierarchy deeper than 16': [bindings.chief, 'vault-memo', s => {
    for (let i = 0; i < 16; i++) s.roles[`r${i}`] = { id: `r${i}`, tenant: 'acme', inherits: [i ? `r${i - 1}` : 'executive'], active: true };
    s.actors.chief!.roles = ['r15']; }],
  'more than 64 effective roles': [bindings.chief, 'vault-memo', s => { s.actors.chief!.roles = [...s.actors.chief!.roles, ...Array.from({ length: 63 }, (_, i) => `extra-${i}`)]; }],
  'inactive senior role': [bindings.chief, 'vault-memo', s => { board(s); s.roles.board!.active = false; }],
  'inactive junior role breaks the path': [bindings.chief, 'vault-memo', s => { board(s); s.roles.executive!.active = false; }],
  'cross-tenant role record is not a hierarchy': [bindings.chief, 'vault-memo', s => { board(s); s.roles.board!.tenant = 'other'; }],
  'group inactive': [bindings.lead, 'board-notes', () => {}],
  'group in another tenant': [bindings.lead, 'board-notes', s => { s.groups.leadership!.active = true; s.groups.leadership!.tenant = 'other'; }],
  'group does not list the agent': [bindings.lead, 'board-notes', s => { s.groups.leadership!.active = true; s.groups.leadership!.members = ['lead']; }],
  'static SoD via direct roles': [bindings.chief, 'handbook', s => { s.actors.chief!.roles.push('requester', 'approver'); }],
  'static SoD via group': [bindings.chief, 'handbook', s => { s.actors.chief!.roles.push('requester');
    s.groups.leadership = { ...s.groups.leadership!, members: ['chief'], roles: ['approver'], active: true }; }],
  'static SoD on the agent': [bindings.chief, 'handbook', s => { s.actors['chief-agent']!.roles.push('requester', 'approver'); }],
  'dynamic SoD without activation': [bindings.lead, 'project-alpha', s => { s.actors.lead!.roles.push('auditor-role'); }],
  'dynamic SoD with both activated': [bindings.lead, 'project-alpha', s => { s.actors.lead!.roles.push('auditor-role');
    s.grants['lead-run']!.activeRoles = ['project', 'auditor-role']; }],
  'activated role not held': [bindings.chief, 'strategy', s => { s.grants['chief-run']!.activeRoles = ['executive', 'board']; }],
  'activation omits the needed role': [bindings.chief, 'strategy', s => { s.grants['chief-run']!.activeRoles = ['staff']; }],
  'malformed SoD constraint fails closed': [bindings.chief, 'handbook', s => { s.constraints['ssd-payments']!.cardinality = 0; }],
  'container cycle': [bindings.chief, 'vault-memo', s => { s.containers['f-executive']!.parent = 'f-vault'; }],
  'cross-tenant container': [bindings.chief, 'board-notes', s => { s.containers['f-executive']!.tenant = 'other'; }],
  'cross-tenant ancestor': [bindings.chief, 'vault-memo', s => { s.containers['kb-corporate']!.tenant = 'other'; }],
  'inactive folder': [bindings.chief, 'vault-memo', s => { s.containers['f-executive']!.active = false; }],
  'inactive knowledge base': [bindings.chief, 'board-notes', s => { s.containers['kb-corporate']!.active = false; }],
  'folder floor above user clearance': [bindings.lead, 'vault-memo', s => { s.groups.leadership!.active = true; }],
  'folder floor above agent clearance': [bindings.chief, 'board-notes', s => { s.actors['chief-agent']!.clearance = 'internal'; }],
  'folder audience excludes the agent': [bindings.chief, 'board-notes', s => { s.actors['chief-agent']!.roles = ['staff']; }],
  'folder project requirement': [bindings.chief, 'board-notes', s => { s.containers['f-executive']!.projects = ['beta']; }],
  'folder with an empty ACL': [bindings.chief, 'board-notes', s => { s.containers['f-executive']!.readerRoles = []; }],
  'missing container': [bindings.chief, 'handbook', s => { s.knowledge.handbook!.container = 'missing'; }],
  'knowledge base with a parent': [bindings.chief, 'staff-faq', s => { s.containers['kb-corporate']!.parent = 'f-vault'; }],
  'folder without a parent': [bindings.chief, 'board-notes', s => { delete s.containers['f-executive']!.parent; }],
  'container chain deeper than 32': [bindings.chief, 'handbook', s => {
    for (let i = 0; i < 33; i++) s.containers[`deep-${i}`] = { ...s.containers['kb-corporate']!, id: `deep-${i}`, ...(i ? { kind: 'folder', parent: `deep-${i - 1}` } : {}) };
    s.knowledge.handbook!.container = 'deep-32'; }],
  'source in a stricter folder': [bindings.intern, 'handbook', s => { s.knowledge.handbook!.sources = [{ id: 'board-notes', version: 1 }]; }],
  'origin missing': [bindings.intern, 'handbook', s => { delete (s.knowledge.handbook as Partial<Knowledge>).origin; }],
  'origin outside the closed enum': [bindings.intern, 'handbook', s => { s.knowledge.handbook!.origin = 'administrator' as never; }],
  'source with unknown origin': [bindings.chief, 'strategy', s => { s.knowledge.strategy!.sources = [{ id: 'handbook', version: 1 }]; s.knowledge.handbook!.origin = 'agent' as never; }]
};
for (const [name, [binding, resource, mutate]] of Object.entries(attacks)) test(`deny 0.3: ${name}`, async () => {
  const { engine } = setup(mutate);
  assert.deepEqual(bare(await engine.openContext(binding, [resource], 'work')), { ok: false, code: 'NOT_AUTHORIZED' });
});

test('decision categories separate definite denial from unestablished authority', () => {
  const s = world(), request = (resource: string): PolicyInput => ({ binding: bindings.chief, action: 'read', resource, purpose: 'work', now });
  assert.deepEqual(decide(s, request('vault-memo')), { effect: 'allow', code: 'AUTHORIZED' });
  assert.deepEqual(decide(world(x => { x.containers['f-executive']!.active = false; }), request('vault-memo')), { effect: 'deny', code: 'KNOWLEDGE_BOUNDARY', category: 'deny' });
  assert.deepEqual(decide(world(x => { x.containers['f-executive']!.parent = 'f-vault'; }), request('vault-memo')), { effect: 'deny', code: 'INVALID_CONTEXT', category: 'defer' });
  assert.deepEqual(decide(s, request('absent')), { effect: 'deny', code: 'NOT_AUTHORIZED', category: 'defer' });
  assert.deepEqual(decide(world(x => { x.actors.chief!.roles.push('requester', 'approver'); }), request('handbook')), { effect: 'deny', code: 'SOD_VIOLATION', category: 'deny' });
});

test('audit reasons carry the internal category; responses stay non-distinguishing', async () => {
  const { engine, store } = setup(s => { delete (s.knowledge.handbook as Partial<Knowledge>).origin; });
  assert.deepEqual(bare(await engine.openContext(bindings.intern, ['vault-memo'], 'work')), { ok: false, code: 'NOT_AUTHORIZED' });
  assert.equal(await lastReason(store), 'DENIED:KNOWLEDGE_BOUNDARY');
  assert.deepEqual(bare(await engine.openContext(bindings.intern, ['handbook'], 'work')), { ok: false, code: 'NOT_AUTHORIZED' });
  assert.equal(await lastReason(store), 'DEFERRED:INVALID_CONTEXT');
});

test('per-tenant epochs: revocation invalidates only the revoking tenant', async () => {
  const { engine, store } = setup();
  const mine = await engine.openContext(bindings.chief, ['strategy'], 'work'), theirs = await engine.openContext(other, ['o-doc'], 'work');
  assert.ok(mine.ok && theirs.ok);
  const revoked = await engine.revoke('acme', 'admin', 'grant', 'lead-run');
  assert.ok(revoked.ok); assert.equal(revoked.value.epoch, 1);
  assert.equal((await engine.derive(bindings.chief, mine.value.context, 'after')).ok, false);
  assert.ok((await engine.derive(other, theirs.value.context, 'unaffected')).ok);
  assert.deepEqual(await store.transaction('acme', async tx => tx.state.epochs), { acme: 1 });
  assert.equal((await engine.revoke('other', 'admin', 'grant', 'o-run')).ok, false, 'admin cannot act in another tenant');
  assert.equal((await engine.revoke('acme', 'o-admin', 'grant', 'chief-run')).ok, false);
  for (const tenant of ['acme', 'other']) { const log = await store.auditLog(tenant); assert.ok(log.length && log[0]!.sequence === 1 && verifyAudit(log)); }
  assert.ok(await store.ready());
});

test('derivation takes the container floor and is model-originated', async () => {
  const { engine, store } = setup();
  const context = await engine.openContext(bindings.chief, ['vault-memo', 'handbook'], 'work'); assert.ok(context.ok);
  const derived = await engine.derive(bindings.chief, context.value.context, 'Summary', 'memory'); assert.ok(derived.ok);
  assert.equal(derived.value.classification, 'restricted', 'vault-memo itself is public; its folder is restricted');
  const record = await store.transaction('acme', async tx => structuredClone(tx.state.knowledge[derived.value.id]!));
  assert.equal(record.origin, 'model'); assert.equal(record.container, undefined);
  assert.equal(await read(engine, bindings.lead, derived.value.id), false);
});

test('effectiveLabel exposes the conjunctive label for indexers', () => {
  const s = world();
  assert.deepEqual(effectiveLabel(s, s.knowledge['vault-memo']!), { classification: 'restricted', projects: [],
    audiences: [{ readers: [], readerRoles: ['staff'] }, { readers: [], readerRoles: ['executive'] }, { readers: [], readerRoles: ['executive'] }, { readers: [], readerRoles: ['staff'] }],
    containers: ['f-vault', 'f-executive', 'kb-corporate'] });
  s.containers['f-executive']!.parent = 'f-vault';
  assert.equal(effectiveLabel(s, s.knowledge['vault-memo']!), null);
});

test('principal tokens and clearance for candidate pre-filters', () => {
  const s = world(board);
  assert.deepEqual(principalTokens(s, s.actors.chief!), ['user:chief', 'role:board', 'role:executive', 'role:staff', 'project:alpha']);
  assert.deepEqual(principalTokens(s, s.actors.chief!, ['staff']), ['user:chief', 'role:staff', 'project:alpha']);
  assert.equal(principalTokens(s, s.actors.chief!, ['security-admin']), null);
  assert.equal(effectiveClearance(s.actors.chief!, s.actors['intern-agent']!), 'internal');
  assert.deepEqual([...effectiveRoles(s, s.actors.lead!)!].sort(), ['project', 'staff']);
});

test('candidate source: every candidate is re-checked; mismatches are dropped and counted', async () => {
  const events: EngineEvent[] = [], seen: Parameters<CandidateSource['candidates']>[0][] = [];
  const source: CandidateSource = { candidates: async input => { seen.push(input); return ['vault-memo', 'o-doc', 'strategy', 'handbook', 'staff-faq', 'constructor'] as string[]; } };
  const { engine, store } = setup(undefined, { candidates: source, onEvent: e => events.push(e) });
  const result = await engine.retrieve(bindings.intern, 'product', 'work', 5); assert.ok(result.ok);
  assert.deepEqual(result.value.documents.map(d => d.id), ['handbook', 'staff-faq']);
  assert.equal(engine.stats().filterMismatches, 3);
  assert.equal(events.filter(e => e.type === 'filter_mismatch').length, 3);
  assert.deepEqual(seen, [{ tenant: 'acme', maxClassification: 'internal', tokens: ['user:intern', 'role:staff'], query: 'product', limit: 20 }]);
  assert.ok(!JSON.stringify(events).includes('vault'));
  const failing = new Engine(store, { clock: () => now, candidates: { candidates: async () => { throw new Error('index offline'); } } });
  assert.equal((await failing.retrieve(bindings.intern, 'product', 'work')).ok, false);
  assert.equal(await lastReason(store), 'DEFERRED:CANDIDATES_UNAVAILABLE');
});

test('control plane: role separation between security-admin, kb-admin and auditor', async () => {
  const { control, store } = setup(s => { s.actors['chief-agent']!.roles.push('security-admin'); });
  const role = { id: 'reviewer', tenant: 'acme', inherits: ['staff'], active: true };
  assert.deepEqual(bare(await control.upsertRole('acme', 'chief', role)), { ok: false, code: 'NOT_AUTHORIZED' });
  assert.deepEqual(bare(await control.upsertRole('acme', 'kb-admin', role)), { ok: false, code: 'NOT_AUTHORIZED' });
  assert.deepEqual(bare(await control.upsertRole('acme', 'chief-agent', role)), { ok: false, code: 'NOT_AUTHORIZED' }, 'agents are never admins');
  assert.deepEqual(bare(await control.upsertRole('acme', 'o-admin', role)), { ok: false, code: 'NOT_AUTHORIZED' }, 'cross-tenant admin');
  assert.ok((await control.upsertRole('acme', 'admin', role)).ok);
  const doc: Knowledge = { ...world().knowledge.handbook!, id: 'policy-doc', content: 'Synthetic policy', origin: 'human', container: 'kb-corporate' };
  assert.deepEqual(bare(await control.upsertKnowledge('acme', 'chief', doc)), { ok: false, code: 'NOT_AUTHORIZED' });
  assert.ok((await control.upsertKnowledge('acme', 'kb-admin', doc)).ok);
  assert.deepEqual(bare(await control.auditLog('acme', 'kb-admin')), { ok: false, code: 'NOT_AUTHORIZED' });
  const log = await control.auditLog('acme', 'admin'); assert.ok(log.ok && verifyAudit(log.value));
  assert.ok(log.value.some(e => e.operation === 'upsert_role' && e.decision === 'deny' && e.reason === 'DENIED:NOT_ADMIN'));
  assert.equal((await store.auditLog('acme')).at(-1)!.operation, 'audit_read');
});

test('control plane: model content and malformed records never become authority', async () => {
  const { control } = setup();
  const base: Knowledge = { ...world().knowledge.handbook!, id: 'ingested', content: 'Synthetic' };
  for (const bad of [{ ...base, origin: 'model' }, { ...base, kind: 'memory' }, { ...base, kind: 'artifact', origin: 'model' },
    { ...base, allowed: true }, { ...base, origin: undefined }, { ...base, tenant: 'other' }, { ...base, container: 'missing' }]) {
    assert.equal((await control.upsertKnowledge('acme', 'admin', bad as Knowledge)).ok, false, JSON.stringify(bad).slice(0, 80));
  }
  assert.ok((await control.upsertKnowledge('acme', 'admin', base)).ok);
  assert.deepEqual(bare(await control.upsertKnowledge('acme', 'admin', base)), { ok: false, code: 'CONFLICT' }, 'versions are monotonic');
  assert.ok((await control.upsertKnowledge('acme', 'admin', { ...base, version: 2, classification: 'confidential' })).ok);
  const folder = { ...world().containers['f-vault']! };
  assert.deepEqual(bare(await control.upsertContainer('acme', 'admin', { ...folder, id: 'f-executive', parent: 'f-vault' })), { ok: false, code: 'INVALID_REQUEST' }, 'cycle');
  assert.deepEqual(bare(await control.upsertContainer('acme', 'admin', { ...world().containers['kb-corporate']!, id: 'kb-2', parent: 'kb-corporate' })), { ok: false, code: 'INVALID_REQUEST' });
  assert.deepEqual(bare(await control.upsertContainer('acme', 'admin', { ...folder, id: 'f-orphan', parent: 'missing' })), { ok: false, code: 'INVALID_REQUEST' });
  assert.deepEqual(bare(await control.upsertRole('acme', 'admin', { id: 'staff', tenant: 'acme', inherits: ['board'], active: true })), { ok: false, code: 'INVALID_REQUEST' }, 'hierarchy cycle');
});

test('control plane: SoD is enforced at assignment, group membership and grant issuance', async () => {
  const { control, engine, store } = setup();
  assert.deepEqual(bare(await control.assignRoles('acme', 'admin', 'chief', ['staff', 'executive', 'requester', 'approver'])), { ok: false, code: 'SOD_VIOLATION' });
  assert.deepEqual(await store.transaction('acme', async tx => tx.state.actors.chief!.roles), ['staff', 'executive']);
  assert.ok((await control.assignRoles('acme', 'admin', 'chief', ['staff', 'executive', 'requester'])).ok);
  assert.deepEqual(bare(await control.upsertGroup('acme', 'admin', { id: 'approvers', tenant: 'acme', members: ['chief'], roles: ['approver'], active: true })), { ok: false, code: 'SOD_VIOLATION' });
  assert.ok((await control.assignRoles('acme', 'admin', 'lead', ['staff', 'project', 'auditor-role'])).ok, 'dynamic SoD allows holding both');
  const grant = { ...world().grants['lead-run']!, id: 'lead-review' };
  assert.deepEqual(bare(await control.issueGrant('acme', 'admin', grant)), { ok: false, code: 'SOD_VIOLATION' }, 'activating both violates DSD');
  assert.deepEqual(bare(await control.issueGrant('acme', 'admin', { ...grant, activeRoles: ['executive'] })), { ok: false, code: 'INVALID_REQUEST' }, 'not held');
  assert.ok((await control.issueGrant('acme', 'admin', { ...grant, activeRoles: ['project'] })).ok);
  assert.ok(await read(engine, { ...bindings.lead, grant: 'lead-review' }, 'project-alpha'));
  assert.deepEqual(bare(await control.issueGrant('acme', 'admin', { ...grant, activeRoles: ['project'] })), { ok: false, code: 'CONFLICT' });
});

test('control plane: updating security metadata advances the tenant epoch', async () => {
  const { control, engine } = setup();
  const context = await engine.openContext(bindings.chief, ['board-notes'], 'work'); assert.ok(context.ok);
  assert.ok((await control.upsertContainer('acme', 'kb-admin', { ...world().containers['f-executive']!, readerRoles: ['executive', 'project'] })).ok);
  assert.equal((await engine.derive(bindings.chief, context.value.context, 'stale')).ok, false);
  assert.equal(await read(engine, bindings.chief, 'board-notes'), false, 'the stale run must be re-provisioned');
  assert.ok(await read(engine, bindings.lead, 'board-notes'), 'a fresh run sees the new folder audience');
});

test('0.1 state upgrades: origins, per-tenant epochs and the retained legacy chain', async () => {
  const old = await (async () => {
    const s = world() as unknown as Record<string, unknown>;
    for (const k of Object.values(s.knowledge as Record<string, Record<string, unknown>>)) { delete k.origin; delete k.container; }
    for (const key of ['epochs', 'roles', 'groups', 'containers', 'constraints']) delete s[key];
    (s.knowledge as Record<string, Record<string, unknown>>).note = { ...(s.knowledge as Record<string, Record<string, unknown>>).handbook, id: 'note', kind: 'memory' };
    return Object.assign(s, { schema: 'akac-state/0.1', epoch: 2, audits: [] });
  })();
  const upgraded = upgradeState(old);
  assert.equal(upgraded.schema, 'akac-state/0.3');
  assert.equal(upgraded.knowledge.handbook!.origin, 'system'); assert.equal(upgraded.knowledge.note!.origin, 'model');
  assert.deepEqual(upgraded.epochs, { acme: 2, other: 2 });
  assert.throws(() => upgradeState({ schema: 'akac-state/9' }));
  const dir = mkdtempSync(join(tmpdir(), 'akac-upgrade-')), path = join(dir, 'state.sqlite');
  try {
    const legacy = { ...old, audits: [] as unknown[] };
    const seeded = new MemoryStore(upgradeState(legacy));
    await new Engine(seeded, { clock: () => now }).openContext(bindings.chief, ['strategy'], 'work');
    const db = new DatabaseSync(path);
    db.exec('CREATE TABLE akac_state (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)');
    db.prepare('INSERT INTO akac_state(id,body) VALUES(1,?)').run(JSON.stringify(legacy)); db.close();
    const store = new SqliteStore(path);
    assert.ok(await store.ready());
    assert.ok((await new Engine(store, { clock: () => now }).openContext(bindings.chief, ['strategy'], 'work')).ok);
    assert.equal(await store.transaction('acme', async tx => tx.state.schema), 'akac-state/0.3');
    await store.close();
  } finally { rmSync(dir, { recursive: true }); }
  assert.ok(verifyLegacyAudit([]));
});

// ---- Properties -------------------------------------------------------------

const level = fc.constantFrom(...LEVELS);
const roleSet = fc.subarray(['staff', 'executive', 'project', 'board'], { minLength: 0 });
const containerArb = fc.record({ level, roles: roleSet, readers: fc.subarray(['chief', 'chief-agent']), active: fc.boolean(), projects: fc.subarray(['alpha']) });
const scenario = fc.record({
  userRoles: roleSet, agentRoles: roleSet, user: level, agent: level, doc: level, docRoles: roleSet,
  kb: containerArb, folder: fc.option(containerArb, { nil: undefined })
});
type Scenario = typeof scenario extends fc.Arbitrary<infer T> ? T : never;
function scenarioState(x: Scenario, withContainer: boolean): State {
  const s = world();
  Object.assign(s.actors.chief!, { roles: [...x.userRoles], clearance: x.user });
  Object.assign(s.actors['chief-agent']!, { roles: [...x.agentRoles], clearance: x.agent });
  const doc = s.knowledge.strategy!; Object.assign(doc, { classification: x.doc, readerRoles: [...x.docRoles] });
  const make = (id: string, c: Scenario['kb'], parent?: string) => {
    s.containers[id] = { id, tenant: 'acme', kind: parent ? 'folder' : 'knowledge-base', ...(parent ? { parent } : {}), classification: c.level,
      readerRoles: [...c.roles], readers: [...c.readers], projects: [...c.projects], active: c.active };
  };
  make('p-kb', x.kb); if (x.folder) make('p-folder', x.folder, 'p-kb');
  if (withContainer) doc.container = x.folder ? 'p-folder' : 'p-kb';
  return s;
}
type Oracle = (s: State, input: PolicyInput) => Decision;
/** (b) Monotonic restriction: placing a document into a container never grants access that was denied without it. */
function monotonic(oracle: Oracle) {
  return fc.check(fc.property(scenario, x => {
    const input: PolicyInput = { binding: bindings.chief, action: 'read', resource: 'strategy', purpose: 'work', now };
    const before = oracle(scenarioState(x, false), input).effect, after = oracle(scenarioState(x, true), input).effect;
    return before === 'allow' || after === 'deny';
  }), { seed: 20260930, numRuns: 600 });
}

test('property: adding a container never grants access denied without it', () => {
  const result = monotonic(decide);
  assert.equal(result.failed, false, String(result.counterexample));
  const s = world(), input: PolicyInput = { binding: bindings.chief, action: 'read', resource: 'strategy', purpose: 'work', now };
  assert.equal(decide(s, input).effect, 'allow', 'the property is not vacuous');
});

test('meta: the property harness detects an injected permissive container bug', () => {
  // Bug: container readers are treated as an alternative to, rather than a restriction on, the document ACL.
  const broken: Oracle = (s, input) => {
    const doc = s.knowledge[input.resource], container = doc?.container ? s.containers[doc.container] : undefined;
    return container?.readers.includes(input.binding.subject) ? { effect: 'allow', code: 'AUTHORIZED' } : decide(s, input);
  };
  const result = monotonic(broken);
  assert.equal(result.failed, true, 'a permissive oracle must be caught');
});

test('property: derivation never lowers classification and never widens audience', async () => {
  const docs = ['handbook', 'strategy', 'project-alpha', 'board-notes', 'vault-memo', 'staff-faq'];
  await fc.assert(fc.asyncProperty(fc.subarray(docs, { minLength: 1 }), fc.constantFrom('keep', 'none', 'kb-corporate', 'f-executive', 'f-vault'), level,
    fc.record({ roles: roleSet, clearance: level, projects: fc.subarray(['alpha']) }), async (sources, move, docLevel, probe) => {
      const { engine, store } = setup(s => {
        const first = s.knowledge[sources[0]!]!; first.classification = docLevel;
        if (move === 'none') delete first.container; else if (move !== 'keep') first.container = move;
      });
      const context = await engine.openContext(bindings.chief, sources, 'work');
      if (!context.ok) return;
      const derived = await engine.derive(bindings.chief, context.value.context, 'synthetic', 'artifact'); assert.ok(derived.ok);
      const s = await store.transaction('acme', async tx => structuredClone(tx.state));
      const output = s.knowledge[derived.value.id]!;
      for (const id of sources) assert.ok(LEVELS.indexOf(output.classification) >= LEVELS.indexOf(effectiveLabel(s, s.knowledge[id]!)!.classification));
      // Any principal able to see the derivative can see every source it came from.
      const probeActor = { ...s.actors.intern!, id: 'probe', roles: [...probe.roles], clearance: probe.clearance, projects: [...probe.projects] };
      s.actors.probe = probeActor;
      if (visible(s, probeActor, output, now)) for (const id of sources) assert.ok(visible(s, probeActor, s.knowledge[id]!, now), id);
    }), { seed: 20261001, numRuns: 150 });
});
