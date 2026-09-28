// Regression tests for defects found in the 0.3 adversarial review (see CHANGELOG).
// Each test failed before its fix. PostgreSQL-specific cases live in postgres.test.ts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ControlPlane } from '../reference/control.ts';
import { Engine } from '../reference/engine.ts';
import { hydrate } from '../reference/hydrate.ts';
import { createScim } from '../reference/scim.ts';
import { createAdminGateway } from '../reference/admin.ts';
import { Ingestor } from '../reference/ingest.ts';
import { HashEmbedder } from '../reference/embedding.ts';
import { MemoryVectorIndex } from '../reference/vector.ts';
import { MemoryStore, SqliteStore, importState } from '../reference/store.ts';
import { emptyState } from '../reference/types.ts';
import type { Actor, Audit, Knowledge, Need, State, Store, Tx } from '../reference/types.ts';
import { bindings } from '../examples/fixture.ts';
import { close, listen, start, tokens, world } from './support.ts';

const now = 1800000000000;
const last = (log: Audit[]) => log.at(-1)!;
async function audits(store: Store, tenant = 'acme') { return store.auditLog(tenant); }
const user = (id: string, roles: string[], extra: Partial<Actor> = {}): Actor => ({ id, tenant: 'acme', kind: 'user', roles, projects: [], clearance: 'restricted', active: true, ...extra });

// ---- Finding 2: tenant-scoped keys ------------------------------------------

for (const kind of ['memory', 'sqlite'] as const) {
  test(`${kind} store: the same id may exist in two tenants; a foreign id is neither a conflict nor a takeover`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'akac-keys-'));
    const open = () => kind === 'memory' ? new MemoryStore(world()) : new SqliteStore(join(dir, 'state.sqlite'));
    let store = open();
    try {
      if (kind === 'sqlite') await importState(store, world());
      const control = new ControlPlane(store, { clock: () => now });
      const alien: Actor = { id: 'intern', tenant: 'other', kind: 'user', roles: [], projects: [], clearance: 'public', active: false };
      const fresh = await control.upsertActor('other', 'other-sec', { ...alien, id: 'nobody' });
      const taken = await control.upsertActor('other', 'other-sec', alien);
      assert.deepEqual(taken, { ok: true, value: { id: 'intern' } }, 'same response as for an unused id');
      assert.equal(fresh.ok, true);
      if (kind === 'sqlite') { await store.close(); store = open(); }
      const reread = new ControlPlane(store, { clock: () => now });
      assert.deepEqual(await reread.readActor('acme', 'sec', 'intern'), { ok: true, value: world().actors.intern }, 'the original tenant is untouched');
      assert.deepEqual(await reread.readActor('other', 'other-sec', 'intern'), { ok: true, value: alien });
      assert.ok((await new Engine(store).openContext(bindings.intern, ['handbook'], 'work')).ok);
    } finally { await store.close(); rmSync(dir, { recursive: true }); }
  });

  test(`${kind} store: a tenant transaction cannot write another tenant's records`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'akac-confine-'));
    const store = kind === 'memory' ? new MemoryStore(world()) : new SqliteStore(join(dir, 'state.sqlite'));
    try {
      await assert.rejects(store.transaction('acme', async tx => { tx.state.actors.forged = user('forged', [], { tenant: 'other' }); }), /Cross-tenant/);
      await assert.rejects(store.transaction('acme', async tx => { tx.state.epochs.other = 9; }), /Cross-tenant/);
      assert.equal(await store.transaction('other', async tx => tx.state.actors.forged), undefined);
    } finally { await store.close(); rmSync(dir, { recursive: true }); }
  });
}

test('sqlite store: a whole-state file from an earlier version is split into tenants once', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'akac-split-')), path = join(dir, 'state.sqlite');
  try {
    const { DatabaseSync } = await import('node:sqlite');
    const db = new DatabaseSync(path);
    db.exec('CREATE TABLE akac_state (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)');
    db.prepare('INSERT INTO akac_state(id,body) VALUES(1,?)').run(JSON.stringify(world())); db.close();
    const store = new SqliteStore(path);
    try {
      assert.ok(await store.ready());
      assert.ok((await new Engine(store).openContext(bindings.chief, ['strategy'], 'work')).ok);
      assert.equal(await store.transaction('other', async tx => tx.state.actors['other-sec']?.tenant), 'other');
      assert.equal(await store.transaction('acme', async tx => tx.state.actors['other-sec']), undefined);
    } finally { await store.close(); }
    const again = new SqliteStore(path); assert.ok(await again.ready()); await again.close();
  } finally { rmSync(dir, { recursive: true }); }
});

/** Fails the next `failures` transactions after their body ran. */
class FlakyStore extends MemoryStore {
  failures = 0;
  async transaction<T>(tenant: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    if (this.failures > 0) { this.failures--; return super.transaction(tenant, async tx => { await fn(tx); throw new Error('synthetic store failure'); }); }
    return super.transaction(tenant, fn);
  }
}
test('store errors inside control-plane and engine transactions are audited as DEFERRED:STORE_ERROR and rethrown', async () => {
  const store = new FlakyStore(world());
  const control = new ControlPlane(store), engine = new Engine(store);
  store.failures = 1;
  await assert.rejects(control.upsertActor('acme', 'sec', user('newbie', [])), /synthetic store failure/);
  let entry = last(await audits(store));
  assert.deepEqual([entry.operation, entry.actor, entry.decision, entry.reason], ['upsert_actor', 'sec', 'deny', 'DEFERRED:STORE_ERROR']);
  assert.deepEqual(await control.readActor('acme', 'sec', 'newbie'), { ok: true, value: null }, 'the failed write was rolled back');
  store.failures = 1;
  await assert.rejects(engine.openContext(bindings.intern, ['handbook'], 'work'), /synthetic store failure/);
  entry = last(await audits(store));
  assert.deepEqual([entry.operation, entry.actor, entry.decision, entry.reason], ['read', 'intern', 'deny', 'DEFERRED:STORE_ERROR']);
});

// ---- Finding 1: hydration never requests what cannot contribute -------------

test('hydration does not request roles of inactive groups or juniors of inactive roles', async () => {
  const full = world();
  full.groups.retired = { id: 'retired', tenant: 'acme', members: ['intern'], roles: Array.from({ length: 600 }, (_, i) => `legacy-${i}`), active: false };
  full.roles.dormant = { id: 'dormant', tenant: 'acme', inherits: ['junior-of-dormant'], active: false };
  full.actors.intern!.roles = ['staff', 'dormant'];
  const requested = new Set<string>();
  const state: State = { ...emptyState(), policyVersion: full.policyVersion };
  const tx: Tx = { state, complete: false, load: async (need: Need) => {
    for (const r of need.roles ?? []) { requested.add(r); if (full.roles[r]) state.roles[r] = full.roles[r]!; }
    for (const a of need.actors ?? []) if (full.actors[a]) state.actors[a] = full.actors[a]!;
    for (const m of need.memberships ?? []) for (const g of Object.values(full.groups)) if (g.members.includes(m)) state.groups[g.id] = g;
  } };
  await hydrate(tx, { actors: ['intern'] });
  assert.ok(requested.has('dormant') && requested.has('staff'));
  assert.ok(![...requested].some(r => r.startsWith('legacy-') || r === 'junior-of-dormant'), [...requested].join());
});

// ---- Finding 3: reductions always succeed; holder checks --------------------

test('SCIM DELETE and PATCH active=false succeed for a user who already violates static SoD, and DELETE revokes', async () => {
  const s = world();
  s.actors.bob = user('bob', ['requester', 'approver']); s.actors.carol = user('carol', ['requester', 'approver']);
  const store = new MemoryStore(s), control = new ControlPlane(store, { clock: () => now }), scim = createScim(control);
  const epoch = () => store.transaction('acme', async tx => tx.state.epochs.acme ?? 0);
  const run = (method: string, path: string, body?: unknown) => scim.match(method, path, new URLSearchParams())!.run({ tenant: 'acme', admin: 'sec', params: [], body, query: new URLSearchParams() });
  const before = await epoch();
  assert.equal((await run('DELETE', '/scim/v2/Users/bob')).status, 204);
  assert.equal(((await control.readActor('acme', 'sec', 'bob')) as { value: Actor }).value.active, false);
  assert.ok(await epoch() > before, 'deprovisioning advances the tenant epoch');
  const patch = await run('PATCH', '/scim/v2/Users/carol', { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'active', value: false }] });
  assert.equal(patch.status, 200);
  // Other pure reductions of a violating principal also succeed; widening does not.
  s.actors.dave = user('dave', ['requester', 'approver', 'staff']);
  const store2 = new MemoryStore(s), control2 = new ControlPlane(store2, { clock: () => now });
  assert.ok((await control2.upsertActor('acme', 'sec', user('dave', ['requester', 'approver'], { clearance: 'internal' }))).ok, 'dropping a role and lowering clearance');
  assert.equal((await control2.upsertActor('acme', 'sec', user('dave', ['requester', 'approver'], { projects: ['alpha'] }))).ok, false, 'adding a project is not a reduction');
  assert.ok((await control2.assignRoles('acme', 'sec', 'dave', ['requester'])).ok);
  // A group change is not blocked by a member who was already invalid.
  s.groups.team = { id: 'team', tenant: 'acme', members: ['bob'], roles: [], active: true };
  const control3 = new ControlPlane(new MemoryStore(s), { clock: () => now });
  assert.ok((await control3.upsertGroup('acme', 'sec', { id: 'team', tenant: 'acme', members: ['bob', 'intern'], roles: ['staff'], active: true })).ok);
});

test('constraint and role changes that would invalidate current holders are refused with a count only', async () => {
  const s = world(); s.actors.payer = user('payer', ['approver']);
  const { call, control, stop } = await start({ state: s });
  try {
    const response = await call(tokens.sec, 'PUT', '/admin/v1/constraints/ssd-lead', { kind: 'static', roles: ['staff', 'project'], cardinality: 2 });
    assert.equal(response.status, 409);
    const body = await response.json() as Record<string, unknown>;
    assert.deepEqual(body, { ok: false, code: 'SOD_VIOLATION', holders: 2 }, 'lead and lead-agent, by count only');
    assert.ok((await control.upsertConstraint('acme', 'sec', { id: 'dsd-lead', tenant: 'acme', kind: 'dynamic', roles: ['staff', 'project'], cardinality: 2 })).ok, 'dynamic constraints do not affect standing');
    // Giving `approver` the junior `requester` would put `payer` into ssd-payments.
    const role = await control.upsertRole('acme', 'sec', { id: 'approver', tenant: 'acme', inherits: ['requester'], active: true });
    assert.deepEqual(role, { ok: false, code: 'SOD_VIOLATION', holders: 1 });
    assert.ok((await control.upsertRole('acme', 'sec', { id: 'approver', tenant: 'acme', inherits: [], active: false })).ok, 'deactivation always succeeds');
    const log = (await control.auditLog('acme', 'aud')) as { value: Audit[] };
    assert.ok(!JSON.stringify(log.value).includes('payer'), 'holders are never named');
  } finally { await stop(); }
});

// ---- Finding 4: transitive classification ------------------------------------

test('supplemental policy sees the highest classification over the source graph, and ingestion refuses a document below its sources', async () => {
  const s = world();
  s.knowledge.summary = { id: 'summary', tenant: 'acme', version: 1, kind: 'document', origin: 'system', content: 'Summary of the alpha schedule.',
    classification: 'public', projects: [], readerRoles: ['executive'], readers: [], sources: [{ id: 'project-alpha', version: 1 }], active: true };
  const seen: string[] = [];
  const engine = new Engine(new MemoryStore(s), { policy: { revision: 'test-transitive', check: async input => { seen.push(input.classification); return input.classification === 'public'; } } });
  assert.equal((await engine.openContext(bindings.chief, ['summary'], 'work')).ok, false);
  assert.deepEqual(seen, ['confidential']);

  const control = new ControlPlane(new MemoryStore(world()), { clock: () => now });
  const doc = (id: string, classification: Knowledge['classification'], sources: Knowledge['sources']): Knowledge => ({ id, tenant: 'acme', version: 1, kind: 'document', origin: 'human',
    content: 'Synthetic digest.', classification, projects: [], readerRoles: ['executive'], readers: [], sources, active: true });
  assert.deepEqual(await control.upsertKnowledge('acme', 'kbadm', doc('d1', 'public', [{ id: 'project-alpha', version: 1 }])), { ok: false, code: 'INVALID_REQUEST' });
  assert.deepEqual(await control.upsertKnowledge('acme', 'kbadm', doc('d2', 'internal', [{ id: 'vault-memo', version: 1 }])), { ok: false, code: 'INVALID_REQUEST' }, 'container floor of a source counts');
  assert.deepEqual(await control.upsertKnowledge('acme', 'kbadm', doc('d3', 'confidential', [{ id: 'project-alpha', version: 2 }])), { ok: false, code: 'INVALID_REQUEST' }, 'sources must resolve');
  assert.ok((await control.upsertKnowledge('acme', 'kbadm', doc('d4', 'confidential', [{ id: 'project-alpha', version: 1 }]))).ok);
  assert.ok((await control.upsertKnowledge('acme', 'kbadm', { ...doc('d5', 'internal', [{ id: 'vault-memo', version: 1 }]), container: 'f-vault' })).ok, 'an equal container floor suffices');
});

// ---- Finding 5: idempotent replays are audited ------------------------------

test('admin API: idempotent replays, key reuse and in-flight duplicates are audited and re-authorized', async () => {
  const { call, control, stop } = await start();
  const grant = { id: 'g-replay', subject: 'intern', agent: 'intern-agent', actions: ['read'], resources: ['handbook'], purposes: ['work'],
    notBefore: Date.now() - 1000, expiresAt: Date.now() + 3_600_000, active: true };
  try {
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/grants', grant, { 'idempotency-key': 'k-audit' })).status, 201);
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/grants', grant, { 'idempotency-key': 'k-audit' })).status, 201);
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/grants', { ...grant, resources: ['*'] }, { 'idempotency-key': 'k-audit' })).status, 422);
    const log = (await control.auditLog('acme', 'aud')) as { value: Audit[] };
    const grants = log.value.filter(e => e.operation === 'issue_grant').map(e => `${e.decision}:${e.reason}`);
    assert.deepEqual(grants, ['allow:AUTHORIZED', 'allow:IDEMPOTENT_REPLAY', 'deny:DENIED:IDEMPOTENCY_KEY_REUSED']);
    assert.ok((await control.assignRoles('acme', 'sec', 'sec', [])).ok, 'the administrator gives up security-admin');
    assert.equal((await call(tokens.sec, 'POST', '/admin/v1/grants', grant, { 'idempotency-key': 'k-audit' })).status, 403, 'a replay is re-authorized');
  } finally { await stop(); }
});

// ---- Finding 6: kb-admin removes documents with the real ingestor ------------

test('admin API with the real Ingestor: a kb-admin removes a document; chunks go, the epoch advances, the removal is audited', async () => {
  const store = new MemoryStore(world()), control = new ControlPlane(store), index = new MemoryVectorIndex();
  const ingestor = new Ingestor({ control, store, index, embedder: new HashEmbedder(256) });
  const admin = createAdminGateway(control, { ingestor, credentials: [{ token: tokens.kb, binding: { tenant: 'acme', admin: 'kbadm' } }, { token: tokens.sec, binding: { tenant: 'acme', admin: 'sec' } }] });
  const base = await listen(admin);
  const call = (token: string, method: string, path: string, body?: unknown) => fetch(base + path, { method,
    headers: { authorization: `Bearer ${token}`, ...(body ? { 'content-type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  try {
    const doc = { version: 1, kind: 'document', origin: 'human', content: 'Synthetic retention note for removal.', classification: 'internal', projects: [], readerRoles: ['staff'], readers: [], sources: [], active: true };
    const put = await call(tokens.kb, 'PUT', '/admin/v1/knowledge/retention', doc);
    assert.equal(put.status, 200); assert.ok(((await put.json()) as { value: { chunks: number } }).value.chunks > 0);
    assert.ok((await index.state('acme')).has('retention'));
    const epoch = await store.transaction('acme', async tx => tx.state.epochs.acme ?? 0);
    assert.equal((await call(tokens.sec, 'DELETE', '/admin/v1/knowledge/retention')).status, 403, 'security-admin alone does not manage documents');
    const removed = await call(tokens.kb, 'DELETE', '/admin/v1/knowledge/retention');
    assert.equal(removed.status, 200);
    assert.deepEqual(await removed.json(), { ok: true, value: { id: 'retention', epoch: epoch + 1 } });
    assert.equal((await index.state('acme')).has('retention'), false);
    assert.equal(await store.transaction('acme', async tx => tx.state.knowledge.retention!.active), false);
    const entry = (await store.auditLog('acme')).filter(e => e.operation === 'remove_knowledge').map(e => `${e.actor}:${e.decision}:${e.reason}`);
    assert.deepEqual(entry, ['sec:deny:DENIED:NOT_ADMIN', 'kbadm:allow:AUTHORIZED']);
    assert.equal((await call(tokens.kb, 'DELETE', '/admin/v1/knowledge/strategy-missing')).status, 400);
  } finally { await close(admin); }
});

// ---- Finding 7: lexical content budget ---------------------------------------

test('lexical retrieval refuses a corpus above the content byte budget (deferred, audited)', async () => {
  const store = new MemoryStore(world());
  assert.ok((await new Engine(store).retrieve(bindings.intern, 'product', 'work')).ok, 'within the default budget');
  const tight = new Engine(store, { contentBytes: 64 });
  assert.equal((await tight.retrieve(bindings.intern, 'product', 'work')).ok, false);
  const entry = last(await audits(store));
  assert.deepEqual([entry.operation, entry.reason], ['retrieve', 'DEFERRED:BUDGET_EXCEEDED']);
  assert.throws(() => new Engine(store, { contentBytes: -1 }), /content budget/);
});
