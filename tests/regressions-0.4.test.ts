// Regression tests for defects found in the 0.4 pre-release review (CHANGELOG 0.4.0, Security).
// Each test failed before its fix. PostgreSQL persistence of `revokedAt` is covered by the
// shared column mapping (adapters/postgres.ts) and migration 005.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Engine } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { ProtectedRuntime } from '../reference/runtime.ts';
import { MemoryStore, SqliteStore, importState } from '../reference/store.ts';
import { verifyAudit } from '../reference/audit.ts';
import { canonicalize } from '../reference/jcs.ts';
import { parseObligations, validObligation } from '../reference/decision.ts';
import type { Knowledge, PolicyHook, State, Store } from '../reference/types.ts';
import { bindings, fixture } from '../examples/fixture.ts';
import { destinationWorld, now } from './destinations-fixture.ts';

const restricting = (...lists: string[][]): PolicyHook => ({ revision: 'p1', check: async () => true,
  verdict: async () => ({ allow: true, obligations: lists.map(value => ({ type: 'destination_restricted', value })) }) });
const lastAudit = async (store: Store) => (await store.auditLog('acme')).at(-1)!;

// ---- Finding 1: a policy destination_restricted must admit the actual recipient -------------

test('release is denied when a policy destination_restricted excludes the recipient (unrestricted run)', async () => {
  const store = new MemoryStore(destinationWorld());
  const engine = new Engine(store, { clock: () => now, policy: restricting(['partner-x']) });
  const ctx = await engine.openContext(bindings.chief, ['handbook'], 'work');
  assert.ok(ctx.ok);
  // Implicit internal-user recipient, a principal without a profile, and a profiled service outside the list.
  for (const recipient of ['lead', 'intern-agent', 'legacy-svc', 'llm']) {
    const r = await engine.release(bindings.chief, ctx.value.context, recipient, 'x', 'share');
    assert.equal(r.ok, false, recipient);
    assert.equal((await lastAudit(store)).reasonCode, 'RECIPIENT');
  }
});

test('release is allowed when the policy restriction names the recipient; the result names the destination', async () => {
  const engine = new Engine(new MemoryStore(destinationWorld()), { clock: () => now, policy: restricting(['internal-user', 'eu-llm']) });
  const ctx = await engine.openContext(bindings.chief, ['handbook'], 'work');
  assert.ok(ctx.ok);
  const user = await engine.release(bindings.chief, ctx.value.context, 'lead', 'x', 'share');
  assert.ok(user.ok);
  assert.deepEqual(user.value.destination, { class: 'internal-user' });
  const provider = await engine.release(bindings.chief, ctx.value.context, 'llm', 'x', 'share');
  assert.ok(provider.ok);
  assert.deepEqual(provider.value.destination, { id: 'eu-llm', class: 'model-provider' });
  assert.deepEqual(provider.obligations.find(o => o.type === 'destination_restricted')?.value, ['eu-llm']);
  // Without any restriction the 0.3 result shape is unchanged (R64).
  const legacy = new Engine(new MemoryStore(destinationWorld()), { clock: () => now });
  const c2 = await legacy.openContext(bindings.chief, ['handbook'], 'work');
  assert.ok(c2.ok);
  const plain = await legacy.release(bindings.chief, c2.value.context, 'lead', 'x', 'share');
  assert.ok(plain.ok); assert.equal(plain.value.destination, undefined);
});

test('ProtectedRuntime and evaluate() agree with release() on a policy destination restriction', async () => {
  const provider = { principal: 'llm', generate: async () => 'synthetic answer' };
  const only = new Engine(new MemoryStore(destinationWorld()), { clock: () => now, policy: restricting(['eu-llm']) });
  // The provider is admitted, the subject (implicit internal-user) is not: no answer.
  assert.equal((await new ProtectedRuntime(only, provider).answer(bindings.chief, ['handbook'], 'work', 'summarize')).ok, false);
  const both = new Engine(new MemoryStore(destinationWorld()), { clock: () => now, policy: restricting(['eu-llm', 'internal-user']) });
  const answer = await new ProtectedRuntime(both, provider).answer(bindings.chief, ['handbook'], 'work', 'summarize');
  assert.ok(answer.ok, 'both destinations admitted: the runtime delivers');
  const denied = await only.evaluate(bindings.chief, 'handbook', 'share', 'work', { destination: 'crm-tool' });
  assert.deepEqual([denied.decision, denied.code], [false, 'RECIPIENT']);
  const allowed = await only.evaluate(bindings.chief, 'handbook', 'share', 'work', { destination: 'eu-llm' });
  assert.equal(allowed.decision, true);
});

// ---- Finding 4: conflicting destination restrictions are a clean, audited deny ------------------

test('conflicting destination_restricted obligations deny UNSUPPORTED_OBLIGATION with a well-formed audit entry', async () => {
  const store = new MemoryStore(fixture(now));
  const engine = new Engine(store, { clock: () => now, policy: restricting(['a'], ['b']) });
  const opened = await engine.openContext(bindings.chief, ['handbook'], 'work');
  assert.equal(opened.ok, false);
  assert.equal((await lastAudit(store)).reasonCode, 'UNSUPPORTED_OBLIGATION');
  const verdict = await engine.evaluate(bindings.chief, 'handbook', 'read', 'work');
  assert.deepEqual([verdict.decision, verdict.code], [false, 'UNSUPPORTED_OBLIGATION']);
  assert.ok(verifyAudit(await store.auditLog('acme')));
});

test('restrictions that conflict only across records of one operation also deny cleanly', async () => {
  const store = new MemoryStore(fixture(now));
  const policy: PolicyHook = { revision: 'p1', check: async () => true,
    verdict: async input => ({ allow: true, obligations: [{ type: 'destination_restricted', value: [input.classification === 'public' ? 'a' : 'b'] }] }) };
  const engine = new Engine(store, { clock: () => now, policy });
  const opened = await engine.openContext(bindings.chief, ['handbook', 'strategy'], 'work');
  assert.equal(opened.ok, false);
  assert.equal((await lastAudit(store)).reasonCode, 'UNSUPPORTED_OBLIGATION');
  assert.ok(verifyAudit(await store.auditLog('acme')));
});

// ---- Findings 2 and 3: security revocation and legal hold survive new document versions --------

const world = (): State => {
  const s = fixture(now);
  s.actors.kb = { id: 'kb', tenant: 'acme', kind: 'user', roles: ['kb-admin'], clearance: 'restricted', projects: [], active: true };
  return s;
};
const version = (existing: Knowledge, v: number, patch: Partial<Knowledge> = {}): Knowledge => {
  const { id, tenant, kind, origin, content, classification, readerRoles, projects, readers, sources } = existing;
  return { id, tenant, version: v, kind, origin, content, classification, readerRoles, projects, readers, sources, active: true, ...patch };
};
async function withStores(fn: (open: () => Promise<Store>) => Promise<void>) {
  for (const kind of ['memory', 'sqlite'] as const) {
    const dir = mkdtempSync(join(tmpdir(), 'akac-r04-'));
    const state = world();
    let store: Store | undefined;
    try {
      if (kind === 'memory') { const m = new MemoryStore(state); await fn(async () => m); }
      else {
        const first = new SqliteStore(join(dir, 's.sqlite')); await importState(first, state); await first.close();
        // Every open reads the durable file: markers must survive a restart.
        await fn(async () => { await store?.close(); store = new SqliteStore(join(dir, 's.sqlite')); return store; });
      }
    } finally { await store?.close(); rmSync(dir, { recursive: true, force: true }); }
  }
}
const record = async (store: Store, id: string) => store.transaction('acme', async tx => { await tx.load({ knowledge: [id] }); return structuredClone(tx.state.knowledge[id]!); });

test('a kb-admin cannot undo a security-admin revoke or revokeLineage with a new version; reinstate is security-admin only', async () => {
  await withStores(async open => {
    let store = await open();
    const cp = () => new ControlPlane(store, { clock: () => now });
    const strategy = await record(store, 'strategy');
    assert.ok((await cp().revokeLineage('acme', 'admin', 'strategy')).ok);
    store = await open();
    const re = await cp().upsertKnowledge('acme', 'kb', version(strategy, 2));
    assert.deepEqual([re.ok, !re.ok && re.code], [false, 'CONFLICT']);
    assert.equal((await lastAudit(store)).reasonCode, 'CONFLICT');
    // An inactive new version is accepted and keeps the marker.
    assert.ok((await cp().upsertKnowledge('acme', 'kb', version(strategy, 2, { active: false }))).ok);
    store = await open();
    const kept = await record(store, 'strategy');
    assert.equal(kept.revokedAt, now); assert.equal(kept.active, false);
    assert.equal((await cp().upsertKnowledge('acme', 'kb', version(strategy, 3))).ok, false);
    const engine = new Engine(store, { clock: () => now });
    assert.equal((await cp().issueGrant('acme', 'admin', { ...fixture(now).grants['chief-run']!, id: 'chief-run-2' })).ok, true);
    const fresh = { ...bindings.chief, grant: 'chief-run-2' };
    assert.equal((await engine.openContext(fresh, ['strategy'], 'work')).ok, false);
    // Reinstatement: kb-admin refused, security-admin allowed; then the kb-admin may publish again.
    assert.equal((await cp().reinstate('acme', 'kb', 'strategy')).ok, false);
    assert.ok((await cp().reinstate('acme', 'admin', 'strategy')).ok);
    store = await open();
    assert.equal((await record(store, 'strategy')).revokedAt, undefined);
    assert.ok((await cp().upsertKnowledge('acme', 'kb', version(strategy, 3))).ok);
    assert.ok((await new Engine(store, { clock: () => now }).openContext({ ...bindings.chief, grant: 'chief-run-2' }, ['strategy'], 'work')).ok);
  });
});

test('revoke(knowledge) sets the durable marker too; removeKnowledge (kb-admin) does not', async () => {
  await withStores(async open => {
    const store = await open(), cp = new ControlPlane(store, { clock: () => now });
    const handbook = await record(store, 'handbook');
    assert.ok((await cp.revoke('acme', 'admin', 'knowledge', 'handbook')).ok);
    assert.equal((await cp.upsertKnowledge('acme', 'kb', version(handbook, 2))).ok, false);
    const alpha = await record(store, 'project-alpha');
    assert.ok((await cp.removeKnowledge('acme', 'kb', 'project-alpha')).ok);
    assert.ok((await cp.upsertKnowledge('acme', 'kb', version(alpha, 2))).ok, 'a kb-admin retirement is reversible by the kb-admin');
  });
});

test('a legal hold preserves content: a new version that changes content or sources is CONFLICT (held), metadata may change', async () => {
  await withStores(async open => {
    let store = await open();
    const cp = () => new ControlPlane(store, { clock: () => now });
    const handbook = await record(store, 'handbook');
    assert.ok((await cp().setLegalHold('acme', 'admin', 'handbook', true, 'case-1')).ok);
    store = await open();
    const overwrite = await cp().upsertKnowledge('acme', 'kb', version(handbook, 2, { content: 'x' }));
    assert.deepEqual(overwrite, { ok: false, code: 'CONFLICT', held: 1, decisionId: overwrite.decisionId });
    assert.equal((await record(store, 'handbook')).content, handbook.content);
    const resourced = await cp().upsertKnowledge('acme', 'kb', version(handbook, 2, { sources: [{ id: 'project-alpha', version: 1 }] }));
    assert.deepEqual([resourced.ok, !resourced.ok && resourced.code, !resourced.ok && resourced.held], [false, 'CONFLICT', 1]);
    // Same content and sources, narrower readers: allowed; the hold is kept.
    assert.ok((await cp().upsertKnowledge('acme', 'kb', version(handbook, 2, { readers: ['chief'] }))).ok);
    store = await open();
    const after = await record(store, 'handbook');
    assert.deepEqual([after.version, after.content, after.legalHolds], [2, handbook.content, ['case-1']]);
    // Once the hold is lifted the content may change again.
    assert.ok((await cp().setLegalHold('acme', 'admin', 'handbook', false, 'case-1')).ok);
    assert.ok((await cp().upsertKnowledge('acme', 'kb', version(handbook, 3, { content: 'Revised synthetic handbook.' }))).ok);
  });
});

// ---- Finding 6: sparse arrays -------------------------------------------------------------------

test('JCS rejects sparse arrays; obligation validation rejects holes', () => {
  // eslint-disable-next-line no-sparse-arrays
  assert.throws(() => canonicalize([1, , 2]), /sparse/);
  const holes = new Array(2); holes[0] = 'a';
  assert.throws(() => canonicalize(holes));
  assert.equal(canonicalize([1, null, 2]), '[1,null,2]');
  const dest = ['a', 'b']; delete (dest as unknown as Record<number, unknown>)[1];
  assert.equal(validObligation({ type: 'destination_restricted', value: dest }), false);
  const list: unknown[] = [{ type: 'no_persist' }]; list.length = 2;
  assert.equal(parseObligations(list), null);
  assert.equal(parseObligations([{ type: 'destination_restricted', value: ['a'] }, { type: 'destination_restricted', value: ['b'] }]), null);
});
