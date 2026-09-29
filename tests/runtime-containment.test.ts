// Runtime containment contract (AKAC 0.5 draft, ADR-012, spec/drafts/0.5-runtime-containment.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { Engine } from '../reference/engine.ts';
import { createGateway } from '../reference/http.ts';
import { ControlPlane } from '../reference/control.ts';
import { ProtectedRuntime, RUNTIME_OBLIGATIONS } from '../reference/runtime.ts';
import type { RuntimeEnforcer, RuntimeProfileRef } from '../reference/runtime.ts';
import { AuthzenPdp, mapEvaluation, render } from '../reference/authzen.ts';
import { MemoryStore, SqliteStore, importState } from '../reference/store.ts';
import { containment, containmentAcross } from '../reference/containment.ts';
import { enforceable, merge, parseObligations } from '../reference/decision.ts';
import type { Obligation } from '../reference/decision.ts';
import { verifyAudit } from '../reference/audit.ts';
import { RUNTIME_PROFILE_LIMIT } from '../reference/types.ts';
import type { RuntimeProfilePolicy, State } from '../reference/types.ts';
import { runRuntimeVectors } from '../conformance/run-runtime.ts';
import { runAll, report } from '../conformance/run.ts';
import { exitCode } from '../conformance/outcome.ts';
import { bindings } from '../examples/fixture.ts';
import { start, tokens, world } from './support.ts';

const policy = (id: string, classification: RuntimeProfilePolicy['classification'], profiles: RuntimeProfilePolicy['profiles'], extra: Partial<RuntimeProfilePolicy> = {}): RuntimeProfilePolicy =>
  ({ id, tenant: 'acme', classification, ...extra, profiles, active: true });
const TIERS = [policy('rt-public', 'public', { tool: 'read-only-http' }), policy('rt-confidential', 'confidential', { network: 'internal-only', filesystem: 'read-only-workspace' }),
  policy('rt-restricted', 'restricted', { network: 'deny-all', filesystem: 'workspace-only', credential: 'none' })];
function contained(state: State = world()): State {
  state.runtimeProfiles = Object.fromEntries(TIERS.map(p => [p.id, structuredClone(p)]));
  state.destinations = { 'llm-eu': { id: 'llm-eu', tenant: 'acme', class: 'model-provider', maxClassification: 'restricted', purposes: ['work'], active: true } };
  state.actors.provider = { id: 'provider', tenant: 'acme', kind: 'service', roles: ['staff', 'executive', 'project'], projects: ['alpha'], clearance: 'restricted', active: true, destination: 'llm-eu' };
  return state;
}
const runtimeOnly = (o: readonly Obligation[]) => o.filter(x => x.type === 'runtime_profile' || x.type === 'max_output_classification');
const schema = (name: string) => JSON.parse(readFileSync(new URL(`../schemas/${name}.json`, import.meta.url), 'utf8'));

test('runtime containment conformance vectors pass (conformance/vectors-runtime.json)', async () => {
  const rows = await runRuntimeVectors();
  assert.ok(rows.length >= 30);
  for (const r of rows) assert.ok(r.pass && (r.outcome === 'SUCCESS' || r.outcome === 'SAFE_BLOCK'), `${r.id}: ${r.outcome}`);
  assert.ok(rows.some(r => r.outcome === 'SAFE_BLOCK') && rows.some(r => r.outcome === 'SUCCESS'));
});

test('broken oracles are reported: dropped profiles and a runtime that skips its enforcer are UNSAFE_SUCCESS, blanket deny is FAILURE', async () => {
  const dropped = await runRuntimeVectors({ containment: () => ({ ok: true, obligations: [] }) });
  assert.ok(dropped.some(r => r.outcome === 'UNSAFE_SUCCESS'), 'a derivation that drops every profile leaks containment');
  const lowered: typeof containment = (s, tenant, level, destination) => {
    const c = containment(s, tenant, level, destination);
    return c.ok ? { ok: true, obligations: c.obligations.map(o => o.type === 'max_output_classification' ? { ...o, value: 'public' } : o) } : c;
  };
  assert.ok((await runRuntimeVectors({ containment: lowered })).some(r => r.id === 'RTC-P07' && r.outcome === 'UNSAFE_SUCCESS'), 'a lowered output label is unsafe');
  // A runtime that calls the provider without consulting any enforcer.
  class Skipping {
    private provider: { generate: (r: never) => Promise<string> };
    constructor(_engine: Engine, provider: { generate: (r: never) => Promise<string> }) { this.provider = provider; }
    async answer() { await this.provider.generate({} as never); return { ok: false as const, code: 'NOT_AUTHORIZED' as const, decisionId: '' }; }
  }
  const skipping = await runRuntimeVectors({ runtime: Skipping as unknown as typeof ProtectedRuntime });
  assert.ok(skipping.some(r => r.id === 'RTC-R01' && r.outcome === 'UNSAFE_SUCCESS'), 'a provider call without enforcement is unsafe');
  const blanket = await runRuntimeVectors({ containment: () => ({ ok: false, reason: 'DENIED:UNSUPPORTED_OBLIGATION' }) });
  assert.ok(blanket.some(r => r.outcome === 'FAILURE') && !blanket.some(r => r.outcome === 'UNSAFE_SUCCESS'), 'blanket deny is a failure, not safe');
  const all = report(await runAll({ runtime: { containment: () => ({ ok: true, obligations: [] }) } }));
  assert.equal(exitCode(all.summary), 1, 'the runner exits non-zero');
});

test('obligations: runtime_profile per domain, conflicts unsatisfiable, output label merges to the highest', () => {
  const a: Obligation = { type: 'runtime_profile', domain: 'network', profile: 'deny-all' };
  const b: Obligation = { type: 'runtime_profile', domain: 'network', profile: 'internal-only' };
  const f: Obligation = { type: 'runtime_profile', domain: 'filesystem', profile: 'workspace-only' };
  assert.deepEqual(parseObligations([f, a, a]), [a, f], 'canonical domain order, duplicates collapse');
  assert.equal(parseObligations([a, b]), null, 'two profiles for one domain are unsatisfiable');
  assert.equal(enforceable([a, b], ['runtime_profile']), false);
  assert.equal(enforceable([a], ['audit_level']), false, 'an unsupported type denies');
  assert.equal(enforceable([a, f], ['runtime_profile']), true);
  assert.deepEqual(merge([{ type: 'max_output_classification', value: 'internal' }], [{ type: 'max_output_classification', value: 'restricted' }]), [{ type: 'max_output_classification', value: 'restricted' }]);
  for (const bad of [{ type: 'runtime_profile', domain: 'gpu', profile: 'x' }, { type: 'runtime_profile', domain: 'network', profile: 'has space' },
    { type: 'runtime_profile', domain: 'network', profile: 'x', params: {} }, { type: 'max_output_classification', value: 'secret' }]) assert.equal(parseObligations([bad]), null, JSON.stringify(bad));
  // The 0.4 runtime list stays unchanged, so runtimes reusing it deny the new obligations (fail closed).
  assert.equal(RUNTIME_OBLIGATIONS.includes('runtime_profile'), false);
  assert.equal(enforceable([a], RUNTIME_OBLIGATIONS), false);
});

test('a supplemental policy may add runtime profiles; a conflict with the tenant policy denies UNSUPPORTED_OBLIGATION', async () => {
  const run = async (obligations: unknown[]) => {
    const store = new MemoryStore(contained());
    const engine = new Engine(store, { policy: { revision: 'test/rtc', check: async () => true, verdict: async () => ({ allow: true, obligations }) } });
    const r = await engine.openContext(bindings.chief, ['strategy'], 'work');
    return { r, code: (await store.auditLog('acme')).at(-1)!.reasonCode };
  };
  const same = await run([{ type: 'runtime_profile', domain: 'network', profile: 'deny-all' }]);
  assert.ok(same.r.ok);
  const conflict = await run([{ type: 'runtime_profile', domain: 'network', profile: 'internal-only' }]);
  assert.equal(conflict.r.ok, false); assert.equal(conflict.code, 'UNSUPPORTED_OBLIGATION');
});

test('control plane: security-admin only, validated, audited, epoch advance on every change; auditor reads; tenant isolation; bounded', async () => {
  const store = new MemoryStore(world()), control = new ControlPlane(store);
  const epoch = async () => (await store.auditLog('acme')).at(-1)!.epoch;
  const p = policy('rt-a', 'confidential', { network: 'internal-only' });
  assert.equal((await control.upsertRuntimeProfile('acme', 'kbadm', p)).ok, false, 'kb-admin cannot');
  assert.equal((await control.upsertRuntimeProfile('acme', 'aud', p)).ok, false, 'auditor cannot');
  assert.equal((await control.upsertRuntimeProfile('acme', 'intern-agent', p)).ok, false, 'an agent cannot');
  for (const bad of [{ ...p, profiles: {} }, { ...p, profiles: { network: 'allow all' } }, { ...p, profiles: { gpu: 'x' } }, { ...p, classification: 'secret' },
    { ...p, destinationClass: 'partner' }, { ...p, tenant: 'other' }, { ...p, policy: 'raw vendor text' }]) {
    const r = await control.upsertRuntimeProfile('acme', 'sec', bad as never);
    assert.equal(r.ok ? 'ok' : r.code, 'INVALID_REQUEST', JSON.stringify(bad));
  }
  const before = await epoch();
  const created = await control.upsertRuntimeProfile('acme', 'sec', p);
  assert.ok(created.ok); assert.equal(created.value.epoch, before + 1, 'creation advances the epoch');
  const entry = (await store.auditLog('acme')).at(-1)!;
  assert.equal(entry.operation, 'upsert_runtime_profile'); assert.equal(entry.decision, 'allow'); assert.equal(entry.actor, 'sec');
  const updated = await control.upsertRuntimeProfile('acme', 'sec', { ...p, active: false });
  assert.ok(updated.ok); assert.equal(updated.value.epoch, before + 2, 'a widening (deactivation) is a privileged, audited change that advances the epoch');
  const read = await control.readRuntimeProfile('acme', 'aud', 'rt-a');
  assert.ok(read.ok); assert.deepEqual(read.value, { ...p, active: false });
  const foreign = await control.readRuntimeProfile('other', 'other-sec', 'rt-a');
  assert.ok(foreign.ok); assert.equal(foreign.value, null, 'another tenant reads it as absent');
  assert.equal((await control.readRuntimeProfile('acme', 'kbadm', 'rt-a')).ok, false);
  await store.transaction('acme', async tx => {
    for (let i = 0; i < RUNTIME_PROFILE_LIMIT - 1; i++) tx.state.runtimeProfiles![`bulk-${i}`] = policy(`bulk-${i}`, 'public', { tool: 'read-only-http' }, { active: false });
  });
  const full = await control.upsertRuntimeProfile('acme', 'sec', policy('rt-over', 'public', { tool: 'x' }));
  assert.equal(full.ok ? 'ok' : full.code, 'CONFLICT', 'the per-tenant bound is enforced');
  assert.ok((await control.upsertRuntimeProfile('acme', 'sec', { ...p, active: true })).ok, 'updating an existing record stays possible at the bound');
});

test('a runtime profile change ends open contexts (stale authorization)', async () => {
  const store = new MemoryStore(world()), engine = new Engine(store), control = new ControlPlane(store);
  const context = await engine.openContext(bindings.chief, ['strategy'], 'work');
  assert.ok(context.ok); assert.deepEqual(runtimeOnly(context.obligations), [], 'no policy: no runtime obligation');
  assert.ok((await control.upsertRuntimeProfile('acme', 'sec', TIERS[2]!)).ok);
  const derived = await engine.derive(bindings.chief, context.value.context, 'Synthetic note');
  assert.equal(derived.ok, false, 'the context opened without the profile is stale');
  assert.equal((await store.auditLog('acme')).at(-1)!.reasonCode, 'STALE_CONTEXT');
});

test('ProtectedRuntime applies exactly the governing profiles before the provider and records the revision; the answer carries the output label', async () => {
  const store = new MemoryStore(contained()), engine = new Engine(store);
  const order: string[] = [];
  let applied: readonly RuntimeProfileRef[] = [];
  const enforcer: RuntimeEnforcer = {
    supports: () => true,
    apply: async (profiles, { executionId }) => { order.push('apply'); applied = profiles; held = executionId; return { runtimeRevision: 'sandbox-rev-42', release: async () => { order.push('release'); } }; },
    current: executionId => { order.push('current'); return executionId === held ? 'sandbox-rev-42' : undefined; }
  };
  let held = '';
  const runtime = new ProtectedRuntime(engine, { principal: 'provider', generate: async () => { order.push('provider'); return 'Synthetic answer'; } }, { enforcer });
  const r = await runtime.answer(bindings.chief, ['strategy'], 'work', 'Summarize', { trace: { traceId: '4bf92f3577b34da6a3ce929d0e0e4736', executionId: 'job-17', runtimeRevision: 'forged' } });
  assert.ok(r.ok);
  // The revision is checked before and again after the final release (R124), then the lease is released.
  assert.deepEqual(order, ['apply', 'provider', 'current', 'current', 'release']);
  assert.equal(held, 'job-17', 'the enforcer is scoped to the caller execution id');
  assert.deepEqual(applied, [{ domain: 'network', profile: 'deny-all' }, { domain: 'filesystem', profile: 'workspace-only' }, { domain: 'tool', profile: 'read-only-http' }, { domain: 'credential', profile: 'none' }]);
  assert.ok(r.obligations.some(o => o.type === 'max_output_classification' && o.value === 'restricted'));
  const log = await store.auditLog('acme');
  const [ctx, gate, answer] = log.slice(-3);
  assert.deepEqual([ctx!.operation, gate!.operation, answer!.operation], ['read', 'share', 'share']);
  for (const e of [ctx!, gate!, answer!]) { assert.equal(e.executionId, 'job-17'); assert.equal(e.traceId, '4bf92f3577b34da6a3ce929d0e0e4736'); }
  assert.equal(answer!.runtimeRevision, 'sandbox-rev-42', 'the enforcer revision is recorded on the answer');
  assert.ok(!log.some(e => e.runtimeRevision === 'forged'), 'a caller-supplied revision is never recorded');
  assert.equal(ctx!.runtimeRevision, undefined);
  assert.ok(verifyAudit(log));
});

test('ProtectedRuntime: a slow enforcer is a deny before the provider', async () => {
  const store = new MemoryStore(contained()), engine = new Engine(store);
  let called = false;
  const slow: RuntimeEnforcer = { supports: () => true, apply: () => new Promise(() => {}), current: () => undefined };
  const provider = { principal: 'provider', generate: async () => { called = true; return 'x'; } };
  const r = await new ProtectedRuntime(engine, provider, { enforcer: slow, enforcerDeadlineMs: 20 }).answer(bindings.chief, ['strategy'], 'work', 'Summarize');
  assert.equal(r.ok, false); assert.equal(called, false);
  assert.throws(() => new ProtectedRuntime(engine, provider, { enforcerDeadlineMs: 0 }));
});

test('audit correlation: execution id and runtime revision are format 2 optional members; old entries still verify; schemas accept them', async () => {
  const store = new MemoryStore(contained()), engine = new Engine(store);
  await engine.openContext(bindings.intern, ['handbook'], 'work');
  await engine.openContext(bindings.intern, ['handbook'], 'work', { trace: { executionId: 'sandbox:7f3a', runtimeRevision: 'rev-9' } });
  await engine.openContext(bindings.intern, ['handbook'], 'work', { trace: { executionId: 'not valid!', runtimeRevision: 'x'.repeat(129) } });
  const log = await store.auditLog('acme');
  const [plain, correlated, invalid] = log.slice(-3);
  assert.equal(plain!.executionId, undefined); assert.equal(correlated!.executionId, 'sandbox:7f3a'); assert.equal(correlated!.runtimeRevision, 'rev-9');
  assert.equal(invalid!.executionId, undefined, 'invalid values are ignored, never recorded'); assert.equal(invalid!.runtimeRevision, undefined);
  assert.ok(verifyAudit(log));
  const tampered = structuredClone(log); tampered.at(-2)!.executionId = 'other';
  assert.equal(verifyAudit(tampered), false, 'the members are covered by the hash');
  const ajv = new Ajv2020().addSchema(schema('obligation'));
  const audit = ajv.compile(schema('audit'));
  for (const e of log) assert.ok(audit(e), JSON.stringify(audit.errors));
  assert.equal(audit({ ...correlated, executionId: 'bad id' }), false);
  const profile = new Ajv2020().compile(schema('runtime-profile'));
  for (const p of TIERS) assert.ok(profile(p), JSON.stringify(profile.errors));
  assert.equal(profile({ ...TIERS[0], profiles: {} }), false);
  assert.equal(profile({ ...TIERS[0], profiles: { network: 'x', shell: 'y' } }), false);
});

test('HTTP: x-akac-execution-id is recorded; a malformed one is refused; a runtime revision is never taken from an agent request', async () => {
  const t = await start({ state: contained(), agent: { runtimeObligations: 'trusted-enforcer' } });
  try {
    const post = (headers: Record<string, string>) => t.call(tokens.intern, 'POST', '/v1/contexts', { resources: ['handbook'], purpose: 'work' }, headers, t.agentUrl);
    const ok = await post({ 'x-akac-execution-id': 'job-42', 'x-akac-runtime-revision': 'forged-rev' });
    assert.equal(ok.status, 200);
    const body = await ok.json() as { obligations: Obligation[] };
    assert.deepEqual(runtimeOnly(body.obligations), [{ type: 'runtime_profile', domain: 'tool', profile: 'read-only-http' }, { type: 'max_output_classification', value: 'public' }]);
    const entry = (await t.store.auditLog('acme')).at(-1)!;
    assert.equal(entry.executionId, 'job-42'); assert.equal(entry.runtimeRevision, undefined);
    assert.equal((await post({ 'x-akac-execution-id': 'has space' })).status, 400);
    const admin = await t.call(tokens.sec, 'GET', '/admin/v1/runtime-profiles/rt-public', undefined, { 'x-akac-execution-id': 'change-7' });
    assert.equal(admin.status, 200);
    assert.equal((await t.store.auditLog('acme')).at(-1)!.executionId, 'change-7');
    assert.equal((await t.call(tokens.sec, 'GET', '/admin/v1/audit', undefined, { 'x-akac-execution-id': '../x' })).status, 400);
  } finally { await t.stop(); }
});

test('regression: the agent listener denies disclosures carrying runtime_profile unless declared behind an enforcer (R123)', async () => {
  // Default 'deny': an allow that would carry runtime_profile is refused, rolled back and audited as a denial.
  const t = await start({ state: contained() });
  try {
    const post = (path: string, body: unknown) => t.call(tokens.intern, 'POST', path, body, { 'x-akac-execution-id': 'job-7' }, t.agentUrl);
    const denied = await post('/v1/contexts', { resources: ['handbook'], purpose: 'work' });
    assert.equal(denied.status, 403);
    const body = await denied.json() as Record<string, unknown>;
    assert.deepEqual(Object.keys(body).sort(), ['code', 'decisionId', 'ok']); assert.equal(body.code, 'NOT_AUTHORIZED');
    const entry = (await t.store.auditLog('acme')).at(-1)!;
    assert.equal(entry.decision, 'deny'); assert.equal(entry.reason, 'DENIED:UNSUPPORTED_OBLIGATION'); assert.equal(entry.decisionId, body.decisionId);
    assert.equal(entry.executionId, 'job-7'); assert.deepEqual(entry.obligations, []);
    await t.store.transaction('acme', async tx => { assert.equal(Object.keys(tx.state.contexts).length, 0, 'no context persisted'); });
    assert.equal((await post('/v1/retrieve', { query: 'handbook', purpose: 'work' })).status, 403);
    assert.ok(verifyAudit(await t.store.auditLog('acme')));
  } finally { await t.stop(); }
  // A tenant without runtime profile policies is unaffected by the default.
  const plain = await start();
  try { assert.equal((await plain.call(tokens.intern, 'POST', '/v1/contexts', { resources: ['handbook'], purpose: 'work' }, {}, plain.agentUrl)).status, 200); }
  finally { await plain.stop(); }
  // 'trusted-enforcer': the operator declares an enforcer; the obligations are returned to it.
  const trusted = await start({ state: contained(), agent: { runtimeObligations: 'trusted-enforcer' } });
  try {
    const ok = await trusted.call(tokens.intern, 'POST', '/v1/contexts', { resources: ['handbook'], purpose: 'work' }, {}, trusted.agentUrl);
    assert.equal(ok.status, 200);
    assert.ok((await ok.json() as { obligations: Obligation[] }).obligations.some(o => o.type === 'runtime_profile'));
  } finally { await trusted.stop(); }
  assert.throws(() => createGateway(new Engine(new MemoryStore(contained())), [{ token: tokens.intern, binding: bindings.intern }], { runtimeObligations: 'off' as never }));
  // Engine level: an invalid unenforceable list refuses every allow (fail closed).
  const engine = new Engine(new MemoryStore(world()));
  assert.equal((await engine.openContext(bindings.intern, ['handbook'], 'work', { unenforceable: ['nonsense'] as never })).ok, false);
  assert.equal((await engine.openContext(bindings.intern, ['handbook'], 'work', { unenforceable: ['runtime_profile'] })).ok, true, 'no runtime policy: nothing to refuse');
});

test('admin routes: PUT and GET /admin/v1/runtime-profiles/{id}', async () => {
  const t = await start();
  try {
    const body = { classification: 'restricted', profiles: { network: 'deny-all' }, active: true };
    assert.equal((await t.call(tokens.aud, 'PUT', '/admin/v1/runtime-profiles/rt-x', body)).status, 403, 'auditor cannot write');
    assert.equal((await t.call(tokens.sec, 'PUT', '/admin/v1/runtime-profiles/rt-x', { ...body, tenant: 'other' })).status, 400, 'no other tenant');
    assert.equal((await t.call(tokens.sec, 'PUT', '/admin/v1/runtime-profiles/rt-x', { ...body, profiles: { network: 'allow everything' } })).status, 400);
    const put = await t.call(tokens.sec, 'PUT', '/admin/v1/runtime-profiles/rt-x', body);
    assert.equal(put.status, 200);
    const got = await t.call(tokens.aud, 'GET', '/admin/v1/runtime-profiles/rt-x');
    assert.equal(got.status, 200);
    assert.deepEqual((await got.json() as { value: unknown }).value, { ...body, id: 'rt-x', tenant: 'acme' });
    assert.equal((await t.call(tokens.aud, 'GET', '/admin/v1/runtime-profiles/absent')).status, 404);
    assert.equal((await t.call(tokens.other, 'GET', '/admin/v1/runtime-profiles/rt-x')).status, 404, 'another tenant sees nothing');
  } finally { await t.stop(); }
});

test('AuthZEN facade: runtime_profile and max_output_classification appear in context.obligations', async () => {
  const pdp = new AuthzenPdp(new MemoryStore(contained()));
  const mapped = mapEvaluation('acme', { subject: { type: 'user', id: 'chief', properties: { agent: 'chief-agent', grant: 'chief-run' } },
    resource: { type: 'knowledge', id: 'project-alpha' }, action: { name: 'read' }, context: { purpose: 'work' } });
  assert.ok(mapped.ok);
  const rendered = render(await pdp.evaluate('acme', mapped), 'none') as { decision: boolean; context: { obligations: Obligation[] } };
  assert.equal(rendered.decision, true);
  assert.deepEqual(runtimeOnly(rendered.context.obligations), [{ type: 'runtime_profile', domain: 'network', profile: 'internal-only' },
    { type: 'runtime_profile', domain: 'filesystem', profile: 'read-only-workspace' }, { type: 'runtime_profile', domain: 'tool', profile: 'read-only-http' },
    { type: 'max_output_classification', value: 'confidential' }]);
});

test('the SQLite store keeps runtime profile policies per tenant', async () => {
  const store = new SqliteStore(':memory:');
  try {
    await importState(store, contained());
    const control = new ControlPlane(store);
    const read = await control.readRuntimeProfile('acme', 'sec', 'rt-restricted');
    assert.ok(read.ok); assert.deepEqual(read.value, TIERS[2]);
    const r = await new Engine(store).openContext(bindings.chief, ['strategy'], 'work');
    assert.ok(r.ok); assert.ok(r.obligations.some(o => o.type === 'runtime_profile' && o.profile === 'deny-all'));
  } finally { await store.close(); }
});

// Regressions of the 0.5 adversarial review (repro scripts ported).

/** A sandbox-wide enforcer that records which profile set is in force whenever the provider holds content. */
function sandbox(isolation?: RuntimeEnforcer['isolation']) {
  let inForce = '', holder = '';
  const seen: string[] = [];
  const enforcer: RuntimeEnforcer = {
    ...(isolation ? { isolation } : {}),
    supports: () => true,
    apply: async (profiles, { executionId }) => { inForce = profiles.map(p => p.profile).join(','); holder = executionId; return { runtimeRevision: `rev-${inForce}` }; },
    current: executionId => executionId === holder ? `rev-${inForce}` : undefined
  };
  const provider = { principal: 'provider', generate: async (req: { documents: { id: string }[] }) => {
    const restricted = req.documents.some(d => d.id === 'strategy');
    await new Promise(r => setTimeout(r, 40));
    seen.push(`${restricted ? 'restricted' : 'public'}:${inForce}`);
    return 'Synthetic answer';
  } };
  return { enforcer, provider, seen };
}
test('regression: a runtime change between the last check and the final release withholds the answer and audits it (R124)', async () => {
  const { enforcer: inner, provider } = sandbox();
  let checks = 0;
  const enforcer: RuntimeEnforcer = { ...inner, current: id => checks++ === 0 ? inner.current(id) : 'changed-out-of-band' };
  const store = new MemoryStore(tiered());
  const r = await new ProtectedRuntime(new Engine(store), provider as never, { enforcer }).answer(bindings.chief, ['strategy'], 'work', 'summarize', { trace: { executionId: 'job-late' } });
  assert.equal(r.ok, false); assert.equal(checks, 2, 'verified before and after the final release');
  const log = await store.auditLog('acme'), last = log.at(-1)!, before = log.at(-2)!;
  assert.equal(before.operation, 'share'); assert.equal(before.decision, 'allow');
  assert.equal(last.operation, 'share'); assert.equal(last.decision, 'deny'); assert.equal(last.reason, 'DENIED:UNSUPPORTED_OBLIGATION');
  assert.equal(last.executionId, 'job-late'); assert.equal(last.runtimeRevision, 'rev-deny-all'); assert.equal(r.decisionId, last.decisionId);
  assert.ok(verifyAudit(log));
  // Unchanged revision: the same answer is released.
  const ok = await new ProtectedRuntime(new Engine(new MemoryStore(tiered())), sandbox().provider as never, { enforcer: sandbox().enforcer }).answer(bindings.chief, ['strategy'], 'work', 'summarize');
  assert.equal(ok.ok, true);
});
function tiered(): State {
  const s = contained();
  s.runtimeProfiles = { pub: policy('pub', 'public', { network: 'internal-only' }), res: policy('res', 'restricted', { network: 'deny-all' }) };
  return s;
}

test('regression: concurrent answers through one sandbox-wide enforcer never let a weaker profile govern restricted content', async () => {
  const { enforcer, provider, seen } = sandbox();
  const store = new MemoryStore(tiered());
  const runtime = new ProtectedRuntime(new Engine(store), provider as never, { enforcer });
  const [a, b] = await Promise.all([
    runtime.answer(bindings.chief, ['strategy'], 'work', 'x', { trace: { executionId: 'exec-a' } }),
    (async () => { await new Promise(r => setTimeout(r, 10)); return runtime.answer(bindings.lead, ['handbook'], 'work', 'y', { trace: { executionId: 'exec-b' } }); })(),
  ]);
  assert.ok(a.ok && b.ok);
  assert.deepEqual(seen.sort(), ['public:internal-only', 'restricted:deny-all'], 'each provider call ran under its own profile');
  const log = await store.auditLog('acme');
  const answers = log.filter(e => e.runtimeRevision !== undefined);
  assert.deepEqual(answers.map(e => `${e.executionId}:${e.runtimeRevision}`).sort(), ['exec-a:rev-deny-all', 'exec-b:rev-internal-only']);
  // Two runtimes sharing one enforcer are serialized too.
  const other = sandbox();
  const r1 = new ProtectedRuntime(new Engine(new MemoryStore(tiered())), other.provider as never, { enforcer: other.enforcer });
  const r2 = new ProtectedRuntime(new Engine(new MemoryStore(tiered())), other.provider as never, { enforcer: other.enforcer });
  await Promise.all([r1.answer(bindings.chief, ['strategy'], 'work', 'x'), r2.answer(bindings.lead, ['handbook'], 'work', 'y')]);
  assert.deepEqual(other.seen.sort(), ['public:internal-only', 'restricted:deny-all']);
});

test('regression: a revision that is no longer in force for the execution denies the answer; per-execution enforcers run concurrently', async () => {
  // An enforcer that (wrongly) lets a second apply replace the policy while the first execution is running.
  const { enforcer, provider } = sandbox('per-execution');
  const store = new MemoryStore(tiered());
  const runtime = new ProtectedRuntime(new Engine(store), provider as never, { enforcer });
  const [a, b] = await Promise.all([
    runtime.answer(bindings.chief, ['strategy'], 'work', 'x', { trace: { executionId: 'exec-a' } }),
    (async () => { await new Promise(r => setTimeout(r, 10)); return runtime.answer(bindings.lead, ['handbook'], 'work', 'y', { trace: { executionId: 'exec-b' } }); })(),
  ]);
  assert.equal(a.ok, false, 'exec-a no longer holds its revision: denied');
  assert.ok(b.ok);
  assert.ok(!(await store.auditLog('acme')).some(e => e.executionId === 'exec-a' && e.runtimeRevision !== undefined), 'no answer recorded under a revision that was not in force');
  // The same execution id twice at once is refused.
  const twice = sandbox('per-execution');
  const rt = new ProtectedRuntime(new Engine(new MemoryStore(tiered())), twice.provider as never, { enforcer: twice.enforcer });
  const both = await Promise.all([rt.answer(bindings.chief, ['strategy'], 'work', 'x', { trace: { executionId: 'dup' } }), rt.answer(bindings.chief, ['strategy'], 'work', 'x', { trace: { executionId: 'dup' } })]);
  assert.equal(both.filter(r => r.ok).length, 1);
  // An enforcer without current() supports nothing; a failing lease release denies; a malformed lease denies.
  const base = sandbox();
  const noCurrent = { supports: base.enforcer.supports, apply: base.enforcer.apply } as unknown as RuntimeEnforcer;
  assert.equal((await new ProtectedRuntime(new Engine(new MemoryStore(tiered())), base.provider as never, { enforcer: noCurrent }).answer(bindings.chief, ['strategy'], 'work', 'x')).ok, false);
  const failing: RuntimeEnforcer = { ...base.enforcer, apply: async (p, x) => ({ ...(await base.enforcer.apply(p, x)), release: async () => { throw new Error('restore failed'); } }) };
  assert.equal((await new ProtectedRuntime(new Engine(new MemoryStore(tiered())), base.provider as never, { enforcer: failing }).answer(bindings.chief, ['strategy'], 'work', 'x')).ok, false);
  const malformed: RuntimeEnforcer = { ...base.enforcer, apply: async (p, x) => ({ ...(await base.enforcer.apply(p, x)), release: 'no' as never }) };
  assert.equal((await new ProtectedRuntime(new Engine(new MemoryStore(tiered())), base.provider as never, { enforcer: malformed }).answer(bindings.chief, ['strategy'], 'work', 'x')).ok, false);
});

test('regression: a model-provider-narrowed policy governs the provider hop instead of denying every answer', async () => {
  const s = contained();
  s.runtimeProfiles = { base: policy('base', 'confidential', { network: 'internal-only' }), mp: policy('mp', 'confidential', { network: 'model-provider-only' }, { destinationClass: 'model-provider' }) };
  let applied: readonly RuntimeProfileRef[] = [];
  const { enforcer: inner, provider } = sandbox();
  const enforcer: RuntimeEnforcer = { ...inner, apply: async (p, x) => { applied = p; return inner.apply(p, x); } };
  const store = new MemoryStore(s);
  const r = await new ProtectedRuntime(new Engine(store), provider as never, { enforcer }).answer(bindings.chief, ['strategy'], 'work', 'summarize');
  assert.ok(r.ok);
  assert.deepEqual(applied, [{ domain: 'network', profile: 'model-provider-only' }]);
  assert.ok(r.obligations.some(o => o.type === 'max_output_classification' && o.value === 'restricted'));
  // A genuine same-tier conflict of the provider hop still denies before the provider.
  s.runtimeProfiles.mp2 = policy('mp2', 'confidential', { network: 'deny-all' }, { destinationClass: 'model-provider' });
  let called = false;
  const denied = await new ProtectedRuntime(new Engine(new MemoryStore(s)), { principal: 'provider', generate: async () => { called = true; return 'x'; } }, { enforcer })
    .answer(bindings.chief, ['strategy'], 'work', 'summarize');
  assert.equal(denied.ok, false); assert.equal(called, false);
});

test('regression: share/export without a destination is never weaker than for any destination the run allows', async () => {
  const s = contained();
  s.runtimeProfiles = { base: policy('base', 'confidential', { network: 'internal-only' }), ext: policy('ext', 'confidential', { network: 'deny-all' }, { destinationClass: 'external' }) };
  s.destinations!.ext = { id: 'ext', tenant: 'acme', class: 'external', maxClassification: 'restricted', purposes: ['work'], active: true };
  const engine = new Engine(new MemoryStore(structuredClone(s)));
  const named = await engine.evaluate(bindings.chief, 'strategy', 'share', 'work', { destination: 'ext' });
  assert.ok(named.decision); assert.ok(named.obligations.some(o => o.type === 'runtime_profile' && o.profile === 'deny-all'));
  // R121: an evaluation naming no destination is denied outright (RECIPIENT).
  const unnamed = await engine.evaluate(bindings.chief, 'strategy', 'share', 'work', {});
  assert.equal(unnamed.decision, false, 'no weaker unnarrowed profile'); assert.equal(unnamed.code, 'RECIPIENT');
  const exported = await engine.evaluate(bindings.chief, 'strategy', 'export', 'work', {});
  assert.equal(exported.decision, false);
  // Restricted to the external Destination by id: denied without naming it, its narrowed profile applies when named.
  const restricted = structuredClone(s); restricted.grants['chief-run']!.destinations = ['ext'];
  assert.equal((await new Engine(new MemoryStore(structuredClone(restricted))).evaluate(bindings.chief, 'strategy', 'share', 'work', {})).code, 'RECIPIENT');
  const byId = await new Engine(new MemoryStore(restricted)).evaluate(bindings.chief, 'strategy', 'share', 'work', { destination: 'ext' });
  assert.ok(byId.decision); assert.deepEqual(runtimeOnly(byId.obligations).filter(o => o.type === 'runtime_profile'), [{ type: 'runtime_profile', domain: 'network', profile: 'deny-all' }]);
  // R122: no reachable destination class denies; it never falls back to the unnarrowed derivation.
  assert.deepEqual(containmentAcross(s, 'acme', 'restricted', []), { ok: false, reason: 'DENIED:RECIPIENT' });
  // A release to a service principal without a Destination profile may forward anywhere: contained for every class.
  const svc = structuredClone(s);
  svc.actors['svc-bot'] = { id: 'svc-bot', tenant: 'acme', kind: 'service', roles: ['staff', 'executive', 'project'], projects: ['alpha'], clearance: 'restricted', active: true };
  const e2 = new Engine(new MemoryStore(svc));
  const context = await e2.openContext(bindings.chief, ['strategy'], 'work');
  assert.ok(context.ok);
  assert.equal((await e2.release(bindings.chief, context.value.context, 'svc-bot', 'Synthetic answer')).ok, false);
});

test('policy digest covers the active runtime profile policy set; tenants without one keep the 0.4 digest', async () => {
  const digestOf = async (s: State) => { const store = new MemoryStore(s); await new Engine(store).openContext(bindings.chief, ['strategy'], 'work'); return (await store.auditLog('acme')).at(-1)!.policyDigest; };
  const plain = await digestOf(world());
  const a = await digestOf(contained()), again = await digestOf(contained());
  assert.notEqual(a, plain); assert.equal(a, again, 'deterministic');
  const changed = contained(); changed.runtimeProfiles!['rt-public']!.profiles = { tool: 'none' };
  assert.notEqual(await digestOf(changed), a, 'a changed profile changes the digest');
  const inactive = contained(); for (const p of Object.values(inactive.runtimeProfiles!)) p.active = false;
  assert.equal(await digestOf(inactive), plain, 'only the active set counts');
});
