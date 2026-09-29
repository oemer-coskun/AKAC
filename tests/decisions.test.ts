import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { Engine } from '../reference/engine.ts';
import type { EngineEvent } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { ProtectedRuntime } from '../reference/runtime.ts';
import { MemoryStore } from '../reference/store.ts';
import { OpaPolicy } from '../adapters/opa.ts';
import { classify, enforceable, merge, parseObligations, policyDigest, REASON_CODES, validDecisionId } from '../reference/decision.ts';
import { CORE_VERSION } from '../reference/types.ts';
import type { PolicyHook, PolicyVerdict, State } from '../reference/types.ts';
import { fixture, bindings } from '../examples/fixture.ts';
import { start, tokens } from './support.ts';

/**
 * Starts `opa run --server` on a free-looking port and waits (up to 20 s, polling
 * /health) until it answers. A process that exits early (for example a port in
 * use) is retried on another port.
 */
async function startOpa(args: string[] = []): Promise<{ port: number; proc: ChildProcess }> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const port = 18000 + Math.floor(Math.random() * 2000);
    const proc = spawn(process.env.OPA_BIN!, ['run', '--server', `--addr=127.0.0.1:${port}`, ...args], { stdio: 'ignore' });
    let exited = false; proc.once('exit', () => { exited = true; });
    const deadline = Date.now() + 20_000;
    while (!exited && Date.now() < deadline) {
      try { if ((await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(1000) })).ok) return { port, proc }; } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!exited) { proc.kill(); await once(proc, 'exit'); }
  }
  throw new Error('OPA failed to start within 20 s');
}

const now = 1800000000000;
const TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';
const hook = (verdict: PolicyVerdict | (() => Promise<PolicyVerdict>), revision = 'hook-v1'): PolicyHook => ({
  revision, check: async () => { throw new Error('verdict() is preferred'); },
  verdict: typeof verdict === 'function' ? verdict : async () => structuredClone(verdict)
});
const setup = (options: { policy?: PolicyHook; state?: State } = {}) => {
  const store = new MemoryStore(options.state ?? fixture(now));
  const events: EngineEvent[] = [];
  return { store, events, engine: new Engine(store, { clock: () => now, ...(options.policy ? { policy: options.policy } : {}), onEvent: e => events.push(e) }) };
};
const last = async (store: MemoryStore) => (await store.auditLog('acme')).at(-1)!;

test('decisions: closed reason codes classify every reason the reference records', () => {
  assert.deepEqual(classify('AUTHORIZED'), { code: 'AUTHORIZED' });
  assert.deepEqual(classify('DENIED:KNOWLEDGE_BOUNDARY'), { code: 'KNOWLEDGE_BOUNDARY', category: 'deny' });
  assert.deepEqual(classify('DEFERRED:STORE_ERROR'), { code: 'STORE_ERROR', category: 'defer' });
  for (const invalid of ['DENIED:AUTHORIZED', 'KNOWLEDGE_BOUNDARY', 'DENIED:MADE_UP', 'denied:SOD_VIOLATION', '']) assert.equal(classify(invalid), null, invalid);
  assert.equal(new Set(REASON_CODES).size, REASON_CODES.length);
  assert.equal(policyDigest(['a|b', 'c']) === policyDigest(['a', 'b|c']), false, 'digest input is unambiguous');
});

test('decisions: obligations are a closed set, validated strictly and combined restrictively', () => {
  assert.deepEqual(parseObligations([{ type: 'max_context_ttl_ms', value: 900 }, { type: 'audit_level', value: 'full' }, { type: 'max_context_ttl_ms', value: 300 }]),
    [{ type: 'audit_level', value: 'full' }, { type: 'max_context_ttl_ms', value: 300 }]);
  for (const bad of [[{ type: 'retain_forever' }], [{ type: 'audit_level', value: 'minimal' }], [{ type: 'no_persist', value: true }],
    [{ type: 'max_context_ttl_ms', value: 1.5 }], [{ type: 'destination_restricted', value: [] }], 'no_persist', [null], Array(17).fill({ type: 'no_persist' })]) {
    assert.equal(parseObligations(bad), null, JSON.stringify(bad));
  }
  const narrowed = merge([{ type: 'destination_restricted', value: ['a', 'b'] }], [{ type: 'destination_restricted', value: ['c'] }]);
  assert.deepEqual(narrowed, [{ type: 'destination_restricted', value: [] }]);
  assert.equal(enforceable(narrowed, ['destination_restricted']), false, 'an empty destination set can never be satisfied');
  assert.equal(enforceable([{ type: 'no_persist' }], ['audit_level']), false);
  assert.equal(enforceable([], []), true);
});

test('engine: every result and audit entry carries the same decision id; allows carry core obligations', async () => {
  const { engine, store, events } = setup();
  const read = await engine.openContext(bindings.chief, ['strategy', 'handbook'], 'work', { trace: { traceId: TRACE } });
  assert.ok(read.ok && validDecisionId(read.decisionId));
  // strategy is restricted: full audit, no persistence outside AKAC, bounded by the 300 s context lifetime.
  assert.deepEqual(read.obligations, [{ type: 'audit_level', value: 'full' }, { type: 'max_context_ttl_ms', value: 300_000 }, { type: 'no_persist' }]);
  const entry = await last(store);
  assert.deepEqual({ id: entry.decisionId, code: entry.reasonCode, run: entry.runId, trace: entry.traceId, format: entry.formatVersion, obligations: entry.obligations },
    { id: read.decisionId, code: 'AUTHORIZED', run: 'chief-run', trace: TRACE, format: 2, obligations: read.obligations });
  assert.equal(entry.policyDigest, policyDigest([CORE_VERSION, fixture(now).policyVersion, 'core-only']));
  assert.equal(events.at(-1)?.type === 'decision' && events.at(-1)!.type === 'decision' ? (events.at(-1) as { decisionId?: string }).decisionId : '', read.decisionId);
  const derived = await engine.derive(bindings.chief, read.value.context, 'Synthetic summary', 'artifact', { trace: { traceId: 'not-a-trace' } });
  assert.ok(derived.ok);
  assert.deepEqual(derived.obligations, [{ type: 'audit_level', value: 'full' }, { type: 'no_persist' }], 'derived from restricted material');
  assert.equal((await last(store)).traceId, undefined, 'an invalid trace id is never recorded');
  const handbook = await engine.openContext(bindings.intern, ['handbook'], 'work');
  assert.ok(handbook.ok); assert.deepEqual(handbook.obligations, [{ type: 'max_context_ttl_ms', value: 300_000 }], 'public: only the lifetime');
  const denied = await engine.openContext(bindings.intern, ['strategy'], 'work');
  assert.deepEqual(Object.keys(denied).sort(), ['code', 'decisionId', 'ok']);
  const deniedEntry = await last(store);
  assert.deepEqual([deniedEntry.decisionId, deniedEntry.reasonCode, deniedEntry.decision, deniedEntry.obligations], [denied.decisionId, 'KNOWLEDGE_BOUNDARY', 'deny', []]);
  const early = await engine.openContext({ ...bindings.intern, tenant: '../x' }, ['handbook'], 'work');
  assert.ok(!early.ok && validDecisionId(early.decisionId), 'a request rejected before any transaction still gets an id');
  const revoked = await engine.revoke('acme', 'admin', 'grant', 'lead-run', { trace: { traceId: TRACE } });
  assert.ok(revoked.ok); assert.deepEqual([(await last(store)).decisionId, (await last(store)).traceId], [revoked.decisionId, TRACE]);
});

test('HTTP: a denial body is exactly {ok, code, decisionId} for hidden and nonexistent objects; an allow carries obligations', async () => {
  const { agentUrl, stop, store } = await start();
  try {
    const post = (resources: string[]) => fetch(agentUrl + '/v1/contexts', { method: 'POST', headers: { authorization: `Bearer ${tokens.intern}`, 'content-type': 'application/json' },
      body: JSON.stringify({ resources, purpose: 'work' }) });
    const hidden = await post(['strategy']), absent = await post(['no-such-document']);
    const [a, b] = [await hidden.json(), await absent.json()];
    assert.deepEqual([hidden.status, absent.status], [403, 403]);
    for (const body of [a, b]) { assert.deepEqual(Object.keys(body).sort(), ['code', 'decisionId', 'ok']); assert.equal(body.code, 'NOT_AUTHORIZED'); assert.ok(validDecisionId(body.decisionId)); }
    const log = await store.auditLog('acme');
    assert.deepEqual([a.decisionId, b.decisionId].map(id => log.find(e => e.decisionId === id)?.reasonCode), ['KNOWLEDGE_BOUNDARY', 'NOT_AUTHORIZED'],
      'the distinguishing reason exists only in audit');
    const allowed = await post(['handbook']); const body = await allowed.json();
    assert.equal(allowed.status, 200);
    assert.deepEqual(Object.keys(body).sort(), ['decisionId', 'obligations', 'ok', 'value']);
    assert.ok(Array.isArray(body.obligations) && validDecisionId(body.decisionId));
  } finally { await stop(); }
});

test('supplemental policy: known obligations are merged; unknown or malformed ones deny UNSUPPORTED_OBLIGATION', async () => {
  const ok = setup({ policy: hook({ allow: true, obligations: [{ type: 'max_context_ttl_ms', value: 1000 }, { type: 'audit_level', value: 'full' }] }) });
  const read = await ok.engine.openContext(bindings.intern, ['handbook'], 'work');
  assert.ok(read.ok); assert.deepEqual(read.obligations, [{ type: 'audit_level', value: 'full' }, { type: 'max_context_ttl_ms', value: 1000 }]);
  for (const obligations of [[{ type: 'retain_forever' }], [{ type: 'audit_level', value: 'off' }], [{ type: 'no_persist', extra: 1 }]]) {
    const { engine, store } = setup({ policy: hook({ allow: true, obligations }) });
    const result = await engine.openContext(bindings.intern, ['handbook'], 'work');
    assert.equal(result.ok, false, JSON.stringify(obligations));
    assert.deepEqual([(await last(store)).reason, (await last(store)).reasonCode], ['DENIED:UNSUPPORTED_OBLIGATION', 'UNSUPPORTED_OBLIGATION']);
  }
  const malformed = setup({ policy: hook(async () => ({ allow: 'yes' }) as never) });
  assert.equal((await malformed.engine.openContext(bindings.intern, ['handbook'], 'work')).ok, false);
  assert.equal((await last(malformed.store)).reason, 'DEFERRED:POLICY_UNAVAILABLE');
  const denying = setup({ policy: hook({ allow: false, obligations: [{ type: 'retain_forever' }] }) });
  assert.equal((await denying.engine.openContext(bindings.intern, ['handbook'], 'work')).ok, false);
  assert.equal((await last(denying.store)).reason, 'DENIED:POLICY_DENIED', 'a deny wins over any obligation');
  // A boolean-only hook keeps working and adds no obligations.
  const legacy = setup({ policy: { revision: 'legacy', check: async () => true } });
  const plain = await legacy.engine.openContext(bindings.intern, ['handbook'], 'work');
  assert.ok(plain.ok); assert.deepEqual(plain.obligations, [{ type: 'max_context_ttl_ms', value: 300_000 }]);
});

async function fakeOpa(body: string, fn: (url: string) => Promise<void>) {
  const server = createServer((_req, res) => res.end(body)); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  try { await fn(`http://127.0.0.1:${address.port}`); }
  finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
}
const input = { action: 'read' as const, tenant: 'acme', classification: 'internal' as const, purpose: 'work' };
test('OPA adapter: the exact {allow, revision} document still works; obligations are passed to the engine strictly', async () => {
  await fakeOpa('{"result":{"allow":true,"revision":"akac-company/0.2"}}', async url => {
    const opa = new OpaPolicy(url);
    assert.deepEqual(await opa.verdict(input), { allow: true }); assert.equal(await opa.check(input), true);
  });
  await fakeOpa('{"result":{"allow":true,"revision":"akac-company/0.2","obligations":[{"type":"no_persist"}]}}', async url => {
    const opa = new OpaPolicy(url);
    assert.deepEqual(await opa.verdict(input), { allow: true, obligations: [{ type: 'no_persist' }] });
    assert.equal(await opa.check(input), false, 'a boolean caller cannot enforce obligations');
    const { engine } = setup({ policy: opa });
    const read = await engine.openContext(bindings.intern, ['handbook'], 'work');
    assert.ok(read.ok); assert.ok(read.obligations.some(o => o.type === 'no_persist'));
  });
  await fakeOpa('{"result":{"allow":true,"revision":"akac-company/0.2","obligations":[{"type":"quarantine_forever"}]}}', async url => {
    const { engine, store } = setup({ policy: new OpaPolicy(url) });
    assert.equal((await engine.openContext(bindings.intern, ['handbook'], 'work')).ok, false);
    assert.equal((await last(store)).reasonCode, 'UNSUPPORTED_OBLIGATION');
  });
  for (const body of ['{"result":{"allow":true,"revision":"akac-company/0.2","obligations":{"type":"no_persist"}}}',
    '{"result":{"allow":true,"revision":"akac-company/0.2","advice":[]}}']) {
    await fakeOpa(body, async url => {
      const { engine, store } = setup({ policy: new OpaPolicy(url) });
      assert.equal((await engine.openContext(bindings.intern, ['handbook'], 'work')).ok, false);
      assert.equal((await last(store)).reasonCode, 'POLICY_UNAVAILABLE', body);
      await assert.rejects(new OpaPolicy(url).verdict(input));
    });
  }
});

test('real OPA server: a Rego policy adding obligations is enforced; an unknown obligation denies', { skip: !process.env.OPA_BIN }, async () => {
  // The policy is loaded through the OPA policy API: no policy file on disk.
  const rego = `package akac_obligations
import rego.v1
default allow := false
allow if input.tenant == "acme"
obligations contains {"type": "audit_level", "value": "full"} if input.classification in {"confidential", "restricted"}
obligations contains {"type": "max_context_ttl_ms", "value": 60000}
obligations contains {"type": "retain_forever"} if input.purpose == "archive"
decision := {"allow": allow, "revision": "akac-obligations/test", "obligations": obligations}
`;
  const { port, proc } = await startOpa();
  try {
    const put = await fetch(`http://127.0.0.1:${port}/v1/policies/obligations`, { method: 'PUT', headers: { 'content-type': 'text/plain' }, body: rego });
    assert.equal(put.status, 200, await put.text());
    const policy = new OpaPolicy(`http://127.0.0.1:${port}/v1/data/akac_obligations/decision`, 'akac-obligations/test');
    const state = fixture(now); state.grants['chief-run']!.purposes = ['work', 'archive'];
    const { engine, store } = setup({ policy, state });
    const read = await engine.openContext(bindings.chief, ['strategy'], 'work');
    assert.ok(read.ok);
    assert.deepEqual(read.obligations, [{ type: 'audit_level', value: 'full' }, { type: 'max_context_ttl_ms', value: 60_000 }, { type: 'no_persist' }]);
    assert.equal((await last(store)).reasonCode, 'AUTHORIZED');
    const archive = setup({ policy, state });
    assert.equal((await archive.engine.openContext(bindings.chief, ['handbook'], 'archive')).ok, false);
    assert.equal((await last(archive.store)).reasonCode, 'UNSUPPORTED_OBLIGATION');
  } finally { proc.kill(); await once(proc, 'exit'); }
});

test('runtime: enforces every obligation it receives or fails closed before the provider sees content', async () => {
  const state = fixture(now); state.actors.provider = { ...state.actors.chief!, id: 'provider', kind: 'service' };
  let invoked = 0;
  const provider = { principal: 'provider', generate: async () => { invoked++; return 'Synthetic answer'; } };
  const restricted = setup({ state: structuredClone(state), policy: hook({ allow: true, obligations: [{ type: 'destination_restricted', value: ['eu-provider'] }] }) });
  const denied = await new ProtectedRuntime(restricted.engine, provider).answer(bindings.chief, ['strategy'], 'work', 'Summarize');
  assert.equal(denied.ok, false); assert.equal(invoked, 0, 'an unenforceable obligation stops before inference');
  const normal = setup({ state: structuredClone(state) });
  const answer = await new ProtectedRuntime(normal.engine, provider).answer(bindings.chief, ['strategy'], 'work', 'Summarize', { trace: { traceId: TRACE } });
  assert.ok(answer.ok); assert.equal(invoked, 1);
  assert.deepEqual(answer.obligations, [{ type: 'audit_level', value: 'full' }, { type: 'no_persist' }], 'the answer binds its receiver');
  const log = await normal.store.auditLog('acme');
  assert.equal(log.find(e => e.decisionId === answer.decisionId)?.operation, 'share');
  assert.ok(log.slice(-3).every(e => e.traceId === TRACE), 'context, provider gate and release share the trace');
  // A short context lifetime bounds the provider call.
  const short = setup({ state: structuredClone(state), policy: hook({ allow: true, obligations: [{ type: 'max_context_ttl_ms', value: 20 }] }) });
  let aborted = false;
  const slow = { principal: 'provider', generate: (r: { signal: AbortSignal }) => new Promise<string>(resolve => {
    r.signal.addEventListener('abort', () => { aborted = true; resolve('late'); });
  }) };
  const started = performance.now();
  assert.equal((await new ProtectedRuntime(short.engine, slow).answer(bindings.chief, ['strategy'], 'work', 'Summarize')).ok, false);
  assert.ok(aborted && performance.now() - started < 2000, 'aborted at the obligation deadline, not the 5 s default');
});

test('control plane: results carry decision ids; attempt() only records closed reason codes', async () => {
  const store = new MemoryStore(fixture(now));
  const control = new ControlPlane(store, { clock: () => now }).traced({ traceId: TRACE });
  const ok = await control.attempt('acme', 'admin', 'security-admin', 'replay', { allowed: true, reason: 'IDEMPOTENT_REPLAY' });
  assert.ok(ok.ok && validDecisionId(ok.decisionId));
  assert.deepEqual([(await last(store)).decisionId, (await last(store)).reasonCode, (await last(store)).traceId], [ok.decisionId, 'IDEMPOTENT_REPLAY', TRACE]);
  for (const outcome of [{ allowed: true, reason: 'WHATEVER' }, { allowed: true, reason: 'DENIED:CONFLICT' }, { allowed: false, reason: 'AUTHORIZED' }]) {
    const r = await control.attempt('acme', 'admin', 'security-admin', 'replay', outcome);
    assert.ok(!r.ok && r.code === 'INVALID_REQUEST', JSON.stringify(outcome));
  }
  const refused = await control.upsertKnowledge('acme', 'intern', fixture(now).knowledge.handbook!);
  assert.ok(!refused.ok && validDecisionId(refused.decisionId));
  assert.equal((await last(store)).decisionId, refused.decisionId);
});
