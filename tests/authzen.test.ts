import test from 'node:test';
import assert from 'node:assert/strict';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { randomBytes } from 'node:crypto';
import { AUTHZEN_ACTIONS, AuthzenPdp, createAuthzenGateway, mapEvaluation } from '../reference/authzen.ts';
import type { AuthzenOptions } from '../reference/authzen.ts';
import { PepJwtAuthenticator } from '../adapters/jwt.ts';
import { verifyAudit } from '../reference/audit.ts';
import { decide } from '../reference/policy.ts';
import { validDecisionId } from '../reference/decision.ts';
import { Engine } from '../reference/engine.ts';
import { createGateway } from '../reference/http.ts';
import { createAdminGateway } from '../reference/admin.ts';
import { ControlPlane } from '../reference/control.ts';
import { MemoryStore } from '../reference/store.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';
import type { State } from '../reference/types.ts';
import { AuthzenClient } from '../sdk/typescript/index.ts';
import { readFileSync } from 'node:fs';
import { close, listen } from './support.ts';

const secret = () => `test-only-${randomBytes(24).toString('hex')}`;
const pepToken = secret(), otherToken = secret(), agentToken = secret(), adminToken = secret();
const ask = (user: string, agent: string, grant: string, resource: string, action: string, purpose = 'work') =>
  ({ subject: { type: 'user', id: user, properties: { agent, grant } }, resource: { type: 'knowledge', id: resource }, action: { name: action }, context: { purpose } });
const chief = (resource: string, action = 'read') => ask('chief', 'chief-agent', 'chief-run', resource, action);
function world(): State {
  const s = kbFixture();
  s.actors.aud = { id: 'aud', tenant: 'acme', kind: 'user', roles: ['auditor'], projects: [], clearance: 'restricted', active: true };
  return s;
}
async function setup(options: Partial<AuthzenOptions> = {}, state = world()) {
  const store = new MemoryStore(state);
  const server = createAuthzenGateway(store, { credentials: [{ token: pepToken, binding: { tenant: 'acme', pep: 'gateway-1' } }, { token: otherToken, binding: { tenant: 'other', pep: 'gateway-2' } }], ...options });
  const base = await listen(server);
  const post = (path: string, body: unknown, token = pepToken, headers: Record<string, string> = {}) =>
    fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });
  const one = async (body: unknown, token = pepToken) => { const r = await post('/access/v1/evaluation', body, token); return { status: r.status, body: await r.json() as any, headers: r.headers }; };
  return { store, server, base, post, one, stop: () => close(server) };
}

test('single evaluation: AuthZEN 1.0 request and response shapes', async () => {
  const t = await setup();
  try {
    const allow = await t.one(chief('strategy'));
    assert.equal(allow.status, 200);
    assert.equal(allow.body.decision, true);
    assert.ok(validDecisionId(allow.body.context.id));
    assert.deepEqual(allow.body.context.obligations, [{ type: 'audit_level', value: 'full' }, { type: 'no_persist' }]);
    const deny = await t.one(ask('intern', 'intern-agent', 'intern-run', 'strategy', 'read'));
    assert.deepEqual(Object.keys(deny.body).sort(), ['context', 'decision']);
    assert.equal(deny.body.decision, false);
    assert.deepEqual(Object.keys(deny.body.context), ['id'], 'reasons are hidden by default');
    assert.equal((await t.one(ask('intern', 'intern-agent', 'intern-run', 'handbook', 'read'))).body.decision, true);
    assert.equal(allow.headers.get('cache-control'), 'no-store');
    // Every evaluation is audited without content, with the decision id returned to the PEP.
    const log = await t.store.auditLog('acme');
    assert.ok(verifyAudit(log));
    assert.deepEqual(log.map(e => e.decisionId).slice(0, 2), [allow.body.context.id, deny.body.context.id]);
    assert.ok(log.every(e => e.operation === 'authzen_evaluate'));
    assert.deepEqual(log[0]!.obligations, allow.body.context.obligations);
    assert.ok(!JSON.stringify(log).includes('purchase budget'));
  } finally { await t.stop(); }
});

test('the AuthZEN agent-subject form maps to the same binding', async () => {
  const t = await setup();
  try {
    const viaAgent = { subject: { type: 'agent', id: 'chief-agent', properties: { subject: 'chief', grant: 'chief-run' } }, resource: { type: 'knowledge', id: 'strategy' }, action: { name: 'read' }, context: { purpose: 'work' } };
    assert.equal((await t.one(viaAgent)).body.decision, true);
    assert.equal((await t.one({ ...viaAgent, subject: { ...viaAgent.subject, properties: { subject: 'intern', grant: 'chief-run' } } })).body.decision, false);
  } finally { await t.stop(); }
});

test('tenant comes from the PEP credential only; request members cannot select it', async () => {
  const t = await setup();
  try {
    const forged = { ...chief('strategy'), tenant: 'other', subject: { type: 'user', id: 'chief', properties: { agent: 'chief-agent', grant: 'chief-run', tenant: 'other' } }, context: { purpose: 'work', tenant: 'other' } };
    assert.equal((await t.one(forged)).body.decision, true, 'unknown members are ignored and the credential tenant (acme) applies');
    const mapped = mapEvaluation('acme', forged);
    assert.ok(mapped.ok && mapped.binding.tenant === 'acme');
    // A PEP of another tenant reaches nothing of acme: identities do not exist there.
    const cross = await t.one(chief('strategy'), otherToken);
    assert.equal(cross.body.decision, false);
    assert.equal((await t.store.auditLog('other')).length, 1);
    assert.ok((await t.store.auditLog('acme')).length >= 1);
  } finally { await t.stop(); }
});

test('unknown members are ignored, missing required members are 400, unsupported values are decision false', async () => {
  const t = await setup();
  try {
    assert.equal((await t.one({ ...chief('strategy'), extra: { anything: true }, allowed: true })).body.decision, true);
    for (const bad of [{ ...chief('strategy'), subject: undefined }, { ...chief('strategy'), action: undefined }, { ...chief('strategy'), resource: undefined },
      { ...chief('strategy'), context: undefined }, { ...chief('strategy'), context: { purpose: 7 } },
      { ...chief('strategy'), subject: { type: 'user', id: 'chief' } }, { ...chief('strategy'), subject: { type: 'user', id: 7, properties: { agent: 'chief-agent', grant: 'chief-run' } } }, []])
      assert.equal((await t.one(bad)).status, 400, JSON.stringify(bad));
    for (const soft of [chief('strategy', 'declassify'), chief('strategy', 'delete'), { ...chief('strategy'), resource: { type: 'document', id: 'strategy' } },
      { ...chief('strategy'), subject: { type: 'service', id: 'chief', properties: { agent: 'chief-agent', grant: 'chief-run' } } },
      ask('chief', 'chief-agent', 'chief-run', 'constructor', 'read'), ask('chief', 'chief-agent', 'chief-run', 'strategy', 'read', 'x'.repeat(200)), ask('chief', 'chief-agent', 'chief-run', 'strategy', 'read', 'other-purpose')]) {
      const r = await t.one(soft); assert.equal(r.status, 200, JSON.stringify(soft)); assert.equal(r.body.decision, false);
    }
    assert.equal((await t.post('/access/v1/evaluation', '{oops')).status, 400);
    assert.equal((await t.post('/access/v1/evaluation', { a: 1 }, pepToken, { 'content-type': 'text/plain' })).status, 400);
    assert.equal((await t.post('/access/v1/evaluation', { x: 'x'.repeat(300000) })).status, 413);
  } finally { await t.stop(); }
});

test('reasons: none by default, closed reason code with AKAC_AUTHZEN_REASONS=admin', async () => {
  const t = await setup({ reasons: 'admin' });
  try {
    const deny = await t.one(ask('intern', 'intern-agent', 'intern-run', 'strategy', 'read'));
    assert.deepEqual(deny.body.context.reason_admin, { code: 'KNOWLEDGE_BOUNDARY' });
    assert.equal((await t.one(chief('handbook'))).body.context.reason_admin.code, 'AUTHORIZED');
    assert.equal((await t.one(chief('strategy', 'delete'))).body.context.reason_admin.code, 'INVALID_REQUEST');
  } finally { await t.stop(); }
});

test('batch evaluations: defaults, overrides, semantics and per-evaluation errors', async () => {
  const t = await setup();
  try {
    const call = async (body: unknown) => { const r = await t.post('/access/v1/evaluations', body); return { status: r.status, body: await r.json() as any }; };
    const shared = { subject: chief('x').subject, action: { name: 'read' }, context: { purpose: 'work' } };
    const res = (id: string) => ({ resource: { type: 'knowledge', id } });
    const all = await call({ ...shared, evaluations: [res('handbook'), res('strategy'), { ...res('strategy'), action: { name: 'export' } }, res('nonexistent')] });
    assert.equal(all.status, 200);
    assert.equal(all.body.decision, undefined);
    assert.deepEqual(all.body.evaluations.map((e: any) => e.decision), [true, true, true, false]);
    assert.ok(all.body.evaluations.every((e: any) => validDecisionId(e.context.id)));
    const denyFirst = await call({ ...shared, options: { evaluations_semantic: 'deny_on_first_deny' }, evaluations: [res('handbook'), res('nonexistent'), res('handbook')] });
    assert.deepEqual(denyFirst.body.evaluations.map((e: any) => e.decision), [true, false], 'the remaining evaluations are omitted');
    const permitFirst = await call({ ...shared, options: { evaluations_semantic: 'permit_on_first_permit' }, evaluations: [res('nonexistent'), res('handbook'), res('strategy')] });
    assert.deepEqual(permitFirst.body.evaluations.map((e: any) => e.decision), [false, true]);
    const errors = await call({ ...shared, evaluations: [{ resource: 7 }, 'x', res('handbook')] });
    assert.deepEqual(errors.body.evaluations.map((e: any) => e.decision), [false, false, true]);
    assert.deepEqual(errors.body.evaluations[0].context.error, { status: 400, message: 'Bad Request' });
    for (const bad of [{ ...shared }, { ...shared, evaluations: [] }, { ...shared, evaluations: 'x' }, { ...shared, evaluations: Array(65).fill(res('handbook')) },
      { ...shared, options: { evaluations_semantic: 'first' }, evaluations: [{}] }, { ...shared, options: 'x', evaluations: [{}] }])
      assert.equal((await call(bad)).status, 400, JSON.stringify(bad).slice(0, 80));
    // Every evaluation, including the malformed ones that reached the PDP, is audited.
    assert.ok(verifyAudit(await t.store.auditLog('acme')));
  } finally { await t.stop(); }
});

test('authentication: other listeners credentials are rejected; PEP credentials are rejected elsewhere', async () => {
  const t = await setup();
  const store = new MemoryStore(world());
  const agent = createGateway(new Engine(store), [{ token: agentToken, binding: bindings.intern }]);
  const admin = createAdminGateway(new ControlPlane(store), { credentials: [{ token: adminToken, binding: { tenant: 'acme', admin: 'aud' } }] });
  const [agentUrl, adminUrl] = [await listen(agent), await listen(admin)];
  try {
    for (const token of [agentToken, adminToken, 'x', '']) {
      const r = await t.post('/access/v1/evaluation', chief('strategy'), token); assert.equal(r.status, 401); assert.ok(r.headers.get('www-authenticate'));
    }
    assert.equal((await fetch(t.base + '/access/v1/evaluation', { method: 'POST', body: '{}' })).status, 401);
    assert.equal((await fetch(agentUrl + '/v1/contexts', { method: 'POST', headers: { authorization: `Bearer ${pepToken}`, 'content-type': 'application/json' }, body: '{}' })).status, 401);
    assert.equal((await fetch(adminUrl + '/admin/v1/audit', { headers: { authorization: `Bearer ${pepToken}` } })).status, 401);
    // The PDP listener exposes no agent, admin or SCIM route.
    for (const path of ['/v1/contexts', '/admin/v1/audit', '/scim/v2/Users']) assert.equal((await t.post(path, {})).status, 404);
    assert.equal((await fetch(t.base + '/access/v1/evaluation', { headers: { authorization: `Bearer ${pepToken}` } })).status, 405);
    assert.equal((await fetch(t.base + '/health')).status, 200);
  } finally { await t.stop(); await close(agent, admin); }
});

test('X-Request-ID is echoed; the metadata document exists only with a public URL', async () => {
  const t = await setup();
  const d = await setup({ publicUrl: 'https://pdp.example.test' });
  try {
    assert.equal((await t.post('/access/v1/evaluation', chief('handbook'), pepToken, { 'x-request-id': 'req-123' })).headers.get('x-request-id'), 'req-123');
    assert.equal((await t.post('/access/v1/evaluation', chief('handbook'), pepToken, { 'x-request-id': 'bad id!' })).status, 400);
    assert.equal((await fetch(t.base + '/.well-known/authzen-configuration')).status, 404);
    const meta = await fetch(d.base + '/.well-known/authzen-configuration');
    assert.equal(meta.status, 200);
    assert.deepEqual(await meta.json(), { policy_decision_point: 'https://pdp.example.test', access_evaluation_endpoint: 'https://pdp.example.test/access/v1/evaluation',
      access_evaluations_endpoint: 'https://pdp.example.test/access/v1/evaluations' });
  } finally { await t.stop(); await d.stop(); }
  assert.throws(() => createAuthzenGateway(new MemoryStore(world()), { credentials: [{ token: pepToken, binding: { tenant: 'acme', pep: 'g' } }], publicUrl: 'https://pdp.example.test/base?x=1' }));
});

test('startup rejects weak, duplicate and malformed PEP credentials and mixed modes', () => {
  const store = new MemoryStore(world());
  assert.throws(() => createAuthzenGateway(store, {}));
  assert.throws(() => createAuthzenGateway(store, { credentials: [{ token: 'weak', binding: { tenant: 'acme', pep: 'g' } }] }));
  assert.throws(() => createAuthzenGateway(store, { credentials: [{ token: pepToken, binding: { tenant: 'acme', pep: 'g' } }, { token: pepToken, binding: { tenant: 'acme', pep: 'h' } }] }));
  assert.throws(() => createAuthzenGateway(store, { credentials: [{ token: pepToken, binding: { tenant: 'acme', admin: 'g' } as never }] }));
  assert.throws(() => createAuthzenGateway(store, { credentials: [{ token: pepToken, binding: { tenant: 'acme', pep: 'g' } }], reasons: 'all' as never }));
});

test('PEP JWT authentication: verified subject maps to a trusted tenant; another audience is rejected', async () => {
  const keys = await generateKeyPair('RS256');
  const jwk = { ...await exportJWK(keys.publicKey), kid: 'k', alg: 'RS256', use: 'sig' };
  const config = { issuer: 'https://identity.example.test', audience: 'akac-authzen', jwksUrl: 'https://identity.example.test/jwks', algorithms: ['RS256' as const],
    peps: { 'gateway-service': { tenant: 'acme', pep: 'gateway-1' } } };
  const auth = new PepJwtAuthenticator(config, createLocalJWKSet({ keys: [jwk] }));
  const sign = (aud: string, sub = 'gateway-service', claims: Record<string, unknown> = {}) => { const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ tenant: 'other', ...claims }).setProtectedHeader({ alg: 'RS256', kid: 'k', typ: 'at+jwt' }).setSubject(sub).setIssuer(config.issuer).setAudience(aud)
      .setIssuedAt(now).setExpirationTime(now + 120).setJti(randomBytes(8).toString('hex')).sign(keys.privateKey); };
  assert.deepEqual(await auth.authenticate(await sign('akac-authzen')), { tenant: 'acme', pep: 'gateway-1' }, 'a tenant claim is ignored');
  assert.equal(await auth.authenticate(await sign('akac-gateway')), null);
  assert.equal(await auth.authenticate(await sign('akac-authzen', 'stranger')), null);
  const t = await setup({ credentials: [], authenticator: auth });
  try {
    assert.equal((await t.post('/access/v1/evaluation', chief('strategy'), await sign('akac-authzen'))).status, 200);
    assert.equal((await t.post('/access/v1/evaluation', chief('strategy'), await sign('akac-gateway'))).status, 401);
    assert.equal((await t.post('/access/v1/evaluation', chief('strategy'), pepToken)).status, 401);
  } finally { await t.stop(); }
  assert.throws(() => new PepJwtAuthenticator({ ...config, peps: { s: { tenant: 'acme', admin: 'x' } as never } }));
});

test('parity: AuthZEN decisions equal decide() over generated requests', async () => {
  const state = world();
  const store = new MemoryStore(structuredClone(state));
  const pdp = new AuthzenPdp(store);
  const users = ['intern', 'chief', 'lead', 'admin', 'outsider', 'nobody'], agents = ['intern-agent', 'chief-agent', 'lead-agent', 'outsider', 'nobody-agent'];
  const grants = ['intern-run', 'chief-run', 'lead-run', 'missing-run'];
  const resources = [...Object.keys(state.knowledge), 'missing'], purposes = ['work', 'other'];
  let seed = 20260929; const next = (n: number) => { seed = (seed * 1664525 + 1013904223) >>> 0; return (seed >>> 8) % n; };
  const pick = <T>(xs: readonly T[]) => xs[next(xs.length)]!;
  let allows = 0, denies = 0;
  for (let i = 0; i < 400; i++) {
    // Half of the requests use a matching identity triple so that allows are exercised.
    const who = next(2) ? pick(['intern', 'chief', 'lead']) : undefined;
    const user = who ?? pick(users), agent = who ? `${who}-agent` : pick(agents), grant = who ? `${who}-run` : pick(grants);
    const resource = pick(resources), action = pick(AUTHZEN_ACTIONS), purpose = pick(purposes);
    const mapped = mapEvaluation('acme', ask(user, agent, grant, resource, action, purpose));
    assert.ok(mapped.ok);
    const got = await pdp.evaluate('acme', mapped);
    const want = decide(state, { binding: { tenant: 'acme', subject: user, agent, grant }, resource, action, purpose, now: Date.now() });
    assert.equal(got.decision, want.effect === 'allow', JSON.stringify({ user, agent, grant, resource, action, purpose }));
    // Another tenant's records are invisible inside the tenant transaction, so a cross-tenant identity reads as absent (NOT_AUTHORIZED), as in the engine.
    if (want.effect !== 'allow' && want.code !== 'IDENTITY_BOUNDARY') assert.equal(got.code, want.code);
    got.decision ? allows++ : denies++;
  }
  assert.ok(allows > 20 && denies > 20, `both outcomes exercised (${allows}/${denies})`);
  const log = await store.auditLog('acme');
  assert.ok(verifyAudit(log));
  assert.equal(log.length, 400, 'one audit entry per evaluation');
});

test('obligations match those of the engine for the same decision (audit_level from confidential, no_persist from restricted)', async () => {
  const store = new MemoryStore(world());
  const pdp = new AuthzenPdp(store), engine = new Engine(store);
  for (const [resource, expected] of [['handbook', []], ['project-alpha', ['audit_level']], ['strategy', ['audit_level', 'no_persist']]] as const) {
    const mapped = mapEvaluation('acme', chief(resource)); assert.ok(mapped.ok);
    const got = await pdp.evaluate('acme', mapped);
    assert.deepEqual(got.obligations.map(o => o.type), [...expected]);
    const opened = await engine.openContext(bindings.chief, [resource], 'work'); assert.ok(opened.ok);
    assert.deepEqual(opened.obligations.filter(o => o.type !== 'max_context_ttl_ms'), got.obligations);
  }
});

test('a supplemental policy verdict applies as in the engine, including unsupported obligations', async () => {
  const hook = (verdict: unknown) => ({ revision: 'test-policy', check: async () => true, verdict: async () => verdict as never });
  const run = async (verdict: unknown) => { const t = await setup({ policy: hook(verdict), reasons: 'admin' }); try { return (await t.one(chief('handbook'))).body; } finally { await t.stop(); } };
  assert.equal((await run({ allow: false })).context.reason_admin.code, 'POLICY_DENIED');
  const unknown = await run({ allow: true, obligations: [{ type: 'made_up' }] });
  assert.equal(unknown.decision, false); assert.equal(unknown.context.reason_admin.code, 'UNSUPPORTED_OBLIGATION');
  const restricted = await run({ allow: true, obligations: [{ type: 'destination_restricted', value: ['provider'] }] });
  assert.deepEqual(restricted.context.obligations, [{ type: 'destination_restricted', value: ['provider'] }]);
  assert.equal((await run('garbage')).context.reason_admin.code, 'POLICY_UNAVAILABLE');
});

test('SDK client for PEPs and the published OpenAPI document match the listener', async () => {
  const t = await setup();
  try {
    const client = new AuthzenClient(t.base, pepToken);
    const one = await client.evaluate(chief('strategy') as never);
    assert.equal(one.decision, true);
    const many = await client.evaluations([{ resource: { type: 'knowledge', id: 'handbook' } }, { resource: { type: 'knowledge', id: 'nonexistent' } }],
      { subject: chief('x').subject as never, action: { name: 'read' }, context: { purpose: 'work' } });
    assert.deepEqual(many.evaluations.map(e => e.decision), [true, false]);
    await assert.rejects(new AuthzenClient(t.base, agentToken).evaluate(chief('strategy') as never));
    const doc = JSON.parse(readFileSync(new URL('../docs/openapi-authzen.json', import.meta.url), 'utf8')) as { paths: Record<string, unknown> };
    assert.deepEqual(Object.keys(doc.paths).sort(), ['/.well-known/authzen-configuration', '/access/v1/evaluation', '/access/v1/evaluations', '/health']);
  } finally { await t.stop(); }
});
