import test from 'node:test';
import assert from 'node:assert/strict';
import { ControlPlane } from '../reference/control.ts';
import { Engine } from '../reference/engine.ts';
import { createAdminGateway } from '../reference/admin.ts';
import { createGateway } from '../reference/http.ts';
import { Ingestor } from '../reference/ingest.ts';
import { HashEmbedder } from '../reference/embedding.ts';
import { createMetricsServer, Metrics } from '../reference/metrics.ts';
import { VectorCandidateSource } from '../reference/retrieval.ts';
import { MemoryStore } from '../reference/store.ts';
import { MemoryVectorIndex } from '../reference/vector.ts';
import { emptyState } from '../reference/types.ts';
import type { Actor, Container, Grant, Knowledge } from '../reference/types.ts';
import { close, listen, tokens } from './support.ts';

const T = 'acme', agentTokens = { intern: 'test-only-e2e-intern-agent-token-00000000000', chief: 'test-only-e2e-chief-agent-token-000000000000' };
const bindingOf = (who: 'intern' | 'chief') => ({ tenant: T, subject: who, agent: `${who}-agent`, grant: `${who}-run` });

/** End to end over HTTP: admin gateway, agent gateway and metrics, MemoryStore with the vector path and the hash embedder. */
test('e2e: admin ingestion, permission-aware vector retrieval, derived restriction, SCIM revocation and metrics', async () => {
  const state = emptyState(), now = Date.now();
  for (const [id, roles] of [['sec', ['security-admin']], ['kbadm', ['kb-admin']], ['aud', ['auditor']]] as const)
    state.actors[id] = { id, tenant: T, kind: 'user', roles: [...roles], projects: [], clearance: 'restricted', active: true };
  const store = new MemoryStore(state), metrics = new Metrics(), control = new ControlPlane(store);
  const index = new MemoryVectorIndex(), embedder = new HashEmbedder(256);
  const ingestor = new Ingestor({ control, store, index, embedder, onEvent: metrics.onIngest });
  const engine = new Engine(store, { onEvent: metrics.onEvent, candidates: new VectorCandidateSource({ index, embedder }) });
  const agent = createGateway(engine, (['intern', 'chief'] as const).map(who => ({ token: agentTokens[who], binding: bindingOf(who) })), { metrics });
  const admin = createAdminGateway(control, { metrics, ingestor, credentials: [
    { token: tokens.sec, binding: { tenant: T, admin: 'sec' } }, { token: tokens.kb, binding: { tenant: T, admin: 'kbadm' } }, { token: tokens.aud, binding: { tenant: T, admin: 'aud' } }] });
  const scrape = createMetricsServer(metrics);
  const [agentUrl, adminUrl, metricsUrl] = [await listen(agent), await listen(admin), await listen(scrape)];
  const call = (token: string, method: string, path: string, body?: unknown, base = adminUrl) =>
    fetch(base + path, { method, headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const ok = async (response: Promise<Response>, status = 200) => { const r = await response; assert.equal(r.status, status); return await r.json() as Record<string, any>; };
  try {
    // Identities and grants through the security-admin API.
    const actor = (id: string, roles: string[], clearance: Actor['clearance'], kind: Actor['kind']): Actor => ({ id, tenant: T, kind, roles, projects: [], clearance, active: true });
    for (const [id, roles, clearance] of [['intern', ['staff'], 'internal'], ['chief', ['staff', 'executive'], 'restricted']] as const)
      for (const kind of ['user', 'agent'] as const) await ok(call(tokens.sec, 'PUT', `/admin/v1/actors/${kind === 'user' ? id : `${id}-agent`}`, actor(kind === 'user' ? id : `${id}-agent`, [...roles], clearance, kind)));
    for (const who of ['intern', 'chief'] as const) {
      const b = bindingOf(who);
      const grant: Grant = { id: b.grant, tenant: T, subject: who, agent: b.agent, actions: ['read', 'derive', 'share'], resources: ['*'], purposes: ['work'], notBefore: now - 1000, expiresAt: now + 3_600_000, active: true };
      await ok(call(tokens.sec, 'POST', '/admin/v1/grants', grant), 201);
    }
    // Knowledge base, a confidential executive folder, and two documents.
    const container = (id: string, kind: Container['kind'], classification: Container['classification'], readerRoles: string[], parent?: string): Container =>
      ({ id, tenant: T, kind, ...(parent ? { parent } : {}), classification, readerRoles, readers: [], projects: [], active: true });
    await ok(call(tokens.kb, 'PUT', '/admin/v1/containers/kb-staff', container('kb-staff', 'knowledge-base', 'internal', ['staff'])));
    await ok(call(tokens.kb, 'PUT', '/admin/v1/containers/f-exec', container('f-exec', 'folder', 'confidential', ['executive'], 'kb-staff')));
    const doc = (id: string, content: string, classification: Knowledge['classification'], readerRoles: string[], container: string): Knowledge =>
      ({ id, tenant: T, version: 1, kind: 'document', origin: 'human', content, classification, projects: [], readerRoles, readers: [], sources: [], active: true, container });
    const handbook = await ok(call(tokens.kb, 'PUT', '/admin/v1/knowledge/handbook', doc('handbook', 'Synthetic handbook: the product plan for staff is the onboarding checklist.', 'public', ['staff'], 'kb-staff')));
    assert.ok(handbook.value.chunks >= 1);
    await ok(call(tokens.kb, 'PUT', '/admin/v1/knowledge/strategy', doc('strategy', 'Synthetic strategy: the product plan is a confidential acquisition next quarter.', 'restricted', ['executive'], 'f-exec')));
    // Agent credentials cannot use the admin listener and vice versa.
    assert.equal((await call(agentTokens.chief, 'PUT', '/admin/v1/knowledge/x', {})).status, 401);
    assert.equal((await call(tokens.kb, 'POST', '/v1/retrieve', { query: 'product plan', purpose: 'work' }, agentUrl)).status, 401);

    const retrieve = async (who: 'intern' | 'chief') => (await call(agentTokens[who], 'POST', '/v1/retrieve', { query: 'product plan', purpose: 'work' }, agentUrl));
    const internResult = await retrieve('intern');
    assert.equal(internResult.status, 200);
    assert.deepEqual(((await internResult.json()) as any).value.documents.map((d: { id: string }) => d.id), ['handbook']);
    const chiefResult = await retrieve('chief');
    assert.equal(chiefResult.status, 200);
    const chiefBody = await chiefResult.json() as any;
    assert.deepEqual(chiefBody.value.documents.map((d: { id: string }) => d.id).sort(), ['handbook', 'strategy']);

    // A summary derived from the restricted document inherits its restriction: the intern cannot receive it.
    const derived = await ok(call(agentTokens.chief, 'POST', '/v1/derive', { context: chiefBody.value.context, content: 'Synthetic summary of the plan.', kind: 'artifact' }, agentUrl));
    assert.equal(derived.value.classification, 'restricted');
    const release = await call(agentTokens.chief, 'POST', '/v1/release', { context: chiefBody.value.context, recipient: 'intern', content: 'Synthetic summary of the plan.', action: 'share' }, agentUrl);
    assert.equal(release.status, 403);

    // Reconcile is authorized (kb-admin) and audited; a repeat finds nothing to repair.
    assert.equal((await call(tokens.aud, 'POST', '/admin/v1/index/reconcile')).status, 403);
    assert.deepEqual((await ok(call(tokens.kb, 'POST', '/admin/v1/index/reconcile'))).value, { indexed: 0, removed: 0, failed: 0, truncated: false });

    // SCIM deprovisioning takes effect for the next retrieval.
    await ok(call(tokens.sec, 'PATCH', '/scim/v2/Users/chief', { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'active', value: false }] }));
    assert.equal((await retrieve('chief')).status, 403);
    assert.equal((await retrieve('intern')).status, 403, 'the epoch advanced: the intern run is stale until re-established');

    const text = await (await fetch(`${metricsUrl}/metrics`)).text();
    const value = (name: string, labels: string) => Number(new RegExp(`^${name}\\{${labels}\\} (\\S+)$`, 'm').exec(text)?.[1] ?? 0);
    assert.ok(value('akac_decisions_total', 'operation="retrieve",allowed="true",reason_class="authorized"') >= 2);
    assert.ok(value('akac_decisions_total', 'operation="retrieve",allowed="false",reason_class="denied"') >= 1);
    assert.ok(value('akac_decisions_total', 'operation="share",allowed="false",reason_class="denied"') >= 1);
    assert.match(text, /^akac_index_chunks_written_total [1-9]/m);
    assert.match(text, /^akac_index_reconcile_runs_total 1$/m);
    assert.doesNotMatch(text, /strategy|acquisition|chief|acme/);
  } finally { await close(agent, admin, scrape); }
});
