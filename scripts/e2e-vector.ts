import { readFileSync } from 'node:fs';
// Runs inside the gateway container (CI containers job): synthetic end-to-end check of admin
// ingestion and permission-aware vector retrieval against the seeded credentials.
const agent = process.env.E2E_AGENT_URL ?? 'http://127.0.0.1:8787', admin = process.env.E2E_ADMIN_URL ?? 'http://127.0.0.1:8788', metrics = process.env.E2E_METRICS_URL ?? 'http://127.0.0.1:9464';
const load = (file: string) => JSON.parse(readFileSync(file, 'utf8')) as { token: string; binding: Record<string, string> }[];
const agents = load('data/credentials.json'), admins = load('data/admin-credentials.json');
const agentToken = (subject: string) => agents.find(c => c.binding.subject === subject)!.token;
const adminToken = (id: string) => admins.find(c => c.binding.admin === id)!.token;
const call = async (base: string, token: string, method: string, path: string, body?: unknown) => {
  const r = await fetch(base + path, { method, headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  return { status: r.status, body: await r.json().catch(() => undefined) as any };
};
const expect = (what: string, actual: unknown, wanted: unknown) => { if (JSON.stringify(actual) !== JSON.stringify(wanted)) throw new Error(`${what}: expected ${JSON.stringify(wanted)}, got ${JSON.stringify(actual)}`); console.log(`ok  ${what}`); };
const kb = adminToken('demo-kb-admin');
const doc = (id: string, content: string, classification: string, readerRoles: string[]) => ({ id, tenant: 'acme', version: 1, kind: 'document', origin: 'human', content, classification, projects: [], readerRoles, readers: [], sources: [], active: true });
const ids = async (subject: string, query: string) => {
  const r = await call(agent, agentToken(subject), 'POST', '/v1/retrieve', { query, purpose: 'work', limit: 10 });
  return { status: r.status, ids: r.status === 200 ? (r.body.value.documents as { id: string }[]).map(d => d.id).sort() : [] };
};

// Seeding writes the store directly, so nothing is indexed until reconcile (authorized, audited).
expect('auditor cannot reconcile', (await call(admin, adminToken('demo-auditor'), 'POST', '/admin/v1/index/reconcile')).status, 403);
expect('agent credential is refused on the admin listener', (await call(admin, agentToken('chief'), 'POST', '/admin/v1/index/reconcile')).status, 401);
const reconciled = await call(admin, kb, 'POST', '/admin/v1/index/reconcile');
expect('kb-admin reconciles the seeded documents', [reconciled.status, reconciled.body.value.indexed >= 3, reconciled.body.value.failed], [200, true, 0]);

const shared = 'synthetic vectorcheck quarterly roadmap';
expect('ingest staff document', (await call(admin, kb, 'PUT', '/admin/v1/knowledge/ci-staff-note', doc('ci-staff-note', `${shared} for all staff.`, 'internal', ['staff']))).status, 200);
expect('ingest executive document', (await call(admin, kb, 'PUT', '/admin/v1/knowledge/ci-exec-note', doc('ci-exec-note', `${shared} restricted to executives.`, 'restricted', ['executive']))).status, 200);
expect('intern retrieves only the staff document', await ids('intern', shared), { status: 200, ids: ['ci-staff-note'] });
expect('chief retrieves both documents', await ids('chief', shared), { status: 200, ids: ['ci-exec-note', 'ci-staff-note'] });
const denied = await call(agent, agentToken('intern'), 'POST', '/v1/contexts', { resources: ['ci-exec-note'], purpose: 'work' });
expect('intern cannot open the executive document directly', denied.status, 403);
expect('an unauthorized query looks like no match', (await ids('intern', 'synthetic executives restricted acquisition budget')).ids.includes('ci-exec-note'), false);

const text = await (await fetch(`${metrics}/metrics`)).text();
expect('index metrics are exported', [/^akac_index_chunks_written_total [1-9]/m.test(text), /^akac_index_reconcile_runs_total [1-9]/m.test(text)], [true, true]);
