import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import type { ControlPlane, ControlResult } from './control.ts';
import type { Knowledge } from './types.ts';
import type { AdminAuthenticator, AdminIdentity } from '../adapters/jwt.ts';
import { exactKeys, validId } from './validation.ts';
import { observe } from './observe.ts';
import type { Observability } from './observe.ts';
import { createScim, scimError } from './scim.ts';

/** The authoritative write succeeded but the index lagged: 202, and reconcile repairs it. */
type Pending = { ok: false; code: 'INDEX_PENDING'; id: string; version: number };
export type AdminCredential = { token: string; binding: AdminIdentity };
/** Structural seam for a document indexer (chunking and embedding). Without one, documents go straight to the control plane. */
export type DocumentIngestor = {
  ingest(tenant: string, adminId: string, document: Knowledge): Promise<ControlResult<{ id: string; version: number; chunks?: number }> | Pending>;
  remove(tenant: string, adminId: string, id: string): Promise<ControlResult<unknown> | Pending>;
  /** Repairs index drift for one tenant. The gateway authorizes and audits (kb-admin) before calling. */
  reconcile?(tenant: string): Promise<{ indexed: number; removed: number; failed: number; truncated: boolean }>;
};
export type AdminOptions = Observability & {
  credentials?: AdminCredential[]; authenticator?: AdminAuthenticator; ingestor?: DocumentIngestor;
  /** Mount the SCIM 2.0 subset on this listener (default true). */
  scim?: boolean;
};
export const ADMIN_LIMITS = { concurrent: 16, perMinute: 240, body: 262144, documentBody: 4194304, idempotencyKeys: 256, idempotencyAdmins: 1024, exportPage: 5000 } as const;

const digest = (s: string) => createHash('sha256').update(s).digest('hex');
const HEADERS = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'" };
function send(res: ServerResponse, status: number, body: unknown, type = 'application/json', extra: Record<string, string> = {}) {
  if (res.headersSent) return;
  const payload = body === undefined ? '' : JSON.stringify(body);
  res.writeHead(status, { ...HEADERS, ...extra, ...(payload ? { 'content-type': type } : {}) });
  res.end(payload);
}
const STATUS = { INVALID_REQUEST: 400, NOT_AUTHORIZED: 403, CONFLICT: 409, SOD_VIOLATION: 409, INDEX_PENDING: 202 } as const;
export const statusOf = (r: ControlResult<unknown> | Pending, ok = 200) => r.ok ? ok : STATUS[r.code];
const plain = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const outcome = (status: number) => status < 300 ? 'ok' : status === 400 ? 'invalid' : status === 403 ? 'denied' : status === 404 ? 'not_found' : status === 409 ? 'conflict' : 'error';

type Out = { status: number; body?: unknown; extra?: Record<string, string> } | 'streamed';
type Ctx = { tenant: string; admin: string; params: string[]; body: unknown; query: URLSearchParams; req: IncomingMessage; res: ServerResponse };
type Route = { method: string; pattern: RegExp; label: string; operation: string; body: 'none' | 'json' | 'document'; run(ctx: Ctx): Promise<Out> };

const result = (r: ControlResult<unknown> | Pending, ok = 200): Out => ({ status: statusOf(r, ok), body: r.ok ? r : r.code === 'INDEX_PENDING' ? { ok: false, code: r.code, id: r.id, version: r.version }
  : { ok: false, code: r.code, ...(r.holders !== undefined ? { holders: r.holders } : {}) } });
const invalid: Out = { status: 400, body: { ok: false, code: 'INVALID_REQUEST' } };
/**
 * Tenant and id come from the credential and the path. A body may repeat them, but a
 * mismatch is rejected: the caller can never choose another tenant.
 */
function pin(ctx: Ctx, id: string): Record<string, unknown> | null {
  const b = ctx.body;
  if (!plain(b) || (Object.hasOwn(b, 'tenant') && b.tenant !== ctx.tenant) || (Object.hasOwn(b, 'id') && b.id !== id)) return null;
  return { ...b, id, tenant: ctx.tenant };
}
const put = (path: string, operation: string, call: (ctx: Ctx, record: never) => Promise<ControlResult<unknown> | Pending>, body: Route['body'] = 'json'): Route => ({
  method: 'PUT', pattern: new RegExp(`^/admin/v1/${path}/([^/]+)$`), label: `/admin/v1/${path}/{id}`, operation, body,
  run: async ctx => { const r = pin(ctx, ctx.params[0]!); return r ? result(await call(ctx, r as never)) : invalid; }
});

/**
 * Operator-facing API on its own listener. Credentials are administrator identities
 * (tenant + admin actor), a different population from agent bindings; the two
 * listeners never accept each other's credentials. Authority comes from the admin
 * actor's standing roles, enforced and audited by the control plane on every call.
 */
export function createAdminGateway(control: ControlPlane, options: AdminOptions = {}): Server {
  const credentials = options.credentials ?? [];
  if (!credentials.length && !options.authenticator) throw new Error('Authentication is required');
  if (credentials.length && options.authenticator) throw new Error('Authentication modes cannot be mixed');
  const auth = new Map<string, AdminIdentity>();
  for (const c of credentials) {
    if (typeof c?.token !== 'string' || c.token.length < 32 || c.token.length > 512 || !exactKeys(c.binding, ['tenant', 'admin'])
      || !validId(c.binding.tenant) || !validId(c.binding.admin) || auth.has(digest(c.token))) throw new Error('Invalid credential configuration');
    auth.set(digest(c.token), { tenant: c.binding.tenant, admin: c.binding.admin });
  }
  const ingestor = options.ingestor;
  const scim = options.scim === false ? undefined : createScim(control);
  const routes: Route[] = [
    put('actors', 'put_actor', (x, a) => control.upsertActor(x.tenant, x.admin, a)),
    { method: 'PUT', pattern: /^\/admin\/v1\/actors\/([^/]+)\/roles$/, label: '/admin/v1/actors/{id}/roles', operation: 'assign_roles', body: 'json',
      run: async ctx => ctx.params[0] && exactKeys(ctx.body, ['roles']) ? result(await control.assignRoles(ctx.tenant, ctx.admin, ctx.params[0], ctx.body.roles as string[])) : invalid },
    put('roles', 'put_role', (x, r) => control.upsertRole(x.tenant, x.admin, r)),
    put('groups', 'put_group', (x, g) => control.upsertGroup(x.tenant, x.admin, g)),
    put('constraints', 'put_constraint', (x, k) => control.upsertConstraint(x.tenant, x.admin, k)),
    put('containers', 'put_container', (x, k) => control.upsertContainer(x.tenant, x.admin, k)),
    put('knowledge', 'put_knowledge', (x, d: Knowledge) => ingestor ? ingestor.ingest(x.tenant, x.admin, d) : control.upsertKnowledge(x.tenant, x.admin, d), 'document'),
    { method: 'DELETE', pattern: /^\/admin\/v1\/knowledge\/([^/]+)$/, label: '/admin/v1/knowledge/{id}', operation: 'delete_knowledge', body: 'none',
      run: async ctx => result(ingestor ? await ingestor.remove(ctx.tenant, ctx.admin, ctx.params[0]!) : await control.removeKnowledge(ctx.tenant, ctx.admin, ctx.params[0]!)) },
    { method: 'POST', pattern: /^\/admin\/v1\/index\/reconcile$/, label: '/admin/v1/index/reconcile', operation: 'index_reconcile', body: 'none',
      run: async ctx => {
        if (!ingestor?.reconcile) return { status: 404, body: { ok: false, code: 'NOT_FOUND' } };
        const allowed = await control.authorize(ctx.tenant, ctx.admin, 'kb-admin', 'index_reconcile');
        if (!allowed.ok) return result(allowed);
        return { status: 200, body: { ok: true, value: await ingestor.reconcile(ctx.tenant) } };
      } },
    { method: 'POST', pattern: /^\/admin\/v1\/grants$/, label: '/admin/v1/grants', operation: 'issue_grant', body: 'json',
      run: async ctx => {
        const id = plain(ctx.body) && validId(ctx.body.id) ? ctx.body.id : undefined;
        const grant = id ? pin(ctx, id) : null;
        return grant ? result(await control.issueGrant(ctx.tenant, ctx.admin, grant as never), 201) : invalid;
      } },
    { method: 'POST', pattern: /^\/admin\/v1\/revocations$/, label: '/admin/v1/revocations', operation: 'revoke', body: 'json',
      run: async ctx => exactKeys(ctx.body, ['type', 'id']) && ['grant', 'knowledge', 'actor'].includes(ctx.body.type as string) && validId(ctx.body.id)
        ? result(await control.revoke(ctx.tenant, ctx.admin, ctx.body.type as 'grant', ctx.body.id)) : invalid },
    { method: 'GET', pattern: /^\/admin\/v1\/audit$/, label: '/admin/v1/audit', operation: 'audit_read', body: 'none',
      run: async ctx => {
        const q = paging(ctx.query, ['after', 'limit']); if (!q) return invalid;
        const r = await control.auditLog(ctx.tenant, ctx.admin, q.after, q.limit ?? 1000);
        return r.ok ? { status: 200, body: { ok: true, value: { entries: r.value, next: r.value.length ? r.value.at(-1)!.sequence : null } } } : result(r);
      } },
    { method: 'GET', pattern: /^\/admin\/v1\/audit\/export$/, label: '/admin/v1/audit/export', operation: 'audit_export', body: 'none',
      run: async ctx => {
        const q = paging(ctx.query, ['after']); if (!q) return invalid;
        // Pages are authorized and audited one by one; an export therefore leaves audit_read entries.
        let after = q.after, first = true;
        for (;;) {
          const r = await control.auditLog(ctx.tenant, ctx.admin, after, ADMIN_LIMITS.exportPage);
          if (!r.ok) return result(r);
          if (first) { ctx.res.writeHead(200, { ...HEADERS, 'content-type': 'application/x-ndjson' }); first = false; }
          for (const entry of r.value) {
            if (!ctx.res.write(JSON.stringify(entry) + '\n')) await new Promise<void>(resolve => { ctx.res.once('drain', resolve); ctx.res.once('close', resolve); });
            if (ctx.res.destroyed) return 'streamed';
          }
          if (r.value.length < ADMIN_LIMITS.exportPage) { ctx.res.end(); return 'streamed'; }
          after = r.value.at(-1)!.sequence;
        }
      } }
  ];

  // In-memory and per instance: a retry that reaches another replica is not deduplicated.
  const idem = new Map<string, Map<string, { fingerprint: string; out?: Out }>>();
  const buckets = new Map<string, { minute: number; count: number }>();
  let active = 0;
  const server = createServer(async (req, res) => {
    const obs = observe('admin', req, res, options);
    const isScim = (req.url ?? '').startsWith('/scim/');
    const refuse = (status: number, error: string, detail = error) => {
      req.resume();
      if (isScim) send(res, status, scimError(status, detail), 'application/scim+json'); else send(res, status, { error });
    };
    if (active >= ADMIN_LIMITS.concurrent) { obs.setRoute('unmatched'); refuse(503, 'BUSY'); return; }
    active++;
    try {
      let url: URL;
      try { url = new URL(req.url ?? '', 'http://admin.invalid'); } catch { refuse(400, 'INVALID_REQUEST'); return; }
      if (url.pathname === '/health' && req.method === 'GET') { obs.setRoute('/health'); send(res, 200, { status: 'ok', listener: 'admin' }); return; }
      const header = req.headers.authorization;
      const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
      const who = options.authenticator ? await options.authenticator.authenticate(token) : auth.get(token.length <= 512 ? digest(token) : '');
      if (!who) { res.setHeader('www-authenticate', 'Bearer'); refuse(401, 'UNAUTHENTICATED', 'Authentication required'); return; }
      const minute = Math.floor(Date.now() / 60000), bucketKey = digest(`${who.tenant}\u0000${who.admin}`);
      for (const [key, value] of buckets) if (value.minute !== minute) buckets.delete(key);
      if (!buckets.has(bucketKey) && buckets.size >= 10000) { refuse(503, 'BUSY'); return; }
      const bucket = buckets.get(bucketKey) ?? { minute, count: 0 };
      buckets.set(bucketKey, bucket);
      if (++bucket.count > ADMIN_LIMITS.perMinute) { refuse(429, 'RATE_LIMITED'); return; }

      let label = 'unmatched', operation = 'unknown', bodyKind: Route['body'] = 'none', params: string[] = [];
      let run: ((ctx: Ctx) => Promise<Out>) | undefined;
      let type = 'application/json';
      if (scim && url.pathname.startsWith('/scim/v2/')) {
        const m = scim.match(req.method ?? '', url.pathname, url.searchParams);
        type = 'application/scim+json';
        if (m) { label = m.label; operation = m.operation; bodyKind = m.body ? 'json' : 'none'; run = ctx => m.run(ctx); }
      } else {
        const known = routes.filter(r => r.pattern.test(url.pathname));
        const route = known.find(r => r.method === req.method);
        if (known.length && !route) { obs.setRoute(known[0]!.label); refuse(405, 'METHOD_NOT_ALLOWED'); return; }
        if (route) {
          label = route.label; operation = route.operation; bodyKind = route.body; run = route.run;
          params = route.pattern.exec(url.pathname)!.slice(1).map(p => { try { return decodeURIComponent(p); } catch { return ''; } });
          if (!params.every(validId)) { obs.setRoute(label); refuse(400, 'INVALID_REQUEST'); return; }
        }
      }
      obs.setRoute(label);
      if (!run) { refuse(404, 'NOT_FOUND', 'Resource not found'); return; }
      const finish = (out: Out) => {
        if (out === 'streamed') { options.metrics?.admin(operation, 'ok'); return; }
        options.metrics?.admin(operation, outcome(out.status));
        send(res, out.status, out.body, type, out.extra);
      };
      let body: unknown;
      if (bodyKind !== 'none') {
        const mime = req.headers['content-type']?.split(';')[0]?.trim().toLowerCase();
        if (mime !== 'application/json' && !(isScim && mime === 'application/scim+json')) { refuse(400, 'INVALID_REQUEST', 'Content-Type must be application/json'); return; }
        const limit = bodyKind === 'document' ? ADMIN_LIMITS.documentBody : ADMIN_LIMITS.body;
        const chunks: Buffer[] = []; let size = 0;
        for await (const chunk of req) {
          size += chunk.length;
          if (size > limit) { refuse(413, 'REQUEST_TOO_LARGE'); return; }
          chunks.push(Buffer.from(chunk));
        }
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { refuse(400, 'INVALID_JSON', 'Invalid JSON'); return; }
      } else req.resume();

      const ctx: Ctx = { tenant: who.tenant, admin: who.admin, params, body, query: url.searchParams, req, res };
      const key = req.headers['idempotency-key'];
      if (key !== undefined && operation === 'issue_grant') {
        if (typeof key !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(key)) { refuse(400, 'INVALID_REQUEST'); return; }
        const owner = digest(`${who.tenant}\u0000${who.admin}`);
        let mine = idem.get(owner);
        if (!mine) {
          if (idem.size >= ADMIN_LIMITS.idempotencyAdmins) idem.delete(idem.keys().next().value!);
          mine = new Map(); idem.set(owner, mine);
        }
        const fingerprint = digest(JSON.stringify(body)), seen = mine.get(key);
        if (seen) {
          mine.delete(key); mine.set(key, seen); // most recently used
          // Answered from the cache, but still an administrative attempt: re-check the
          // standing role now and audit the outcome (R31).
          const outcome = seen.fingerprint !== fingerprint ? { allowed: false, reason: 'DENIED:IDEMPOTENCY_KEY_REUSED' }
            : !seen.out ? { allowed: false, reason: 'DENIED:CONFLICT' } : { allowed: true, reason: 'IDEMPOTENT_REPLAY' };
          const allowed = await control.attempt(who.tenant, who.admin, 'security-admin', operation, outcome);
          if (!allowed.ok) { finish(result(allowed)); return; }
          if (seen.fingerprint !== fingerprint) { finish({ status: 422, body: { ok: false, code: 'IDEMPOTENCY_KEY_REUSED' } }); return; }
          if (!seen.out) { finish({ status: 409, body: { ok: false, code: 'CONFLICT' } }); return; }
          finish({ ...seen.out as Exclude<Out, 'streamed'>, extra: { 'idempotent-replayed': 'true' } }); return;
        }
        if (mine.size >= ADMIN_LIMITS.idempotencyKeys) mine.delete(mine.keys().next().value!);
        const entry: { fingerprint: string; out?: Out } = { fingerprint }; mine.set(key, entry);
        try {
          const out = await run(ctx);
          // Transient failures are not remembered: the caller may retry with the same key.
          if (out !== 'streamed' && out.status < 500) entry.out = out; else mine.delete(key);
          finish(out);
        } catch (error) { mine.delete(key); throw error; }
        return;
      }
      finish(await run(ctx));
    } catch { if (!res.headersSent) { options.metrics?.admin('unknown', 'error'); refuse(503, 'UNAVAILABLE', 'Service unavailable'); } else res.destroy(); }
    finally { active--; }
  });
  server.requestTimeout = 30000; server.headersTimeout = 5000; server.timeout = 0; server.maxHeadersCount = 32;
  return server;
}
/** Strict query parsing: only known parameters, unsigned decimal integers. */
function paging(query: URLSearchParams, allowed: string[]): { after: number; limit?: number } | null {
  const number = (name: string) => { const v = query.get(name); return v === null ? undefined : /^\d{1,15}$/.test(v) ? Number(v) : NaN; };
  if ([...query.keys()].some(k => !allowed.includes(k)) || [...query.keys()].length !== new Set(query.keys()).size) return null;
  const after = number('after') ?? 0, limit = number('limit');
  if (Number.isNaN(after) || (limit !== undefined && (Number.isNaN(limit) || limit < 1 || limit > 10000))) return null;
  return limit === undefined ? { after } : { after, limit };
}
