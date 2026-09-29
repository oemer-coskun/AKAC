import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import type { ControlPlane, ControlResult } from './control.ts';
import type { Knowledge } from './types.ts';
import type { AdminAuthenticator, AdminIdentity } from '../adapters/jwt.ts';
import { DpopGuard } from '../adapters/dpop.ts';
import type { DpopOptions } from '../adapters/dpop.ts';
import { exactKeys, safeNumber, validId } from './validation.ts';
import { QUARANTINE_REASONS } from './types.ts';
import type { QuarantineReason } from './types.ts';
import { observe } from './observe.ts';
import type { Observability } from './observe.ts';
import { createScim, scimError } from './scim.ts';
import { EXECUTION_HEADER, executionHeader } from './http.ts';
import { IDEMPOTENCY_KEY, MemoryIdempotency, MemoryJobLock, MemoryRateLimits } from './limits.ts';
import type { IdempotencyStore, JobLock, RateLimitStore } from './limits.ts';
import type { Sweeper } from './sweeper.ts';
import { validRange } from './knowledge.ts';

/** The authoritative write succeeded but the index lagged: 202, and reconcile repairs it. */
type Pending = { ok: false; code: 'INDEX_PENDING'; id: string; version: number; decisionId?: string };
export type AdminCredential = { token: string; binding: AdminIdentity };
/** Structural seam for a document indexer (chunking and embedding). Without one, documents go straight to the control plane. */
export type DocumentIngestor = {
  ingest(tenant: string, adminId: string, document: Knowledge): Promise<ControlResult<{ id: string; version: number; chunks?: number }> | Pending>;
  remove(tenant: string, adminId: string, id: string): Promise<ControlResult<unknown> | Pending>;
  /** Repairs index drift for one tenant. The gateway authorizes and audits (kb-admin) before calling. */
  reconcile?(tenant: string): Promise<{ indexed: number; removed: number; failed: number; truncated: boolean }>;
  /** Lifecycle wrappers (0.4): the control-plane operation, then the index follows. Without them the gateway calls the control plane directly. */
  quarantine?(tenant: string, adminId: string, id: string, reason: QuarantineReason): Promise<ControlResult<unknown> | Pending>;
  release?(tenant: string, adminId: string, id: string): Promise<ControlResult<unknown> | Pending>;
  erase?(tenant: string, adminId: string, id: string, options?: { cascade?: boolean }): Promise<ControlResult<unknown> | Pending>;
  revokeLineage?(tenant: string, adminId: string, id: string): Promise<ControlResult<unknown> | Pending>;
  reinstate?(tenant: string, adminId: string, id: string): Promise<ControlResult<unknown> | Pending>;
};
export type AdminOptions = Observability & {
  credentials?: AdminCredential[]; authenticator?: AdminAuthenticator; ingestor?: DocumentIngestor;
  /** Optional DPoP (RFC 9449) sender constraint for signed-token authentication; independent of the agent listener. */
  dpop?: DpopOptions;
  /** Mount the SCIM 2.0 subset on this listener (default true). */
  scim?: boolean;
  /**
   * Shared state for several instances (0.6, ADR-016). Defaults are per process:
   * rate windows (MemoryRateLimits), Idempotency-Key records (MemoryIdempotency) and
   * the retention/reconcile job lock (MemoryJobLock). adapters/postgres-ha.ts shares
   * them through PostgreSQL.
   */
  limiter?: RateLimitStore; idempotency?: IdempotencyStore; jobs?: JobLock;
  /**
   * Cascade sweeper (0.6, R193, R194). With it, a successful quarantine, erasure,
   * revocation, lineage revocation or document version sweeps the record's lineage in the
   * background, and lifting a legal hold runs the pending erasures; the sweep and erasure
   * routes use it. Without it those routes run single control-plane batches.
   */
  sweeper?: Sweeper;
  /** Embedding anchor monitor (0.6, ADR-020): enables POST /admin/v1/index/anchors/rebaseline. Without it the route answers 404. */
  anchors?: { readonly state: string; rebaseline(): Promise<void> };
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
/** APPROVAL_REQUIRED (0.6): accepted, not executed; the body names the pending approval. */
const STATUS = { INVALID_REQUEST: 400, NOT_AUTHORIZED: 403, CONFLICT: 409, SOD_VIOLATION: 409, INDEX_PENDING: 202, APPROVAL_REQUIRED: 202 } as const;
export const statusOf = (r: ControlResult<unknown> | Pending, ok = 200) => r.ok ? ok : STATUS[r.code];
const plain = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const outcome = (status: number) => status < 300 ? 'ok' : status === 400 ? 'invalid' : status === 403 ? 'denied' : status === 404 ? 'not_found' : status === 409 ? 'conflict' : 'error';

type Out = { status: number; body?: unknown; extra?: Record<string, string> } | 'streamed';
type Ctx = { control: ControlPlane; tenant: string; admin: string; params: string[]; body: unknown; query: URLSearchParams; req: IncomingMessage; res: ServerResponse };
type Route = { method: string; pattern: RegExp; label: string; operation: string; body: 'none' | 'json' | 'document'; run(ctx: Ctx): Promise<Out> };

const result = (r: ControlResult<unknown> | Pending, ok = 200): Out => ({ status: statusOf(r, ok), body: r.ok ? r : r.code === 'INDEX_PENDING' ? { ok: false, code: r.code, id: r.id, version: r.version, ...(r.decisionId ? { decisionId: r.decisionId } : {}) }
  : { ok: false, code: r.code, ...(r.holders !== undefined ? { holders: r.holders } : {}), ...(r.held !== undefined ? { held: r.held } : {}), ...(r.pending ? { pending: true } : {}),
    ...(r.approval !== undefined ? { approval: r.approval } : {}), decisionId: r.decisionId } });
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
  if (options.dpop && !options.authenticator) throw new Error('DPoP requires signed-token authentication');
  const dpop = options.dpop ? new DpopGuard(options.dpop) : undefined;
  const auth = new Map<string, AdminIdentity>();
  for (const c of credentials) {
    if (typeof c?.token !== 'string' || c.token.length < 32 || c.token.length > 512 || !exactKeys(c.binding, ['tenant', 'admin'])
      || !validId(c.binding.tenant) || !validId(c.binding.admin) || auth.has(digest(c.token))) throw new Error('Invalid credential configuration');
    auth.set(digest(c.token), { tenant: c.binding.tenant, admin: c.binding.admin });
  }
  const ingestor = options.ingestor;
  const scimEnabled = options.scim !== false;
  const limiter = options.limiter ?? new MemoryRateLimits({ maxBuckets: 10_000 });
  const idem = options.idempotency ?? new MemoryIdempotency({ keys: ADMIN_LIMITS.idempotencyKeys, owners: ADMIN_LIMITS.idempotencyAdmins });
  const jobs = options.jobs ?? new MemoryJobLock();
  /**
   * Runs a maintenance job under the job lock. When another instance runs the same job for
   * the tenant, the attempt is still authorized and audited (DENIED:CONFLICT) and answered 409.
   */
  const exclusive = async (job: 'retention' | 'reconcile', ctx: Ctx, role: 'security-admin' | 'kb-admin', operation: string, fn: () => Promise<Out>): Promise<Out> => {
    let locked;
    try { locked = await jobs.run(job, ctx.tenant, fn); }
    catch (error) { options.metrics?.job(job, 'failed'); throw error; }
    options.metrics?.job(job, locked.ran ? 'ran' : 'skipped');
    if (locked.ran) return locked.value;
    const denied = await ctx.control.attempt(ctx.tenant, ctx.admin, role, operation, { allowed: false, reason: 'DENIED:CONFLICT' });
    return denied.ok ? { status: 409, body: { ok: false, code: 'CONFLICT' } } : result(denied);
  };
  const sweeper = options.sweeper;
  /** Background follow-up of a successful lifecycle change (R193): lazy denial already holds; the sweep only makes it explicit. */
  const followUp = (ctx: Ctx, id: string, out: Out, erasures = false): Out => {
    if (sweeper && out !== 'streamed' && out.status < 300 && validId(id)) {
      const work = erasures ? sweeper.applyPendingErasures(ctx.tenant, ctx.admin) : sweeper.sweep(ctx.tenant, ctx.admin, id);
      void work.then(() => options.metrics?.job(erasures ? 'erasure' : 'sweep', 'ran'), () => options.metrics?.job(erasures ? 'erasure' : 'sweep', 'failed'));
    }
    return out;
  };
  const routes: Route[] = [
    put('actors', 'put_actor', (x, a) => x.control.upsertActor(x.tenant, x.admin, a)),
    { method: 'PUT', pattern: /^\/admin\/v1\/actors\/([^/]+)\/roles$/, label: '/admin/v1/actors/{id}/roles', operation: 'assign_roles', body: 'json',
      run: async ctx => ctx.params[0] && exactKeys(ctx.body, ['roles']) ? result(await ctx.control.assignRoles(ctx.tenant, ctx.admin, ctx.params[0], ctx.body.roles as string[])) : invalid },
    put('roles', 'put_role', (x, r) => x.control.upsertRole(x.tenant, x.admin, r)),
    put('groups', 'put_group', (x, g) => x.control.upsertGroup(x.tenant, x.admin, g)),
    put('constraints', 'put_constraint', (x, k) => x.control.upsertConstraint(x.tenant, x.admin, k)),
    put('containers', 'put_container', (x, k) => x.control.upsertContainer(x.tenant, x.admin, k)),
    { method: 'PUT', pattern: /^\/admin\/v1\/knowledge\/([^/]+)$/, label: '/admin/v1/knowledge/{id}', operation: 'put_knowledge', body: 'document',
      run: async ctx => {
        const d = pin(ctx, ctx.params[0]!) as Knowledge | null;
        if (!d) return invalid;
        const out = result(ingestor ? await ingestor.ingest(ctx.tenant, ctx.admin, d) : await ctx.control.upsertKnowledge(ctx.tenant, ctx.admin, d));
        // A new version may raise the label: descendants whose stored classification is lower are raised (R193).
        return (d as { version?: unknown }).version !== 1 ? followUp(ctx, ctx.params[0]!, out) : out;
      } },
    { method: 'DELETE', pattern: /^\/admin\/v1\/knowledge\/([^/]+)$/, label: '/admin/v1/knowledge/{id}', operation: 'delete_knowledge', body: 'none',
      run: async ctx => result(ingestor ? await ingestor.remove(ctx.tenant, ctx.admin, ctx.params[0]!) : await ctx.control.removeKnowledge(ctx.tenant, ctx.admin, ctx.params[0]!)) },
    { method: 'POST', pattern: /^\/admin\/v1\/knowledge\/([^/]+)\/quarantine$/, label: '/admin/v1/knowledge/{id}/quarantine', operation: 'quarantine', body: 'json',
      run: async ctx => exactKeys(ctx.body, ['reason']) && QUARANTINE_REASONS.includes(ctx.body.reason as QuarantineReason)
        ? followUp(ctx, ctx.params[0]!, result(ingestor?.quarantine ? await ingestor.quarantine(ctx.tenant, ctx.admin, ctx.params[0]!, ctx.body.reason as QuarantineReason) : await ctx.control.quarantine(ctx.tenant, ctx.admin, ctx.params[0]!, ctx.body.reason as QuarantineReason))) : invalid },
    { method: 'POST', pattern: /^\/admin\/v1\/knowledge\/([^/]+)\/release$/, label: '/admin/v1/knowledge/{id}/release', operation: 'release', body: 'none',
      run: async ctx => result(ingestor?.release ? await ingestor.release(ctx.tenant, ctx.admin, ctx.params[0]!) : await ctx.control.release(ctx.tenant, ctx.admin, ctx.params[0]!)) },
    { method: 'GET', pattern: /^\/admin\/v1\/knowledge\/([^/]+)\/descendants$/, label: '/admin/v1/knowledge/{id}/descendants', operation: 'lineage_read', body: 'none',
      run: async ctx => {
        const keys = [...ctx.query.keys()], raw = ctx.query.get('limit');
        if (keys.some(k => k !== 'limit') || keys.length > 1 || (raw !== null && !/^\d{1,4}$/.test(raw))) return invalid;
        return result(await ctx.control.descendants(ctx.tenant, ctx.admin, ctx.params[0]!, raw === null ? {} : { limit: Number(raw) }));
      } },
    { method: 'POST', pattern: /^\/admin\/v1\/knowledge\/([^/]+)\/revoke-lineage$/, label: '/admin/v1/knowledge/{id}/revoke-lineage', operation: 'revoke_lineage', body: 'none',
      run: async ctx => followUp(ctx, ctx.params[0]!, result(ingestor?.revokeLineage ? await ingestor.revokeLineage(ctx.tenant, ctx.admin, ctx.params[0]!) : await ctx.control.revokeLineage(ctx.tenant, ctx.admin, ctx.params[0]!))) },
    { method: 'POST', pattern: /^\/admin\/v1\/knowledge\/([^/]+)\/reinstate$/, label: '/admin/v1/knowledge/{id}/reinstate', operation: 'reinstate', body: 'none',
      run: async ctx => result(ingestor?.reinstate ? await ingestor.reinstate(ctx.tenant, ctx.admin, ctx.params[0]!) : await ctx.control.reinstate(ctx.tenant, ctx.admin, ctx.params[0]!)) },
    { method: 'PUT', pattern: /^\/admin\/v1\/knowledge\/([^/]+)\/legal-holds\/([^/]+)$/, label: '/admin/v1/knowledge/{id}/legal-holds/{holdId}', operation: 'legal_hold_set', body: 'none',
      run: async ctx => result(await ctx.control.setLegalHold(ctx.tenant, ctx.admin, ctx.params[0]!, true, ctx.params[1]!)) },
    { method: 'DELETE', pattern: /^\/admin\/v1\/knowledge\/([^/]+)\/legal-holds\/([^/]+)$/, label: '/admin/v1/knowledge/{id}/legal-holds/{holdId}', operation: 'legal_hold_lift', body: 'none',
      // Lifting a hold may unblock pending erasures (R194): they run in the background with the sweeper.
      run: async ctx => followUp(ctx, ctx.params[0]!, result(await ctx.control.setLegalHold(ctx.tenant, ctx.admin, ctx.params[0]!, false, ctx.params[1]!)), true) },
    { method: 'POST', pattern: /^\/admin\/v1\/knowledge\/([^/]+)\/erase$/, label: '/admin/v1/knowledge/{id}/erase', operation: 'erase', body: 'json',
      run: async ctx => {
        if (!exactKeys(ctx.body, [], ['cascade']) || (Object.hasOwn(ctx.body, 'cascade') && typeof ctx.body.cascade !== 'boolean')) return invalid;
        const options = Object.hasOwn(ctx.body, 'cascade') ? { cascade: ctx.body.cascade as boolean } : {};
        return result(ingestor?.erase ? await ingestor.erase(ctx.tenant, ctx.admin, ctx.params[0]!, options) : await ctx.control.erase(ctx.tenant, ctx.admin, ctx.params[0]!, options));
      } },
    // Knowledge semantics (0.6, ADR-022).
    { method: 'POST', pattern: /^\/admin\/v1\/knowledge\/([^/]+)\/sweep$/, label: '/admin/v1/knowledge/{id}/sweep', operation: 'sweep_lineage', body: 'json',
      run: async ctx => {
        if (!exactKeys(ctx.body, [], ['after']) || (Object.hasOwn(ctx.body, 'after') && !validId(ctx.body.after))) return invalid;
        const after = ctx.body.after as string | undefined;
        if (!sweeper) return result(await ctx.control.sweepLineage(ctx.tenant, ctx.admin, ctx.params[0]!, after ? { after } : {}));
        const r = await sweeper.sweep(ctx.tenant, ctx.admin, ctx.params[0]!, after ? { after } : {});
        if (!r.ran) { const denied = await ctx.control.attempt(ctx.tenant, ctx.admin, 'kb-admin', 'sweep_lineage', { allowed: false, reason: 'DENIED:CONFLICT' }); return denied.ok ? { status: 409, body: { ok: false, code: 'CONFLICT' } } : result(denied); }
        return r.refused ? { status: r.refused === 'INVALID_REQUEST' ? 400 : r.refused === 'NOT_AUTHORIZED' ? 403 : 409, body: { ok: false, code: r.refused } } : { status: 200, body: { ok: true, value: r } };
      } },
    { method: 'POST', pattern: /^\/admin\/v1\/models\/([^/]+)\/recall$/, label: '/admin/v1/models/{id}/recall', operation: 'quarantine_by_model', body: 'json',
      run: async ctx => {
        if (!validRange(ctx.body)) return invalid;
        const range = ctx.body as { from?: string; to?: string };
        if (!sweeper) return result(await ctx.control.quarantineByModel(ctx.tenant, ctx.admin, ctx.params[0]!, range));
        const r = await sweeper.recallModel(ctx.tenant, ctx.admin, ctx.params[0]!, range);
        if (!r.ran) { const denied = await ctx.control.attempt(ctx.tenant, ctx.admin, 'security-admin', 'quarantine_by_model', { allowed: false, reason: 'DENIED:CONFLICT' }); return denied.ok ? { status: 409, body: { ok: false, code: 'CONFLICT' } } : result(denied); }
        return r.refused ? { status: r.refused === 'INVALID_REQUEST' ? 400 : r.refused === 'NOT_AUTHORIZED' ? 403 : 409, body: { ok: false, code: r.refused } } : { status: 200, body: { ok: true, value: r } };
      } },
    { method: 'POST', pattern: /^\/admin\/v1\/erasures\/apply$/, label: '/admin/v1/erasures/apply', operation: 'apply_pending_erasures', body: 'json',
      run: async ctx => {
        if (!exactKeys(ctx.body, [], ['after']) || (Object.hasOwn(ctx.body, 'after') && !validId(ctx.body.after))) return invalid;
        const after = ctx.body.after as string | undefined;
        if (!sweeper) return result(await ctx.control.applyPendingErasures(ctx.tenant, ctx.admin, after ? { after } : {}));
        const r = await sweeper.applyPendingErasures(ctx.tenant, ctx.admin);
        if (!r.ran) { const denied = await ctx.control.attempt(ctx.tenant, ctx.admin, 'security-admin', 'apply_pending_erasures', { allowed: false, reason: 'DENIED:CONFLICT' }); return denied.ok ? { status: 409, body: { ok: false, code: 'CONFLICT' } } : result(denied); }
        return r.refused ? { status: r.refused === 'INVALID_REQUEST' ? 400 : r.refused === 'NOT_AUTHORIZED' ? 403 : 409, body: { ok: false, code: r.refused } } : { status: 200, body: { ok: true, value: r } };
      } },
    { method: 'PUT', pattern: /^\/admin\/v1\/combination-rules\/([^/]+)$/, label: '/admin/v1/combination-rules/{id}', operation: 'put_combination_rule', body: 'json',
      run: async ctx => { const r = pin(ctx, ctx.params[0]!); return r ? result(await ctx.control.upsertCombinationRule(ctx.tenant, ctx.admin, r as never)) : invalid; } },
    { method: 'GET', pattern: /^\/admin\/v1\/combination-rules\/([^/]+)$/, label: '/admin/v1/combination-rules/{id}', operation: 'read_combination_rule', body: 'none',
      run: async ctx => {
        const r = await ctx.control.readCombinationRule(ctx.tenant, ctx.admin, ctx.params[0]!);
        return r.ok && r.value === null ? { status: 404, body: { ok: false, code: 'NOT_FOUND', decisionId: r.decisionId } } : result(r);
      } },
    { method: 'POST', pattern: /^\/admin\/v1\/retention\/apply$/, label: '/admin/v1/retention/apply', operation: 'retention_apply', body: 'json',
      run: async ctx => {
        const b = ctx.body;
        if (!exactKeys(b, [], ['now', 'after', 'limit']) || (Object.hasOwn(b, 'now') && !safeNumber(b.now)) || (Object.hasOwn(b, 'after') && !validId(b.after))
          || (Object.hasOwn(b, 'limit') && !(Number.isSafeInteger(b.limit) && (b.limit as number) >= 1 && (b.limit as number) <= 100))) return invalid;
        const options: { after?: string; limit?: number } = {};
        if (Object.hasOwn(b, 'after')) options.after = b.after as string;
        if (Object.hasOwn(b, 'limit')) options.limit = b.limit as number;
        // One retention run per tenant across every instance; a concurrent run is refused (409), not queued.
        return exclusive('retention', ctx, 'security-admin', 'retention_apply', async (): Promise<Out> => {
          const r = await ctx.control.applyRetention(ctx.tenant, ctx.admin, Object.hasOwn(b, 'now') ? b.now as number : undefined, options);
          // Retention erases through the control plane: reconcile drops the chunks of what it erased.
          if (r.ok && r.value.erased > 0 && ingestor?.reconcile) {
            try { await ingestor.reconcile(ctx.tenant); } catch { return result({ ok: false, code: 'INDEX_PENDING', id: 'retention', version: 0, decisionId: r.decisionId }); }
          }
          return result(r);
        });
      } },
    { method: 'PUT', pattern: /^\/admin\/v1\/destinations\/([^/]+)$/, label: '/admin/v1/destinations/{id}', operation: 'put_destination', body: 'json',
      run: async ctx => {
        // Present once the control plane implements destination profiles; absent, the route does not exist.
        const upsert = (ctx.control as unknown as { upsertDestination?: (tenant: string, adminId: string, destination: unknown) => Promise<ControlResult<unknown>> }).upsertDestination;
        if (typeof upsert !== 'function') return { status: 404, body: { ok: false, code: 'NOT_FOUND' } };
        const d = pin(ctx, ctx.params[0]!);
        return d ? result(await upsert.call(ctx.control, ctx.tenant, ctx.admin, d)) : invalid;
      } },
    { method: 'GET', pattern: /^\/admin\/v1\/destinations\/([^/]+)$/, label: '/admin/v1/destinations/{id}', operation: 'read_destination', body: 'none',
      run: async ctx => {
        const r = await ctx.control.readDestination(ctx.tenant, ctx.admin, ctx.params[0]!);
        return r.ok && r.value === null ? { status: 404, body: { ok: false, code: 'NOT_FOUND', decisionId: r.decisionId } } : result(r);
      } },
    put('runtime-profiles', 'put_runtime_profile', (x, p) => x.control.upsertRuntimeProfile(x.tenant, x.admin, p)),
    { method: 'GET', pattern: /^\/admin\/v1\/runtime-profiles\/([^/]+)$/, label: '/admin/v1/runtime-profiles/{id}', operation: 'read_runtime_profile', body: 'none',
      run: async ctx => {
        const r = await ctx.control.readRuntimeProfile(ctx.tenant, ctx.admin, ctx.params[0]!);
        return r.ok && r.value === null ? { status: 404, body: { ok: false, code: 'NOT_FOUND', decisionId: r.decisionId } } : result(r);
      } },
    { method: 'POST', pattern: /^\/admin\/v1\/index\/reconcile$/, label: '/admin/v1/index/reconcile', operation: 'index_reconcile', body: 'none',
      run: async ctx => {
        if (!ingestor?.reconcile) return { status: 404, body: { ok: false, code: 'NOT_FOUND' } };
        const allowed = await ctx.control.authorize(ctx.tenant, ctx.admin, 'kb-admin', 'index_reconcile');
        if (!allowed.ok) return result(allowed);
        const reconcile = ingestor.reconcile.bind(ingestor);
        return exclusive('reconcile', ctx, 'kb-admin', 'index_reconcile', async (): Promise<Out> => ({ status: 200, body: { ok: true, value: await reconcile(ctx.tenant) } }));
      } },
    // Embedding anchors (0.6, ADR-020): accepts the current embedder as the new baseline and re-enables vector retrieval. Instance-wide (one embedder serves every tenant of the instance), so it needs security-admin, not kb-admin.
    { method: 'POST', pattern: /^\/admin\/v1\/index\/anchors\/rebaseline$/, label: '/admin/v1/index/anchors/rebaseline', operation: 'index_rebaseline', body: 'none',
      run: async ctx => {
        const monitor = options.anchors;
        if (!monitor) return { status: 404, body: { ok: false, code: 'NOT_FOUND' } };
        const allowed = await ctx.control.authorize(ctx.tenant, ctx.admin, 'security-admin', 'index_rebaseline');
        if (!allowed.ok) return result(allowed);
        try { await monitor.rebaseline(); } catch { return { status: 503, body: { ok: false, code: 'UNAVAILABLE' } }; }
        return { status: 200, body: { ok: true, value: { state: monitor.state }, decisionId: allowed.decisionId } };
      } },
    { method: 'POST', pattern: /^\/admin\/v1\/grants$/, label: '/admin/v1/grants', operation: 'issue_grant', body: 'json',
      run: async ctx => {
        const id = plain(ctx.body) && validId(ctx.body.id) ? ctx.body.id : undefined;
        const grant = id ? pin(ctx, id) : null;
        return grant ? result(await ctx.control.issueGrant(ctx.tenant, ctx.admin, grant as never), 201) : invalid;
      } },
    // Identity and authority (0.6, ADR-019).
    { method: 'POST', pattern: /^\/admin\/v1\/grants\/([^/]+)\/heartbeat$/, label: '/admin/v1/grants/{id}/heartbeat', operation: 'grant_heartbeat', body: 'none',
      run: async ctx => result(await ctx.control.heartbeat(ctx.tenant, ctx.admin, ctx.params[0]!)) },
    { method: 'POST', pattern: /^\/admin\/v1\/break-glass$/, label: '/admin/v1/break-glass', operation: 'issue_break_glass', body: 'json',
      run: async ctx => plain(ctx.body) ? result(await ctx.control.issueBreakGlass(ctx.tenant, ctx.admin, ctx.body as never), 201) : invalid },
    { method: 'GET', pattern: /^\/admin\/v1\/approvals$/, label: '/admin/v1/approvals', operation: 'approval_list', body: 'none',
      run: async ctx => [...ctx.query.keys()].length ? invalid : result(await ctx.control.listApprovals(ctx.tenant, ctx.admin)) },
    { method: 'GET', pattern: /^\/admin\/v1\/approvals\/([^/]+)$/, label: '/admin/v1/approvals/{id}', operation: 'approval_read', body: 'none',
      run: async ctx => {
        const r = await ctx.control.readApproval(ctx.tenant, ctx.admin, ctx.params[0]!);
        return r.ok && r.value === null ? { status: 404, body: { ok: false, code: 'NOT_FOUND', decisionId: r.decisionId } } : result(r);
      } },
    { method: 'POST', pattern: /^\/admin\/v1\/approvals\/([^/]+)\/approve$/, label: '/admin/v1/approvals/{id}/approve', operation: 'approval_grant', body: 'none',
      run: async ctx => result(await ctx.control.approve(ctx.tenant, ctx.admin, ctx.params[0]!)) },
    { method: 'POST', pattern: /^\/admin\/v1\/approvals\/([^/]+)\/reject$/, label: '/admin/v1/approvals/{id}/reject', operation: 'approval_reject', body: 'none',
      run: async ctx => result(await ctx.control.reject(ctx.tenant, ctx.admin, ctx.params[0]!)) },
    { method: 'POST', pattern: /^\/admin\/v1\/approvals\/([^/]+)\/execute$/, label: '/admin/v1/approvals/{id}/execute', operation: 'approval_execute', body: 'none',
      run: async ctx => result(await ctx.control.executeApproval(ctx.tenant, ctx.admin, ctx.params[0]!)) },
    { method: 'POST', pattern: /^\/admin\/v1\/risk-signals$/, label: '/admin/v1/risk-signals', operation: 'risk_signal', body: 'json',
      run: async ctx => plain(ctx.body) ? result(await ctx.control.putRiskSignal(ctx.tenant, ctx.admin, ctx.body as never)) : invalid },
    { method: 'PUT', pattern: /^\/admin\/v1\/settings$/, label: '/admin/v1/settings', operation: 'put_settings', body: 'json',
      run: async ctx => {
        const b = ctx.body;
        if (!plain(b) || (Object.hasOwn(b, 'tenant') && b.tenant !== ctx.tenant) || (Object.hasOwn(b, 'id') && b.id !== ctx.tenant)) return invalid;
        return result(await ctx.control.putSettings(ctx.tenant, ctx.admin, { ...b, id: ctx.tenant, tenant: ctx.tenant } as never));
      } },
    { method: 'GET', pattern: /^\/admin\/v1\/settings$/, label: '/admin/v1/settings', operation: 'read_settings', body: 'none',
      run: async ctx => [...ctx.query.keys()].length ? invalid : result(await ctx.control.readSettings(ctx.tenant, ctx.admin)) },
    { method: 'POST', pattern: /^\/admin\/v1\/revocations$/, label: '/admin/v1/revocations', operation: 'revoke', body: 'json',
      run: async ctx => {
        if (!(exactKeys(ctx.body, ['type', 'id']) && ['grant', 'knowledge', 'actor'].includes(ctx.body.type as string) && validId(ctx.body.id))) return invalid;
        const out = result(await ctx.control.revoke(ctx.tenant, ctx.admin, ctx.body.type as 'grant', ctx.body.id));
        return ctx.body.type === 'knowledge' ? followUp(ctx, ctx.body.id, out) : out;
      } },
    { method: 'GET', pattern: /^\/admin\/v1\/audit$/, label: '/admin/v1/audit', operation: 'audit_read', body: 'none',
      run: async ctx => {
        const q = paging(ctx.query, ['after', 'limit']); if (!q) return invalid;
        const r = await ctx.control.auditLog(ctx.tenant, ctx.admin, q.after, q.limit ?? 1000);
        return r.ok ? { status: 200, body: { ok: true, value: { entries: r.value, next: r.value.length ? r.value.at(-1)!.sequence : null } } } : result(r);
      } },
    { method: 'GET', pattern: /^\/admin\/v1\/audit\/export$/, label: '/admin/v1/audit/export', operation: 'audit_export', body: 'none',
      run: async ctx => {
        const q = paging(ctx.query, ['after']); if (!q) return invalid;
        // Pages are authorized and audited one by one; an export therefore leaves audit_read entries.
        let after = q.after, first = true;
        for (;;) {
          const r = await ctx.control.auditLog(ctx.tenant, ctx.admin, after, ADMIN_LIMITS.exportPage);
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
    ,
    { method: 'GET', pattern: /^\/admin\/v1\/audit\/checkpoint$/, label: '/admin/v1/audit/checkpoint', operation: 'audit_checkpoint', body: 'none',
      run: async ctx => {
        if ([...ctx.query.keys()].length) return invalid;
        const r = await ctx.control.latestCheckpoint(ctx.tenant, ctx.admin);
        return result(r);
      } },
    { method: 'GET', pattern: /^\/admin\/v1\/audit\/proof$/, label: '/admin/v1/audit/proof', operation: 'audit_proof', body: 'none',
      run: async ctx => {
        const q = numbers(ctx.query, ['leafIndex', 'treeSize']); if (!q) return invalid;
        return result(await ctx.control.auditProof(ctx.tenant, ctx.admin, q.leafIndex!, q.treeSize!));
      } },
    { method: 'GET', pattern: /^\/admin\/v1\/audit\/consistency$/, label: '/admin/v1/audit/consistency', operation: 'audit_consistency', body: 'none',
      run: async ctx => {
        const q = numbers(ctx.query, ['first', 'second']); if (!q) return invalid;
        return result(await ctx.control.auditConsistency(ctx.tenant, ctx.admin, q.first!, q.second!));
      } }
  ];
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
      let who: AdminIdentity | null | undefined, challenge: string[] = ['Bearer'];
      if (dpop) {
        const outcome = await dpop.authorize(req, (t, proof) => options.authenticator!.authenticate(t, proof));
        if (outcome.ok) who = outcome.value; else challenge = outcome.challenge;
      } else {
        const header = req.headers.authorization;
        const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
        who = options.authenticator ? await options.authenticator.authenticate(token) : auth.get(token.length <= 512 ? digest(token) : '');
      }
      if (!who) { res.setHeader('www-authenticate', challenge); refuse(401, 'UNAUTHENTICATED', 'Authentication required'); return; }
      let limited;
      try { limited = await limiter.take(who.tenant, 'admin', digest(`${who.tenant}\u0000${who.admin}`), ADMIN_LIMITS.perMinute, 60_000); }
      catch { options.metrics?.rateLimited('admin', 'unavailable'); refuse(503, 'UNAVAILABLE', 'Service unavailable'); return; }
      if (!limited.ok) {
        options.metrics?.rateLimited('admin', limited.reason);
        res.setHeader('retry-after', String(limited.retryAfter)); refuse(limited.status, limited.status === 429 ? 'RATE_LIMITED' : 'BUSY'); return;
      }

      // The W3C trace id of the request (a valid traceparent, else a fresh one) and the execution id are recorded with every audited decision.
      const executionId = executionHeader(req.headers[EXECUTION_HEADER]);
      if (executionId === null) { refuse(400, 'INVALID_REQUEST'); return; }
      const traced = control.traced({ traceId: obs.traceId, ...(executionId ? { executionId } : {}) });
      let label = 'unmatched', operation = 'unknown', bodyKind: Route['body'] = 'none', params: string[] = [];
      let run: ((ctx: Ctx) => Promise<Out>) | undefined;
      let type = 'application/json';
      if (scimEnabled && url.pathname.startsWith('/scim/v2/')) {
        const m = createScim(traced).match(req.method ?? '', url.pathname, url.searchParams);
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

      const ctx: Ctx = { control: traced, tenant: who.tenant, admin: who.admin, params, body, query: url.searchParams, req, res };
      const key = req.headers['idempotency-key'];
      if (key !== undefined && operation === 'issue_grant') {
        if (typeof key !== 'string' || !IDEMPOTENCY_KEY.test(key)) { refuse(400, 'INVALID_REQUEST'); return; }
        const owner = digest(`${who.tenant}\u0000${who.admin}`), fingerprint = digest(JSON.stringify(body));
        let claim;
        try { claim = await idem.claim(who.tenant, owner, key, fingerprint); }
        catch { options.metrics?.idempotent('unavailable'); refuse(503, 'UNAVAILABLE', 'Service unavailable'); return; }
        if (claim.state === 'seen') {
          // Answered from the record, but still an administrative attempt: re-check the
          // standing role now and audit the outcome (R31).
          const outcome = claim.fingerprint !== fingerprint ? { allowed: false, reason: 'DENIED:IDEMPOTENCY_KEY_REUSED' }
            : !claim.response ? { allowed: false, reason: 'DENIED:CONFLICT' } : { allowed: true, reason: 'IDEMPOTENT_REPLAY' };
          const allowed = await traced.attempt(who.tenant, who.admin, 'security-admin', operation, outcome);
          if (!allowed.ok) { finish(result(allowed)); return; }
          if (claim.fingerprint !== fingerprint) { options.metrics?.idempotent('reused'); finish({ status: 422, body: { ok: false, code: 'IDEMPOTENCY_KEY_REUSED' } }); return; }
          if (!claim.response) { options.metrics?.idempotent('in_flight'); finish({ status: 409, body: { ok: false, code: 'CONFLICT' } }); return; }
          options.metrics?.idempotent('replayed');
          finish({ status: claim.response.status, body: claim.response.body, extra: { 'idempotent-replayed': 'true' } }); return;
        }
        let out: Out;
        try { out = await run(ctx); }
        catch (error) { await idem.release(who.tenant, owner, key).catch(() => {}); throw error; }
        // Transient failures are not remembered: the caller may retry with the same key.
        if (out !== 'streamed' && out.status < 500) {
          // If recording fails the response still stands; the claim lapses with its lease.
          try { await idem.complete(who.tenant, owner, key, { status: out.status, ...(out.body === undefined ? {} : { body: out.body }) }); options.metrics?.idempotent('stored'); }
          catch { options.metrics?.idempotent('unavailable'); }
        } else await idem.release(who.tenant, owner, key).catch(() => {});
        finish(out);
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
/** Strict query parsing for proof routes: exactly the named parameters, once each, unsigned decimal integers. */
function numbers(query: URLSearchParams, names: string[]): Record<string, number> | null {
  const keys = [...query.keys()];
  if (keys.length !== names.length || new Set(keys).size !== keys.length || !names.every(n => query.has(n))) return null;
  const out: Record<string, number> = {};
  for (const n of names) { const v = query.get(n)!; if (!/^\d{1,15}$/.test(v)) return null; out[n] = Number(v); }
  return out;
}
