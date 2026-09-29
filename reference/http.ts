import { createServer } from 'node:http';
import type { ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { Engine, validId } from './engine.ts';
import type { Binding } from './types.ts';
import type { Authenticator } from '../adapters/jwt.ts';
import { DpopGuard } from '../adapters/dpop.ts';
import type { DpopOptions } from '../adapters/dpop.ts';
import { observe } from './observe.ts';
import { MemoryRateLimits } from './limits.ts';
import type { RateLimitStore, RateVerdict } from './limits.ts';
import type { Observability } from './observe.ts';
import { Backoff, Equaliser } from './protection.ts';
import type { BackoffOptions, TimingOptions } from './protection.ts';
import type { ObligationType } from './decision.ts';
import { MODALITIES } from './types.ts';
import type { Modality } from './types.ts';
import type { DeriveOptions } from './engine.ts';

export type Credential = { token: string; binding: Binding };
/**
 * Optional `x-akac-execution-id` request header (0.5, ADR-012): the agent
 * execution (sandbox, job) the request belongs to, recorded as `executionId` with
 * the audited decision. Correlation only, never authority; a malformed or repeated
 * header is a 400. A runtime revision is never accepted over HTTP: an agent could
 * claim any revision, so only a trusted in-process runtime enforcer path
 * (ProtectedRuntime) records one.
 */
export const EXECUTION_HEADER = 'x-akac-execution-id';
/** undefined: absent; null: malformed (the request is refused). */
export function executionHeader(value: string | string[] | undefined): string | undefined | null {
  if (value === undefined) return undefined;
  return typeof value === 'string' && validId(value) ? value : null;
}
const digest = (token: string) => createHash('sha256').update(token).digest('hex');
/** DELETE /v1/sessions/{id} (0.6, R190). */
const SESSION = /^\/v1\/sessions\/([a-zA-Z0-9][a-zA-Z0-9._:-]{0,127})$/;
/** Optional derive() fields (0.6, ADR-022): modality, session {id, ttlMs?}, container; null when malformed. */
function deriveOptions(body: Record<string, unknown>): DeriveOptions | null {
  const s = body.session as Record<string, unknown> | undefined;
  if (body.modality !== undefined && !(MODALITIES as readonly unknown[]).includes(body.modality)) return null;
  if (body.container !== undefined && !validId(body.container)) return null;
  if (s !== undefined && !(keys(s, ['id'], ['ttlMs']) && validId(s.id) && (s.ttlMs === undefined || Number.isSafeInteger(s.ttlMs)))) return null;
  return { ...(body.modality !== undefined ? { modality: body.modality as Modality } : {}), ...(body.container !== undefined ? { container: body.container as string } : {}),
    ...(s !== undefined ? { session: { id: s.id as string, ...(s.ttlMs !== undefined ? { ttlMs: s.ttlMs as number } : {}) } } : {}) };
}
const text = (v: unknown, max: number) => typeof v === 'string' && v.length > 0 && v.length <= max;
function keys(value: unknown, required: string[], optional: string[] = []): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
    && required.every(k => Object.hasOwn(value, k))
    && Object.keys(value).every(k => [...required, ...optional].includes(k));
}
function send(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'" });
  res.end(JSON.stringify(body));
}
/**
 * Fixed-window rate limits (0.4, R-HARD-1..4; shared state 0.6, ADR-016). Budgets are requests per window:
 * `credential` covers every authenticated request of one binding; `retrieve`, `contexts` and `write`
 * (derive and release) are separate budgets per (tenant, agent, grant) run. By default the windows live in
 * process memory (MemoryRateLimits) and are NOT shared: with N instances the effective limit is up to N
 * times the budget. Pass `limiter` (adapters/postgres-ha.ts PostgresRateLimits) to count every instance
 * into the same windows. In memory at most `maxBuckets` windows are tracked per scope; when full, a
 * request that would need a new bucket is refused with 503 (fail closed) rather than evicting another
 * caller's counter. A limiter error is a 503 as well.
 */
export type RateLimits = { credential?: number; retrieve?: number; contexts?: number; write?: number; windowMs?: number; maxBuckets?: number; clock?: () => number };
export const RATE_LIMITS = { credential: 120, retrieve: 60, contexts: 60, write: 30, windowMs: 60000, maxBuckets: 10000 } as const;
const budgetOf = (url: string | undefined): 'retrieve' | 'contexts' | 'write' | undefined =>
  url === '/v1/retrieve' ? 'retrieve' : url === '/v1/contexts' ? 'contexts' : url === '/v1/derive' || url === '/v1/release' ? 'write' : undefined;
/**
 * How the agent listener treats `runtime_profile` obligations (0.6, R123). The
 * listener returns content to the agent credential and cannot confine the runtime
 * that receives it:
 * - 'deny' (default): a retrieve, context, derive or release whose allow would carry
 *   a runtime_profile obligation is denied (UNSUPPORTED_OBLIGATION, R38); the
 *   operation is rolled back and the denial audited.
 * - 'trusted-enforcer': the operator declares that every client of this listener
 *   runs inside a runtime enforcer that applies the returned runtime_profile
 *   obligations before the content is used (R112). AKAC cannot verify this.
 */
export type RuntimeObligationMode = 'deny' | 'trusted-enforcer';
export const RUNTIME_OBLIGATION_MODES: readonly RuntimeObligationMode[] = ['deny', 'trusted-enforcer'];
/**
 * Release and retrieval protections of the agent listener (0.6, ADR-020, spec/AKAC-0.6.md):
 * - `timing`: response-time floor with jitter for /v1/retrieve and /v1/contexts, so a denial, a no-match and a match
 *   answer within the same time as long as the work stays below the floor (pick a floor above the p99 latency).
 * - `denialHints` (default off): a denial may carry a closed `hint` about the caller's own grant, credential or budget
 *   (never about a resource); see DENIAL_HINTS in reference/decision.ts.
 * - `backoff`: repeated denials of one (tenant, user, agent) earn exponentially longer 429 answers with Retry-After.
 */
export type ProtectionOptions = { timing?: TimingOptions; denialHints?: boolean; backoff?: BackoffOptions };
export function createGateway(engine: Engine, credentials: Credential[], options: { authenticator?: Authenticator; dpop?: DpopOptions; rateLimits?: RateLimits; limiter?: RateLimitStore; runtimeObligations?: RuntimeObligationMode } & ProtectionOptions & Observability = {}) {
  if (!credentials.length && !options.authenticator) throw new Error('Authentication is required');
  if (options.denialHints !== undefined && typeof options.denialHints !== 'boolean') throw new Error('Invalid denial hints setting');
  const equaliser = options.timing ? new Equaliser(options.timing) : undefined;
  const backoff = options.backoff ? new Backoff(options.backoff) : undefined;
  const hints = options.denialHints === true;
  const runtimeMode = options.runtimeObligations ?? 'deny';
  if (!RUNTIME_OBLIGATION_MODES.includes(runtimeMode)) throw new Error('Invalid runtime obligation mode');
  // Opaque credentials carry no key confirmation, so DPoP cannot apply to them.
  if (options.dpop && !options.authenticator) throw new Error('DPoP requires signed-token authentication');
  const dpop = options.dpop ? new DpopGuard(options.dpop) : undefined;
  if (credentials.length && options.authenticator) throw new Error('Authentication modes cannot be mixed');
  const auth = new Map<string, Binding>();
  for (const credential of credentials) {
    if (!text(credential.token, 512) || credential.token.length < 32
      || !keys(credential.binding, ['tenant', 'subject', 'agent', 'grant'])
      || !Object.values(credential.binding).every(validId) || auth.has(digest(credential.token))) throw new Error('Invalid credential configuration');
    auth.set(digest(credential.token), structuredClone(credential.binding));
  }
  const rl = { ...RATE_LIMITS, ...options.rateLimits };
  for (const v of [rl.credential, rl.retrieve, rl.contexts, rl.write, rl.windowMs, rl.maxBuckets]) if (!Number.isSafeInteger(v) || v < 1) throw new Error('Invalid rate limit configuration');
  const limiter = options.limiter ?? new MemoryRateLimits({ maxBuckets: rl.maxBuckets, clock: options.rateLimits?.clock ?? Date.now });
  /** A limiter failure (shared store unreachable) refuses the request: 503, never an unlimited pass. */
  const take = async (tenant: string, scope: string, key: string, limit: number): Promise<RateVerdict | 'unavailable'> => {
    try { return await limiter.take(tenant, scope, key, limit, rl.windowMs); } catch { return 'unavailable'; }
  };
  let active = 0;
  const routes = new Set(['/health', '/ready', '/v1/retrieve', '/v1/contexts', '/v1/derive', '/v1/release']);
  const server = createServer(async (req, res) => {
    const obs = observe('agent', req, res, options);
    obs.setRoute(routes.has(req.url ?? '') ? req.url! : SESSION.test(req.url ?? '') ? '/v1/sessions/{id}' : 'unmatched');
    if (active >= 32) { req.resume(); send(res, 503, { error: 'BUSY' }); return; }
    active++;
    try {
    if (req.url === '/health' && req.method === 'GET') { send(res, 200, { status: 'ok', specification: '0.6-draft' }); return; }
    const executionId = executionHeader(req.headers[EXECUTION_HEADER]);
    if (executionId === null) { req.resume(); send(res, 400, { error: 'INVALID_REQUEST' }); return; }
    let binding: Binding | null | undefined;
    if (dpop) {
      const outcome = await dpop.authorize(req, (t, proof) => options.authenticator!.authenticate(t, proof));
      if (outcome.ok) binding = outcome.value; else res.setHeader('www-authenticate', outcome.challenge);
    } else {
      const header = req.headers.authorization;
      const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
      binding = options.authenticator ? await options.authenticator.authenticate(token)
        : auth.get(token.length <= 512 ? digest(token) : '');
    }
    if (!binding) { req.resume(); send(res, 401, { error: 'UNAUTHENTICATED' }); return; }
    const throttle = (r: Exclude<RateVerdict, { ok: true }> | 'unavailable') => {
      req.resume();
      options.metrics?.rateLimited('agent', r === 'unavailable' ? 'unavailable' : r.reason);
      if (r === 'unavailable') { send(res, 503, { error: 'UNAVAILABLE' }); return; }
      res.setHeader('retry-after', String(r.retryAfter)); send(res, r.status, { error: r.status === 429 ? 'RATE_LIMITED' : 'BUSY', ...(hints && r.status === 429 ? { hint: 'RATE_LIMITED' } : {}) });
    };
    const overall = await take(binding.tenant, 'agent-credential', digest(JSON.stringify(binding)), rl.credential);
    if (overall === 'unavailable' || !overall.ok) { throttle(overall); return; }
    const budget = req.method === 'POST' ? budgetOf(req.url) : undefined;
    // Progressive backoff (ADR-020): a principal with a run of denials is refused for a growing time, without touching the engine.
    if (budget && backoff) {
      const wait = backoff.blocked(binding);
      if (wait) { req.resume(); options.metrics?.rateLimited('agent', 'limited'); res.setHeader('retry-after', String(wait)); send(res, 429, { error: 'RATE_LIMITED', ...(hints ? { hint: 'RATE_LIMITED' } : {}) }); return; }
    }
    if (budget) {
      // Separate budget per operation class and (tenant, agent, grant) run; JSON-encoded so fields cannot collide.
      const run = await take(binding.tenant, 'agent-run', digest(JSON.stringify([budget, binding.tenant, binding.agent, binding.grant])), rl[budget]);
      if (run === 'unavailable' || !run.ok) { throttle(run); return; }
    }
    // Session close (0.6, R190): removes the session-scoped records of the credential's own run. No body.
    const session = req.method === 'DELETE' ? SESSION.exec(req.url ?? '') : null;
    if (session) {
      req.resume();
      const closed = await engine.closeSession(binding, session[1]!, { trace: { traceId: obs.traceId, ...(executionId ? { executionId } : {}) } });
      send(res, closed.ok ? 200 : 403, closed); return;
    }
    if (req.url === '/ready' && req.method === 'GET') {
      const ready = await engine.ready(binding.tenant); send(res, ready ? 200 : 503, { status: ready ? 'ready' : 'unavailable' }); return;
    }
    // Response-time equalisation (ADR-020): everything answered from here on for retrieve and contexts waits for the floor.
    const equalised = equaliser && req.method === 'POST' && (req.url === '/v1/retrieve' || req.url === '/v1/contexts');
    const started = equalised ? equaliser.start() : 0;
    const reply = async (status: number, body: unknown) => { if (equalised) await equaliser.pad(started); send(res, status, body); };
    if (req.method !== 'POST' || req.headers['content-type']?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
      req.resume(); await reply(400, { error: 'INVALID_REQUEST' }); return;
    }
    try {
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 131072) { await reply(413, { error: 'REQUEST_TOO_LARGE' }); return; }
        chunks.push(Buffer.from(chunk));
      }
      let body: unknown;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { await reply(400, { error: 'INVALID_JSON' }); return; }
      let result;
      // The W3C trace id of the request (valid traceparent, else fresh) and the execution id are recorded with the audited decision; neither carries authority.
      // approval_required needs an approval workflow this listener does not have: an allow carrying it is refused (fail closed).
      const unenforceable: ObligationType[] = ['approval_required', ...(runtimeMode === 'deny' ? ['runtime_profile' as const] : [])];
      const call = { trace: { traceId: obs.traceId, ...(executionId ? { executionId } : {}) }, unenforceable, ...(hints ? { hints: true as const } : {}) };
      if (req.url === '/v1/retrieve' && keys(body, ['query', 'purpose'], ['limit'])
        && text(body.query, 4096) && text(body.purpose, 128)
        && (body.limit === undefined || (Number.isInteger(body.limit) && Number(body.limit) >= 1 && Number(body.limit) <= 20))) {
        result = await engine.retrieve(binding, body.query as string, body.purpose as string, body.limit as number | undefined, call);
      } else if (req.url === '/v1/contexts' && keys(body, ['resources', 'purpose'])
        && Array.isArray(body.resources) && body.resources.length > 0 && body.resources.length <= 64
        && body.resources.every(validId) && text(body.purpose, 128)) {
        result = await engine.openContext(binding, body.resources, body.purpose as string, call);
      } else if (req.url === '/v1/derive' && keys(body, ['context', 'content', 'kind'], ['modality', 'session', 'container'])
        && validId(body.context) && text(body.content, 100000) && ['memory', 'artifact'].includes(body.kind as string) && deriveOptions(body)) {
        // Caller options only narrow (ADR-022); the model lineage is never taken from a request (R191).
        result = await engine.derive(binding, body.context, body.content as string, body.kind as 'memory' | 'artifact', call, deriveOptions(body)!);
      } else if (req.url === '/v1/release' && keys(body, ['context', 'recipient', 'content', 'action'])
        && validId(body.context) && validId(body.recipient) && text(body.content, 100000)
        && ['share', 'export'].includes(body.action as string)) {
        result = await engine.release(binding, body.context, body.recipient, body.content as string, body.action as 'share' | 'export', call);
      } else { await reply(400, { error: 'INVALID_REQUEST' }); return; }
      if (backoff && budget) {
        if (result.ok) backoff.allowed(binding);
        else { const wait = backoff.denied(binding); if (wait) res.setHeader('retry-after', String(wait)); }
      }
      await reply(result.ok ? 200 : 403, result);
    } catch { if (!res.headersSent) await reply(503, { error: 'UNAVAILABLE' }); }
    } catch { if (!res.headersSent) send(res, 503, { error: 'UNAVAILABLE' }); }
    finally { active--; }
  });
  server.requestTimeout = 10000; server.headersTimeout = 5000; server.timeout = 15000;
  server.maxHeadersCount = 32;
  return server;
}
