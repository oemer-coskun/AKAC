import { createServer } from 'node:http';
import type { ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { Engine, validId } from './engine.ts';
import type { Binding } from './types.ts';
import type { Authenticator } from '../adapters/jwt.ts';
import { DpopGuard } from '../adapters/dpop.ts';
import type { DpopOptions } from '../adapters/dpop.ts';
import { observe } from './observe.ts';
import type { Observability } from './observe.ts';

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
 * Per-instance fixed-window rate limits (0.4, R-HARD-1..4). Budgets are requests per window:
 * `credential` covers every authenticated request of one binding; `retrieve`, `contexts` and `write`
 * (derive and release) are separate budgets per (tenant, agent, grant) run. State is in process memory
 * and is NOT shared between gateway instances: with N instances the effective limit is up to N times
 * the budget, so deployments that need a global limit MUST also enforce one at the edge. At most
 * `maxBuckets` windows are tracked per limiter; when full, requests that would need a new bucket are
 * refused with 503 (fail closed) rather than evicting another caller's counter.
 */
export type RateLimits = { credential?: number; retrieve?: number; contexts?: number; write?: number; windowMs?: number; maxBuckets?: number; clock?: () => number };
export const RATE_LIMITS = { credential: 120, retrieve: 60, contexts: 60, write: 30, windowMs: 60000, maxBuckets: 10000 } as const;
class Limiter {
  private buckets = new Map<string, { window: number; count: number }>();
  private swept = -1;
  private windowMs: number; private maxBuckets: number; private clock: () => number;
  constructor(windowMs: number, maxBuckets: number, clock: () => number) { this.windowMs = windowMs; this.maxBuckets = maxBuckets; this.clock = clock; }
  take(key: string, limit: number): { ok: true } | { ok: false; status: 429 | 503; retryAfter: number } {
    const now = this.clock(), window = Math.floor(now / this.windowMs);
    const retryAfter = Math.max(1, Math.ceil(((window + 1) * this.windowMs - now) / 1000));
    if (window !== this.swept || this.buckets.size >= this.maxBuckets) {
      for (const [k, v] of this.buckets) if (v.window !== window) this.buckets.delete(k);
      this.swept = window;
    }
    let bucket = this.buckets.get(key);
    if (!bucket) {
      if (this.buckets.size >= this.maxBuckets) return { ok: false, status: 503, retryAfter };
      bucket = { window, count: 0 }; this.buckets.set(key, bucket);
    }
    return ++bucket.count > limit ? { ok: false, status: 429, retryAfter } : { ok: true };
  }
}
const budgetOf = (url: string | undefined): 'retrieve' | 'contexts' | 'write' | undefined =>
  url === '/v1/retrieve' ? 'retrieve' : url === '/v1/contexts' ? 'contexts' : url === '/v1/derive' || url === '/v1/release' ? 'write' : undefined;
export function createGateway(engine: Engine, credentials: Credential[], options: { authenticator?: Authenticator; dpop?: DpopOptions; rateLimits?: RateLimits } & Observability = {}) {
  if (!credentials.length && !options.authenticator) throw new Error('Authentication is required');
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
  const clock = options.rateLimits?.clock ?? Date.now;
  const perCredential = new Limiter(rl.windowMs, rl.maxBuckets, clock), perRun = new Limiter(rl.windowMs, rl.maxBuckets, clock);
  let active = 0;
  const routes = new Set(['/health', '/ready', '/v1/retrieve', '/v1/contexts', '/v1/derive', '/v1/release']);
  const server = createServer(async (req, res) => {
    const obs = observe('agent', req, res, options);
    obs.setRoute(routes.has(req.url ?? '') ? req.url! : 'unmatched');
    if (active >= 32) { req.resume(); send(res, 503, { error: 'BUSY' }); return; }
    active++;
    try {
    if (req.url === '/health' && req.method === 'GET') { send(res, 200, { status: 'ok', specification: '0.5-draft' }); return; }
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
    const throttle = (r: { ok: false; status: 429 | 503; retryAfter: number }) => {
      req.resume(); res.setHeader('retry-after', String(r.retryAfter)); send(res, r.status, { error: r.status === 429 ? 'RATE_LIMITED' : 'BUSY' });
    };
    const overall = perCredential.take(digest(JSON.stringify(binding)), rl.credential);
    if (!overall.ok) { throttle(overall); return; }
    const budget = req.method === 'POST' ? budgetOf(req.url) : undefined;
    if (budget) {
      // Separate budget per operation class and (tenant, agent, grant) run; JSON-encoded so fields cannot collide.
      const run = perRun.take(digest(JSON.stringify([budget, binding.tenant, binding.agent, binding.grant])), rl[budget]);
      if (!run.ok) { throttle(run); return; }
    }
    if (req.url === '/ready' && req.method === 'GET') {
      const ready = await engine.ready(binding.tenant); send(res, ready ? 200 : 503, { status: ready ? 'ready' : 'unavailable' }); return;
    }
    if (req.method !== 'POST' || req.headers['content-type']?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
      req.resume(); send(res, 400, { error: 'INVALID_REQUEST' }); return;
    }
    try {
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 131072) { send(res, 413, { error: 'REQUEST_TOO_LARGE' }); return; }
        chunks.push(Buffer.from(chunk));
      }
      let body: unknown;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { send(res, 400, { error: 'INVALID_JSON' }); return; }
      let result;
      // The W3C trace id of the request (valid traceparent, else fresh) and the execution id are recorded with the audited decision; neither carries authority.
      const call = { trace: { traceId: obs.traceId, ...(executionId ? { executionId } : {}) } };
      if (req.url === '/v1/retrieve' && keys(body, ['query', 'purpose'], ['limit'])
        && text(body.query, 4096) && text(body.purpose, 128)
        && (body.limit === undefined || (Number.isInteger(body.limit) && Number(body.limit) >= 1 && Number(body.limit) <= 20))) {
        result = await engine.retrieve(binding, body.query as string, body.purpose as string, body.limit as number | undefined, call);
      } else if (req.url === '/v1/contexts' && keys(body, ['resources', 'purpose'])
        && Array.isArray(body.resources) && body.resources.length > 0 && body.resources.length <= 64
        && body.resources.every(validId) && text(body.purpose, 128)) {
        result = await engine.openContext(binding, body.resources, body.purpose as string, call);
      } else if (req.url === '/v1/derive' && keys(body, ['context', 'content', 'kind'])
        && validId(body.context) && text(body.content, 100000) && ['memory', 'artifact'].includes(body.kind as string)) {
        result = await engine.derive(binding, body.context, body.content as string, body.kind as 'memory' | 'artifact', call);
      } else if (req.url === '/v1/release' && keys(body, ['context', 'recipient', 'content', 'action'])
        && validId(body.context) && validId(body.recipient) && text(body.content, 100000)
        && ['share', 'export'].includes(body.action as string)) {
        result = await engine.release(binding, body.context, body.recipient, body.content as string, body.action as 'share' | 'export', call);
      } else { send(res, 400, { error: 'INVALID_REQUEST' }); return; }
      send(res, result.ok ? 200 : 403, result);
    } catch { if (!res.headersSent) send(res, 503, { error: 'UNAVAILABLE' }); }
    } catch { if (!res.headersSent) send(res, 503, { error: 'UNAVAILABLE' }); }
    finally { active--; }
  });
  server.requestTimeout = 10000; server.headersTimeout = 5000; server.timeout = 15000;
  server.maxHeadersCount = 32;
  return server;
}
