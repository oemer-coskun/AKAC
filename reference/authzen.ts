import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { appendAudit } from './audit.ts';
import { CORE_VERSION } from './types.ts';
import type { Action, Binding, PolicyHook, State, Store } from './types.ts';
import { validId } from './validation.ts';
import { classify, executionOf, newDecisionId, policyDigest, traceOf } from './decision.ts';
import type { Call } from './decision.ts';
import type { Obligation, ReasonCode } from './decision.ts';
import { Engine } from './engine.ts';
import type { EngineEvent } from './engine.ts';
import type { PepAuthenticator, PepIdentity } from '../adapters/jwt.ts';
import { DpopGuard } from '../adapters/dpop.ts';
import type { DpopOptions } from '../adapters/dpop.ts';
import { observe } from './observe.ts';
import { EXECUTION_HEADER, executionHeader } from './http.ts';
import type { Observability } from './observe.ts';
import { MemoryRateLimits } from './limits.ts';
import type { RateLimitStore, RateVerdict } from './limits.ts';
import { Equaliser } from './protection.ts';
import type { TimingOptions } from './protection.ts';
import type { DecisionCache } from './decision-cache.ts';
import type { RiskProvider } from './risk.ts';

/**
 * AuthZEN PDP facade (AKAC 0.4, ADR-011, spec/drafts/0.4-authzen.md). A read-only,
 * audited policy decision point for trusted enforcement points (gateways) speaking the
 * OpenID AuthZEN Authorization API 1.0 (Final, 11 January 2026). It answers
 * "would AKAC permit this?" with the same pure decide() the engine uses; it never
 * discloses content, opens contexts or changes state other than appending audit.
 * The tenant comes from the PEP credential only.
 */
export type PepCredential = { token: string; binding: PepIdentity };
export type AuthzenReasons = 'none' | 'admin';
export type AuthzenOptions = Observability & {
  credentials?: PepCredential[]; authenticator?: PepAuthenticator;
  dpop?: DpopOptions;
  /** Supplemental policy hook (for example OPA), applied exactly as the engine applies it. */
  policy?: PolicyHook; clock?: () => number;
  /** Decision reason exposure: none (default) or admin (closed reason code in context.reason_admin). */
  reasons?: AuthzenReasons;
  /** Externally visible base URL (origin only). Enables the metadata document; also the DPoP `htu` base. */
  publicUrl?: string;
  /** Same event hook as the engine (metrics); events carry no content or resource ids. */
  onEvent?: (event: EngineEvent) => void;
  /** Rate windows shared by several instances (0.6, ADR-016); default per process (MemoryRateLimits). */
  limiter?: RateLimitStore;
  /**
   * Response-time floor with jitter (0.6, ADR-020), so a deny and an allow take the same time within the floor. It applies to
   * every response after authentication (200, 400, 404, 405, 413, 429, 500, 503), so a malformed or failing request cannot be
   * told apart from an evaluation by its timing either.
   */
  timing?: TimingOptions;
  /** In-process cache of allow verdicts (0.6, ADR-020); off unless given. Invalidated by the tenant epoch. */
  decisionCache?: DecisionCache;
  /** External risk source (0.6, R152), applied exactly as the agent engine applies it: it can only lower clearance; a failure denies. */
  risk?: RiskProvider;
};
export const AUTHZEN_LIMITS = { concurrent: 64, perMinute: 1200, body: 262144, evaluations: 64 } as const;
/** The actions of the AKAC profile (declassify is not exposed). */
export const AUTHZEN_ACTIONS = ['read', 'derive', 'write_memory', 'share', 'export'] as const satisfies readonly Action[];
export const SEMANTICS = ['execute_all', 'deny_on_first_deny', 'permit_on_first_permit'] as const;

const plain = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const str = (x: unknown): x is string => typeof x === 'string';
const digest = (s: string) => createHash('sha256').update(s).digest('hex');

/** One evaluation after the documented mapping: malformed (HTTP 400) or unsupported (decision false) or a policy input. */
export type Mapped =
  | { ok: true; binding: Binding; resource: string; action: Action; purpose: string;
    /** Destination profile id the PEP will send to (context.destination, ADR-008); absent when not named. */
    destination?: string }
  | { ok: false; kind: 'malformed' }
  | { ok: false; kind: 'unsupported'; actor?: string; grant?: string };
/**
 * The AKAC AuthZEN profile mapping. `tenant` is the PEP credential's tenant and is
 * never read from the request. Unknown members are ignored (AuthZEN 1.0 section 10.1.1);
 * a missing or mistyped required member is malformed.
 *   subject  {type:'user', id: user,  properties:{agent, grant}} or
 *            {type:'agent', id: agent, properties:{subject: user, grant}}
 *   resource {type:'knowledge', id}    action {name}    context {purpose, destination?}
 * `context.destination` (optional, ADR-008) names the Destination profile the PEP
 * sends to; a present but invalid value is unsupported (decision false).
 */
export function mapEvaluation(tenant: string, e: unknown): Mapped {
  const malformed = { ok: false, kind: 'malformed' } as const;
  if (!plain(e)) return malformed;
  const { subject, resource, action, context } = e;
  if (!plain(subject) || !str(subject.type) || !str(subject.id) || !plain(resource) || !str(resource.type) || !str(resource.id)
    || !plain(action) || !str(action.name) || !plain(context) || !str(context.purpose)) return malformed;
  // An unknown subject type is unsupported (decision false); a missing counterpart or grant is malformed.
  if (subject.type !== 'user' && subject.type !== 'agent') return { ok: false, kind: 'unsupported' };
  const props = subject.properties;
  if (!plain(props) || !str(props.grant) || !str(subject.type === 'user' ? props.agent : props.subject)) return malformed;
  const user = subject.type === 'user' ? subject.id : props.subject as string, agent = subject.type === 'user' ? props.agent as string : subject.id;
  const grant = props.grant;
  const unsupported = { ok: false, kind: 'unsupported', ...(validId(user) ? { actor: user } : {}), ...(validId(grant) ? { grant } : {}) } as const;
  if (![user, agent, grant, resource.id].every(validId) || resource.type !== 'knowledge'
    || !(AUTHZEN_ACTIONS as readonly string[]).includes(action.name) || !context.purpose || context.purpose.length > 128
    || (context.destination !== undefined && !validId(context.destination))) return unsupported;
  return { ok: true, binding: { tenant, subject: user, agent, grant }, resource: resource.id, action: action.name as Action, purpose: context.purpose,
    ...(context.destination !== undefined ? { destination: context.destination as string } : {}) };
}

/** The outcome of one evaluation. `code` is internal: it reaches the PEP only with reasons=admin. */
export type Evaluation = { decision: boolean; id: string; code: ReasonCode; obligations: Obligation[] };

export class AuthzenPdp {
  private store: Store; private hook?: PolicyHook; private clock: () => number;
  private emit: (event: EngineEvent) => void;
  private engine: Engine;
  constructor(store: Store, options: Pick<AuthzenOptions, 'policy' | 'clock' | 'onEvent' | 'decisionCache' | 'risk'> = {}) {
    if (options.policy && (!options.policy.revision || options.policy.revision.length > 128)) throw new Error('Policy revision required');
    this.store = store; this.hook = options.policy; this.clock = options.clock ?? Date.now;
    this.engine = new Engine(store, { ...(options.policy ? { policy: options.policy } : {}), clock: this.clock, ...(options.onEvent ? { onEvent: options.onEvent } : {}), ...(options.decisionCache ? { decisionCache: options.decisionCache } : {}),
      ...(options.risk ? { risk: options.risk } : {}) });
    const listener = options.onEvent;
    this.emit = event => { try { listener?.(event); } catch { /* metrics never affect decisions */ } };
  }
  private record(s: State, tenant: string, actor: string, id: string, trace: string | undefined, runId: string | undefined, allowed: boolean, reason: string, obligations: Obligation[], execution?: string) {
    const code = classify(reason);
    if (!code || !code.category !== allowed) throw new Error('Unclassified decision reason');
    const parts = [CORE_VERSION, s.policyVersion, this.hook?.revision ?? 'core-only'];
    appendAudit(s, { time: this.clock(), tenant, actor: validId(actor) ? actor : 'invalid', operation: 'authzen_evaluate', decision: allowed ? 'allow' : 'deny',
      reason, policyVersion: parts.join('|'), epoch: s.epochs[tenant] ?? 0, decisionId: id, reasonCode: code.code, policyDigest: policyDigest(parts),
      obligations: allowed ? obligations : [], ...(runId && validId(runId) ? { runId } : {}), ...(trace ? { traceId: trace } : {}),
      ...(execution ? { executionId: execution } : {}) });
    this.emit({ type: 'decision', tenant, operation: 'authzen_evaluate', allowed, reason, decisionId: id, code: code.code });
    return code.code;
  }
  /** Audits an evaluation that could not be mapped to a policy input (a denial, DEFERRED:INVALID_REQUEST). */
  async refuse(tenant: string, mapped: Extract<Mapped, { ok: false }>, call?: Call): Promise<Evaluation> {
    const id = newDecisionId(), trace = traceOf(call), execution = executionOf(call);
    const actor = mapped.kind === 'unsupported' ? mapped.actor ?? 'invalid' : 'invalid';
    const runId = mapped.kind === 'unsupported' ? mapped.grant : undefined;
    return this.audited(tenant, actor, id, s => this.record(s, tenant, actor, id, trace, runId, false, 'DEFERRED:INVALID_REQUEST', [], execution))
      .then(code => ({ decision: false, id, code, obligations: [] as Obligation[] }));
  }
  private async audited(tenant: string, actor: string, id: string, fn: (s: State) => ReasonCode): Promise<ReasonCode> {
    try {
      return await this.store.transaction(tenant, async tx => { await tx.load({ epoch: true, audit: true }); return fn(tx.state); });
    } catch (error) {
      try { await this.store.transaction(tenant, async tx => { await tx.load({ epoch: true, audit: true }); this.record(tx.state, tenant, actor, id, undefined, undefined, false, 'DEFERRED:STORE_ERROR', []); }); }
      catch { /* best effort */ }
      throw error;
    }
  }
  /**
   * One audited decision (Engine.evaluate): the same hydration, decide(), supplemental
   * policy and core obligations as the engine's gates (audit_level full from
   * confidential, no_persist from restricted), in one tenant transaction, with no
   * context and no disclosure. A tenant beyond the load budget is a deferred denial.
   */
  async evaluate(tenant: string, mapped: Extract<Mapped, { ok: true }>, call?: Call): Promise<Evaluation> {
    const b = mapped.binding;
    if (b.tenant !== tenant) throw new Error('Binding tenant differs from the PEP tenant');
    const v = await this.engine.evaluate(b, mapped.resource, mapped.action, mapped.purpose,
      { operation: 'authzen_evaluate', ...(mapped.destination !== undefined ? { destination: mapped.destination } : {}) }, call);
    return { decision: v.decision, id: v.decisionId, code: v.code, obligations: v.obligations };
  }
}

const HEADERS = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'" };
function send(res: ServerResponse, status: number, body: unknown) {
  if (res.headersSent) return;
  res.writeHead(status, { ...HEADERS, 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}
/** Decision entity (AuthZEN 1.0 section 5.5): `context.id` is the audited AKAC decision id. */
export function render(e: Evaluation, reasons: AuthzenReasons, error?: { status: number; message: string }) {
  const context: Record<string, unknown> = { id: e.id };
  if (error) context.error = error;
  if (reasons === 'admin') context.reason_admin = { code: e.code };
  if (e.decision && e.obligations.length) context.obligations = e.obligations;
  return { decision: e.decision, context };
}
const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;

export function createAuthzenGateway(store: Store, options: AuthzenOptions = {}): Server {
  const credentials = options.credentials ?? [];
  if (!credentials.length && !options.authenticator) throw new Error('Authentication is required');
  if (credentials.length && options.authenticator) throw new Error('Authentication modes cannot be mixed');
  if (options.dpop && !options.authenticator) throw new Error('DPoP requires signed-token authentication');
  const reasons = options.reasons ?? 'none';
  if (!['none', 'admin'].includes(reasons)) throw new Error('Invalid reasons setting');
  let discovery: Record<string, unknown> | undefined;
  if (options.publicUrl !== undefined) {
    const url = new URL(options.publicUrl);
    if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Invalid AuthZEN public URL');
    // The PDP identifier is an https URL without query or fragment (AuthZEN 1.0 section 9.1.1); http is for local development.
    discovery = { policy_decision_point: url.origin, access_evaluation_endpoint: `${url.origin}/access/v1/evaluation`, access_evaluations_endpoint: `${url.origin}/access/v1/evaluations` };
  }
  const dpop = options.dpop ? new DpopGuard(options.dpop) : undefined;
  const auth = new Map<string, PepIdentity>();
  for (const c of credentials) {
    if (typeof c?.token !== 'string' || c.token.length < 32 || c.token.length > 512 || !plain(c.binding) || Object.keys(c.binding).sort().join() !== 'pep,tenant'
      || !validId(c.binding.tenant) || !validId(c.binding.pep) || auth.has(digest(c.token))) throw new Error('Invalid credential configuration');
    auth.set(digest(c.token), { tenant: c.binding.tenant, pep: c.binding.pep });
  }
  const pdp = new AuthzenPdp(store, options);
  const equaliser = options.timing ? new Equaliser(options.timing) : undefined;
  const limiter = options.limiter ?? new MemoryRateLimits({ maxBuckets: 10_000 });
  /** Charges `cost` units to the PEP's window; true when the request was answered (refused). */
  const limited = async (res: ServerResponse, pep: PepIdentity, cost: number, reply: (status: number, body: unknown) => Promise<void>): Promise<boolean> => {
    let r: RateVerdict;
    try { r = await limiter.take(pep.tenant, 'authzen', digest(`${pep.tenant}\u0000${pep.pep}`), AUTHZEN_LIMITS.perMinute, 60_000, cost); }
    catch { options.metrics?.rateLimited('authzen', 'unavailable'); await reply(503, { error: 'UNAVAILABLE' }); return true; }
    if (r.ok) return false;
    options.metrics?.rateLimited('authzen', r.reason);
    res.setHeader('retry-after', String(r.retryAfter)); await reply(r.status, { error: r.status === 429 ? 'RATE_LIMITED' : 'BUSY' }); return true;
  };
  let active = 0;
  const routes = new Set(['/access/v1/evaluation', '/access/v1/evaluations', '/.well-known/authzen-configuration', '/health']);
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const obs = observe('authzen', req, res, options);
    const path = (req.url ?? '').split('?', 1)[0]!;
    obs.setRoute(routes.has(path) ? path : 'unmatched');
    // AuthZEN 1.0 section 10.1.3: a request identifier sent by the PEP is echoed in the response.
    const rid = req.headers['x-request-id'];
    if (rid !== undefined) {
      if (typeof rid !== 'string' || !REQUEST_ID.test(rid)) { req.resume(); send(res, 400, { error: 'INVALID_REQUEST' }); return; }
      res.setHeader('x-request-id', rid);
    }
    if (active >= AUTHZEN_LIMITS.concurrent) { req.resume(); send(res, 503, { error: 'BUSY' }); return; }
    active++;
    /** Set once the PEP is authenticated: from then on every response is padded to the timing floor (ADR-020). */
    let started: number | undefined;
    const reply = async (status: number, body: unknown) => {
      if (equaliser && started !== undefined) { try { await equaliser.pad(started); } catch { /* padding never changes the answer */ } }
      send(res, status, body);
    };
    try {
      if (path === '/health' && req.method === 'GET') { send(res, 200, { status: 'ok', listener: 'authzen' }); return; }
      if (path === '/.well-known/authzen-configuration') {
        req.resume();
        if (!discovery) { send(res, 404, { error: 'NOT_FOUND' }); return; }
        if (req.method !== 'GET') { send(res, 405, { error: 'METHOD_NOT_ALLOWED' }); return; }
        send(res, 200, discovery); return;
      }
      let pep: PepIdentity | null | undefined, challenge: string[] = ['Bearer'];
      if (dpop) {
        const outcome = await dpop.authorize(req, (t, proof) => options.authenticator!.authenticate(t, proof));
        if (outcome.ok) pep = outcome.value; else challenge = outcome.challenge;
      } else {
        const header = req.headers.authorization;
        const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
        pep = options.authenticator ? await options.authenticator.authenticate(token) : auth.get(token.length <= 512 ? digest(token) : '');
      }
      if (!pep) { req.resume(); res.setHeader('www-authenticate', challenge); send(res, 401, { error: 'UNAUTHENTICATED' }); return; }
      started = equaliser ? equaliser.start() : 0;
      if (await limited(res, pep, 1, reply)) { req.resume(); return; }
      const single = path === '/access/v1/evaluation', batch = path === '/access/v1/evaluations';
      if (!single && !batch) { req.resume(); await reply(404, { error: 'NOT_FOUND' }); return; }
      if (req.method !== 'POST') { req.resume(); await reply(405, { error: 'METHOD_NOT_ALLOWED' }); return; }
      if (req.headers['content-type']?.split(';')[0]?.trim().toLowerCase() !== 'application/json') { req.resume(); await reply(400, { error: 'INVALID_REQUEST' }); return; }
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > AUTHZEN_LIMITS.body) { await reply(413, { error: 'REQUEST_TOO_LARGE' }); return; }
        chunks.push(Buffer.from(chunk));
      }
      let body: unknown;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { await reply(400, { error: 'INVALID_JSON' }); return; }
      if (!plain(body)) { await reply(400, { error: 'INVALID_REQUEST' }); return; }
      // The agent execution the PEP evaluates for (0.5, R117): recorded with every evaluation, correlation only; malformed is a 400.
      const executionId = executionHeader(req.headers[EXECUTION_HEADER]);
      if (executionId === null) { await reply(400, { error: 'INVALID_REQUEST' }); return; }
      const call: Call = { trace: { traceId: obs.traceId, ...(executionId ? { executionId } : {}) } };
      if (single) {
        const mapped = mapEvaluation(pep.tenant, body);
        // A missing or mistyped required member is a protocol error (400); nothing was evaluated.
        if (!mapped.ok && mapped.kind === 'malformed') { await reply(400, { error: 'INVALID_REQUEST' }); return; }
        const out = mapped.ok ? await pdp.evaluate(pep.tenant, mapped, call) : await pdp.refuse(pep.tenant, mapped, call);
        await reply(200, render(out, reasons)); return;
      }
      const list = body.evaluations, options_ = body.options;
      if (!Array.isArray(list) || !list.length || list.length > AUTHZEN_LIMITS.evaluations) { await reply(400, { error: 'INVALID_REQUEST' }); return; }
      if (options_ !== undefined && !plain(options_)) { await reply(400, { error: 'INVALID_REQUEST' }); return; }
      const semantic = plain(options_) && options_.evaluations_semantic !== undefined ? options_.evaluations_semantic : 'execute_all';
      // The specification does not say what an unknown semantic means: refuse it rather than guess.
      if (!(SEMANTICS as readonly unknown[]).includes(semantic)) { await reply(400, { error: 'INVALID_REQUEST' }); return; }
      // Each evaluation costs one unit of the PEP's rate limit.
      if (list.length > 1 && await limited(res, pep, list.length - 1, reply)) return;
      const defaults: Record<string, unknown> = {};
      for (const k of ['subject', 'action', 'resource', 'context']) if (Object.hasOwn(body, k)) defaults[k] = body[k];
      const evaluations: unknown[] = [];
      for (const item of list) {
        // Top-level members are defaults; members of an evaluation override them (AuthZEN 1.0 section 7.1.1).
        const mapped = plain(item) ? mapEvaluation(pep.tenant, { ...defaults, ...item }) : { ok: false, kind: 'malformed' } as const;
        const out = mapped.ok ? await pdp.evaluate(pep.tenant, mapped, call) : await pdp.refuse(pep.tenant, mapped, call);
        // A malformed evaluation is an error of that evaluation (section 7.2.1), not of the request.
        evaluations.push(render(out, reasons, !mapped.ok && mapped.kind === 'malformed' ? { status: 400, message: 'Bad Request' } : undefined));
        if ((semantic === 'deny_on_first_deny' && !out.decision) || (semantic === 'permit_on_first_permit' && out.decision)) break;
      }
      await reply(200, { evaluations });
    } catch { if (!res.headersSent) await reply(500, { error: 'UNAVAILABLE' }); }
    finally { active--; }
  });
  server.requestTimeout = 10000; server.headersTimeout = 5000; server.timeout = 15000; server.maxHeadersCount = 32;
  return server;
}
