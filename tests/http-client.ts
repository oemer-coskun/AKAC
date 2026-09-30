import type { Result, Projection } from '../reference/engine.ts';
import type { ConsistencyProof, InclusionProof, TreeHead } from '../reference/evidence.ts';
import type { AuditCheckpoint } from '../reference/checkpoint.ts';
import type { DenialHint, Obligation } from '../reference/decision.ts';
const HINTS: readonly string[] = ['GRANT_EXPIRED', 'PURPOSE_NOT_GRANTED', 'ACTION_NOT_GRANTED', 'RATE_LIMITED', 'APPROVAL_REQUIRED', 'RUNTIME_ENFORCER_REQUIRED'];
import type { Actor, Audit, Container, Destination, Grant, Group, Knowledge, QuarantineReason, Role, RuntimeProfilePolicy, SodConstraint } from '../reference/types.ts';

/**
 * Optional DPoP (RFC 9449) signer. Called once per request with the HTTP method and the request URL without
 * query or fragment (the `htu`); returns a fresh compact `dpop+jwt` proof whose `ath` is the SHA-256 of the
 * access token and whose key matches the token's `cnf.jkt`. The client then sends `Authorization: DPoP <token>`.
 * The private key stays with the caller; the client never sees it.
 */
export type DpopSigner = (method: string, url: string) => Promise<string> | string;
/**
 * `executionId` (0.5): sent as `x-akac-execution-id` with every request and recorded with each
 * audited decision for correlation with the runtime's own logs. Never authority.
 */
export type ClientOptions = { dpop?: DpopSigner; executionId?: string };
async function authHeaders(token: string, method: string, url: string, signer?: DpopSigner): Promise<Record<string, string>> {
  if (!signer) return { authorization: `Bearer ${token}` };
  return { authorization: `DPoP ${token}`, dpop: await signer(method, url.split(/[?#]/, 1)[0]!) };
}

/** Service-side test client. Never put these credentials into a browser or a model prompt. */
export class AkacClient {
  private base: string; private token: string; private dpop: DpopSigner | undefined; private execution: Record<string, string>;
  constructor(base: string, token: string, options: ClientOptions = {}) {
    this.base = base.replace(/\/$/, ''); this.token = token; this.dpop = options.dpop;
    this.execution = options.executionId !== undefined ? { 'x-akac-execution-id': options.executionId } : {};
  }
  private async post<T>(path: string, data: unknown): Promise<Result<T>> {
    const res = await fetch(`${this.base}${path}`, { method: 'POST', redirect: 'error',
      headers: { ...await authHeaders(this.token, 'POST', `${this.base}${path}`, this.dpop), ...this.execution, 'content-type': 'application/json' },
      body: JSON.stringify(data), signal: AbortSignal.timeout(10000) });
    if (res.status === 403) {
      // Denials are non-distinguishing: NOT_AUTHORIZED and the decision id (for audit correlation) only, plus, when the
      // operator enabled denial hints (0.6), one closed hint about the caller's own grant or budget; anything else is dropped.
      const body = await res.json().catch(() => null) as { decisionId?: unknown; hint?: unknown } | null;
      const hint = typeof body?.hint === 'string' && HINTS.includes(body.hint) ? body.hint as DenialHint : undefined;
      return { ok: false, code: 'NOT_AUTHORIZED', decisionId: typeof body?.decisionId === 'string' ? body.decisionId : '', ...(hint ? { hint } : {}) };
    }
    if (!res.ok) throw new Error(`AKAC transport failed (${res.status})`);
    return await res.json() as Result<T>;
  }
  retrieve(query: string, purpose: string, limit = 5) { return this.post<Projection>('/v1/retrieve', { query, purpose, limit }); }
  context(resources: string[], purpose: string) { return this.post<Projection>('/v1/contexts', { resources, purpose }); }
  derive(context: string, content: string, kind: 'memory' | 'artifact' = 'memory') {
    return this.post<{ id: string; classification: string }>('/v1/derive', { context, content, kind });
  }
  release(context: string, recipient: string, content: string, action: 'share' | 'export' = 'share') {
    return this.post<{ recipient: string; content: string }>('/v1/release', { context, recipient, content, action });
  }
}

/** Administrative failure codes as returned by the admin listener (400, 403, 409 and 422 map to these). */
export type AdminResult<T> = { ok: true; value: T; decisionId?: string }
  | { ok: false; code: 'NOT_AUTHORIZED' | 'INVALID_REQUEST' | 'CONFLICT' | 'SOD_VIOLATION' | 'IDEMPOTENCY_KEY_REUSED' | 'INDEX_PENDING' | 'APPROVAL_REQUIRED'; decisionId?: string;
    /** CONFLICT from erase(): how many records of the lineage are under legal hold (a count, never which). */
    held?: number;
    /** APPROVAL_REQUIRED (202, 0.6): the pending approval the operation waits for. */
    approval?: string };
/** Approval of a sensitive administrative operation (0.6, ADR-019), without its arguments. */
export type ApprovalSummary = { id: string; tenant: string; class: string; operation: string; requester: string; digest: string; approvers: string[];
  required: number; external: boolean; createdAt: number; expiresAt: number; status: 'pending' | 'executed' | 'rejected'; executedAt?: number };
type Body<T> = Omit<T, 'tenant' | 'id'> & { tenant?: string };
/**
 * Operator test client for the admin listener (default port 8788). Uses an administrator credential, which is a
 * different population from agent credentials. The tenant is fixed by the credential; never pass one.
 * Run it from trusted operator tooling only.
 */
export class AdminClient {
  private base: string; private token: string; private dpop: DpopSigner | undefined;
  constructor(base: string, token: string, options: ClientOptions = {}) { this.base = base.replace(/\/$/, ''); this.token = token; this.dpop = options.dpop; }
  private async call<T>(method: string, path: string, data?: unknown, headers: Record<string, string> = {}): Promise<AdminResult<T>> {
    const res = await this.raw(method, path, data, headers);
    if ([400, 403, 409, 422].includes(res.status)) return await res.json() as AdminResult<T>;
    if (!res.ok) throw new Error(`AKAC admin transport failed (${res.status})`);
    return await res.json() as AdminResult<T>;
  }
  private async raw(method: string, path: string, data?: unknown, headers: Record<string, string> = {}) {
    return fetch(`${this.base}${path}`, { method, redirect: 'error', signal: AbortSignal.timeout(30000),
      headers: { ...await authHeaders(this.token, method, `${this.base}${path}`, this.dpop), ...(data !== undefined ? { 'content-type': 'application/json' } : {}), ...headers },
      ...(data !== undefined ? { body: JSON.stringify(data) } : {}) });
  }
  putActor(id: string, actor: Body<Actor>) { return this.call<{ id: string }>('PUT', `/admin/v1/actors/${encodeURIComponent(id)}`, actor); }
  setRoles(id: string, roles: string[]) { return this.call<{ id: string; roles: string[] }>('PUT', `/admin/v1/actors/${encodeURIComponent(id)}/roles`, { roles }); }
  putRole(id: string, role: Body<Role>) { return this.call<{ id: string }>('PUT', `/admin/v1/roles/${encodeURIComponent(id)}`, role); }
  putGroup(id: string, group: Body<Group>) { return this.call<{ id: string }>('PUT', `/admin/v1/groups/${encodeURIComponent(id)}`, group); }
  putConstraint(id: string, constraint: Body<SodConstraint>) { return this.call<{ id: string }>('PUT', `/admin/v1/constraints/${encodeURIComponent(id)}`, constraint); }
  putContainer(id: string, container: Body<Container>) { return this.call<{ id: string }>('PUT', `/admin/v1/containers/${encodeURIComponent(id)}`, container); }
  /** security-admin: destination profile (0.4); the id must not equal a destination class name. */
  putDestination(id: string, destination: Body<Destination>) { return this.call<{ id: string }>('PUT', `/admin/v1/destinations/${encodeURIComponent(id)}`, destination); }
  /** security-admin or auditor: read a destination profile (0.4); 404 NOT_FOUND when absent. */
  getDestination(id: string) { return this.call<Destination>('GET', `/admin/v1/destinations/${encodeURIComponent(id)}`); }
  /** security-admin: runtime profile policy (0.5); every accepted change advances the tenant epoch. */
  putRuntimeProfile(id: string, policy: Body<RuntimeProfilePolicy>) { return this.call<{ id: string; epoch: number }>('PUT', `/admin/v1/runtime-profiles/${encodeURIComponent(id)}`, policy); }
  /** security-admin or auditor: read a runtime profile policy (0.5); 404 NOT_FOUND when absent. */
  getRuntimeProfile(id: string) { return this.call<RuntimeProfilePolicy>('GET', `/admin/v1/runtime-profiles/${encodeURIComponent(id)}`); }
  putKnowledge(id: string, document: Body<Knowledge>) { return this.call<{ id: string; version: number; chunks?: number }>('PUT', `/admin/v1/knowledge/${encodeURIComponent(id)}`, document); }
  deleteKnowledge(id: string) { return this.call<unknown>('DELETE', `/admin/v1/knowledge/${encodeURIComponent(id)}`); }
  /** kb-admin or security-admin: the record and its whole lineage become invisible to every gate until release(). */
  quarantine(id: string, reason: QuarantineReason) { return this.call<{ id: string; epoch: number }>('POST', `/admin/v1/knowledge/${encodeURIComponent(id)}/quarantine`, { reason }); }
  /** security-admin only (separation of duty from quarantine). */
  release(id: string) { return this.call<{ id: string; epoch: number }>('POST', `/admin/v1/knowledge/${encodeURIComponent(id)}/release`); }
  /** auditor or security-admin: blast radius, metadata only (limit 1-1000, default 100). */
  descendants(id: string, limit?: number) {
    return this.call<{ records: { id: string; version: number; kind: string; classification: string; active: boolean; lifecycle?: string }[]; truncated: boolean }>(
      'GET', `/admin/v1/knowledge/${encodeURIComponent(id)}/descendants${limit === undefined ? '' : `?limit=${limit}`}`);
  }
  /** security-admin: deactivates the record's whole lineage explicitly (idempotent). */
  revokeLineage(id: string) { return this.call<{ id: string; revoked: number; epoch: number }>('POST', `/admin/v1/knowledge/${encodeURIComponent(id)}/revoke-lineage`); }
  /** security-admin: lifts a security revocation (revokedAt) of this record only and reactivates it. */
  reinstate(id: string) { return this.call<{ id: string; epoch: number }>('POST', `/admin/v1/knowledge/${encodeURIComponent(id)}/reinstate`); }
  /** security-admin: a legal hold blocks erasure and retention of the record until lifted. */
  setLegalHold(id: string, holdId: string) { return this.call<{ id: string; holds: number }>('PUT', `/admin/v1/knowledge/${encodeURIComponent(id)}/legal-holds/${encodeURIComponent(holdId)}`); }
  liftLegalHold(id: string, holdId: string) { return this.call<{ id: string; holds: number }>('DELETE', `/admin/v1/knowledge/${encodeURIComponent(id)}/legal-holds/${encodeURIComponent(holdId)}`); }
  /** security-admin: tombstones the record and (cascade, default true) its lineage. A legal hold is 409 with `held`. */
  erase(id: string, options: { cascade?: boolean } = {}) { return this.call<{ id: string; erased: number; epoch: number }>('POST', `/admin/v1/knowledge/${encodeURIComponent(id)}/erase`, options); }
  /** security-admin: erases records past `retainUntil` (at most `limit` per call, 1-100); repeat with `after: next` until `next` is absent. */
  applyRetention(options: { now?: number; after?: string; limit?: number } = {}) {
    return this.call<{ erased: number; held: number; deferred: number; next?: string }>('POST', '/admin/v1/retention/apply', options);
  }
  /** security-admin (0.6, ADR-020): accepts the current embedder output as the new anchor baseline and re-enables vector retrieval after drift. Instance-wide; 404 when no anchors are configured. */
  rebaselineAnchors() { return this.call<{ state: string }>('POST', '/admin/v1/index/anchors/rebaseline'); }
  /** Pass an idempotency key to make retries safe (deduplicated per gateway instance). */
  issueGrant(grant: Body<Grant> & { id: string }, idempotencyKey?: string) {
    return this.call<{ id: string }>('POST', '/admin/v1/grants', grant, idempotencyKey ? { 'idempotency-key': idempotencyKey } : {});
  }
  /** runtime role (0.6): report that a heartbeat-bound run is alive; 409 once it lapsed (final). */
  heartbeat(grantId: string) { return this.call<{ id: string; lastHeartbeatAt: number; validUntil: number }>('POST', `/admin/v1/grants/${encodeURIComponent(grantId)}/heartbeat`); }
  /** security-admin (0.6): request an emergency read grant; answers APPROVAL_REQUIRED with the approval id until a second security-admin approves. */
  requestBreakGlass(request: { id: string; subject: string; agent: string; resources: string[]; purposes: string[]; ttlMs: number; activeRoles?: string[] }) {
    return this.call<{ id: string; notBefore: number; expiresAt: number }>('POST', '/admin/v1/break-glass', request);
  }
  /** security-admin (0.6): pending approvals, oldest first, without arguments. */
  approvals() { return this.call<ApprovalSummary[]>('GET', '/admin/v1/approvals'); }
  /** security-admin (0.6): one approval with its arguments. */
  getApproval(id: string) { return this.call<ApprovalSummary & { payload: unknown[] }>('GET', `/admin/v1/approvals/${encodeURIComponent(id)}`); }
  /** security-admin, never the requester (0.6): executes the operation once the quorum is met. */
  approve(id: string) { return this.call<{ approval: ApprovalSummary; execution?: AdminResult<unknown> }>('POST', `/admin/v1/approvals/${encodeURIComponent(id)}/approve`); }
  reject(id: string) { return this.call<ApprovalSummary>('POST', `/admin/v1/approvals/${encodeURIComponent(id)}/reject`); }
  /** The requester (0.6): executes an approval whose quorum is met after an external workflow confirmed it. */
  executeApproval(id: string) { return this.call<unknown>('POST', `/admin/v1/approvals/${encodeURIComponent(id)}/execute`); }
  /** security-admin or risk-ingest (0.6): the caller's risk signal for a principal; caps its clearance until it expires. */
  riskSignal(signal: { principal: string; level: 'none' | 'low' | 'medium' | 'high' | 'critical'; ttlMs?: number; event?: string }) {
    return this.call<{ id: string; level: string; expiresAt: number; epoch: number }>('POST', '/admin/v1/risk-signals', signal);
  }
  /** security-admin (0.6): approval quorums, approval lifetime, risk caps; a relaxation answers APPROVAL_REQUIRED. */
  putSettings(settings: { approvalQuorum?: Record<string, number>; approvalTtlMs?: number; riskCaps?: Record<string, string> }) {
    return this.call<{ id: string; epoch: number }>('PUT', '/admin/v1/settings', settings);
  }
  getSettings() { return this.call<{ approvalQuorum: Record<string, number>; approvalTtlMs: number; riskCaps: Record<string, string>; configured: boolean }>('GET', '/admin/v1/settings'); }
  revoke(type: 'grant' | 'knowledge' | 'actor', id: string) { return this.call<{ epoch: number }>('POST', '/admin/v1/revocations', { type, id }); }
  audit(after = 0, limit = 1000) { return this.call<{ entries: Audit[]; next: number | null }>('GET', `/admin/v1/audit?after=${after}&limit=${limit}`); }
  /** auditor: current RFC 9162 tree head and, when the server holds a checkpoint key, its signed format 2 checkpoint. */
  checkpoint() { return this.call<{ head: TreeHead; checkpoint?: AuditCheckpoint }>('GET', '/admin/v1/audit/checkpoint'); }
  /** auditor: inclusion proof of the entry with sequence leafIndex + 1 in the tree of the first treeSize entries. */
  auditProof(leafIndex: number, treeSize: number) { return this.call<InclusionProof>('GET', `/admin/v1/audit/proof?leafIndex=${leafIndex}&treeSize=${treeSize}`); }
  /** auditor: proof that the tree of `second` entries extends the tree of `first` entries. */
  auditConsistency(first: number, second: number) { return this.call<ConsistencyProof>('GET', `/admin/v1/audit/consistency?first=${first}&second=${second}`); }
  /** Streams the tenant audit log as parsed NDJSON records (for SIEM forwarding). */
  async *auditExport(after = 0): AsyncGenerator<Audit> {
    const res = await this.raw('GET', `/admin/v1/audit/export?after=${after}`);
    if (!res.ok || !res.body) throw new Error(`AKAC admin export failed (${res.status})`);
    let pending = '';
    for await (const chunk of res.body.pipeThrough(new TextDecoderStream())) {
      pending += chunk;
      for (let i = pending.indexOf('\n'); i >= 0; i = pending.indexOf('\n')) {
        const line = pending.slice(0, i); pending = pending.slice(i + 1);
        if (line) yield JSON.parse(line) as Audit;
      }
    }
    if (pending.trim()) throw new Error('AKAC admin export truncated');
  }
}

/** One AuthZEN evaluation in the AKAC profile (docs/AUTHZEN.md). The tenant is never sent: it comes from the PEP credential. */
export type AuthzenEvaluation = {
  subject: { type: 'user' | 'agent'; id: string; properties: { grant: string; agent?: string; subject?: string } };
  resource: { type: 'knowledge'; id: string };
  action: { name: 'read' | 'derive' | 'write_memory' | 'share' | 'export' };
  context: { purpose: string };
};
export type AuthzenDecision = { decision: boolean; context?: { id?: string; obligations?: Obligation[]; reason_admin?: { code: string }; error?: { status: number; message: string } } };
/**
* Test client for a policy enforcement point (a trusted gateway) calling the AuthZEN PDP listener. A PEP MUST treat a transport
 * failure, any non-200 status and `decision: false` as a deny, and MUST deny an allow whose `context.obligations` it cannot enforce.
 */
export class AuthzenClient {
  private base: string; private token: string; private dpop: DpopSigner | undefined;
  constructor(base: string, token: string, options: ClientOptions = {}) { this.base = base.replace(/\/$/, ''); this.token = token; this.dpop = options.dpop; }
  private async post<T>(path: string, data: unknown): Promise<T> {
    const res = await fetch(`${this.base}${path}`, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000),
      headers: { ...await authHeaders(this.token, 'POST', `${this.base}${path}`, this.dpop), 'content-type': 'application/json' }, body: JSON.stringify(data) });
    if (!res.ok) throw new Error(`AKAC AuthZEN transport failed (${res.status})`);
    return await res.json() as T;
  }
  evaluate(request: AuthzenEvaluation) { return this.post<AuthzenDecision>('/access/v1/evaluation', request); }
  /** Members of `defaults` apply to every evaluation that does not set them (AuthZEN 1.0 section 7.1.1). */
  evaluations(evaluations: Partial<AuthzenEvaluation>[], defaults: Partial<AuthzenEvaluation> = {}, semantic: 'execute_all' | 'deny_on_first_deny' | 'permit_on_first_permit' = 'execute_all') {
    return this.post<{ evaluations: AuthzenDecision[] }>('/access/v1/evaluations', { ...defaults, evaluations, options: { evaluations_semantic: semantic } });
  }
}
