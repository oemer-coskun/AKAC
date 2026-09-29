import { appendAudit } from './audit.ts';
import { BudgetExceeded, hydrate } from './hydrate.ts';
import type { Seed } from './hydrate.ts';
import { containerChain, effectiveLabel, effectiveRoles, sessionRoles, sodViolated, standingRoles, transitiveClassification, validGrantChain } from './policy.ts';
import { ACTIONS, APPROVAL_CLASSES, BREAK_GLASS, CORE_VERSION, DESTINATION_CLASSES, HEARTBEAT, LEVELS, MAX_RESULTS, QUARANTINE_REASONS, RISK_LEVELS, RUNTIME_PROFILE_LIMIT } from './types.ts';
import type { Actor, Approval, ApprovalClass, Audit, Container, Destination, Grant, Group, Knowledge, QuarantineReason, RiskLevel, Role, RuntimeProfilePolicy, SodConstraint, State, Store, TenantSettings, Tx } from './types.ts';
import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { APPROVAL, APPROVER_ROLES, approvalDigest, approvalTtl, jsonValue, quorumOf, settingsQuorum, settingsRelax, validSettings } from './approvals.ts';
import type { ApprovalGate } from './approvals.ts';
import { RISK_SIGNAL, riskSignalId, SSF_EVENT } from './risk.ts';
import { DEFAULT_RISK_CAPS } from './types.ts';
import { validRuntimeProfile } from './containment.ts';
import { held, LIFECYCLE, lineage, lineageRecord, materialize, retentionDue, tombstone } from './lifecycle.ts';
import type { LineageRecord } from './lifecycle.ts';
import { exactKeys, safeNumber, validId } from './validation.ts';
import { classify, executionOf, newDecisionId, policyDigest, traceOf } from './decision.ts';
import type { Call } from './decision.ts';
import { consistencyProof, inclusionProof, treeHead } from './evidence.ts';
import type { ConsistencyProof, InclusionProof, TreeHead } from './evidence.ts';
import { signTreeHead } from './checkpoint.ts';
import type { AuditCheckpoint, CheckpointV2 } from './checkpoint.ts';
import { signCheckpointWith, signTreeHeadWith } from './custody.ts';
import type { CheckpointSigner } from './custody.ts';
import { inRange, validCombinationRule, validModality, validRange, validRegion, validResidency, validTags } from './knowledge.ts';
import type { VersionRange } from './knowledge.ts';
import { KNOWLEDGE } from './types.ts';
import type { CombinationRule, KnowledgeMeta } from './types.ts';

/** Every result carries the id of the audited decision (0.4). */
export type ControlResult<T> = { ok: true; value: T; decisionId: string }
  | { ok: false; code: 'NOT_AUTHORIZED' | 'INVALID_REQUEST' | 'CONFLICT' | 'SOD_VIOLATION' | 'APPROVAL_REQUIRED';
    /** APPROVAL_REQUIRED (0.6, R153): the pending approval that the operation now waits for. */
    approval?: string;
    /** SOD_VIOLATION from a role or constraint change: how many currently valid principals it would invalidate (never which). */
    holders?: number;
    /** CONFLICT from erase() or upsertKnowledge(): how many records are under legal hold (never which). */
    held?: number;
    /** CONFLICT from erase() (0.6, R194): the erasure is stored as pending and runs once no legal hold blocks it. */
    pending?: true; decisionId: string };
/**
 * security-admin: identities, roles, groups, constraints, grants, revocation, approvals. kb-admin: containers, documents. auditor: audit.
 * runtime (0.6): grant heartbeats only. risk-ingest (0.6): risk signals only. The two service roles are the only
 * roles a `service` principal can exercise; every other role requires a `user` (R148, R152).
 */
export type AdminRole = 'security-admin' | 'kb-admin' | 'auditor' | 'runtime' | 'risk-ingest';
const SERVICE_ROLES: readonly AdminRole[] = ['runtime', 'risk-ingest'];
/** Control-plane events for metrics (content-free). */
export type ControlEvent = { type: 'break_glass'; tenant: string } | { type: 'approval'; tenant: string; class: ApprovalClass; outcome: 'requested' | 'approved' | 'executed' | 'rejected' };
type Failure = Exclude<ControlResult<never>, { ok: true }>['code'];
/** `audit` overrides the recorded decision and reason (attempts handled outside the control plane). */
type Refusal = { ok: false; code: Failure; holders?: number; held?: number; approval?: string; pending?: true;
  /** Recorded reason when it differs from `code` (a role missing for this particular change: NOT_ADMIN). Never returned. */
  denied?: 'NOT_ADMIN';
  /** Flag the audit entry as break-glass (R150). Never returned. */
  breakGlass?: true };
/** One audited control-plane decision and its correlation fields (never authority). */
type Op = { id: string; trace?: string; execution?: string };
type Checked<T> = { ok: true; value: T; audit?: { allowed: boolean; reason: string }; breakGlass?: true } | Refusal;
/** Outcome of the approval gate: proceed (then call done() after the change), or the refusal to return. */
type Gate = { ok: true; done: () => void } | Refusal;
/** Relaxation of a SoD constraint (R153): static to dynamic, a role removed or a higher cardinality. */
const relaxesConstraint = (old: SodConstraint, next: SodConstraint) => (old.kind === 'static' && next.kind === 'dynamic')
  || !within(old.roles, next.roles) || next.cardinality > old.cardinality;
/** Widening of a destination profile (R153): a new active profile, reactivation, a higher classification, a purpose added or another class. */
const widensDestination = (old: Destination | undefined, next: Destination) => !old ? next.active === true
  : (old.active !== true && next.active === true) || LEVELS.indexOf(next.maxClassification) > LEVELS.indexOf(old.maxClassification)
    || !within(next.purposes, old.purposes) || next.class !== old.class
    // A region added or changed can receive content of another residency (R187).
    || (next.region !== undefined && next.region !== old.region);
/** Relaxation of a combination rule (R188): deactivation, a tag removed, deny to uplift, a lower or open uplift. */
const relaxesRule = (old: CombinationRule, next: CombinationRule) => (old.active && !next.active) || !within(old.tagsA, next.tagsA) || !within(old.tagsB, next.tagsB)
  || (old.effect === 'deny' && next.effect !== 'deny')
  || (old.effect === 'uplift' && next.effect === 'uplift' && old.upliftTo !== undefined && (next.upliftTo === undefined || LEVELS.indexOf(next.upliftTo) < LEVELS.indexOf(old.upliftTo)));
/** Break-glass request (R149): lifetime instead of times; actions are always ['read']. */
export type BreakGlassRequest = { id: string; subject: string; agent: string; resources: string[]; purposes: string[]; ttlMs: number; activeRoles?: string[] };
/** Risk signal ingestion (R151): the source is the caller, never a request field. */
export type RiskSignalInput = { principal: string; level: RiskLevel; ttlMs?: number; event?: string };
/** Approval as returned to administrators (the payload only through readApproval()). */
export type ApprovalSummary = Omit<Approval, 'payload'>;
const summary = (a: Approval): ApprovalSummary => { const { payload: _payload, ...rest } = structuredClone(a); return rest; };
const refuse = (code: Failure): Refusal => ({ ok: false, code });
const within = (small: readonly string[], large: readonly string[]) => small.every(x => large.includes(x));
const rank = (l: string) => LEVELS.indexOf(l as never);
/**
 * R15 (0.6 R126): a new document version whose label grants more than the
 * current one: a lower own classification, a reader or reader role added, a
 * project removed (projects are a conjunctive restriction), another container, an
 * access expiry removed or extended, or a source dropped (provenance restricts
 * visibility). Such a version is a declassification and needs a security-admin.
 */
const widensLabel = (old: Knowledge, next: Knowledge) => rank(next.classification) < rank(old.classification)
  || !within(next.readers, old.readers) || !within(next.readerRoles, old.readerRoles) || !within(old.projects, next.projects)
  || next.container !== old.container
  || (old.accessExpiresAt !== undefined && (next.accessExpiresAt === undefined || next.accessExpiresAt > old.accessExpiresAt))
  || !old.sources.every(r => next.sources.some(n => n.id === r.id))
  // 0.6 (R186, R187): a tag removed (combination rules and policy packs read tags) or a residency widened or dropped.
  || !within(old.tags ?? [], next.tags ?? [])
  || (old.residency !== undefined && (next.residency === undefined || !within(next.residency, old.residency)));
/** Deactivation, or no new role, project, clearance or reactivation: can only remove authority. */
const reducesActor = (old: Actor, next: Actor) => next.active === false
  || ((old.active === true || next.active !== true) && within(next.roles, old.roles) && within(next.projects, old.projects) && rank(next.clearance) <= rank(old.clearance)
    && next.destination === old.destination && within(next.runtimeFor ?? [], old.runtimeFor ?? []));

/** A principal that can approve (R154): an active user of the tenant holding a standing approver role. */
const approver = (s: State, tenant: string, a: Actor | undefined): boolean => a?.kind === 'user' && a.active === true && a.tenant === tenant
  && APPROVER_ROLES.some(r => !!standingRoles(s, a)?.has(r));
/** Whether the closure of this one role grants an approver role (a role record may be named like one or inherit one). */
const grantsApproval = (s: State, tenant: string, role: string, unknown: boolean): boolean => {
  const held = effectiveRoles(s, { id: '-', tenant, kind: 'user', roles: [role], projects: [], clearance: 'public', active: true });
  return held ? APPROVER_ROLES.some(r => held.has(r)) : unknown; // an unknown closure: not granting before, granting after (fail closed)
};
/**
 * Principals a pending elevation (R158) would make approvers: they never count towards, nor may they cast,
 * an approval of their own elevation. Role changes affect holders not named in the payload; those do not hold an
 * approver role yet, so they cannot approve anyway.
 */
const elevationTargets = (a: Pick<Approval, 'operation' | 'payload'>): string[] => {
  const first = Array.isArray(a.payload) ? (a.payload as unknown[])[0] : undefined;
  const o = first && typeof first === 'object' ? first as { id?: unknown; members?: unknown } : undefined;
  if (a.operation === 'upsert_actor') return validId(o?.id) ? [o!.id as string] : [];
  if (a.operation === 'assign_roles') return validId(first) ? [first as string] : [];
  if (a.operation === 'upsert_group') return Array.isArray(o?.members) ? (o!.members as unknown[]).filter(validId) as string[] : [];
  return [];
};
const ids = (x: unknown, max = 256): x is string[] => Array.isArray(x) && x.length <= max && x.every(validId) && new Set(x).size === x.length;
const level = (x: unknown) => LEVELS.includes(x as never);
const bool = (x: unknown) => typeof x === 'boolean';
const optional = (x: unknown, check: (y: unknown) => boolean) => x === undefined || check(x);
const destinationId = (x: unknown) => validId(x) && !DESTINATION_CLASSES.includes(x as never);
const sameRefs = (a: Knowledge['sources'], b: Knowledge['sources']) => a.length === b.length && a.every((r, i) => r.id === b[i]?.id && r.version === b[i]?.version);
const refs = (x: unknown) => Array.isArray(x) && x.length <= 256 && x.every(r => exactKeys(r, ['id', 'version']) && validId(r.id) && safeNumber(r.version) && r.version >= 1);

export const shapes = {
  actor: (a: unknown): a is Actor => exactKeys(a, ['id', 'tenant', 'kind', 'roles', 'projects', 'clearance', 'active'], ['destination', 'runtimeFor'])
    && validId(a.id) && validId(a.tenant) && ['user', 'agent', 'service'].includes(a.kind as string)
    && ids(a.roles, 64) && ids(a.projects) && level(a.clearance) && bool(a.active) && optional(a.destination, destinationId)
    && optional(a.runtimeFor, x => ids(x, 256)),
  /** A destination id is never a class name, so a grant entry is unambiguous (ADR-008). */
  destination: (d: unknown): d is Destination => exactKeys(d, ['id', 'tenant', 'class', 'maxClassification', 'purposes', 'active'], ['region'])
    && destinationId(d.id) && validId(d.tenant) && DESTINATION_CLASSES.includes(d.class as never) && level(d.maxClassification)
    && Array.isArray(d.purposes) && d.purposes.length <= 64 && d.purposes.every(p => typeof p === 'string' && p.length > 0 && p.length <= 128)
    && new Set(d.purposes).size === d.purposes.length && bool(d.active) && optional(d.region, validRegion),
  /** Runtime profile policy (0.5, ADR-012): profile ids only, never runtime policy text. */
  runtimeProfile: (p: unknown): p is RuntimeProfilePolicy => validRuntimeProfile(p),
  role: (r: unknown): r is Role => exactKeys(r, ['id', 'tenant', 'inherits', 'active'])
    && validId(r.id) && validId(r.tenant) && ids(r.inherits, 64) && !(r.inherits as string[]).includes(r.id) && bool(r.active),
  group: (g: unknown): g is Group => exactKeys(g, ['id', 'tenant', 'members', 'roles', 'active'])
    && validId(g.id) && validId(g.tenant) && ids(g.members, 1024) && ids(g.roles, 64) && bool(g.active),
  constraint: (c: unknown): c is SodConstraint => exactKeys(c, ['id', 'tenant', 'kind', 'roles', 'cardinality'])
    && validId(c.id) && validId(c.tenant) && ['static', 'dynamic'].includes(c.kind as string) && ids(c.roles, 64)
    && Number.isSafeInteger(c.cardinality) && (c.cardinality as number) >= 2 && (c.cardinality as number) <= (c.roles as string[]).length,
  container: (c: unknown): c is Container => exactKeys(c, ['id', 'tenant', 'kind', 'classification', 'readerRoles', 'readers', 'projects', 'active'], ['parent', 'tags', 'residency'])
    && validId(c.id) && validId(c.tenant) && level(c.classification) && ids(c.readerRoles) && ids(c.readers) && ids(c.projects) && bool(c.active)
    && optional(c.tags, validTags) && optional(c.residency, validResidency)
    && (c.kind === 'knowledge-base' ? c.parent === undefined : c.kind === 'folder' && validId(c.parent) && c.parent !== c.id),
  /** Administrative ingestion accepts human or system documents only; model output enters via derive(). */
  /** Tags, residency and modality (0.6) are optional; model lineage, session scope and erasure requests are never accepted from a caller. */
  document: (k: unknown): k is Knowledge => exactKeys(k, ['id', 'tenant', 'version', 'kind', 'origin', 'content', 'classification', 'projects', 'readerRoles', 'readers', 'sources', 'active'],
    ['accessExpiresAt', 'container', 'retainUntil', 'modality', 'tags', 'residency'])
    && validId(k.id) && validId(k.tenant) && safeNumber(k.version) && (k.version as number) >= 1 && k.kind === 'document'
    && ['human', 'system'].includes(k.origin as string) && typeof k.content === 'string' && k.content.length > 0 && k.content.length <= 1_000_000
    && level(k.classification) && ids(k.projects) && ids(k.readerRoles) && ids(k.readers) && refs(k.sources) && bool(k.active)
    && optional(k.accessExpiresAt, safeNumber) && optional(k.container, validId) && optional(k.retainUntil, safeNumber)
    && optional(k.modality, validModality) && optional(k.tags, validTags) && optional(k.residency, validResidency),
  /** Combination rule (0.6, R188). */
  combinationRule: (r: unknown): r is CombinationRule => validCombinationRule(r),
  /** `lastHeartbeatAt` and `breakGlass` are set by the control plane only (R147, R149); a request carrying them is malformed. */
  grant: (g: unknown): g is Grant => exactKeys(g, ['id', 'tenant', 'subject', 'agent', 'actions', 'resources', 'purposes', 'notBefore', 'expiresAt', 'active'], ['parent', 'activeRoles', 'destinations', 'maxResults', 'heartbeatTtlMs'])
    && [g.id, g.tenant, g.subject, g.agent].every(validId) && Array.isArray(g.actions) && g.actions.length > 0
    && g.actions.every(a => ACTIONS.includes(a)) && new Set(g.actions).size === g.actions.length
    && Array.isArray(g.resources) && g.resources.length <= 256 && g.resources.every(r => r === '*' || validId(r))
    && Array.isArray(g.purposes) && g.purposes.length <= 64 && g.purposes.every(p => typeof p === 'string' && p.length > 0 && p.length <= 128)
    && safeNumber(g.notBefore) && safeNumber(g.expiresAt) && (g.notBefore as number) < (g.expiresAt as number)
    && bool(g.active) && optional(g.parent, validId) && optional(g.activeRoles, x => ids(x, 64))
    && optional(g.destinations, x => ids(x, 64) && (x as string[]).length > 0)
    && optional(g.maxResults, x => Number.isSafeInteger(x) && (x as number) >= 1 && (x as number) <= MAX_RESULTS)
    && optional(g.heartbeatTtlMs, x => Number.isSafeInteger(x) && (x as number) >= HEARTBEAT.minTtlMs && (x as number) <= HEARTBEAT.maxTtlMs),
  breakGlass: (r: unknown): r is BreakGlassRequest => exactKeys(r, ['id', 'subject', 'agent', 'resources', 'purposes', 'ttlMs'], ['activeRoles'])
    && [r.id, r.subject, r.agent].every(validId) && ids(r.resources, BREAK_GLASS.resources) && (r.resources as string[]).length >= 1
    && Array.isArray(r.purposes) && r.purposes.length >= 1 && r.purposes.length <= 64 && r.purposes.every(p => typeof p === 'string' && p.length > 0 && p.length <= 128)
    && Number.isSafeInteger(r.ttlMs) && (r.ttlMs as number) >= BREAK_GLASS.minTtlMs && (r.ttlMs as number) <= BREAK_GLASS.maxTtlMs
    && optional(r.activeRoles, x => ids(x, 64))
};

/**
 * Trusted administrative operations. Every call is authorized against the
 * caller's standing roles in the same tenant and audited, allowed or not. This is
 * a library for an operator-facing API; it MUST NOT be reachable from agent
 * credentials or model output. Updating an existing security-relevant record
 * advances the tenant epoch, so running contexts must re-establish authority.
 */
export type ControlOptions = {
  clock?: () => number;
  /**
   * Optional Ed25519 key with which latestCheckpoint() signs format 2 checkpoints.
   * A server-held key attests only what this server saw; anchor checkpoints signed
   * with an offline key (scripts/checkpoint.ts) for independent evidence. A
   * CheckpointSigner (0.6, reference/custody.ts) keeps the key in a KMS or HSM.
   */
  checkpoint?: { privatePem: string; keyId: string } | CheckpointSigner;
  /** External approval workflow (0.6, R155): can only require more than the tenant quorum. */
  approvalGate?: ApprovalGate;
  /** Metrics hook (break-glass, approvals). Events carry no identities or content. */
  onEvent?: (event: ControlEvent) => void;
};
export class ControlPlane {
  private store: Store;
  private clock: () => number;
  private signer?: { privatePem: string; keyId: string } | CheckpointSigner;
  private trace?: string;
  private execution?: string;
  private options: ControlOptions;
  constructor(store: Store, options: ControlOptions = {}) {
    this.store = store; this.clock = options.clock ?? Date.now; this.signer = options.checkpoint; this.options = options;
  }
  private emit(event: ControlEvent) { try { this.options.onEvent?.(event); } catch { /* metrics never affect decisions */ } }
  /**
   * The same control plane, recording this W3C trace id and execution id (when
   * valid) with every decision. A runtime revision is never taken from here:
   * administrative calls do not act through a runtime enforcer.
   */
  traced(trace?: Call['trace']): ControlPlane {
    const next = new ControlPlane(this.store, { ...this.options, clock: this.clock, ...(this.signer ? { checkpoint: this.signer } : {}) });
    next.trace = traceOf(trace ? { trace } : {}) ?? this.trace;
    next.execution = executionOf(trace ? { trace } : {}) ?? this.execution;
    return next;
  }
  private record(s: State, tenant: string, adminId: string, o: Op, operation: string, allowed: boolean, reason: string, breakGlass?: true) {
    const code = classify(reason);
    if (!code || !code.category !== allowed) throw new Error('Unclassified decision reason');
    appendAudit(s, { time: this.clock(), tenant, actor: validId(adminId) ? adminId : 'invalid', operation,
      decision: allowed ? 'allow' : 'deny', reason, policyVersion: `${CORE_VERSION}|${s.policyVersion}|control-plane`, epoch: s.epochs[tenant] ?? 0,
      decisionId: o.id, reasonCode: code.code, policyDigest: policyDigest([CORE_VERSION, s.policyVersion, 'control-plane']), obligations: [],
      ...(o.trace ? { traceId: o.trace } : {}), ...(o.execution ? { executionId: o.execution } : {}), ...(breakGlass ? { breakGlass } : {}) });
  }
  /**
   * Authorizes, runs and audits one operation in one tenant transaction. If the
   * transaction fails (store error or an exceeded load budget), the attempt is
   * audited best effort as DEFERRED:STORE_ERROR / DEFERRED:BUDGET_EXCEEDED in a
   * separate transaction and the original error is rethrown (never masked).
   */
  private async run<T>(tenant: string, adminId: string, role: AdminRole | readonly AdminRole[], operation: string, seed: Seed,
    body: (s: State, tx: Tx) => Checked<T> | Promise<Checked<T>>): Promise<ControlResult<T>> {
    const o: Op = { id: newDecisionId(), ...(this.trace ? { trace: this.trace } : {}), ...(this.execution ? { execution: this.execution } : {}) };
    if (!validId(tenant)) return { ok: false, code: 'NOT_AUTHORIZED', decisionId: o.id };
    try {
      return await this.store.transaction(tenant, async tx => {
        await hydrate(tx, { ...seed, actors: [...(seed.actors ?? []), ...(validId(adminId) ? [adminId] : [])] });
        const s = tx.state;
        const admin = validId(adminId) && Object.hasOwn(s.actors, adminId) ? s.actors[adminId] : undefined;
        const roles = (admin?.kind === 'user' || admin?.kind === 'service') && admin.active && admin.tenant === tenant ? standingRoles(s, admin) : null;
        // A service principal (runtime, risk connector) may exercise the service roles only.
        if (!(typeof role === 'string' ? [role] : role).some(r => roles?.has(r) && (admin!.kind === 'user' || SERVICE_ROLES.includes(r)))) { this.record(s, tenant, adminId, o, operation, false, 'DENIED:NOT_ADMIN'); return { ok: false, code: 'NOT_AUTHORIZED', decisionId: o.id }; }
        const result = await body(s, tx);
        if (result.ok) {
          this.record(s, tenant, adminId, o, operation, result.audit?.allowed ?? true, result.audit?.reason ?? 'AUTHORIZED', result.breakGlass);
          return { ok: true, value: result.value, decisionId: o.id };
        }
        const { denied, breakGlass, ...refusal } = result;
        this.record(s, tenant, adminId, o, operation, false, `DENIED:${denied ?? result.code}`, breakGlass);
        return { ...refusal, decisionId: o.id };
      });
    } catch (error) {
      await this.failed(tenant, adminId, o, operation, error);
      throw error;
    }
  }
  private async failed(tenant: string, adminId: string, o: Op, operation: string, error: unknown) {
    const reason = error instanceof BudgetExceeded ? 'DEFERRED:BUDGET_EXCEEDED' : 'DEFERRED:STORE_ERROR';
    try {
      await this.store.transaction(tenant, async tx => { await tx.load({ epoch: true, audit: true }); this.record(tx.state, tenant, adminId, o, operation, false, reason); });
    } catch { /* best effort: the caller still receives the original failure */ }
  }
  private bump(s: State, tenant: string) { s.epochs[tenant] = (s.epochs[tenant] ?? 0) + 1; }
  /** Every principal must remain valid (closure established, no static SoD violation) after a change. */
  private standing(s: State, actors: (Actor | undefined)[]): Failure | null {
    for (const actor of actors) {
      if (!actor) continue;
      const roles = effectiveRoles(s, actor);
      if (!roles) return 'INVALID_REQUEST';
      if (sodViolated(s, actor.tenant, 'static', roles)) return 'SOD_VIOLATION';
    }
    return null;
  }
  /**
   * Applies `change` and counts the principals it turns from valid into invalid.
   * Principals that were already invalid are not counted: a change unrelated to
   * them must not be blocked by them (they are denied by every decision anyway).
   */
  private invalidates(s: State, actors: Actor[], change: () => void): { code: Failure; holders: number } | null {
    const valid = actors.filter(a => !this.standing(s, [a]));
    change();
    let holders = 0, sod = false;
    for (const a of valid) { const p = this.standing(s, [a]); if (p) { holders++; sod ||= p === 'SOD_VIOLATION'; } }
    return holders ? { code: sod ? 'SOD_VIOLATION' : 'INVALID_REQUEST', holders } : null;
  }
  /** Every active principal of the tenant, with memberships and roles (bounded; BudgetExceeded above it). */
  private async principals(tx: Tx, tenant: string): Promise<Actor[]> {
    await hydrate(tx, { principals: true });
    return Object.values(tx.state.actors).filter(a => a.tenant === tenant && a.active === true);
  }
  /** Principals for a holder check, or null when the tenant exceeds the load budget and the store can count server-side. */
  private async holdersOf(tx: Tx, tenant: string): Promise<Actor[] | null> {
    try { return await this.principals(tx, tenant); }
    catch (error) { if (error instanceof BudgetExceeded && tx.countSodHolders) return null; throw error; }
  }

  private settingsOf(s: State, tenant: string): TenantSettings | undefined {
    const found = s.settings && Object.hasOwn(s.settings, tenant) ? s.settings[tenant] : undefined;
    return found?.tenant === tenant ? found : undefined;
  }
  /** Calls the external approval gate with a deadline; any failure is null (the caller fails closed). */
  private async ask<T>(fn: () => Promise<T> | undefined): Promise<T | null> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const pending = fn();
      if (pending === undefined) return null;
      const deadline = new Promise<never>((_r, reject) => { timer = setTimeout(() => reject(new Error('deadline')), APPROVAL.gateTimeoutMs); });
      return await Promise.race([pending, deadline]);
    } catch { return null; } finally { if (timer) clearTimeout(timer); }
  }
  /**
   * Approval gate of a sensitive operation (R153..R157). Without `approval`: proceed
   * when the effective quorum is 1 and no external workflow is required, otherwise
   * store a pending approval and refuse with APPROVAL_REQUIRED. With `approval`: the
   * operation executes an approval, which must be pending, unexpired, of the same class,
   * operation, requester and argument digest, and meet the quorum (the higher of the
   * quorum recorded at request time and the current one) with approvers who are still
   * standing security-admins, and the external workflow when one was required.
   */
  private async gated(s: State, tx: Tx, tenant: string, adminId: string, cls: ApprovalClass, operation: string, payload: unknown,
    approval: string | undefined, quorum?: number): Promise<Gate> {
    const settings = this.settingsOf(s, tenant), current = quorum ?? quorumOf(settings, cls), digest = approvalDigest(payload), now = this.clock();
    const flag = cls === 'break_glass' ? { breakGlass: true as const } : {};
    if (approval === undefined) {
      const gate = this.options.approvalGate;
      let extra: { quorum?: unknown; external?: unknown } | null = {};
      if (gate?.requirements) extra = await this.ask(() => gate.requirements!({ tenant, class: cls, operation, requester: adminId, digest }));
      // An unanswered or malformed gate requires the external workflow (fail closed).
      const valid = !!extra && typeof extra === 'object' && (extra.quorum === undefined || (Number.isSafeInteger(extra.quorum) && (extra.quorum as number) >= 1))
        && (extra.external === undefined || typeof extra.external === 'boolean');
      const external = !valid || extra!.external === true;
      const required = Math.min(APPROVAL.maxQuorum, Math.max(current, valid && typeof extra!.quorum === 'number' ? extra!.quorum : 1));
      if (required <= 1 && !external) return { ok: true, done: () => {} };
      const id = randomUUID();
      (s.approvals ??= {})[id] = { id, tenant, class: cls, operation, requester: adminId, payload: jsonValue(payload), digest, approvers: [], required, external,
        createdAt: now, expiresAt: now + approvalTtl(settings), status: 'pending' };
      this.emit({ type: 'approval', tenant, class: cls, outcome: 'requested' });
      return { ok: false, code: 'APPROVAL_REQUIRED', approval: id, ...flag };
    }
    if (!validId(approval)) return { ...refuse('CONFLICT'), ...flag };
    await hydrate(tx, { approvals: [approval] });
    const record = s.approvals && Object.hasOwn(s.approvals, approval) ? s.approvals[approval] : undefined;
    if (!record || record.tenant !== tenant || record.class !== cls || record.operation !== operation || record.requester !== adminId
      || record.digest !== digest || record.status !== 'pending' || !(now < record.expiresAt)) return { ...refuse('CONFLICT'), ...flag };
    if (!await this.quorumMet(s, tx, tenant, record, Math.max(record.required, current))) return { ok: false, code: 'APPROVAL_REQUIRED', approval: record.id, ...flag };
    return { ok: true, done: () => { record.status = 'executed'; record.executedAt = now; this.emit({ type: 'approval', tenant, class: cls, outcome: 'executed' }); } };
  }
  /** Requester plus distinct approvers that still hold security-admin reach `required`, and the external workflow (if required) is satisfied. */
  private async quorumMet(s: State, tx: Tx, tenant: string, record: Approval, required: number): Promise<boolean> {
    await hydrate(tx, { actors: record.approvers.filter(validId) });
    const targets = elevationTargets(record);
    const valid = new Set(record.approvers.filter(id => id !== record.requester && !targets.includes(id)
      && approver(s, tenant, Object.hasOwn(s.actors, id) ? s.actors[id] : undefined)));
    if (valid.size + 1 < required) return false;
    if (!record.external) return true;
    const gate = this.options.approvalGate;
    const ok = gate?.satisfied ? await this.ask(() => gate.satisfied!({ tenant, approval: record.id, class: record.class, operation: record.operation,
      digest: record.digest, requester: record.requester, approvers: [...valid] })) : null;
    return ok === true;
  }

  /**
   * Approval gate of an elevation (0.6b, R158): a change that makes some principal newly hold an approver role
   * (APPROVER_ROLES) needs the highest quorum of any class (settingsQuorum, at least the break-glass quorum), so one
   * administrator can never create the second approver of a four-eyes rule. The elevated principals never count.
   */
  private elevation(s: State, tx: Tx, tenant: string, adminId: string, operation: string, payload: unknown, approval: string | undefined): Promise<Gate> {
    return this.gated(s, tx, tenant, adminId, 'role_widening', operation, payload, approval, settingsQuorum(this.settingsOf(s, tenant)));
  }
  /** Creating or changing a principal; one that becomes (or is reactivated as) an approver passes the elevation gate (R158). */
  upsertActor(tenant: string, adminId: string, actor: Actor, options: { approval?: string } = {}) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_actor', { actors: validId(actor?.id) ? [actor.id] : [] }, async (s, tx) => {
      if (!shapes.actor(actor) || actor.tenant !== tenant) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.actors, actor.id) ? s.actors[actor.id] : undefined;
      if (existing && (existing.tenant !== tenant || existing.kind !== actor.kind)) return refuse('CONFLICT');
      const was = approver(s, tenant, existing);
      s.actors[actor.id] = structuredClone(actor);
      const restore = () => { if (existing) s.actors[actor.id] = existing; else delete s.actors[actor.id]; };
      // Deactivation and other pure reductions always succeed, even for a principal
      // that already violates a constraint (for example SCIM deprovisioning).
      const problem = existing && reducesActor(existing, actor) ? null : this.standing(s, [s.actors[actor.id]]);
      if (problem) { restore(); return refuse(problem); }
      // R158: becoming an approver needs the elevation quorum; R147 (0.6b): a new runtime binding is a role widening.
      const elevates = !was && approver(s, tenant, s.actors[actor.id]), binds = !within(actor.runtimeFor ?? [], existing?.runtimeFor ?? []);
      if (elevates || binds || options.approval !== undefined) {
        const gate = await this.gated(s, tx, tenant, adminId, 'role_widening', 'upsert_actor', [actor], options.approval,
          elevates ? settingsQuorum(this.settingsOf(s, tenant)) : undefined);
        if (!gate.ok) { restore(); return gate; }
        gate.done();
      }
      if (existing) this.bump(s, tenant);
      return { ok: true, value: { id: actor.id } };
    });
  }
  /**
   * Role assignment is where static SoD is enforced administratively; decisions enforce it again.
   * An assignment that makes the principal an approver passes the elevation gate (R158).
   */
  assignRoles(tenant: string, adminId: string, actorId: string, roles: string[], options: { approval?: string } = {}) {
    return this.run(tenant, adminId, 'security-admin', 'assign_roles', { actors: validId(actorId) ? [actorId] : [], roles: ids(roles, 64) ? roles : [] }, async (s, tx) => {
      const actor = validId(actorId) && Object.hasOwn(s.actors, actorId) ? s.actors[actorId] : undefined;
      if (!actor || actor.tenant !== tenant || !ids(roles, 64)) return refuse('INVALID_REQUEST');
      const was = approver(s, tenant, actor);
      const previous = actor.roles; actor.roles = [...roles];
      const problem = within(roles, previous) ? null : this.standing(s, [actor]);
      if (problem) { actor.roles = previous; return refuse(problem); }
      if ((!was && approver(s, tenant, actor)) || options.approval !== undefined) {
        const gate = await this.elevation(s, tx, tenant, adminId, 'assign_roles', [actorId, roles], options.approval);
        if (!gate.ok) { actor.roles = previous; return gate; }
        gate.done();
      }
      this.bump(s, tenant); return { ok: true, value: { id: actor.id, roles: [...roles] } };
    });
  }
  /**
   * A change that can widen a role's closure (new role, new juniors, reactivation)
   * is rejected with SOD_VIOLATION if it would put any currently valid active
   * principal of the tenant into a static violation (the response carries only the
   * count). Deactivation and removing juniors always succeed.
   */
  upsertRole(tenant: string, adminId: string, role: Role, options: { approval?: string } = {}) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_role', { roles: shapes.role(role) ? [role.id, ...role.inherits] : [] }, async (s, tx) => {
      if (!shapes.role(role) || role.tenant !== tenant) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.roles, role.id) ? s.roles[role.id] : undefined;
      if (existing && existing.tenant !== tenant) return refuse('CONFLICT');
      // R158: does this role's closure grant an approver role now (before the change)?
      const granted = grantsApproval(s, tenant, role.id, false);
      const reduces = existing && (role.active === false || ((existing.active === true || role.active !== true) && within(role.inherits, existing.inherits)));
      const holders = reduces ? [] : await this.holdersOf(tx, tenant);
      // Beyond the load budget the store counts server-side. Widening is an authority
      // increase: newly violating principals refuse it, an unknown count refuses it too
      // (BudgetExceeded, a deferred denial). Widening only adds roles, so the increase
      // is the count under the new hierarchy minus the count under the stored one.
      let counted = 0;
      if (!holders) {
        const constraints = Object.values(s.constraints).filter(c => c.tenant === tenant && c.kind === 'static');
        const [after, before] = [await tx.countSodHolders!({ constraints, role }), await tx.countSodHolders!({ constraints })];
        if (after === 'unknown' || before === 'unknown') throw new BudgetExceeded('role holders');
        counted = Math.max(0, after - before);
      }
      const broken = holders ? this.invalidates(s, holders, () => { s.roles[role.id] = structuredClone(role); })
        : (s.roles[role.id] = structuredClone(role), counted ? { code: 'SOD_VIOLATION' as Failure, holders: counted } : null);
      const restore = () => { if (existing) s.roles[role.id] = existing; else delete s.roles[role.id]; };
      // The hierarchy below this role must stay acyclic and within budget.
      if (!effectiveRoles(s, { id: '-', tenant, kind: 'user', roles: [role.id], projects: [], clearance: 'public', active: true })) { restore(); return refuse('INVALID_REQUEST'); }
      if (broken) { restore(); return { ok: false, code: broken.code, holders: broken.holders }; }
      // R153: widening an existing role, or a new role that inherits others, passes the approval gate. R158: when
      // the change makes the role's closure grant an approver role (inheritance, (re)activation), with the elevation quorum.
      const elevates = !granted && grantsApproval(s, tenant, role.id, true);
      if ((!reduces && (existing !== undefined || role.inherits.length > 0)) || elevates || options.approval !== undefined) {
        const gate = await this.gated(s, tx, tenant, adminId, 'role_widening', 'upsert_role', [role], options.approval,
          elevates ? settingsQuorum(this.settingsOf(s, tenant)) : undefined);
        if (!gate.ok) { restore(); return gate; }
        gate.done();
      }
      // Every accepted change advances the epoch (0.6b): even a new role can change the session roles of holders of its name.
      this.bump(s, tenant);
      return { ok: true, value: { id: role.id } };
    });
  }
  /** Group upsert; members that the change makes approvers pass the elevation gate (R158). Advances the epoch. */
  upsertGroup(tenant: string, adminId: string, group: Group, options: { approval?: string } = {}) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_group', { actors: shapes.group(group) ? group.members : [], roles: shapes.group(group) ? group.roles : [], groups: validId(group?.id) ? [group.id] : [] }, async (s, tx) => {
      if (!shapes.group(group) || group.tenant !== tenant) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.groups, group.id) ? s.groups[group.id] : undefined;
      if (existing && existing.tenant !== tenant) return refuse('CONFLICT');
      const restore = () => { if (existing) s.groups[group.id] = existing; else delete s.groups[group.id]; };
      // Only members that the change turns invalid count: removing members or roles,
      // or deactivating the group, always succeeds.
      const members = group.members.flatMap(m => Object.hasOwn(s.actors, m) ? [s.actors[m]!] : []);
      const before = new Set(members.filter(a => approver(s, tenant, a)).map(a => a.id));
      const broken = this.invalidates(s, members, () => { s.groups[group.id] = structuredClone(group); });
      if (broken) { restore(); return refuse(broken.code); }
      if (members.some(a => !before.has(a.id) && approver(s, tenant, a)) || options.approval !== undefined) {
        const gate = await this.elevation(s, tx, tenant, adminId, 'upsert_group', [group], options.approval);
        if (!gate.ok) { restore(); return gate; }
        gate.done();
      }
      // Every accepted change advances the epoch (0.6b): a new group can add roles that a dynamic SoD constraint forbids in a session.
      this.bump(s, tenant);
      return { ok: true, value: { id: group.id } };
    });
  }
  /**
   * A static constraint that some currently valid active principal of the tenant
   * would violate is rejected with SOD_VIOLATION and the number of such holders
   * (never their ids); resolve the assignments first. Dynamic constraints and
   * relaxations (fewer roles, higher cardinality) do not affect standing. Decisions
   * enforce every stored constraint regardless (R24).
   */
  upsertConstraint(tenant: string, adminId: string, constraint: SodConstraint, options: { approval?: string } = {}) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_constraint', {}, async (s, tx) => {
      if (!shapes.constraint(constraint) || constraint.tenant !== tenant) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.constraints, constraint.id) ? s.constraints[constraint.id] : undefined;
      if (existing && existing.tenant !== tenant) return refuse('CONFLICT');
      const relaxes = constraint.kind === 'dynamic' || (existing?.kind === 'static' && within(constraint.roles, existing.roles) && constraint.cardinality >= existing.cardinality);
      const holders = relaxes ? [] : await this.holdersOf(tx, tenant);
      // A tenant beyond the load budget is counted in SQL; when that count is unknown the
      // constraint is still accepted (tightening must never be blocked, and every decision
      // enforces static SoD anyway) and the result reports holders: 'unknown'.
      const counted = holders ? 0 : constraint.kind === 'static' ? await tx.countSodHolders!({ constraints: [constraint] }) : 0;
      const broken = holders ? this.invalidates(s, holders, () => { s.constraints[constraint.id] = structuredClone(constraint); })
        : (s.constraints[constraint.id] = structuredClone(constraint), typeof counted === 'number' && counted ? { code: 'SOD_VIOLATION' as Failure, holders: counted } : null);
      if (broken) {
        if (existing) s.constraints[constraint.id] = existing; else delete s.constraints[constraint.id];
        return { ok: false, code: broken.code, holders: broken.holders };
      }
      // R153: relaxing an existing constraint passes the approval gate.
      if ((existing && relaxesConstraint(existing, constraint)) || options.approval !== undefined) {
        const gate = await this.gated(s, tx, tenant, adminId, 'sod_relaxation', 'upsert_constraint', [constraint], options.approval);
        if (!gate.ok) { if (existing) s.constraints[constraint.id] = existing; else delete s.constraints[constraint.id]; return gate; }
        gate.done();
      }
      this.bump(s, tenant);
      return { ok: true, value: counted === 'unknown' ? { id: constraint.id, holders: 'unknown' as const } : { id: constraint.id } };
    });
  }
  upsertContainer(tenant: string, adminId: string, container: Container) {
    return this.run(tenant, adminId, 'kb-admin', 'upsert_container', { containers: shapes.container(container) ? [container.id, ...(container.parent ? [container.parent] : [])] : [] }, s => {
      if (!shapes.container(container) || container.tenant !== tenant) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.containers, container.id) ? s.containers[container.id] : undefined;
      if (existing && (existing.tenant !== tenant || existing.kind !== container.kind)) return refuse('CONFLICT');
      s.containers[container.id] = structuredClone(container);
      if (!containerChain(s, { tenant, container: container.id })) {
        if (existing) s.containers[container.id] = existing; else delete s.containers[container.id];
        return refuse('INVALID_REQUEST');
      }
      if (existing) this.bump(s, tenant);
      return { ok: true, value: { id: container.id } };
    });
  }
  /**
   * Versions are monotonic: an update must carry exactly the next version. A
   * document with sources must resolve them (same tenant, referenced version) and
   * its effective classification must be at least the transitive effective
   * classification of every source (R25); otherwise INVALID_REQUEST. A record
   * under legal hold keeps its content and sources: a new version that changes
   * either is a CONFLICT carrying `held` (R55). A record revoked by a
   * security-admin (`revokedAt`) cannot be reactivated here: a new version with
   * `active: true` is a CONFLICT until reinstate() (R49).
   *
   * Label widening is a declassification (R15, 0.6 R126): a new version that
   * widens the label (widensLabel) needs an administrator holding security-admin;
   * a kb-admin without it is refused with CONFLICT. A security-admin without
   * kb-admin may publish only such a relabelling version of an existing document
   * with unchanged content (NOT_ADMIN otherwise): content stays with kb-admins.
   */
  upsertKnowledge(tenant: string, adminId: string, document: Knowledge, options: {
    /** Store the document quarantined (ingestion scanner); it is then invisible and unindexed until release(). */
    quarantine?: QuarantineReason;
    /** Execute this approval (0.6, R153); set by the control plane when a label-widening version reaches its quorum. */
    approval?: string;
  } = {}) {
    const sources = shapes.document(document) ? document.sources.map(r => r.id) : [];
    return this.run(tenant, adminId, ['kb-admin', 'security-admin'], 'upsert_knowledge', { knowledge: validId(document?.id) ? [document.id, ...sources] : [],
      containers: validId(document?.container) ? [document.container] : [] }, async (s, tx) => {
      if (!shapes.document(document) || document.tenant !== tenant
        || (options.quarantine !== undefined && !QUARANTINE_REASONS.includes(options.quarantine))) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.knowledge, document.id) ? s.knowledge[document.id] : undefined;
      // run() admitted an active user of this tenant holding kb-admin or security-admin.
      const roles = standingRoles(s, s.actors[adminId]!) ?? new Set<string>();
      const kb = roles.has('kb-admin'), security = roles.has('security-admin');
      const widening = existing !== undefined && existing.kind === 'document' && widensLabel(existing, document);
      if (!kb && (!widening || document.content !== existing!.content || options.quarantine !== undefined)) return { ok: false, code: 'NOT_AUTHORIZED', denied: 'NOT_ADMIN' };
      if (existing ? existing.tenant !== tenant || existing.kind !== 'document' || document.version !== existing.version + 1 : document.version !== 1) return refuse('CONFLICT');
      // R15: widening the label of an existing document is a declassification; a kb-admin alone cannot do it.
      if (widening && !security) return refuse('CONFLICT');
      // An erased id is burned (R-LIFE-9). A new version never lifts a quarantine or a legal hold.
      if (existing?.lifecycle !== undefined && existing.lifecycle !== 'quarantined') return refuse('CONFLICT');
      // A legal hold preserves the held content: only metadata (labels, readers, activity, retention) may change.
      if (existing && held(existing) && (document.content !== existing.content || !sameRefs(document.sources, existing.sources))) return { ok: false, code: 'CONFLICT', held: 1 };
      // A security-admin revocation survives new versions; only reinstate() lifts it.
      if (existing?.revokedAt !== undefined && document.active !== false) return refuse('CONFLICT');
      const next: Knowledge = structuredClone(document);
      if (existing?.revokedAt !== undefined) next.revokedAt = existing.revokedAt;
      // A pending erasure request (R194) survives new versions.
      if (existing?.erasureRequestedAt !== undefined) next.erasureRequestedAt = existing.erasureRequestedAt;
      if (existing?.lifecycle === 'quarantined') {
        next.lifecycle = 'quarantined';
        if (existing.lifecycleAt !== undefined) next.lifecycleAt = existing.lifecycleAt;
        if (existing.quarantineReason !== undefined) next.quarantineReason = existing.quarantineReason;
      } else if (options.quarantine) Object.assign(next, { lifecycle: 'quarantined', lifecycleAt: this.clock(), quarantineReason: options.quarantine });
      if (existing && held(existing)) next.legalHolds = structuredClone(existing.legalHolds);
      if (document.container !== undefined && !containerChain(s, document)) return refuse('INVALID_REQUEST');
      if (document.sources.length) {
        const own = effectiveLabel(s, document)?.classification, top = transitiveClassification(s, document);
        if (!own || !top || rank(top) > rank(own)) return refuse('INVALID_REQUEST');
      }
      // R153: a label-widening version (a declassification) passes the approval gate.
      if (widening || options.approval !== undefined) {
        const gate = await this.gated(s, tx, tenant, adminId, 'label_widening', 'upsert_knowledge', [document, ...(options.quarantine ? [options.quarantine] : [])], options.approval);
        if (!gate.ok) return gate;
        gate.done();
      }
      s.knowledge[document.id] = next;
      if (existing) this.bump(s, tenant);
      return { ok: true, value: { id: document.id, version: document.version, ...(next.lifecycle ? { quarantined: true as const } : {}) } };
    });
  }
  /**
   * Destination profile (security-admin, ADR-008). Principals reference it through
   * `Actor.destination`. Updating an existing profile advances the tenant epoch, so
   * open contexts re-establish authority under the new profile.
   */
  upsertDestination(tenant: string, adminId: string, destination: Destination, options: { approval?: string } = {}) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_destination', { destinations: validId(destination?.id) ? [destination.id] : [] }, async (s, tx) => {
      if (!shapes.destination(destination) || destination.tenant !== tenant) return refuse('INVALID_REQUEST');
      const records = s.destinations ??= {};
      const existing = Object.hasOwn(records, destination.id) ? records[destination.id] : undefined;
      if (existing && existing.tenant !== tenant) return refuse('CONFLICT');
      // R153: a profile that can receive more (new active, reactivated, higher classification, more purposes, another class) passes the approval gate.
      if (widensDestination(existing, destination) || options.approval !== undefined) {
        const gate = await this.gated(s, tx, tenant, adminId, 'destination_widening', 'upsert_destination', [destination], options.approval);
        if (!gate.ok) return gate;
        gate.done();
      }
      records[destination.id] = structuredClone(destination);
      if (existing) this.bump(s, tenant);
      return { ok: true, value: { id: destination.id } };
    });
  }
  /**
   * Runtime profile policy (security-admin, 0.5, ADR-012). The control plane
   * requires a standing security-admin user, so a change that widens runtime
   * authority (deactivation, a lower tier, a different profile) is always a
   * privileged, human-authorized and audited decision; agents and model output
   * never reach it (R31). Every accepted change, including creation, advances the
   * tenant epoch: open contexts end and re-establish authority under the new
   * obligations. At most RUNTIME_PROFILE_LIMIT records per tenant (CONFLICT above).
   */
  upsertRuntimeProfile(tenant: string, adminId: string, policy: RuntimeProfilePolicy, options: { approval?: string } = {}) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_runtime_profile', { runtimeProfiles: true }, async (s, tx) => {
      if (!shapes.runtimeProfile(policy) || policy.tenant !== tenant) return refuse('INVALID_REQUEST');
      const records = s.runtimeProfiles ??= {};
      const existing = Object.hasOwn(records, policy.id) ? records[policy.id] : undefined;
      if (existing && existing.tenant !== tenant) return refuse('CONFLICT');
      if (!existing && Object.values(records).filter(p => p?.tenant === tenant).length >= RUNTIME_PROFILE_LIMIT) return refuse('CONFLICT');
      // R153: changing an existing runtime profile policy passes the approval gate (a new one only adds obligations).
      if ((existing && !isDeepStrictEqual(existing, policy)) || options.approval !== undefined) {
        const gate = await this.gated(s, tx, tenant, adminId, 'runtime_profile', 'upsert_runtime_profile', [policy], options.approval);
        if (!gate.ok) return gate;
        gate.done();
      }
      records[policy.id] = structuredClone(policy);
      this.bump(s, tenant);
      return { ok: true, value: { id: policy.id, epoch: s.epochs[tenant]! } };
    });
  }
  /** Issues a root or attenuated grant. Session activation must be held by the subject and satisfy dynamic SoD. */
  issueGrant(tenant: string, adminId: string, grant: Grant) {
    return this.run(tenant, adminId, 'security-admin', 'issue_grant', { grants: shapes.grant(grant) ? [grant.id, ...(grant.parent ? [grant.parent] : [])] : [],
      actors: shapes.grant(grant) ? [grant.subject, grant.agent] : [] }, s => {
      if (!shapes.grant(grant) || grant.tenant !== tenant) return refuse('INVALID_REQUEST');
      if (Object.hasOwn(s.grants, grant.id)) return refuse('CONFLICT');
      // A heartbeat-bound grant starts alive: its issuance is its first heartbeat (R147).
      if (grant.heartbeatTtlMs !== undefined) grant = { ...grant, lastHeartbeatAt: this.clock() };
      const next: State = { ...s, grants: { ...s.grants, [grant.id]: grant } };
      const user = Object.hasOwn(s.actors, grant.subject) ? s.actors[grant.subject] : undefined;
      if (!user || !validGrantChain(next, grant, this.clock())) return refuse('INVALID_REQUEST');
      const held = effectiveRoles(s, user);
      const session = held && sessionRoles(s, user, held, grant);
      if (!held || !session) return refuse('INVALID_REQUEST');
      if (sodViolated(s, tenant, 'static', held) || sodViolated(s, tenant, 'dynamic', session)) return refuse('SOD_VIOLATION');
      s.grants[grant.id] = structuredClone(grant);
      return { ok: true, value: { id: grant.id } };
    });
  }
  /**
   * Break-glass grant (security-admin, 0.6, R149, R150): read-only, on named
   * resources, for at most two hours, never delegable, never across tenants. It lifts
   * only the audience clauses of the named records; lifecycle (quarantine, erasure),
   * activity, clearance and risk caps still apply, and it changes no record, so legal
   * holds and erasure are untouched. It always passes the approval gate (quorum at
   * least 2) and every audit entry of its issuance and use is flagged `breakGlass`.
   * The lifetime starts when the grant is issued (after the quorum is reached).
   */
  issueBreakGlass(tenant: string, adminId: string, request: BreakGlassRequest, options: { approval?: string } = {}) {
    const valid = shapes.breakGlass(request);
    return this.run(tenant, adminId, 'security-admin', 'issue_break_glass', valid ? { grants: [request.id], actors: [request.subject, request.agent] } : {}, async (s, tx) => {
      if (!valid) return { ...refuse('INVALID_REQUEST'), breakGlass: true };
      if (Object.hasOwn(s.grants, request.id)) return { ...refuse('CONFLICT'), breakGlass: true };
      const now = this.clock();
      const grant: Grant = { id: request.id, tenant, subject: request.subject, agent: request.agent, actions: ['read'], resources: [...request.resources],
        purposes: [...request.purposes], notBefore: now, expiresAt: now + request.ttlMs, active: true, breakGlass: true,
        ...(request.activeRoles ? { activeRoles: [...request.activeRoles] } : {}) };
      const user = Object.hasOwn(s.actors, grant.subject) ? s.actors[grant.subject] : undefined;
      if (!user || !validGrantChain({ ...s, grants: { ...s.grants, [grant.id]: grant } }, grant, now)) return { ...refuse('INVALID_REQUEST'), breakGlass: true };
      const held = effectiveRoles(s, user), session = held && sessionRoles(s, user, held, grant);
      if (!held || !session) return { ...refuse('INVALID_REQUEST'), breakGlass: true };
      if (sodViolated(s, tenant, 'static', held) || sodViolated(s, tenant, 'dynamic', session)) return { ...refuse('SOD_VIOLATION'), breakGlass: true };
      const gate = await this.gated(s, tx, tenant, adminId, 'break_glass', 'issue_break_glass', [request], options.approval);
      if (!gate.ok) return gate;
      s.grants[grant.id] = grant;
      gate.done();
      this.emit({ type: 'break_glass', tenant });
      return { ok: true, value: { id: grant.id, notBefore: grant.notBefore, expiresAt: grant.expiresAt }, breakGlass: true };
    });
  }
  /**
   * Grant heartbeat (runtime role, 0.6, R147, R148): a trusted runtime reports that
   * the run is alive. Only a heartbeat-bound grant whose whole chain is still valid can
   * be refreshed; a lapsed, expired or revoked grant (or one whose ancestor lapsed)
   * is a CONFLICT and stays invalid: a lapse is final. No epoch change. 0.6b: the caller
   * must be bound to the grant's agent (Actor.runtimeFor); any other grant is refused
   * (NOT_AUTHORIZED, audited NOT_ADMIN), whether it exists or not.
   */
  heartbeat(tenant: string, adminId: string, grantId: string) {
    return this.run(tenant, adminId, 'runtime', 'grant_heartbeat', { grants: validId(grantId) ? [grantId] : [] }, s => {
      const g = validId(grantId) && Object.hasOwn(s.grants, grantId) ? s.grants[grantId] : undefined;
      // run() admitted an active principal of this tenant holding the runtime role.
      const bound = s.actors[adminId]!.runtimeFor;
      if (!g || g.tenant !== tenant || !Array.isArray(bound) || !bound.includes(g.agent)) return { ok: false, code: 'NOT_AUTHORIZED', denied: 'NOT_ADMIN' };
      if (g.heartbeatTtlMs === undefined) return refuse('INVALID_REQUEST');
      const now = this.clock();
      if (!validGrantChain(s, g, now)) return refuse('CONFLICT');
      g.lastHeartbeatAt = now;
      return { ok: true, value: { id: g.id, lastHeartbeatAt: now, validUntil: Math.min(now + g.heartbeatTtlMs, g.expiresAt) } };
    });
  }
  /**
   * Risk signal ingestion (security-admin or risk-ingest, 0.6, R151, R152). One
   * signal per (caller, principal): the source is the authenticated caller, so a
   * connector can only replace its own signals. A higher level than the caller's
   * previous unexpired one advances the tenant epoch (open contexts re-establish
   * authority under the cap). Lifetime `ttlMs` (60 s .. 30 days, default 24 h).
   */
  putRiskSignal(tenant: string, adminId: string, input: RiskSignalInput) {
    const principal = input && typeof input === 'object' ? input.principal : undefined;
    return this.run(tenant, adminId, ['security-admin', 'risk-ingest'], 'risk_signal', { actors: validId(principal) ? [principal] : [] }, s => {
      if (!exactKeys(input, ['principal', 'level'], ['ttlMs', 'event']) || !validId(input.principal) || !RISK_LEVELS.includes(input.level as RiskLevel)
        || (input.ttlMs !== undefined && !(Number.isSafeInteger(input.ttlMs) && (input.ttlMs as number) >= 60_000 && (input.ttlMs as number) <= RISK_SIGNAL.maxTtlMs))
        || (input.event !== undefined && !(typeof input.event === 'string' && SSF_EVENT.test(input.event)))) return refuse('INVALID_REQUEST');
      const actor = Object.hasOwn(s.actors, input.principal) ? s.actors[input.principal] : undefined;
      if (!actor || actor.tenant !== tenant) return refuse('INVALID_REQUEST');
      const signals = s.riskSignals ??= {}, id = riskSignalId(adminId, input.principal), now = this.clock();
      const previous = Object.hasOwn(signals, id) ? signals[id] : undefined;
      const level = input.level as RiskLevel, ttl = (input.ttlMs as number | undefined) ?? RISK_SIGNAL.defaultTtlMs;
      signals[id] = { id, tenant, principal: input.principal, level, source: adminId, issuedAt: now, expiresAt: now + ttl, ...(input.event !== undefined ? { event: input.event as string } : {}) };
      const before = previous && previous.tenant === tenant && now < previous.expiresAt ? RISK_LEVELS.indexOf(previous.level) : 0;
      if (RISK_LEVELS.indexOf(level) > before) this.bump(s, tenant);
      return { ok: true, value: { id, level, expiresAt: now + ttl, epoch: s.epochs[tenant] ?? 0 } };
    });
  }
  /**
   * Tenant settings (security-admin, 0.6): approval quorums, approval lifetime and risk
   * caps. Tightening applies at once; any relaxation (a lower quorum, a longer
   * lifetime, a higher risk cap) passes the approval gate with the highest quorum of
   * any class (R156). Advances the tenant epoch.
   */
  putSettings(tenant: string, adminId: string, settings: TenantSettings, options: { approval?: string } = {}) {
    return this.run(tenant, adminId, 'security-admin', 'put_settings', {}, async (s, tx) => {
      if (!validSettings(settings, tenant)) return refuse('INVALID_REQUEST');
      const current = this.settingsOf(s, tenant);
      if (settingsRelax(current, settings) || options.approval !== undefined) {
        const gate = await this.gated(s, tx, tenant, adminId, 'settings', 'put_settings', [settings], options.approval, settingsQuorum(current));
        if (!gate.ok) return gate;
        gate.done();
      }
      (s.settings ??= {})[tenant] = structuredClone(settings);
      this.bump(s, tenant);
      return { ok: true, value: { id: tenant, epoch: s.epochs[tenant]! } };
    });
  }
  /** Effective tenant settings (security-admin or auditor): every class quorum, the approval lifetime and every risk cap. */
  readSettings(tenant: string, adminId: string) {
    return this.run(tenant, adminId, ['security-admin', 'auditor'], 'read_settings', {}, s => {
      const current = this.settingsOf(s, tenant);
      const riskCaps = Object.fromEntries(RISK_LEVELS.map(l => [l, l === 'critical' ? 'deny' : current?.riskCaps?.[l] ?? DEFAULT_RISK_CAPS[l]]));
      return { ok: true, value: { id: tenant, tenant, approvalQuorum: Object.fromEntries(APPROVAL_CLASSES.map(c => [c, quorumOf(current, c)])),
        approvalTtlMs: approvalTtl(current), riskCaps, lineageDepth: current?.lineageDepth ?? KNOWLEDGE.defaultDepth, configured: current !== undefined } };
    });
  }
  /** A pending, unexpired approval of this tenant, or null. */
  private pending(s: State, tenant: string, id: string): Approval | null {
    const a = validId(id) && s.approvals && Object.hasOwn(s.approvals, id) ? s.approvals[id] : undefined;
    return a && a.tenant === tenant && a.status === 'pending' && this.clock() < a.expiresAt ? a : null;
  }
  /**
   * Approves a pending request (security-admin, R154): the approver must not be the
   * requester and must not have approved it already (CONFLICT, audited). When the
   * quorum is met (and no external workflow is required), the operation executes
   * immediately as the requester, who must still hold the operation's role; the
   * result carries its outcome. Otherwise it stays pending.
   */
  async approve(tenant: string, adminId: string, id: string): Promise<ControlResult<{ approval: ApprovalSummary; execution?: ControlResult<unknown> }>> {
    let ready = false;
    const approved = await this.run(tenant, adminId, 'security-admin', 'approval_grant', { approvals: validId(id) ? [id] : [] }, s => {
      const a = this.pending(s, tenant, id);
      const flag = a?.class === 'break_glass' ? { breakGlass: true as const } : {};
      if (!a) return refuse('CONFLICT');
      // Four eyes: never the requester, never twice the same approver.
      if (a.requester === adminId || a.approvers.includes(adminId)) return { ...refuse('CONFLICT'), ...flag };
      // R158: never the principal an elevation would make an approver.
      if (elevationTargets(a).includes(adminId)) return { ...refuse('CONFLICT'), ...flag };
      a.approvers.push(adminId);
      ready = a.approvers.length + 1 >= Math.max(a.required, quorumOf(this.settingsOf(s, tenant), a.class)) && !a.external;
      this.emit({ type: 'approval', tenant, class: a.class, outcome: 'approved' });
      return { ok: true, value: summary(a), ...flag };
    });
    if (!approved.ok) return approved;
    if (!ready) return { ok: true, value: { approval: approved.value }, decisionId: approved.decisionId };
    const execution = await this.execute(tenant, approved.value.requester, approved.value.id);
    const after = execution.ok || execution.code !== 'APPROVAL_REQUIRED' ? await this.store.transaction(tenant, async tx => {
      await tx.load({ approvals: [id] }); const a = tx.state.approvals?.[id]; return a ? summary(a) : approved.value;
    }) : approved.value;
    return { ok: true, value: { approval: after, execution }, decisionId: approved.decisionId };
  }
  /** Rejects (any security-admin) or withdraws (the requester) a pending approval (R154). */
  reject(tenant: string, adminId: string, id: string): Promise<ControlResult<ApprovalSummary>> {
    return this.run(tenant, adminId, 'security-admin', 'approval_reject', { approvals: validId(id) ? [id] : [] }, s => {
      const a = this.pending(s, tenant, id);
      if (!a) return refuse('CONFLICT');
      a.status = 'rejected';
      this.emit({ type: 'approval', tenant, class: a.class, outcome: 'rejected' });
      return { ok: true, value: summary(a), ...(a.class === 'break_glass' ? { breakGlass: true as const } : {}) };
    });
  }
  /**
   * Executes an approval whose quorum is met (the requester only, R155): the
   * route to use when an external workflow completed after the last approval. The
   * operation re-validates its arguments against the current state.
   */
  async executeApproval(tenant: string, adminId: string, id: string): Promise<ControlResult<unknown>> {
    const read = await this.run(tenant, adminId, ['security-admin', 'kb-admin'], 'approval_execute', { approvals: validId(id) ? [id] : [] }, s => {
      const a = this.pending(s, tenant, id);
      return a && a.requester === adminId ? { ok: true, value: true } : refuse('CONFLICT');
    });
    return read.ok ? this.execute(tenant, adminId, id) : read;
  }
  /** Runs the approved operation as `requester` with the approval id; every check of the operation applies again. */
  private async execute(tenant: string, requester: string, id: string): Promise<ControlResult<unknown>> {
    const a = await this.store.transaction(tenant, async tx => { await tx.load({ approvals: [id] }); const r = tx.state.approvals?.[id]; return r ? structuredClone(r) : undefined; });
    const args = a && Array.isArray(a.payload) ? a.payload as unknown[] : [];
    const approval = { approval: id };
    switch (a?.operation) {
      case 'upsert_actor': return this.upsertActor(tenant, requester, args[0] as Actor, approval);
      case 'assign_roles': return this.assignRoles(tenant, requester, args[0] as string, args[1] as string[], approval);
      case 'upsert_group': return this.upsertGroup(tenant, requester, args[0] as Group, approval);
      case 'upsert_knowledge': return this.upsertKnowledge(tenant, requester, args[0] as Knowledge, { ...(args[1] !== undefined ? { quarantine: args[1] as QuarantineReason } : {}), ...approval });
      case 'upsert_role': return this.upsertRole(tenant, requester, args[0] as Role, approval);
      case 'upsert_constraint': return this.upsertConstraint(tenant, requester, args[0] as SodConstraint, approval);
      case 'upsert_destination': return this.upsertDestination(tenant, requester, args[0] as Destination, approval);
      case 'upsert_runtime_profile': return this.upsertRuntimeProfile(tenant, requester, args[0] as RuntimeProfilePolicy, approval);
      case 'issue_break_glass': return this.issueBreakGlass(tenant, requester, args[0] as BreakGlassRequest, approval);
      case 'put_settings': return this.putSettings(tenant, requester, args[0] as TenantSettings, approval);
      case 'upsert_combination_rule': return this.upsertCombinationRule(tenant, requester, args[0] as CombinationRule, approval);
      default: return this.attempt(tenant, requester, 'security-admin', 'approval_execute', { allowed: false, reason: 'DENIED:CONFLICT' }).then(r => r.ok ? { ok: false, code: 'CONFLICT', decisionId: r.decisionId } : r);
    }
  }
  /** One approval with its arguments (security-admin: approvers must see what they approve). Another tenant's id reads as absent. */
  readApproval(tenant: string, adminId: string, id: string): Promise<ControlResult<Approval | null>> {
    return this.run(tenant, adminId, 'security-admin', 'approval_read', { approvals: validId(id) ? [id] : [] }, s => {
      const a = validId(id) && s.approvals && Object.hasOwn(s.approvals, id) ? s.approvals[id] : undefined;
      return { ok: true, value: a && a.tenant === tenant ? structuredClone(a) : null };
    });
  }
  /** Pending, unexpired approvals of the tenant, oldest first, without arguments (security-admin; at most APPROVAL.list). */
  listApprovals(tenant: string, adminId: string): Promise<ControlResult<ApprovalSummary[]>> {
    return this.run(tenant, adminId, 'security-admin', 'approval_list', { pendingApprovals: this.clock() }, s => {
      const now = this.clock();
      const list = Object.values(s.approvals ?? {}).filter(a => a.tenant === tenant && a.status === 'pending' && now < a.expiresAt)
        .sort((x, y) => x.createdAt - y.createdAt || x.id.localeCompare(y.id)).slice(0, APPROVAL.list).map(summary);
      return { ok: true, value: list };
    });
  }
  /** Marks the target inactive and advances only this tenant's epoch, invalidating only its contexts. */
  revoke(tenant: string, adminId: string, type: 'grant' | 'knowledge' | 'actor', id: string) {
    const seed: Seed = !validId(id) ? {} : type === 'grant' ? { grants: [id] } : type === 'knowledge' ? { knowledge: [id] } : { actors: [id] };
    return this.run(tenant, adminId, 'security-admin', 'revoke', seed, s => {
      const collection: Record<string, { tenant: string; active: boolean }> = type === 'grant' ? s.grants : type === 'knowledge' ? s.knowledge : type === 'actor' ? s.actors : {};
      const target = validId(id) && Object.hasOwn(collection, id) ? collection[id] : undefined;
      if (!target || target.tenant !== tenant) return refuse('INVALID_REQUEST');
      target.active = false; this.bump(s, tenant);
      // Durable marker: a later document version cannot reactivate the record (only reinstate()).
      if (type === 'knowledge') { const k = target as Knowledge; k.revokedAt ??= this.clock(); }
      return { ok: true, value: { epoch: s.epochs[tenant]! } };
    });
  }
  /**
   * Retires a document (kb-admin): marks it inactive and advances this tenant's
   * epoch, so running contexts that read it must re-establish authority. Memory and
   * artifacts are not documents; revoke them with revoke() (security-admin).
   */
  removeKnowledge(tenant: string, adminId: string, id: string) {
    return this.run(tenant, adminId, 'kb-admin', 'remove_knowledge', { knowledge: validId(id) ? [id] : [] }, s => {
      const k = validId(id) && Object.hasOwn(s.knowledge, id) ? s.knowledge[id] : undefined;
      if (!k || k.tenant !== tenant || k.kind !== 'document') return refuse('INVALID_REQUEST');
      k.active = false; this.bump(s, tenant);
      return { ok: true, value: { id, epoch: s.epochs[tenant]! } };
    });
  }
  /** The target of a lifecycle operation: an existing record of this tenant (another tenant's id reads as absent). */
  private target(s: State, tenant: string, id: string): Knowledge | undefined {
    const k = validId(id) && Object.hasOwn(s.knowledge, id) ? s.knowledge[id] : undefined;
    return k && k.tenant === tenant ? k : undefined;
  }
  /** Target plus its complete lineage (bounded); a lineage beyond LIFECYCLE.cascade is a deferred denial that changes nothing. */
  private async cascade(s: State, tx: Tx, tenant: string, root: Knowledge): Promise<Knowledge[]> {
    const found = await lineage(tx, tenant, [root.id], LIFECYCLE.cascade - 1);
    if (found.truncated) throw new BudgetExceeded('lineage');
    await materialize(tx, found.records.map(k => k.id));
    const out = [root];
    for (const meta of found.records) {
      const k = this.target(s, tenant, meta.id);
      if (!k) throw new BudgetExceeded('lineage load');
      out.push(k);
    }
    return out;
  }
  /**
   * Quarantine (kb-admin or security-admin): the record and every record whose
   * provenance includes it become invisible to every gate (read, derive,
   * write_memory, share, export, retrieval) until release(). Lazy and unbounded:
   * descendants are denied by traversal, none is rewritten. Advances the tenant
   * epoch, so open contexts end. Idempotent; an erased record is a CONFLICT.
   */
  quarantine(tenant: string, adminId: string, id: string, reason: QuarantineReason) {
    return this.run(tenant, adminId, ['kb-admin', 'security-admin'], 'quarantine', { knowledge: validId(id) ? [id] : [] }, s => {
      const k = this.target(s, tenant, id);
      if (!k || !QUARANTINE_REASONS.includes(reason)) return refuse('INVALID_REQUEST');
      if (k.lifecycle === 'erased') return refuse('CONFLICT');
      if (k.lifecycle !== 'quarantined') { Object.assign(k, { lifecycle: 'quarantined', lifecycleAt: this.clock(), quarantineReason: reason }); this.bump(s, tenant); }
      return { ok: true, value: { id, epoch: s.epochs[tenant] ?? 0 } };
    });
  }
  /**
   * Release (security-admin only: separation of duty from the kb-admin who may
   * quarantine). Restores visibility; descendants become visible again unless
   * something else denies them. Advances the tenant epoch. Idempotent.
   */
  release(tenant: string, adminId: string, id: string) {
    return this.run(tenant, adminId, 'security-admin', 'release', { knowledge: validId(id) ? [id] : [] }, s => {
      const k = this.target(s, tenant, id);
      if (!k) return refuse('INVALID_REQUEST');
      if (k.lifecycle === 'erased') return refuse('CONFLICT');
      if (k.lifecycle === 'quarantined') {
        delete k.lifecycle; delete k.quarantineReason; k.lifecycleAt = this.clock(); this.bump(s, tenant);
      }
      return { ok: true, value: { id, epoch: s.epochs[tenant] ?? 0 } };
    });
  }
  /**
   * Blast radius (auditor or security-admin): metadata of every record whose
   * provenance includes `id` (any version, transitively), at most `limit`
   * (1..1000, default 100), sorted by id, with `truncated` when more exist.
   */
  descendants(tenant: string, adminId: string, id: string, options: { limit?: number } = {}): Promise<ControlResult<{ records: LineageRecord[]; truncated: boolean }>> {
    const limit = options.limit ?? 100;
    return this.run(tenant, adminId, ['auditor', 'security-admin'], 'lineage_read', { knowledge: validId(id) ? [id] : [] }, async (s, tx) => {
      if (!this.target(s, tenant, id) || !Number.isSafeInteger(limit) || limit < 1 || limit > LIFECYCLE.list) return refuse('INVALID_REQUEST');
      const found = await lineage(tx, tenant, [id], limit);
      return { ok: true, value: { records: found.records.map(lineageRecord), truncated: found.truncated } };
    });
  }
  /**
   * Revokes a record and explicitly deactivates its whole lineage (security-admin),
   * in addition to the lazy transitive denial. Bounded by LIFECYCLE.cascade
   * (beyond it: deferred denial, nothing changed). Idempotent; returns how many
   * records it deactivated now.
   */
  revokeLineage(tenant: string, adminId: string, id: string) {
    return this.run(tenant, adminId, 'security-admin', 'revoke_lineage', { knowledge: validId(id) ? [id] : [] }, async (s, tx) => {
      const k = this.target(s, tenant, id);
      if (!k) return refuse('INVALID_REQUEST');
      let revoked = 0;
      const at = this.clock();
      for (const r of await this.cascade(s, tx, tenant, k)) {
        if (r.active !== false) { r.active = false; revoked++; }
        r.revokedAt ??= at;
      }
      this.bump(s, tenant);
      return { ok: true, value: { id, revoked, epoch: s.epochs[tenant]! } };
    });
  }
  /**
   * Reinstates a record revoked by revoke() or revokeLineage() (security-admin
   * only: a kb-admin cannot undo a security revocation). Clears `revokedAt` and
   * reactivates this record only, not its lineage. Advances the tenant epoch.
   * Idempotent; a record without the marker is unchanged; an erased one is a CONFLICT.
   */
  reinstate(tenant: string, adminId: string, id: string) {
    return this.run(tenant, adminId, 'security-admin', 'reinstate', { knowledge: validId(id) ? [id] : [] }, s => {
      const k = this.target(s, tenant, id);
      if (!k) return refuse('INVALID_REQUEST');
      if (k.lifecycle === 'erased') return refuse('CONFLICT');
      if (k.revokedAt !== undefined) { delete k.revokedAt; k.active = true; this.bump(s, tenant); }
      return { ok: true, value: { id, epoch: s.epochs[tenant] ?? 0 } };
    });
  }
  /** Places (hold) or lifts (!hold) one legal hold on a record (security-admin). Holds block erasure and retention. Idempotent. */
  setLegalHold(tenant: string, adminId: string, id: string, hold: boolean, holdId: string) {
    return this.run(tenant, adminId, 'security-admin', hold === true ? 'legal_hold_set' : 'legal_hold_lift', { knowledge: validId(id) ? [id] : [] }, s => {
      const k = this.target(s, tenant, id);
      if (!k || typeof hold !== 'boolean' || !validId(holdId) || (k.legalHolds !== undefined && !ids(k.legalHolds, 64))) return refuse('INVALID_REQUEST');
      if (k.lifecycle === 'erased') return refuse('CONFLICT');
      const holds = new Set(k.legalHolds ?? []);
      if (hold) { if (!holds.has(holdId) && holds.size >= 64) return refuse('CONFLICT'); holds.add(holdId); } else holds.delete(holdId);
      if (holds.size) k.legalHolds = [...holds].sort(); else delete k.legalHolds;
      return { ok: true, value: { id, holds: holds.size } };
    });
  }
  /**
   * Erasure (security-admin; supports GDPR Art. 17). Tombstones the record and,
   * with `cascade` (default), every record whose provenance includes it, since
   * derived content may contain the erased data. Without `cascade`, a live
   * descendant is a CONFLICT. A legal hold on the record or any descendant is a
   * CONFLICT carrying only the number of held records; nothing is erased. Audit
   * entries are kept (content-free). Advances the tenant epoch. Idempotent.
   */
  erase(tenant: string, adminId: string, id: string, options: { cascade?: boolean } = {}) {
    return this.eraseAs(tenant, adminId, id, options.cascade ?? true, 'erase');
  }
  private eraseAs(tenant: string, adminId: string, id: string, cascade: boolean, operation: 'erase' | 'retention_erase' | 'pending_erase', due?: number) {
    return this.run(tenant, adminId, 'security-admin', operation, { knowledge: validId(id) ? [id] : [] }, async (s, tx) => {
      const k = this.target(s, tenant, id);
      if (!k || typeof cascade !== 'boolean') return refuse('INVALID_REQUEST');
      // A retention run re-checks the deadline inside the transaction (it may have changed since listing).
      if (due !== undefined && !(k.lifecycle !== 'erased' && safeNumber(k.retainUntil) && k.retainUntil <= due)) return { ok: true, value: { id, erased: 0, epoch: s.epochs[tenant] ?? 0 } };
      // A pending erasure re-checks that it is still requested (R194).
      if (operation === 'pending_erase' && (k.lifecycle === 'erased' || k.erasureRequestedAt === undefined)) return { ok: true, value: { id, erased: 0, epoch: s.epochs[tenant] ?? 0 } };
      const records = await this.cascade(s, tx, tenant, k);
      const live = records.filter(r => r.lifecycle !== 'erased');
      const holds = live.filter(held).length;
      // R194: an erasure (with cascade) blocked by a legal hold is stored as pending and runs once no hold blocks it.
      if (holds && operation === 'erase' && cascade && k.lifecycle !== 'erased') { k.erasureRequestedAt ??= this.clock(); return { ok: false, code: 'CONFLICT', held: holds, pending: true }; }
      if (holds) return { ok: false, code: 'CONFLICT', held: holds };
      if (!cascade && live.some(r => r !== k)) return refuse('CONFLICT');
      const now = this.clock();
      let erased = 0;
      for (const r of records) if (tombstone(r, now)) erased++;
      if (erased) this.bump(s, tenant);
      return { ok: true, value: { id, erased, epoch: s.epochs[tenant] ?? 0 } };
    });
  }
  /**
   * Retention job (security-admin): erases, with cascade, records whose
   * `retainUntil` is at or before `now` and that are not under legal hold, at most
   * `limit` (1..100) per call, ordered by id after `after`. Resumable: call again
   * with `after: next` until `next` is absent. Each erasure is its own audited
   * decision (retention_erase); a record whose lineage is held is skipped (`held`).
   */
  async applyRetention(tenant: string, adminId: string, now = this.clock(), options: { after?: string; limit?: number } = {}):
    Promise<ControlResult<{ erased: number; held: number; deferred: number; next?: string }>> {
    const after = options.after ?? '', limit = options.limit ?? LIFECYCLE.retentionBatch;
    const listed = await this.run(tenant, adminId, 'security-admin', 'apply_retention', {}, async (_s, tx) => {
      if (!safeNumber(now) || (after !== '' && !validId(after)) || !Number.isSafeInteger(limit) || limit < 1 || limit > LIFECYCLE.retentionBatch) return refuse('INVALID_REQUEST');
      return { ok: true, value: await retentionDue(tx, tenant, now, after, limit + 1) };
    });
    if (!listed.ok) return listed;
    const due = listed.value.slice(0, limit);
    let erased = 0, holds = 0, deferred = 0;
    for (const id of due) {
      try {
        const r = await this.eraseAs(tenant, adminId, id, true, 'retention_erase', now);
        if (r.ok) erased += r.value.erased; else if (r.code === 'CONFLICT') holds++; else deferred++;
      } catch { deferred++; }
    }
    return { ok: true, value: { erased, held: holds, deferred, ...(listed.value.length > limit ? { next: due.at(-1)! } : {}) }, decisionId: listed.decisionId };
  }
  /**
   * Pending erasures (security-admin, 0.6, R194): runs, with cascade, every erasure
   * that was requested while a legal hold blocked it and that no hold blocks any more, at
   * most `limit` (1..100) per call, ordered by id after `after`. Resumable like
   * applyRetention(); each erasure is its own audited decision (`pending_erase`); a record
   * whose lineage is still held stays pending (`held`).
   */
  async applyPendingErasures(tenant: string, adminId: string, options: { after?: string; limit?: number } = {}):
    Promise<ControlResult<{ erased: number; held: number; deferred: number; next?: string }>> {
    const after = options.after ?? '', limit = options.limit ?? LIFECYCLE.retentionBatch;
    const listed = await this.run(tenant, adminId, 'security-admin', 'apply_pending_erasures', {}, async (_s, tx) => {
      if ((after !== '' && !validId(after)) || !Number.isSafeInteger(limit) || limit < 1 || limit > LIFECYCLE.retentionBatch) return refuse('INVALID_REQUEST');
      if (!tx.complete) {
        if (!tx.pendingErasures) throw new Error('Store cannot list pending erasures');
        return { ok: true, value: (await tx.pendingErasures(after, limit + 1)).filter(validId).slice(0, limit + 1) };
      }
      return { ok: true, value: Object.values(tx.state.knowledge).filter(k => k.tenant === tenant && k.id > after && k.lifecycle !== 'erased' && k.erasureRequestedAt !== undefined)
        .map(k => k.id).sort().slice(0, limit + 1) };
    });
    if (!listed.ok) return listed;
    const due = listed.value.slice(0, limit);
    let erased = 0, holds = 0, deferred = 0;
    for (const id of due) {
      try {
        const r = await this.eraseAs(tenant, adminId, id, true, 'pending_erase');
        if (r.ok) erased += r.value.erased; else if (r.code === 'CONFLICT') holds++; else deferred++;
      } catch { deferred++; }
    }
    return { ok: true, value: { erased, held: holds, deferred, ...(listed.value.length > limit ? { next: due.at(-1)! } : {}) }, decisionId: listed.decisionId };
  }
  /**
   * Combination rule (security-admin, 0.6, R188). Tightening applies at once; a
   * relaxation of an existing rule (deactivation, a tag removed, deny to uplift, a lower
   * uplift) passes the approval gate (class settings). At most KNOWLEDGE.combinationRules
   * per tenant. Every accepted change advances the tenant epoch.
   */
  upsertCombinationRule(tenant: string, adminId: string, rule: CombinationRule, options: { approval?: string } = {}) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_combination_rule', {}, async (s, tx) => {
      if (!shapes.combinationRule(rule) || rule.tenant !== tenant) return refuse('INVALID_REQUEST');
      const records = s.combinationRules ??= {};
      const existing = Object.hasOwn(records, rule.id) ? records[rule.id] : undefined;
      if (existing && existing.tenant !== tenant) return refuse('CONFLICT');
      if (!existing && Object.values(records).filter(r => r?.tenant === tenant).length >= KNOWLEDGE.combinationRules) return refuse('CONFLICT');
      if ((existing && relaxesRule(existing, rule)) || options.approval !== undefined) {
        const gate = await this.gated(s, tx, tenant, adminId, 'settings', 'upsert_combination_rule', [rule], options.approval);
        if (!gate.ok) return gate;
        gate.done();
      }
      records[rule.id] = structuredClone(rule);
      this.bump(s, tenant);
      return { ok: true, value: { id: rule.id, epoch: s.epochs[tenant]! } };
    });
  }
  readCombinationRule(tenant: string, adminId: string, id: string): Promise<ControlResult<CombinationRule | null>> {
    return this.run(tenant, adminId, ['security-admin', 'auditor'], 'read_combination_rule', {}, s => {
      const r = validId(id) && s.combinationRules && Object.hasOwn(s.combinationRules, id) ? s.combinationRules[id] : undefined;
      return { ok: true, value: r && r.tenant === tenant ? structuredClone(r) : null };
    });
  }
  /**
   * One sweep batch over the lineage of `id` (kb-admin or security-admin, 0.6, R193;
   * reference/sweeper.ts drives it). When the record is revoked, inactive, erased or
   * quarantined, up to `limit` (1..100) descendants after `after` (by id) that are not yet
   * in a lifecycle state are quarantined (`poisoned` below a record quarantined as
   * poisoned, else `ancestor_revoked`). When the record is live (for example relabelled
   * upward by a new version or a container change), descendants whose provenance no
   * longer resolves (a superseded version) are quarantined (`ancestor_revoked`) and
   * descendants whose stored classification is below their transitive classification
   * are raised to it. Lazy denial stays authoritative; the sweep only
   * makes it explicit. Advances the tenant epoch when anything changed. The listing is
   * bounded by LIFECYCLE.rows descendants (`truncated` beyond).
   */
  sweepLineage(tenant: string, adminId: string, id: string, options: { after?: string; limit?: number } = {}) {
    const after = options.after ?? '', limit = options.limit ?? LIFECYCLE.retentionBatch;
    return this.run(tenant, adminId, ['kb-admin', 'security-admin'], 'sweep_lineage', { knowledge: validId(id) ? [id] : [] }, async (s, tx) => {
      const root = this.target(s, tenant, id);
      if (!root || (after !== '' && !validId(after)) || !Number.isSafeInteger(limit) || limit < 1 || limit > LIFECYCLE.retentionBatch) return refuse('INVALID_REQUEST');
      const dead = root.lifecycle !== undefined || root.revokedAt !== undefined || root.active !== true;
      const reason: QuarantineReason = root.lifecycle === 'quarantined' && (root.quarantineReason === 'poisoned' || root.quarantineReason === 'suspected_poisoning') ? 'poisoned' : 'ancestor_revoked';
      const found = await lineage(tx, tenant, [root.id], LIFECYCLE.rows);
      const pending = found.records.filter(k => k.id > after);
      const batch = pending.slice(0, limit);
      await materialize(tx, batch.map(k => k.id));
      const changed: { id: string; kind: Knowledge['kind'] }[] = [];
      const now = this.clock();
      for (const meta of batch) {
        const k = this.target(s, tenant, meta.id);
        if (!k) throw new BudgetExceeded('lineage load');
        if (dead) {
          if (k.lifecycle !== undefined) continue;
          Object.assign(k, { lifecycle: 'quarantined', lifecycleAt: now, quarantineReason: reason });
          changed.push({ id: k.id, kind: k.kind });
        } else {
          // A descendant whose provenance no longer resolves (for example it cites a superseded version) is already denied lazily: mark it.
          const top = transitiveClassification(s, k);
          if (!top) { if (k.lifecycle === undefined) { Object.assign(k, { lifecycle: 'quarantined', lifecycleAt: now, quarantineReason: 'ancestor_revoked' }); changed.push({ id: k.id, kind: k.kind }); } }
          else if (rank(top) > rank(k.classification)) { k.classification = top; changed.push({ id: k.id, kind: k.kind }); }
        }
      }
      if (changed.length) this.bump(s, tenant);
      return { ok: true, value: { id, mode: dead ? 'quarantine' as const : 'relabel' as const, changed, truncated: found.truncated,
        ...(pending.length > limit ? { next: batch.at(-1)!.id } : {}), epoch: s.epochs[tenant] ?? 0 } };
    });
  }
  /**
   * Model recall (security-admin, 0.6, R191): quarantines (`model_recall`) up to
   * `limit` (1..100) records produced by model `model` with a version in `range`
   * (inclusive bounds, numeric-aware order), ordered by id after `after`. Returns the ids
   * it quarantined so that their descendants can be swept (reference/sweeper.ts).
   */
  quarantineByModel(tenant: string, adminId: string, model: string, range: VersionRange, options: { after?: string; limit?: number } = {}) {
    const after = options.after ?? '', limit = options.limit ?? LIFECYCLE.retentionBatch;
    return this.run(tenant, adminId, 'security-admin', 'quarantine_by_model', {}, async (s, tx) => {
      if (!validId(model) || !validRange(range) || (after !== '' && !validId(after)) || !Number.isSafeInteger(limit) || limit < 1 || limit > LIFECYCLE.retentionBatch) return refuse('INVALID_REQUEST');
      let listed: KnowledgeMeta[];
      if (tx.complete) listed = Object.values(s.knowledge).filter(k => k.tenant === tenant && k.model?.id === model && k.id > after).sort((a, b) => a.id < b.id ? -1 : 1).slice(0, limit + 1);
      else if (tx.modelRecords) listed = (await tx.modelRecords(model, after, limit + 1)).filter(k => k.tenant === tenant && k.model?.id === model);
      else throw new Error('Store cannot list model lineage');
      const batch = listed.slice(0, limit);
      await materialize(tx, batch.map(k => k.id));
      const quarantined: string[] = [];
      const now = this.clock();
      for (const meta of batch) {
        const k = this.target(s, tenant, meta.id);
        if (!k) throw new BudgetExceeded('model lineage load');
        if (k.lifecycle !== undefined || typeof k.model?.version !== 'string' || !inRange(k.model.version, range)) continue;
        Object.assign(k, { lifecycle: 'quarantined', lifecycleAt: now, quarantineReason: 'model_recall' });
        quarantined.push(k.id);
      }
      if (quarantined.length) this.bump(s, tenant);
      return { ok: true, value: { quarantined, ...(listed.length > limit ? { next: batch.at(-1)!.id } : {}), epoch: s.epochs[tenant] ?? 0 } };
    });
  }
  /**
   * Audits an administrative attempt that was answered outside the control plane
   * (for example an idempotent replay) after the same standing-role check. `ok`
   * means the caller holds the role now; the outcome is recorded as given.
   */
  attempt(tenant: string, adminId: string, role: AdminRole, operation: string, outcome: { allowed: boolean; reason: string }): Promise<ControlResult<true>> {
    // The recorded reason must be a closed code (reference/decision.ts) consistent with the outcome.
    const code = typeof outcome?.reason === 'string' ? classify(outcome.reason) : null;
    const valid = !!code && typeof outcome.allowed === 'boolean' && !code.category === outcome.allowed;
    return this.run(tenant, adminId, role, operation, {}, () => valid ? { ok: true, value: true, audit: outcome } : refuse('INVALID_REQUEST'));
  }
  /** Administrative reads (SCIM, tooling). Audited; a record of another tenant reads as absent. */
  readActor(tenant: string, adminId: string, id: string): Promise<ControlResult<Actor | null>> {
    return this.run(tenant, adminId, 'security-admin', 'read_actor', { actors: validId(id) ? [id] : [] }, s => {
      const a = validId(id) && Object.hasOwn(s.actors, id) ? s.actors[id] : undefined;
      return { ok: true, value: a && a.tenant === tenant ? structuredClone(a) : null };
    });
  }
  readGroup(tenant: string, adminId: string, id: string): Promise<ControlResult<Group | null>> {
    return this.run(tenant, adminId, 'security-admin', 'read_group', { groups: validId(id) ? [id] : [] }, s => {
      const g = validId(id) && Object.hasOwn(s.groups, id) ? s.groups[id] : undefined;
      return { ok: true, value: g && g.tenant === tenant ? structuredClone(g) : null };
    });
  }
  readDestination(tenant: string, adminId: string, id: string): Promise<ControlResult<Destination | null>> {
    return this.run(tenant, adminId, ['security-admin', 'auditor'], 'read_destination', { destinations: validId(id) ? [id] : [] }, s => {
      const d = validId(id) && s.destinations && Object.hasOwn(s.destinations, id) ? s.destinations[id] : undefined;
      return { ok: true, value: d && d.tenant === tenant ? structuredClone(d) : null };
    });
  }
  readRuntimeProfile(tenant: string, adminId: string, id: string): Promise<ControlResult<RuntimeProfilePolicy | null>> {
    return this.run(tenant, adminId, ['security-admin', 'auditor'], 'read_runtime_profile', { runtimeProfiles: true }, s => {
      const p = validId(id) && s.runtimeProfiles && Object.hasOwn(s.runtimeProfiles, id) ? s.runtimeProfiles[id] : undefined;
      return { ok: true, value: p && p.tenant === tenant ? structuredClone(p) : null };
    });
  }
  /** Audited role check for operations executed outside the control plane (for example index maintenance). */
  authorize(tenant: string, adminId: string, role: AdminRole, operation: string): Promise<ControlResult<true>> {
    return this.run(tenant, adminId, role, operation, {}, () => ({ ok: true, value: true }));
  }
  /** Audit read access is itself audited. */
  async auditLog(tenant: string, adminId: string, after = 0, limit = 1000): Promise<ControlResult<Audit[]>> {
    if (!safeNumber(after) || !Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) return { ok: false, code: 'INVALID_REQUEST', decisionId: newDecisionId() };
    const allowed = await this.run(tenant, adminId, 'auditor', 'audit_read', {}, () => ({ ok: true, value: true }));
    if (!allowed.ok) return allowed;
    return { ok: true, value: await this.store.auditLog(tenant, after, limit), decisionId: allowed.decisionId };
  }
  /** Stream size before this operation's own entry: the audit head of the snapshot (every store loads it). */
  private size(s: State, tenant: string): number {
    let size = 0;
    for (const a of s.audits) if (a.tenant === tenant && a.sequence > size) size = a.sequence;
    return size;
  }
  /**
   * auditor: RFC 9162 inclusion proof of the entry at 0-based `leafIndex` (sequence
   * leafIndex + 1) in the tree of the first `treeSize` entries. Audited as
   * audit_proof; a range outside the stream is refused (INVALID_REQUEST, audited).
   */
  async auditProof(tenant: string, adminId: string, leafIndex: number, treeSize: number): Promise<ControlResult<InclusionProof>> {
    const allowed = await this.run(tenant, adminId, 'auditor', 'audit_proof', {}, s =>
      safeNumber(leafIndex) && safeNumber(treeSize) && leafIndex < treeSize && treeSize <= this.size(s, tenant) ? { ok: true, value: true } : refuse('INVALID_REQUEST'));
    if (!allowed.ok) return allowed;
    return { ok: true, value: await inclusionProof(this.store, tenant, leafIndex, treeSize), decisionId: allowed.decisionId };
  }
  /** auditor: RFC 9162 consistency proof that the tree of `second` entries extends the tree of `first` (1 <= first <= second). */
  async auditConsistency(tenant: string, adminId: string, first: number, second: number): Promise<ControlResult<ConsistencyProof>> {
    const allowed = await this.run(tenant, adminId, 'auditor', 'audit_consistency', {}, s =>
      safeNumber(first) && safeNumber(second) && first >= 1 && first <= second && second <= this.size(s, tenant) ? { ok: true, value: true } : refuse('INVALID_REQUEST'));
    if (!allowed.ok) return allowed;
    return { ok: true, value: await consistencyProof(this.store, tenant, first, second), decisionId: allowed.decisionId };
  }
  /**
   * auditor: the current tree head of the tenant stream (including this read's own
   * audit entry) and, when a checkpoint key is configured, its format 2 signature.
   */
  async latestCheckpoint(tenant: string, adminId: string): Promise<ControlResult<{ head: TreeHead; checkpoint?: AuditCheckpoint }>> {
    const allowed = await this.run(tenant, adminId, 'auditor', 'audit_checkpoint', {}, () => ({ ok: true, value: true }));
    if (!allowed.ok) return allowed;
    const head = await treeHead(this.store, tenant);
    const signer = this.signer;
    const checkpoint = !signer ? undefined : 'privatePem' in signer ? signTreeHead(head, signer.privatePem, signer.keyId, this.clock())
      : await signCheckpointWith(head, signer, this.clock());
    return { ok: true, value: { head, ...(checkpoint ? { checkpoint } : {}) }, decisionId: allowed.decisionId };
  }
}
