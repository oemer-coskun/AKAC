import { appendAudit } from './audit.ts';
import { BudgetExceeded, hydrate } from './hydrate.ts';
import type { Seed } from './hydrate.ts';
import { containerChain, effectiveLabel, effectiveRoles, sessionRoles, sodViolated, standingRoles, transitiveClassification, validGrantChain } from './policy.ts';
import { ACTIONS, CORE_VERSION, DESTINATION_CLASSES, LEVELS, MAX_RESULTS, QUARANTINE_REASONS, RUNTIME_PROFILE_LIMIT } from './types.ts';
import type { Actor, Audit, Container, Destination, Grant, Group, Knowledge, QuarantineReason, Role, RuntimeProfilePolicy, SodConstraint, State, Store, Tx } from './types.ts';
import { validRuntimeProfile } from './containment.ts';
import { held, LIFECYCLE, lineage, lineageRecord, materialize, retentionDue, tombstone } from './lifecycle.ts';
import type { LineageRecord } from './lifecycle.ts';
import { exactKeys, safeNumber, validId } from './validation.ts';
import { classify, executionOf, newDecisionId, policyDigest, traceOf } from './decision.ts';
import type { Call } from './decision.ts';
import { consistencyProof, inclusionProof, treeHead } from './evidence.ts';
import type { ConsistencyProof, InclusionProof, TreeHead } from './evidence.ts';
import { signTreeHead } from './checkpoint.ts';
import type { CheckpointV2 } from './checkpoint.ts';

/** Every result carries the id of the audited decision (0.4). */
export type ControlResult<T> = { ok: true; value: T; decisionId: string }
  | { ok: false; code: 'NOT_AUTHORIZED' | 'INVALID_REQUEST' | 'CONFLICT' | 'SOD_VIOLATION';
    /** SOD_VIOLATION from a role or constraint change: how many currently valid principals it would invalidate (never which). */
    holders?: number;
    /** CONFLICT from erase() or upsertKnowledge(): how many records are under legal hold (never which). */
    held?: number; decisionId: string };
/** security-admin: identities, roles, groups, constraints, grants, revocation. kb-admin: containers, documents. auditor: audit. */
export type AdminRole = 'security-admin' | 'kb-admin' | 'auditor';
type Failure = Exclude<ControlResult<never>, { ok: true }>['code'];
/** `audit` overrides the recorded decision and reason (attempts handled outside the control plane). */
type Refusal = { ok: false; code: Failure; holders?: number; held?: number };
/** One audited control-plane decision and its correlation fields (never authority). */
type Op = { id: string; trace?: string; execution?: string };
type Checked<T> = { ok: true; value: T; audit?: { allowed: boolean; reason: string } } | Refusal;
const refuse = (code: Failure): Refusal => ({ ok: false, code });
const within = (small: readonly string[], large: readonly string[]) => small.every(x => large.includes(x));
const rank = (l: string) => LEVELS.indexOf(l as never);
/** Deactivation, or no new role, project, clearance or reactivation: can only remove authority. */
const reducesActor = (old: Actor, next: Actor) => next.active === false
  || ((old.active === true || next.active !== true) && within(next.roles, old.roles) && within(next.projects, old.projects) && rank(next.clearance) <= rank(old.clearance)
    && next.destination === old.destination);

const ids = (x: unknown, max = 256): x is string[] => Array.isArray(x) && x.length <= max && x.every(validId) && new Set(x).size === x.length;
const level = (x: unknown) => LEVELS.includes(x as never);
const bool = (x: unknown) => typeof x === 'boolean';
const optional = (x: unknown, check: (y: unknown) => boolean) => x === undefined || check(x);
const destinationId = (x: unknown) => validId(x) && !DESTINATION_CLASSES.includes(x as never);
const sameRefs = (a: Knowledge['sources'], b: Knowledge['sources']) => a.length === b.length && a.every((r, i) => r.id === b[i]?.id && r.version === b[i]?.version);
const refs = (x: unknown) => Array.isArray(x) && x.length <= 256 && x.every(r => exactKeys(r, ['id', 'version']) && validId(r.id) && safeNumber(r.version) && r.version >= 1);

export const shapes = {
  actor: (a: unknown): a is Actor => exactKeys(a, ['id', 'tenant', 'kind', 'roles', 'projects', 'clearance', 'active'], ['destination'])
    && validId(a.id) && validId(a.tenant) && ['user', 'agent', 'service'].includes(a.kind as string)
    && ids(a.roles, 64) && ids(a.projects) && level(a.clearance) && bool(a.active) && optional(a.destination, destinationId),
  /** A destination id is never a class name, so a grant entry is unambiguous (ADR-008). */
  destination: (d: unknown): d is Destination => exactKeys(d, ['id', 'tenant', 'class', 'maxClassification', 'purposes', 'active'])
    && destinationId(d.id) && validId(d.tenant) && DESTINATION_CLASSES.includes(d.class as never) && level(d.maxClassification)
    && Array.isArray(d.purposes) && d.purposes.length <= 64 && d.purposes.every(p => typeof p === 'string' && p.length > 0 && p.length <= 128)
    && new Set(d.purposes).size === d.purposes.length && bool(d.active),
  /** Runtime profile policy (0.5, ADR-012): profile ids only, never runtime policy text. */
  runtimeProfile: (p: unknown): p is RuntimeProfilePolicy => validRuntimeProfile(p),
  role: (r: unknown): r is Role => exactKeys(r, ['id', 'tenant', 'inherits', 'active'])
    && validId(r.id) && validId(r.tenant) && ids(r.inherits, 64) && !(r.inherits as string[]).includes(r.id) && bool(r.active),
  group: (g: unknown): g is Group => exactKeys(g, ['id', 'tenant', 'members', 'roles', 'active'])
    && validId(g.id) && validId(g.tenant) && ids(g.members, 1024) && ids(g.roles, 64) && bool(g.active),
  constraint: (c: unknown): c is SodConstraint => exactKeys(c, ['id', 'tenant', 'kind', 'roles', 'cardinality'])
    && validId(c.id) && validId(c.tenant) && ['static', 'dynamic'].includes(c.kind as string) && ids(c.roles, 64)
    && Number.isSafeInteger(c.cardinality) && (c.cardinality as number) >= 2 && (c.cardinality as number) <= (c.roles as string[]).length,
  container: (c: unknown): c is Container => exactKeys(c, ['id', 'tenant', 'kind', 'classification', 'readerRoles', 'readers', 'projects', 'active'], ['parent'])
    && validId(c.id) && validId(c.tenant) && level(c.classification) && ids(c.readerRoles) && ids(c.readers) && ids(c.projects) && bool(c.active)
    && (c.kind === 'knowledge-base' ? c.parent === undefined : c.kind === 'folder' && validId(c.parent) && c.parent !== c.id),
  /** Administrative ingestion accepts human or system documents only; model output enters via derive(). */
  document: (k: unknown): k is Knowledge => exactKeys(k, ['id', 'tenant', 'version', 'kind', 'origin', 'content', 'classification', 'projects', 'readerRoles', 'readers', 'sources', 'active'], ['accessExpiresAt', 'container', 'retainUntil'])
    && validId(k.id) && validId(k.tenant) && safeNumber(k.version) && (k.version as number) >= 1 && k.kind === 'document'
    && ['human', 'system'].includes(k.origin as string) && typeof k.content === 'string' && k.content.length > 0 && k.content.length <= 1_000_000
    && level(k.classification) && ids(k.projects) && ids(k.readerRoles) && ids(k.readers) && refs(k.sources) && bool(k.active)
    && optional(k.accessExpiresAt, safeNumber) && optional(k.container, validId) && optional(k.retainUntil, safeNumber),
  grant: (g: unknown): g is Grant => exactKeys(g, ['id', 'tenant', 'subject', 'agent', 'actions', 'resources', 'purposes', 'notBefore', 'expiresAt', 'active'], ['parent', 'activeRoles', 'destinations', 'maxResults'])
    && [g.id, g.tenant, g.subject, g.agent].every(validId) && Array.isArray(g.actions) && g.actions.length > 0
    && g.actions.every(a => ACTIONS.includes(a)) && new Set(g.actions).size === g.actions.length
    && Array.isArray(g.resources) && g.resources.length <= 256 && g.resources.every(r => r === '*' || validId(r))
    && Array.isArray(g.purposes) && g.purposes.length <= 64 && g.purposes.every(p => typeof p === 'string' && p.length > 0 && p.length <= 128)
    && safeNumber(g.notBefore) && safeNumber(g.expiresAt) && (g.notBefore as number) < (g.expiresAt as number)
    && bool(g.active) && optional(g.parent, validId) && optional(g.activeRoles, x => ids(x, 64))
    && optional(g.destinations, x => ids(x, 64) && (x as string[]).length > 0)
    && optional(g.maxResults, x => Number.isSafeInteger(x) && (x as number) >= 1 && (x as number) <= MAX_RESULTS)
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
   * with an offline key (scripts/checkpoint.ts) for independent evidence.
   */
  checkpoint?: { privatePem: string; keyId: string };
};
export class ControlPlane {
  private store: Store;
  private clock: () => number;
  private signer?: { privatePem: string; keyId: string };
  private trace?: string;
  private execution?: string;
  constructor(store: Store, options: ControlOptions = {}) {
    this.store = store; this.clock = options.clock ?? Date.now; this.signer = options.checkpoint;
  }
  /**
   * The same control plane, recording this W3C trace id and execution id (when
   * valid) with every decision. A runtime revision is never taken from here:
   * administrative calls do not act through a runtime enforcer.
   */
  traced(trace?: Call['trace']): ControlPlane {
    const next = new ControlPlane(this.store, { clock: this.clock, ...(this.signer ? { checkpoint: this.signer } : {}) });
    next.trace = traceOf(trace ? { trace } : {}) ?? this.trace;
    next.execution = executionOf(trace ? { trace } : {}) ?? this.execution;
    return next;
  }
  private record(s: State, tenant: string, adminId: string, o: Op, operation: string, allowed: boolean, reason: string) {
    const code = classify(reason);
    if (!code || !code.category !== allowed) throw new Error('Unclassified decision reason');
    appendAudit(s, { time: this.clock(), tenant, actor: validId(adminId) ? adminId : 'invalid', operation,
      decision: allowed ? 'allow' : 'deny', reason, policyVersion: `${CORE_VERSION}|${s.policyVersion}|control-plane`, epoch: s.epochs[tenant] ?? 0,
      decisionId: o.id, reasonCode: code.code, policyDigest: policyDigest([CORE_VERSION, s.policyVersion, 'control-plane']), obligations: [],
      ...(o.trace ? { traceId: o.trace } : {}), ...(o.execution ? { executionId: o.execution } : {}) });
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
        const roles = admin?.kind === 'user' && admin.active && admin.tenant === tenant ? standingRoles(s, admin) : null;
        if (!(typeof role === 'string' ? [role] : role).some(r => roles?.has(r))) { this.record(s, tenant, adminId, o, operation, false, 'DENIED:NOT_ADMIN'); return { ok: false, code: 'NOT_AUTHORIZED', decisionId: o.id }; }
        const result = await body(s, tx);
        if (result.ok) {
          this.record(s, tenant, adminId, o, operation, result.audit?.allowed ?? true, result.audit?.reason ?? 'AUTHORIZED');
          return { ok: true, value: result.value, decisionId: o.id };
        }
        this.record(s, tenant, adminId, o, operation, false, `DENIED:${result.code}`);
        return { ...result, decisionId: o.id };
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

  upsertActor(tenant: string, adminId: string, actor: Actor) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_actor', { actors: validId(actor?.id) ? [actor.id] : [] }, s => {
      if (!shapes.actor(actor) || actor.tenant !== tenant) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.actors, actor.id) ? s.actors[actor.id] : undefined;
      if (existing && (existing.tenant !== tenant || existing.kind !== actor.kind)) return refuse('CONFLICT');
      s.actors[actor.id] = structuredClone(actor);
      // Deactivation and other pure reductions always succeed, even for a principal
      // that already violates a constraint (for example SCIM deprovisioning).
      const problem = existing && reducesActor(existing, actor) ? null : this.standing(s, [s.actors[actor.id]]);
      if (problem) { if (existing) s.actors[actor.id] = existing; else delete s.actors[actor.id]; return refuse(problem); }
      if (existing) this.bump(s, tenant);
      return { ok: true, value: { id: actor.id } };
    });
  }
  /** Role assignment is where static SoD is enforced administratively; decisions enforce it again. */
  assignRoles(tenant: string, adminId: string, actorId: string, roles: string[]) {
    return this.run(tenant, adminId, 'security-admin', 'assign_roles', { actors: validId(actorId) ? [actorId] : [], roles: ids(roles, 64) ? roles : [] }, s => {
      const actor = validId(actorId) && Object.hasOwn(s.actors, actorId) ? s.actors[actorId] : undefined;
      if (!actor || actor.tenant !== tenant || !ids(roles, 64)) return refuse('INVALID_REQUEST');
      const previous = actor.roles; actor.roles = [...roles];
      const problem = within(roles, previous) ? null : this.standing(s, [actor]);
      if (problem) { actor.roles = previous; return refuse(problem); }
      this.bump(s, tenant); return { ok: true, value: { id: actor.id, roles: [...roles] } };
    });
  }
  /**
   * A change that can widen a role's closure (new role, new juniors, reactivation)
   * is rejected with SOD_VIOLATION if it would put any currently valid active
   * principal of the tenant into a static violation (the response carries only the
   * count). Deactivation and removing juniors always succeed.
   */
  upsertRole(tenant: string, adminId: string, role: Role) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_role', { roles: shapes.role(role) ? [role.id, ...role.inherits] : [] }, async (s, tx) => {
      if (!shapes.role(role) || role.tenant !== tenant) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.roles, role.id) ? s.roles[role.id] : undefined;
      if (existing && existing.tenant !== tenant) return refuse('CONFLICT');
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
      if (existing) this.bump(s, tenant);
      return { ok: true, value: { id: role.id } };
    });
  }
  upsertGroup(tenant: string, adminId: string, group: Group) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_group', { actors: shapes.group(group) ? group.members : [], roles: shapes.group(group) ? group.roles : [], groups: validId(group?.id) ? [group.id] : [] }, s => {
      if (!shapes.group(group) || group.tenant !== tenant) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.groups, group.id) ? s.groups[group.id] : undefined;
      if (existing && existing.tenant !== tenant) return refuse('CONFLICT');
      // Only members that the change turns invalid count: removing members or roles,
      // or deactivating the group, always succeeds.
      const members = group.members.flatMap(m => Object.hasOwn(s.actors, m) ? [s.actors[m]!] : []);
      const broken = this.invalidates(s, members, () => { s.groups[group.id] = structuredClone(group); });
      if (broken) { if (existing) s.groups[group.id] = existing; else delete s.groups[group.id]; return refuse(broken.code); }
      if (existing) this.bump(s, tenant);
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
  upsertConstraint(tenant: string, adminId: string, constraint: SodConstraint) {
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
   */
  upsertKnowledge(tenant: string, adminId: string, document: Knowledge, options: {
    /** Store the document quarantined (ingestion scanner); it is then invisible and unindexed until release(). */
    quarantine?: QuarantineReason;
  } = {}) {
    const sources = shapes.document(document) ? document.sources.map(r => r.id) : [];
    return this.run(tenant, adminId, 'kb-admin', 'upsert_knowledge', { knowledge: validId(document?.id) ? [document.id, ...sources] : [],
      containers: validId(document?.container) ? [document.container] : [] }, s => {
      if (!shapes.document(document) || document.tenant !== tenant
        || (options.quarantine !== undefined && !QUARANTINE_REASONS.includes(options.quarantine))) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.knowledge, document.id) ? s.knowledge[document.id] : undefined;
      if (existing ? existing.tenant !== tenant || existing.kind !== 'document' || document.version !== existing.version + 1 : document.version !== 1) return refuse('CONFLICT');
      // An erased id is burned (R-LIFE-9). A new version never lifts a quarantine or a legal hold.
      if (existing?.lifecycle !== undefined && existing.lifecycle !== 'quarantined') return refuse('CONFLICT');
      // A legal hold preserves the held content: only metadata (labels, readers, activity, retention) may change.
      if (existing && held(existing) && (document.content !== existing.content || !sameRefs(document.sources, existing.sources))) return { ok: false, code: 'CONFLICT', held: 1 };
      // A security-admin revocation survives new versions; only reinstate() lifts it.
      if (existing?.revokedAt !== undefined && document.active !== false) return refuse('CONFLICT');
      const next: Knowledge = structuredClone(document);
      if (existing?.revokedAt !== undefined) next.revokedAt = existing.revokedAt;
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
  upsertDestination(tenant: string, adminId: string, destination: Destination) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_destination', { destinations: validId(destination?.id) ? [destination.id] : [] }, s => {
      if (!shapes.destination(destination) || destination.tenant !== tenant) return refuse('INVALID_REQUEST');
      const records = s.destinations ??= {};
      const existing = Object.hasOwn(records, destination.id) ? records[destination.id] : undefined;
      if (existing && existing.tenant !== tenant) return refuse('CONFLICT');
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
  upsertRuntimeProfile(tenant: string, adminId: string, policy: RuntimeProfilePolicy) {
    return this.run(tenant, adminId, 'security-admin', 'upsert_runtime_profile', { runtimeProfiles: true }, s => {
      if (!shapes.runtimeProfile(policy) || policy.tenant !== tenant) return refuse('INVALID_REQUEST');
      const records = s.runtimeProfiles ??= {};
      const existing = Object.hasOwn(records, policy.id) ? records[policy.id] : undefined;
      if (existing && existing.tenant !== tenant) return refuse('CONFLICT');
      if (!existing && Object.values(records).filter(p => p?.tenant === tenant).length >= RUNTIME_PROFILE_LIMIT) return refuse('CONFLICT');
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
  private eraseAs(tenant: string, adminId: string, id: string, cascade: boolean, operation: 'erase' | 'retention_erase', due?: number) {
    return this.run(tenant, adminId, 'security-admin', operation, { knowledge: validId(id) ? [id] : [] }, async (s, tx) => {
      const k = this.target(s, tenant, id);
      if (!k || typeof cascade !== 'boolean') return refuse('INVALID_REQUEST');
      // A retention run re-checks the deadline inside the transaction (it may have changed since listing).
      if (due !== undefined && !(k.lifecycle !== 'erased' && safeNumber(k.retainUntil) && k.retainUntil <= due)) return { ok: true, value: { id, erased: 0, epoch: s.epochs[tenant] ?? 0 } };
      const records = await this.cascade(s, tx, tenant, k);
      const live = records.filter(r => r.lifecycle !== 'erased');
      const holds = live.filter(held).length;
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
  async latestCheckpoint(tenant: string, adminId: string): Promise<ControlResult<{ head: TreeHead; checkpoint?: CheckpointV2 }>> {
    const allowed = await this.run(tenant, adminId, 'auditor', 'audit_checkpoint', {}, () => ({ ok: true, value: true }));
    if (!allowed.ok) return allowed;
    const head = await treeHead(this.store, tenant);
    const checkpoint = this.signer ? signTreeHead(head, this.signer.privatePem, this.signer.keyId, this.clock()) : undefined;
    return { ok: true, value: { head, ...(checkpoint ? { checkpoint } : {}) }, decisionId: allowed.decisionId };
  }
}
