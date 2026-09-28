import { appendAudit } from './audit.ts';
import { BudgetExceeded, hydrate } from './hydrate.ts';
import type { Seed } from './hydrate.ts';
import { containerChain, effectiveLabel, effectiveRoles, sessionRoles, sodViolated, standingRoles, transitiveClassification, validGrantChain } from './policy.ts';
import { ACTIONS, CORE_VERSION, LEVELS } from './types.ts';
import type { Actor, Audit, Container, Grant, Group, Knowledge, Role, SodConstraint, State, Store, Tx } from './types.ts';
import { exactKeys, safeNumber, validId } from './validation.ts';

export type ControlResult<T> = { ok: true; value: T }
  | { ok: false; code: 'NOT_AUTHORIZED' | 'INVALID_REQUEST' | 'CONFLICT' | 'SOD_VIOLATION';
    /** SOD_VIOLATION from a role or constraint change: how many currently valid principals it would invalidate (never which). */
    holders?: number };
/** security-admin: identities, roles, groups, constraints, grants, revocation. kb-admin: containers, documents. auditor: audit. */
export type AdminRole = 'security-admin' | 'kb-admin' | 'auditor';
type Failure = Exclude<ControlResult<never>, { ok: true }>['code'];
/** `audit` overrides the recorded decision and reason (attempts handled outside the control plane). */
type Refusal = { ok: false; code: Failure; holders?: number };
type Checked<T> = { ok: true; value: T; audit?: { allowed: boolean; reason: string } } | Refusal;
const refuse = (code: Failure): Refusal => ({ ok: false, code });
const within = (small: readonly string[], large: readonly string[]) => small.every(x => large.includes(x));
const rank = (l: string) => LEVELS.indexOf(l as never);
/** Deactivation, or no new role, project, clearance or reactivation: can only remove authority. */
const reducesActor = (old: Actor, next: Actor) => next.active === false
  || ((old.active === true || next.active !== true) && within(next.roles, old.roles) && within(next.projects, old.projects) && rank(next.clearance) <= rank(old.clearance));

const ids = (x: unknown, max = 256): x is string[] => Array.isArray(x) && x.length <= max && x.every(validId) && new Set(x).size === x.length;
const level = (x: unknown) => LEVELS.includes(x as never);
const bool = (x: unknown) => typeof x === 'boolean';
const optional = (x: unknown, check: (y: unknown) => boolean) => x === undefined || check(x);
const refs = (x: unknown) => Array.isArray(x) && x.length <= 256 && x.every(r => exactKeys(r, ['id', 'version']) && validId(r.id) && safeNumber(r.version) && r.version >= 1);

export const shapes = {
  actor: (a: unknown): a is Actor => exactKeys(a, ['id', 'tenant', 'kind', 'roles', 'projects', 'clearance', 'active'])
    && validId(a.id) && validId(a.tenant) && ['user', 'agent', 'service'].includes(a.kind as string)
    && ids(a.roles, 64) && ids(a.projects) && level(a.clearance) && bool(a.active),
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
  document: (k: unknown): k is Knowledge => exactKeys(k, ['id', 'tenant', 'version', 'kind', 'origin', 'content', 'classification', 'projects', 'readerRoles', 'readers', 'sources', 'active'], ['accessExpiresAt', 'container'])
    && validId(k.id) && validId(k.tenant) && safeNumber(k.version) && (k.version as number) >= 1 && k.kind === 'document'
    && ['human', 'system'].includes(k.origin as string) && typeof k.content === 'string' && k.content.length > 0 && k.content.length <= 1_000_000
    && level(k.classification) && ids(k.projects) && ids(k.readerRoles) && ids(k.readers) && refs(k.sources) && bool(k.active)
    && optional(k.accessExpiresAt, safeNumber) && optional(k.container, validId),
  grant: (g: unknown): g is Grant => exactKeys(g, ['id', 'tenant', 'subject', 'agent', 'actions', 'resources', 'purposes', 'notBefore', 'expiresAt', 'active'], ['parent', 'activeRoles'])
    && [g.id, g.tenant, g.subject, g.agent].every(validId) && Array.isArray(g.actions) && g.actions.length > 0
    && g.actions.every(a => ACTIONS.includes(a)) && new Set(g.actions).size === g.actions.length
    && Array.isArray(g.resources) && g.resources.length <= 256 && g.resources.every(r => r === '*' || validId(r))
    && Array.isArray(g.purposes) && g.purposes.length <= 64 && g.purposes.every(p => typeof p === 'string' && p.length > 0 && p.length <= 128)
    && safeNumber(g.notBefore) && safeNumber(g.expiresAt) && (g.notBefore as number) < (g.expiresAt as number)
    && bool(g.active) && optional(g.parent, validId) && optional(g.activeRoles, x => ids(x, 64))
};

/**
 * Trusted administrative operations. Every call is authorized against the
 * caller's standing roles in the same tenant and audited, allowed or not. This is
 * a library for an operator-facing API; it MUST NOT be reachable from agent
 * credentials or model output. Updating an existing security-relevant record
 * advances the tenant epoch, so running contexts must re-establish authority.
 */
export class ControlPlane {
  private store: Store;
  private clock: () => number;
  constructor(store: Store, options: { clock?: () => number } = {}) { this.store = store; this.clock = options.clock ?? Date.now; }

  private record(s: State, tenant: string, adminId: string, operation: string, allowed: boolean, reason: string) {
    appendAudit(s, { time: this.clock(), tenant, actor: validId(adminId) ? adminId : 'invalid', operation,
      decision: allowed ? 'allow' : 'deny', reason, policyVersion: `${CORE_VERSION}|${s.policyVersion}|control-plane`, epoch: s.epochs[tenant] ?? 0 });
  }
  /**
   * Authorizes, runs and audits one operation in one tenant transaction. If the
   * transaction fails (store error or an exceeded load budget), the attempt is
   * audited best effort as DEFERRED:STORE_ERROR / DEFERRED:BUDGET_EXCEEDED in a
   * separate transaction and the original error is rethrown (never masked).
   */
  private async run<T>(tenant: string, adminId: string, role: AdminRole, operation: string, seed: Seed,
    body: (s: State, tx: Tx) => Checked<T> | Promise<Checked<T>>): Promise<ControlResult<T>> {
    if (!validId(tenant)) return { ok: false, code: 'NOT_AUTHORIZED' };
    try {
      return await this.store.transaction(tenant, async tx => {
        await hydrate(tx, { ...seed, actors: [...(seed.actors ?? []), ...(validId(adminId) ? [adminId] : [])] });
        const s = tx.state;
        const admin = validId(adminId) && Object.hasOwn(s.actors, adminId) ? s.actors[adminId] : undefined;
        const roles = admin?.kind === 'user' && admin.active && admin.tenant === tenant ? standingRoles(s, admin) : null;
        if (!roles?.has(role)) { this.record(s, tenant, adminId, operation, false, 'DENIED:NOT_ADMIN'); return { ok: false, code: 'NOT_AUTHORIZED' }; }
        const result = await body(s, tx);
        if (result.ok) {
          this.record(s, tenant, adminId, operation, result.audit?.allowed ?? true, result.audit?.reason ?? 'AUTHORIZED');
          return { ok: true, value: result.value };
        }
        this.record(s, tenant, adminId, operation, false, `DENIED:${result.code}`);
        return result;
      });
    } catch (error) {
      await this.failed(tenant, adminId, operation, error);
      throw error;
    }
  }
  private async failed(tenant: string, adminId: string, operation: string, error: unknown) {
    const reason = error instanceof BudgetExceeded ? 'DEFERRED:BUDGET_EXCEEDED' : 'DEFERRED:STORE_ERROR';
    try {
      await this.store.transaction(tenant, async tx => { await tx.load({ epoch: true, audit: true }); this.record(tx.state, tenant, adminId, operation, false, reason); });
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
   * classification of every source (R25); otherwise INVALID_REQUEST.
   */
  upsertKnowledge(tenant: string, adminId: string, document: Knowledge) {
    const sources = shapes.document(document) ? document.sources.map(r => r.id) : [];
    return this.run(tenant, adminId, 'kb-admin', 'upsert_knowledge', { knowledge: validId(document?.id) ? [document.id, ...sources] : [],
      containers: validId(document?.container) ? [document.container] : [] }, s => {
      if (!shapes.document(document) || document.tenant !== tenant) return refuse('INVALID_REQUEST');
      const existing = Object.hasOwn(s.knowledge, document.id) ? s.knowledge[document.id] : undefined;
      if (existing ? existing.tenant !== tenant || existing.kind !== 'document' || document.version !== existing.version + 1 : document.version !== 1) return refuse('CONFLICT');
      if (document.container !== undefined && !containerChain(s, document)) return refuse('INVALID_REQUEST');
      if (document.sources.length) {
        const own = effectiveLabel(s, document)?.classification, top = transitiveClassification(s, document);
        if (!own || !top || rank(top) > rank(own)) return refuse('INVALID_REQUEST');
      }
      s.knowledge[document.id] = structuredClone(document);
      if (existing) this.bump(s, tenant);
      return { ok: true, value: { id: document.id, version: document.version } };
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
  /**
   * Audits an administrative attempt that was answered outside the control plane
   * (for example an idempotent replay) after the same standing-role check. `ok`
   * means the caller holds the role now; the outcome is recorded as given.
   */
  attempt(tenant: string, adminId: string, role: AdminRole, operation: string, outcome: { allowed: boolean; reason: string }): Promise<ControlResult<true>> {
    return this.run(tenant, adminId, role, operation, {}, () => ({ ok: true, value: true, audit: outcome }));
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
  /** Audited role check for operations executed outside the control plane (for example index maintenance). */
  authorize(tenant: string, adminId: string, role: AdminRole, operation: string): Promise<ControlResult<true>> {
    return this.run(tenant, adminId, role, operation, {}, () => ({ ok: true, value: true }));
  }
  /** Audit read access is itself audited. */
  async auditLog(tenant: string, adminId: string, after = 0, limit = 1000): Promise<ControlResult<Audit[]>> {
    if (!safeNumber(after) || !Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) return { ok: false, code: 'INVALID_REQUEST' };
    const allowed = await this.run(tenant, adminId, 'auditor', 'audit_read', {}, () => ({ ok: true, value: true }));
    if (!allowed.ok) return allowed;
    return { ok: true, value: await this.store.auditLog(tenant, after, limit) };
  }
}
