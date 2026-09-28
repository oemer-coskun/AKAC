import { ACTIONS, LEVELS, ORIGINS } from './types.ts';
import type { Actor, Container, Context, Decision, Grant, HolderQuery, Knowledge, KnowledgeMeta, Level, PolicyInput, SodConstraint, State } from './types.ts';
import { exactKeys, validId, safeNumber } from './validation.ts';

const deny = (code: string): Decision => ({ effect: 'deny', code, category: 'deny' });
/** Authorization could not be established (malformed, missing or over budget); still a deny. */
const defer = (code: string): Decision => ({ effect: 'deny', code, category: 'defer' });
const allow: Decision = { effect: 'allow', code: 'AUTHORIZED' };
export const subset = (small: readonly string[], large: readonly string[]) => small.every(x => large.includes('*') || large.includes(x));
/** Own-property lookup: record ids never resolve to Object.prototype members. */
const get = <T>(records: Record<string, T>, id: unknown): T | undefined =>
  typeof id === 'string' && Object.hasOwn(records, id) ? records[id] : undefined;
export const LIMITS = { roles: 64, roleDepth: 16, containerDepth: 32, nodes: 1024, edges: 4096, path: 128, grants: 32 } as const;

type Labelled = { tenant: string; classification: Level; projects: string[]; readers: string[]; readerRoles: string[] };
function audience(actor: Actor, roles: ReadonlySet<string>, r: Labelled): boolean {
  const clearance = LEVELS.indexOf(actor.clearance);
  const classification = LEVELS.indexOf(r.classification);
  return actor.active === true && actor.tenant === r.tenant && classification >= 0 && clearance >= classification
    && r.projects.every(p => actor.projects.includes(p))
    && (r.readers.includes(actor.id) || r.readerRoles.some(role => roles.has(role)));
}

/**
 * Closure over the role hierarchy. A name with a same-tenant Role record expands
 * to its juniors while the record is active; an inactive record contributes
 * nothing. A name without a same-tenant record is a flat 0.2-compatible role.
 * Cycles, more than 64 roles or paths longer than 16 roles cannot be established.
 */
function closeRoles(state: State, tenant: string, seeds: readonly unknown[]): Set<string> | null {
  const held = new Set<string>(), height = new Map<string, number>(), path = new Set<string>();
  const visit = (name: unknown): number => {
    if (typeof name !== 'string' || !name) throw new Error('role');
    const found = get(state.roles, name);
    const role = found?.tenant === tenant ? found : undefined;
    if (role && role.active !== true) return 0;
    if (path.has(name)) throw new Error('cycle');
    const known = height.get(name);
    if (known !== undefined) return known;
    held.add(name);
    if (held.size > LIMITS.roles) throw new Error('budget');
    path.add(name);
    let h = 1;
    if (role && !Array.isArray(role.inherits)) throw new Error('role');
    for (const junior of role?.inherits ?? []) h = Math.max(h, 1 + visit(junior));
    path.delete(name);
    if (h > LIMITS.roleDepth) throw new Error('depth');
    height.set(name, h); return h;
  };
  try { for (const seed of seeds) visit(seed); return held; } catch { return null; }
}
/** Effective roles of an actor: direct roles plus roles of active same-tenant groups, closed over the hierarchy. */
export function effectiveRoles(state: State, actor: Actor): Set<string> | null {
  try {
    const groups = Object.values(state.groups).filter(g => {
      if (g.tenant !== actor.tenant) return false;
      if (!Array.isArray(g.members) || !Array.isArray(g.roles)) throw new Error('group');
      return g.active === true && g.members.includes(actor.id);
    });
    if (!Array.isArray(actor.roles)) return null;
    return closeRoles(state, actor.tenant, [...actor.roles, ...groups.flatMap(g => g.roles)]);
  } catch { return null; }
}
/** Session roles of a grant: activated roles and their juniors, else every effective role. */
export function sessionRoles(state: State, user: Actor, held: ReadonlySet<string>, grant: Grant): Set<string> | null {
  if (grant.activeRoles === undefined) return new Set(held);
  if (!Array.isArray(grant.activeRoles) || !grant.activeRoles.every(r => typeof r === 'string' && held.has(r))) return null;
  return closeRoles(state, user.tenant, grant.activeRoles);
}
/** True when the role set meets a constraint of this kind. A malformed constraint fails closed. */
export function sodViolated(state: State, tenant: string, kind: SodConstraint['kind'], roles: ReadonlySet<string>): boolean {
  for (const c of Object.values(state.constraints)) {
    if (c.tenant !== tenant) continue;
    if (!['static', 'dynamic'].includes(c.kind) || !Number.isSafeInteger(c.cardinality) || c.cardinality < 2 || !Array.isArray(c.roles)) return true;
    if (c.kind === kind && new Set(c.roles.filter(r => roles.has(r))).size >= c.cardinality) return true;
  }
  return false;
}
/** Effective roles of a principal that is valid for decisions at all (no static SoD violation). */
export function standingRoles(state: State, actor: Actor): Set<string> | null {
  const roles = effectiveRoles(state, actor);
  return roles && !sodViolated(state, actor.tenant, 'static', roles) ? roles : null;
}
/** Reference semantics of `Tx.countSodHolders` over a complete snapshot. */
export function countSodHolders(state: State, tenant: string, query: HolderQuery): number | 'unknown' {
  const view: State = query.role ? { ...state, roles: { ...state.roles, [query.role.id]: query.role } } : state;
  let holders = 0;
  for (const actor of Object.values(state.actors)) {
    if (actor.tenant !== tenant || actor.active !== true) continue;
    const roles = effectiveRoles(view, actor);
    if (!roles) return 'unknown';
    if (query.constraints.some(c => new Set(c.roles.filter(r => roles.has(r))).size >= c.cardinality)) holders++;
  }
  return holders;
}

/** Ancestor chain, nearest first. Missing, cyclic, cross-tenant, too deep or malformed chains are null. */
export function containerChain(state: State, k: Pick<Knowledge, 'tenant' | 'container'>): Container[] | null {
  const chain: Container[] = [];
  let id = k.container;
  while (id !== undefined) {
    if (!validId(id) || chain.length >= LIMITS.containerDepth || chain.some(c => c.id === id)) return null;
    const c = get(state.containers, id);
    if (!c || c.tenant !== k.tenant || c.id !== id
      || !(c.kind === 'knowledge-base' ? c.parent === undefined : c.kind === 'folder' && c.parent !== undefined)) return null;
    chain.push(c); id = c.parent;
  }
  return chain;
}
export type EffectiveLabel = {
  classification: Level; projects: string[];
  /** Conjunctive audience clauses: the document first, then each ancestor container. */
  audiences: { readers: string[]; readerRoles: string[] }[];
  containers: string[];
};
/** Pure label for indexers: highest classification, union of projects, every ancestor ACL. */
export function effectiveLabel(state: State, k: KnowledgeMeta): EffectiveLabel | null {
  const chain = containerChain(state, k);
  const levels = [k, ...(chain ?? [])].map(x => LEVELS.indexOf(x.classification));
  if (!chain || levels.some(l => l < 0) || !ORIGINS.includes(k.origin)) return null;
  return { classification: LEVELS[Math.max(...levels)]!, projects: [...new Set([k, ...chain].flatMap(x => x.projects))].sort(),
    audiences: [k, ...chain].map(x => ({ readers: [...x.readers], readerRoles: [...x.readerRoles] })), containers: chain.map(c => c.id) };
}
/**
 * Highest effective classification (R25) over an object and every transitive
 * source, bounded like visible() (nodes, edges, path; cycles fail). Sources must
 * resolve in the object's tenant at the referenced version. Null when that cannot
 * be established. Supplemental policy (OPA) and document ingestion use it, so a
 * source above the object's own chain is never hidden from them.
 */
export function transitiveClassification(state: State, root: KnowledgeMeta): Level | null {
  const done = new Map<string, number>(), visiting = new Set<string>();
  let nodes = 0, edges = 0;
  const visit = (k: KnowledgeMeta, depth: number): number => {
    if (depth >= LIMITS.path || visiting.has(k.id)) throw new Error('cycle');
    const known = done.get(k.id);
    if (known !== undefined) return known;
    const label = ++nodes <= LIMITS.nodes ? effectiveLabel(state, k) : null;
    if (!label || !Array.isArray(k.sources)) throw new Error('label');
    let level = LEVELS.indexOf(label.classification);
    visiting.add(k.id);
    for (const ref of k.sources) {
      if (++edges > LIMITS.edges || !validId(ref?.id)) throw new Error('budget');
      const source = get(state.knowledge, ref.id);
      if (!source || source.tenant !== k.tenant || source.version !== ref.version) throw new Error('source');
      level = Math.max(level, visit(source, depth + 1));
    }
    visiting.delete(k.id); done.set(k.id, level); return level;
  };
  try { return LEVELS[visit(root, 0)] ?? null; } catch { return null; }
}
/** Pre-filter tokens for retrieval candidates. They narrow a search; they never authorize. */
export function principalTokens(state: State, actor: Actor, activeRoles?: string[]): string[] | null {
  const held = standingRoles(state, actor);
  const roles = held && (activeRoles ? activeRoles.every(r => held.has(r)) && closeRoles(state, actor.tenant, activeRoles) : held);
  if (!roles) return null;
  return [`user:${actor.id}`, ...[...roles].sort().map(r => `role:${r}`), ...[...actor.projects].sort().map(p => `project:${p}`)];
}
export function effectiveClearance(user: Actor, agent: Actor): Level | null {
  const level = Math.min(LEVELS.indexOf(user.clearance), LEVELS.indexOf(agent.clearance));
  return level >= 0 ? LEVELS[level]! : null;
}
/** A context is usable only in its tenant's current epoch, under the current revision, before expiry. */
export function contextFresh(state: State, c: Context, now: number, revision: string): boolean {
  return c.active === true && c.epoch === (state.epochs[c.tenant] ?? 0) && c.policyVersion === revision && safeNumber(now) && now < c.expiresAt;
}

function grantValid(state: State, grant: Grant, now: number, seen = new Set<string>()): boolean {
  const subject = get(state.actors, grant.subject), agent = get(state.actors, grant.agent);
  if (!subject?.active || !agent?.active || subject.kind !== 'user' || agent.kind !== 'agent'
    || subject.tenant !== grant.tenant || agent.tenant !== grant.tenant) return false;
  if (seen.has(grant.id) || seen.size >= LIMITS.grants || !grant.active || !Number.isSafeInteger(now)
    || !Number.isSafeInteger(grant.notBefore) || !Number.isSafeInteger(grant.expiresAt)
    || now < grant.notBefore || now >= grant.expiresAt || !grant.actions.length
    || grant.actions.some(a => !ACTIONS.includes(a))
    || (grant.activeRoles !== undefined && (!Array.isArray(grant.activeRoles) || grant.activeRoles.length > LIMITS.roles
      || grant.activeRoles.some(r => typeof r !== 'string' || !r)))) return false;
  seen.add(grant.id);
  if (!grant.parent) return true;
  const parent = get(state.grants, grant.parent);
  return !!parent && parent.tenant === grant.tenant && parent.subject === grant.subject
    && subset(grant.actions, parent.actions) && subset(grant.resources, parent.resources)
    && subset(grant.purposes, parent.purposes) && grant.notBefore >= parent.notBefore
    && grant.expiresAt <= parent.expiresAt
    && (parent.activeRoles === undefined || (grant.activeRoles !== undefined && grant.activeRoles.every(r => parent.activeRoles!.includes(r))))
    && grantValid(state, parent, now, seen);
}

/**
 * Memoized DAG traversal: bounded nodes, edges and depth; cycles fail closed.
 * Every node and every ancestor container of every node must admit the actor.
 */
export function visible(state: State, actor: Actor, r: Knowledge, now: number, roles?: ReadonlySet<string>): boolean {
  const held = roles ?? standingRoles(state, actor);
  if (!held) return false;
  const visiting = new Set<string>(), completed = new Map<string, number>(), admitted = new Map<string, boolean>();
  let edges = 0, nodes = 0;
  const contained = (resource: Knowledge): boolean => {
    const chain = containerChain(state, resource);
    return !!chain && chain.every(c => {
      if (!admitted.has(c.id)) admitted.set(c.id, c.active === true && audience(actor, held, c));
      return admitted.get(c.id)!;
    });
  };
  const visit = (resource: Knowledge, depth: number): boolean => {
    if (depth >= LIMITS.path || visiting.has(resource.id)) return false;
    if (completed.has(resource.id)) return depth + completed.get(resource.id)! <= LIMITS.path;
    if (++nodes > LIMITS.nodes || !resource.active || !safeNumber(resource.version) || resource.version < 1
      || !ORIGINS.includes(resource.origin)
      || (resource.accessExpiresAt !== undefined && (!safeNumber(resource.accessExpiresAt) || now >= resource.accessExpiresAt))
      || !audience(actor, held, resource) || !contained(resource)) return false;
    visiting.add(resource.id);
    let height = 1;
    for (const ref of resource.sources) {
      if (++edges > LIMITS.edges || !validId(ref.id)) return false;
      const source = get(state.knowledge, ref.id);
      if (!source || source.version !== ref.version || !visit(source, depth + 1)) return false;
      height = Math.max(height, 1 + completed.get(source.id)!);
    }
    visiting.delete(resource.id); completed.set(resource.id, height); return depth + height <= LIMITS.path;
  };
  try { return safeNumber(now) && visit(r, 0); } catch { return false; }
}

/** No I/O and no model output: identical authoritative snapshots give identical decisions. */
export function decide(state: State, input: PolicyInput): Decision {
  try { return evaluate(state, input); } catch { return defer('INVALID_CONTEXT'); }
}

function evaluate(state: State, input: PolicyInput): Decision {
  const { binding: b, resource, action, purpose, now } = input;
  if (!exactKeys(input, ['binding', 'resource', 'action', 'purpose', 'now'])
    || !exactKeys(b, ['tenant', 'subject', 'agent', 'grant']) || !Object.values(b).every(validId)
    || !validId(resource) || !ACTIONS.includes(action) || typeof purpose !== 'string' || !purpose || purpose.length > 128
    || !safeNumber(now)) return defer('INVALID_REQUEST');
  const user = get(state.actors, b.subject), agent = get(state.actors, b.agent), grant = get(state.grants, b.grant);
  const r = get(state.knowledge, resource);
  if (!user || !agent || !grant || !r) return defer('NOT_AUTHORIZED');
  if (user.kind !== 'user' || agent.kind !== 'agent' || !user.active || !agent.active
    || [user.tenant, agent.tenant, grant.tenant, r.tenant].some(t => t !== b.tenant)) return deny('IDENTITY_BOUNDARY');
  if (grant.subject !== user.id || grant.agent !== agent.id || !grantValid(state, grant, now)) return deny('INVALID_DELEGATION');
  if (!grant.actions.includes(action) || !subset([resource], grant.resources)
    || !subset([purpose], grant.purposes)) return deny('OUT_OF_SCOPE');
  // Declassification is intentionally not implemented in the reference profile.
  if (action === 'declassify') return deny('UNSUPPORTED_OBLIGATION');
  const userRoles = effectiveRoles(state, user), agentRoles = effectiveRoles(state, agent);
  if (!userRoles || !agentRoles) return defer('INVALID_CONTEXT');
  const session = sessionRoles(state, user, userRoles, grant);
  if (!session) return deny('INVALID_DELEGATION');
  // Dynamic SoD applies to the activated set; without activation every held role is active.
  if (sodViolated(state, b.tenant, 'static', userRoles) || sodViolated(state, b.tenant, 'static', agentRoles)
    || sodViolated(state, b.tenant, 'dynamic', session)) return deny('SOD_VIOLATION');
  if (!ORIGINS.includes(r.origin) || !containerChain(state, r)) return defer('INVALID_CONTEXT');
  if (!visible(state, user, r, now, session) || !visible(state, agent, r, now, agentRoles)) return deny('KNOWLEDGE_BOUNDARY');
  return allow;
}

export function canDelegate(state: State, parent: Grant, child: Grant, now: number): boolean {
  const next: State = { ...state, grants: { ...state.grants, [child.id]: child } };
  const agent = get(next.actors, child.agent);
  return child.id !== parent.id && child.parent === parent.id && child.tenant === parent.tenant
    && child.subject === parent.subject && !!agent && agent.tenant === child.tenant
    && agent.kind === 'agent' && agent.active && grantValid(next, child, now);
}
/** Delegation-chain validity (liveness, time, attenuation, session-role narrowing) for control-plane issuance. */
export const validGrantChain = (state: State, grant: Grant, now: number): boolean => { try { return grantValid(state, grant, now); } catch { return false; } };
