import { ACTIONS, BREAK_GLASS, DEFAULT_RISK_CAPS, DESTINATION_CLASSES, HEARTBEAT, LEVELS, MAX_RESULTS, ORIGINS, RISK_LEVELS } from './types.ts';
import type { Action, Actor, Container, Context, Decision, Destination, DestinationClass, Grant, HolderQuery, Knowledge, KnowledgeMeta, Level, PolicyInput, SodConstraint, State } from './types.ts';
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
/**
 * `limit`: the risk cap of the actor (a LEVELS index; riskLimit()). `open` (break-glass,
 * R149): the reader, reader-role and project clauses are not applied; tenant,
 * activity, clearance and the risk cap still are.
 */
function audience(actor: Actor, roles: ReadonlySet<string>, r: Labelled, limit: number = LEVELS.length - 1, open = false): boolean {
  const clearance = Math.min(LEVELS.indexOf(actor.clearance), limit);
  const classification = LEVELS.indexOf(r.classification);
  return actor.active === true && actor.tenant === r.tenant && classification >= 0 && clearance >= classification
    && (open || (r.projects.every(p => actor.projects.includes(p))
      && (r.readers.includes(actor.id) || r.readerRoles.some(role => roles.has(role)))));
}
/**
 * Risk cap of a principal (0.6, R151) as a LEVELS index; -1 denies everything.
 * The highest unexpired risk level of the principal's same-tenant signals selects
 * the cap; the cap of a level is the lowest cap configured for it or any lower
 * level (so a higher risk never widens), and `critical` always denies. Throws when
 * a signal of the principal or the tenant's cap configuration is malformed.
 */
export function riskLimit(state: State, actor: Pick<Actor, 'id' | 'tenant'>, now: number): number {
  let level = 0;
  for (const signal of Object.values(state.riskSignals ?? {})) {
    if (signal?.tenant !== actor.tenant || signal.principal !== actor.id) continue;
    const rank = RISK_LEVELS.indexOf(signal.level);
    if (rank < 0 || !safeNumber(signal.expiresAt)) throw new Error('risk');
    if (now < signal.expiresAt) level = Math.max(level, rank);
  }
  if (level === 0) return LEVELS.length - 1;
  const found = get(state.settings ?? {}, actor.tenant);
  const caps = found?.tenant === actor.tenant ? found.riskCaps : undefined;
  if (caps !== undefined && (!caps || typeof caps !== 'object' || Array.isArray(caps))) throw new Error('risk');
  let limit = LEVELS.length - 1;
  for (const [rank, name] of RISK_LEVELS.entries()) {
    if (rank > level) break;
    const cap = name === 'critical' ? 'deny' : caps && Object.hasOwn(caps, name) ? caps[name] : DEFAULT_RISK_CAPS[name];
    const index = cap === 'deny' ? -1 : LEVELS.indexOf(cap as Level);
    if (cap !== 'deny' && index < 0) throw new Error('risk');
    limit = Math.min(limit, index);
  }
  return limit;
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

/** A well-formed grant destination list: 1..64 distinct ids (destination classes are ids too). */
const destinationList = (x: unknown): x is string[] => Array.isArray(x) && x.length >= 1 && x.length <= 64 && x.every(validId) && new Set(x).size === x.length;

/**
 * R147: a heartbeat-bound grant is valid only while its last trusted heartbeat is
 * no older than its TTL (and not in the future). Without a TTL there is no condition.
 */
function heartbeatLive(grant: Grant, now: number): boolean {
  if (grant.heartbeatTtlMs === undefined) return true;
  const ttl = grant.heartbeatTtlMs, last = grant.lastHeartbeatAt;
  return Number.isSafeInteger(ttl) && ttl >= HEARTBEAT.minTtlMs && ttl <= HEARTBEAT.maxTtlMs
    && Number.isSafeInteger(last) && last! <= now && now - last! < ttl;
}
/** R149: a break-glass grant reads named resources only, for at most BREAK_GLASS.maxTtlMs, and is a root grant. */
function breakGlassShape(grant: Grant): boolean {
  if (grant.breakGlass === undefined) return true;
  return grant.breakGlass === true && grant.parent === undefined && Array.isArray(grant.actions) && grant.actions.length === 1 && grant.actions[0] === 'read'
    && Array.isArray(grant.resources) && grant.resources.length >= 1 && grant.resources.length <= BREAK_GLASS.resources && grant.resources.every(validId)
    && grant.expiresAt - grant.notBefore <= BREAK_GLASS.maxTtlMs;
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
      || grant.activeRoles.some(r => typeof r !== 'string' || !r)))
    || (grant.destinations !== undefined && !destinationList(grant.destinations))
    || (grant.maxResults !== undefined && !(Number.isSafeInteger(grant.maxResults) && grant.maxResults >= 1 && grant.maxResults <= MAX_RESULTS))
    || !heartbeatLive(grant, now) || !breakGlassShape(grant)) return false;
  seen.add(grant.id);
  if (!grant.parent) return true;
  const parent = get(state.grants, grant.parent);
  // A break-glass grant is never delegated (R149); a heartbeat-bound parent needs a child bound at most as long (R147).
  return !!parent && parent.tenant === grant.tenant && parent.subject === grant.subject
    && grant.breakGlass === undefined && parent.breakGlass === undefined
    && (parent.heartbeatTtlMs === undefined || (grant.heartbeatTtlMs !== undefined && grant.heartbeatTtlMs <= parent.heartbeatTtlMs))
    && subset(grant.actions, parent.actions) && subset(grant.resources, parent.resources)
    && subset(grant.purposes, parent.purposes) && grant.notBefore >= parent.notBefore
    && grant.expiresAt <= parent.expiresAt
    && (parent.activeRoles === undefined || (grant.activeRoles !== undefined && grant.activeRoles.every(r => parent.activeRoles!.includes(r))))
    // Destinations and result limits only narrow (ADR-008): a restricted parent needs a restricted child.
    && (parent.destinations === undefined || (grant.destinations !== undefined && grant.destinations.every(d => parent.destinations!.includes(d))))
    && (parent.maxResults === undefined || (grant.maxResults !== undefined && grant.maxResults <= parent.maxResults))
    && grantValid(state, parent, now, seen);
}

/**
 * Memoized DAG traversal: bounded nodes, edges and depth; cycles fail closed.
 * Every node and every ancestor container of every node must admit the actor.
 */
/**
 * Options of visible() (0.6): `open` drops the audience clauses for a break-glass read
 * (R149); `risk: false` evaluates without the risk cap (only to tell RISK_CAP from
 * KNOWLEDGE_BOUNDARY, never to allow).
 */
export type VisibleOptions = { open?: boolean; risk?: boolean;
  /** The run (grant id) asking (0.6, R190): a session-scoped record is visible only to its own run. Absent: expiry only (recipient checks). */
  run?: string };
/**
 * R190: a session-scoped (ephemeral) record is live only while well-formed, before
 * its expiry and, when a run is given, for that run only. A record without it is unaffected.
 */
export function ephemeralLive(k: Pick<Knowledge, 'ephemeral'>, now: number, run?: string): boolean {
  const e = k.ephemeral;
  if (e === undefined) return true;
  return exactKeys(e, ['sessionId', 'run', 'expiresAt']) && validId(e.sessionId) && validId(e.run) && safeNumber(e.expiresAt)
    && safeNumber(now) && now < e.expiresAt && (run === undefined || e.run === run);
}
export function visible(state: State, actor: Actor, r: Knowledge, now: number, roles?: ReadonlySet<string>, options: VisibleOptions = {}): boolean {
  const held = roles ?? standingRoles(state, actor);
  if (!held) return false;
  let limit: number;
  try { limit = options.risk === false ? LEVELS.length - 1 : riskLimit(state, actor, now); } catch { return false; }
  const open = options.open === true;
  const visiting = new Set<string>(), completed = new Map<string, number>(), admitted = new Map<string, boolean>();
  let edges = 0, nodes = 0;
  const contained = (resource: Knowledge): boolean => {
    const chain = containerChain(state, resource);
    return !!chain && chain.every(c => {
      if (!admitted.has(c.id)) admitted.set(c.id, c.active === true && audience(actor, held, c, limit, open));
      return admitted.get(c.id)!;
    });
  };
  const visit = (resource: Knowledge, depth: number): boolean => {
    if (depth >= LIMITS.path || visiting.has(resource.id)) return false;
    if (completed.has(resource.id)) return depth + completed.get(resource.id)! <= LIMITS.path;
    // Any lifecycle value (quarantined, erased, or unknown) hides the node and, through
    // this traversal, every record derived from it (R-LIFE-1).
    // An unreadable record (0.6b, R195: its content could not be opened) hides the node like a lifecycle state.
    if (++nodes > LIMITS.nodes || !resource.active || resource.lifecycle !== undefined || resource.unreadable !== undefined || !safeNumber(resource.version) || resource.version < 1
      || !ORIGINS.includes(resource.origin)
      || (resource.accessExpiresAt !== undefined && (!safeNumber(resource.accessExpiresAt) || now >= resource.accessExpiresAt))
      || !ephemeralLive(resource, now, options.run)
      || !audience(actor, held, resource, limit, open) || !contained(resource)) return false;
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

/**
 * True when a record and every transitive source are active, not in a lifecycle
 * state, not access-expired and resolvable (same bounds as visible(), no audience
 * check). Index maintenance uses it so a record derived from quarantined, erased
 * or revoked knowledge is not (re)indexed.
 */
export function lineageLive(state: State, root: KnowledgeMeta, now: number): boolean {
  const done = new Set<string>(), visiting = new Set<string>();
  let nodes = 0, edges = 0;
  const visit = (k: KnowledgeMeta, depth: number): boolean => {
    if (depth >= LIMITS.path || visiting.has(k.id) || ++nodes > LIMITS.nodes) return false;
    if (done.has(k.id)) return true;
    if (k.active !== true || k.lifecycle !== undefined || k.unreadable !== undefined || !Array.isArray(k.sources) || !ephemeralLive(k, now)
      || (k.accessExpiresAt !== undefined && (!safeNumber(k.accessExpiresAt) || now >= k.accessExpiresAt))) return false;
    visiting.add(k.id);
    for (const ref of k.sources) {
      if (++edges > LIMITS.edges || !validId(ref?.id)) return false;
      const source = get(state.knowledge, ref.id);
      if (!source || source.tenant !== k.tenant || source.version !== ref.version || !visit(source, depth + 1)) return false;
    }
    visiting.delete(k.id); done.add(k.id); return true;
  };
  try { return safeNumber(now) && visit(root, 0); } catch { return false; }
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
  // Risk caps (R151): critical (or a cap below public) denies outright; otherwise the cap lowers the clearance in visible().
  const risky = riskLimit(state, user, now) < LEVELS.length - 1 || riskLimit(state, agent, now) < LEVELS.length - 1;
  if (riskLimit(state, user, now) < 0 || riskLimit(state, agent, now) < 0) return deny('RISK_CAP');
  // A valid break-glass grant (read, named resources) lifts the audience clauses, never tenant, lifecycle, clearance or risk (R149).
  const open = grant.breakGlass === true;
  // R190: a session-scoped record (and anything derived from one) is visible to its own run only.
  const run = b.grant;
  if (!visible(state, user, r, now, session, { open, run }) || !visible(state, agent, r, now, agentRoles, { open, run })) {
    return risky && visible(state, user, r, now, session, { open, risk: false, run }) && visible(state, agent, r, now, agentRoles, { open, risk: false, run })
      ? deny('RISK_CAP') : deny('KNOWLEDGE_BOUNDARY');
  }
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

/**
 * The destination a release goes to (ADR-008). `profile`: the recipient's
 * Destination record id. `implicit-user`: a user without a profile (class
 * internal-user). `none`: a non-user principal without a profile. `unspecified`:
 * the enforcement point did not name a recipient (AuthZEN without a destination).
 */
export type DestinationTarget = { kind: 'profile'; id: string } | { kind: 'implicit-user' } | { kind: 'none' } | { kind: 'unspecified' };
export const targetOf = (actor: Actor): DestinationTarget =>
  actor.destination !== undefined ? { kind: 'profile', id: actor.destination } : actor.kind === 'user' ? { kind: 'implicit-user' } : { kind: 'none' };
export type DestinationVerdict = { ok: false } | { ok: true;
  /**
   * The destination_restricted value the enforcement point must honour: the class
   * and id of a governing profile, `internal-user` for a user under a restricted
   * run, the run's list when no recipient was named; absent for unrestricted legacy releases.
   */
  restrict?: string[];
  /** The resolved profile (class, and id when a record governs the release). */
  destination?: { id?: string; class: DestinationClass } };
/**
 * R121 (0.6): a read-only share/export evaluation (Engine.evaluate, AuthZEN) MUST
 * name the Destination the enforcement point sends to. Without a recipient there is
 * nothing to check the content against, so a missing destination denies (RECIPIENT).
 */
export const evaluationTargetNamed = (action: Action, destination: string | undefined): boolean =>
  (action !== 'share' && action !== 'export') || destination !== undefined;
/**
 * Destination gate of share/export (R-DEST-3..7). Pure. `top` is the highest
 * transitive effective classification of everything released (null: unknown, deny).
 * It only adds conditions: every path that allows here was already allowed by
 * decide() and the recipient checks, so a restriction never turns a deny into an allow.
 */
export function destinationGate(state: State, grant: Grant, target: DestinationTarget, tenant: string, top: Level | null, purpose: string): DestinationVerdict {
  try {
    const restrict = grant.destinations;
    if (restrict !== undefined && !destinationList(restrict)) return { ok: false };
    if (!top || !LEVELS.includes(top)) return { ok: false };
    switch (target.kind) {
      case 'profile': {
        const d: Destination | undefined = get(state.destinations ?? {}, target.id);
        if (!d || !validId(target.id) || (DESTINATION_CLASSES as readonly string[]).includes(target.id) || d.id !== target.id || d.tenant !== tenant || d.active !== true || !DESTINATION_CLASSES.includes(d.class)
          || !LEVELS.includes(d.maxClassification) || !Array.isArray(d.purposes)) return { ok: false };
        if (restrict && !restrict.includes(d.class) && !restrict.includes(d.id)) return { ok: false };
        if (LEVELS.indexOf(top) > LEVELS.indexOf(d.maxClassification) || !d.purposes.includes(purpose)) return { ok: false };
        return { ok: true, restrict: [d.class, d.id], destination: { id: d.id, class: d.class } };
      }
      case 'implicit-user':
        if (restrict && !restrict.includes('internal-user')) return { ok: false };
        return restrict ? { ok: true, restrict: ['internal-user'], destination: { class: 'internal-user' } } : { ok: true };
      case 'none': return restrict ? { ok: false } : { ok: true };
      case 'unspecified': return restrict ? { ok: true, restrict: [...restrict] } : { ok: true };
      default: return { ok: false };
    }
  } catch { return { ok: false }; }
}
