import { ACTIONS, LEVELS } from './types.ts';
import type { Actor, Decision, Grant, Knowledge, PolicyInput, State } from './types.ts';
import { exactKeys, validId, safeNumber } from './validation.ts';

const deny = (code: string): Decision => ({ effect: 'deny', code });
const allow: Decision = { effect: 'allow', code: 'AUTHORIZED' };
export const subset = (small: readonly string[], large: readonly string[]) => small.every(x => large.includes('*') || large.includes(x));

function audience(actor: Actor, r: Knowledge): boolean {
  const clearance = LEVELS.indexOf(actor.clearance);
  const classification = LEVELS.indexOf(r.classification);
  return actor.active && actor.tenant === r.tenant && classification >= 0 && clearance >= classification
    && r.projects.every(p => actor.projects.includes(p))
    && (r.readers.includes(actor.id) || r.readerRoles.some(role => actor.roles.includes(role)));
}

function grantValid(state: State, grant: Grant, now: number, seen = new Set<string>()): boolean {
  const subject = state.actors[grant.subject], agent = state.actors[grant.agent];
  if (!subject?.active || !agent?.active || subject.kind !== 'user' || agent.kind !== 'agent'
    || subject.tenant !== grant.tenant || agent.tenant !== grant.tenant) return false;
  if (seen.has(grant.id) || seen.size >= 32 || !grant.active || !Number.isSafeInteger(now)
    || !Number.isSafeInteger(grant.notBefore) || !Number.isSafeInteger(grant.expiresAt)
    || now < grant.notBefore || now >= grant.expiresAt || !grant.actions.length
    || grant.actions.some(a => !ACTIONS.includes(a))) return false;
  seen.add(grant.id);
  if (!grant.parent) return true;
  const parent = state.grants[grant.parent];
  return !!parent && parent.tenant === grant.tenant && parent.subject === grant.subject
    && subset(grant.actions, parent.actions) && subset(grant.resources, parent.resources)
    && subset(grant.purposes, parent.purposes) && grant.notBefore >= parent.notBefore
    && grant.expiresAt <= parent.expiresAt && grantValid(state, parent, now, seen);
}

/** Memoized DAG traversal: bounded nodes, edges and depth; cycles fail closed. */
export function visible(state: State, actor: Actor, r: Knowledge, now: number): boolean {
  const visiting = new Set<string>(), completed = new Map<string, number>();
  let edges = 0, nodes = 0;
  const visit = (resource: Knowledge, depth: number): boolean => {
    if (depth >= 128 || visiting.has(resource.id)) return false;
    if (completed.has(resource.id)) return depth + completed.get(resource.id)! <= 128;
    if (++nodes > 1024 || !resource.active || !safeNumber(resource.version) || resource.version < 1
      || (resource.accessExpiresAt !== undefined && (!safeNumber(resource.accessExpiresAt) || now >= resource.accessExpiresAt))
      || !audience(actor, resource)) return false;
    visiting.add(resource.id);
    let height = 1;
    for (const ref of resource.sources) {
      if (++edges > 4096 || !validId(ref.id)) return false;
      const source = state.knowledge[ref.id];
      if (!source || source.version !== ref.version || !visit(source, depth + 1)) return false;
      height = Math.max(height, 1 + completed.get(source.id)!);
    }
    visiting.delete(resource.id); completed.set(resource.id, height); return depth + height <= 128;
  };
  try { return safeNumber(now) && visit(r, 0); } catch { return false; }
}

/** No I/O and no model output: identical authoritative snapshots give identical decisions. */
export function decide(state: State, input: PolicyInput): Decision {
  try { return evaluate(state, input); } catch { return deny('INVALID_CONTEXT'); }
}

function evaluate(state: State, input: PolicyInput): Decision {
  const { binding: b, resource, action, purpose, now } = input;
  if (!exactKeys(input, ['binding', 'resource', 'action', 'purpose', 'now'])
    || !exactKeys(b, ['tenant', 'subject', 'agent', 'grant']) || !Object.values(b).every(validId)
    || !validId(resource) || !ACTIONS.includes(action) || typeof purpose !== 'string' || !purpose || purpose.length > 128
    || !safeNumber(now)) return deny('INVALID_REQUEST');
  const user = state.actors[b.subject], agent = state.actors[b.agent], grant = state.grants[b.grant];
  const r = state.knowledge[resource];
  if (!user || !agent || !grant || !r) return deny('NOT_AUTHORIZED');
  if (user.kind !== 'user' || agent.kind !== 'agent' || !user.active || !agent.active
    || [user.tenant, agent.tenant, grant.tenant, r.tenant].some(t => t !== b.tenant)) return deny('IDENTITY_BOUNDARY');
  if (grant.subject !== user.id || grant.agent !== agent.id || !grantValid(state, grant, now)) return deny('INVALID_DELEGATION');
  if (!grant.actions.includes(action) || !subset([resource], grant.resources)
    || !subset([purpose], grant.purposes)) return deny('OUT_OF_SCOPE');
  // Declassification is intentionally not implemented in the reference profile.
  if (action === 'declassify') return deny('UNSUPPORTED_OBLIGATION');
  if (!visible(state, user, r, now) || !visible(state, agent, r, now)) return deny('KNOWLEDGE_BOUNDARY');
  return allow;
}

export function canDelegate(state: State, parent: Grant, child: Grant, now: number): boolean {
  const next = structuredClone(state);
  next.grants[child.id] = child;
  return child.id !== parent.id && child.parent === parent.id && child.tenant === parent.tenant
    && child.subject === parent.subject && !!next.actors[child.agent]
    && next.actors[child.agent]!.tenant === child.tenant
    && next.actors[child.agent]!.kind === 'agent' && next.actors[child.agent]!.active
    && grantValid(next, child, now);
}
