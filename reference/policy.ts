import { ACTIONS, LEVELS } from './types.ts';
import type { Actor, Decision, Grant, Knowledge, PolicyInput, State } from './types.ts';

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

/** Source ACLs are evaluated transitively, not flattened into an unsafe union. */
export function visible(state: State, actor: Actor, r: Knowledge, seen = new Set<string>()): boolean {
  if (!r.active || !Number.isSafeInteger(r.version) || r.version < 1 || seen.has(r.id) || seen.size >= 128 || !audience(actor, r)) return false;
  const next = new Set(seen); next.add(r.id);
  return r.sources.every(ref => {
    const source = state.knowledge[ref.id];
    return !!source && source.version === ref.version && visible(state, actor, source, next);
  });
}

/** No I/O and no model output: identical authoritative snapshots give identical decisions. */
export function decide(state: State, input: PolicyInput): Decision {
  const { binding: b, resource, action, purpose, now } = input;
  if (!ACTIONS.includes(action) || !purpose || !Number.isSafeInteger(now)) return deny('INVALID_REQUEST');
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
  if (!visible(state, user, r) || !visible(state, agent, r)) return deny('KNOWLEDGE_BOUNDARY');
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
