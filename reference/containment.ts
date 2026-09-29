import { DESTINATION_CLASSES, LEVELS, RUNTIME_PROFILE_LIMIT } from './types.ts';
import type { DestinationClass, Level, RuntimeProfilePolicy, State } from './types.ts';
import { RUNTIME_DOMAINS } from './decision.ts';
import type { Obligation } from './decision.ts';
import { exactKeys, validId } from './validation.ts';
import { createHash } from 'node:crypto';
import { canonicalize } from './jcs.ts';

/**
 * Runtime containment contract (AKAC 0.5 draft, ADR-012, spec/drafts/0.5-runtime-containment.md).
 * AKAC decides which operator-reviewed runtime profile each containment domain
 * needs and states it as `runtime_profile` obligations; the runtime enforcer
 * (a policy enforcement point) applies them or the decision is a deny. AKAC never
 * emits vendor runtime policy.
 */

/** Closed shape of a runtime profile policy record: at least one domain, profile ids are identifiers. */
export function validRuntimeProfile(p: unknown): p is RuntimeProfilePolicy {
  if (!exactKeys(p, ['id', 'tenant', 'classification', 'profiles', 'active'], ['destinationClass'])) return false;
  const profiles = p.profiles;
  return validId(p.id) && validId(p.tenant) && (LEVELS as readonly unknown[]).includes(p.classification)
    && (p.destinationClass === undefined || (DESTINATION_CLASSES as readonly unknown[]).includes(p.destinationClass))
    && exactKeys(profiles, [], [...RUNTIME_DOMAINS]) && Object.keys(profiles).length >= 1 && Object.values(profiles).every(validId)
    && typeof p.active === 'boolean';
}

export type Containment = { ok: true; obligations: Obligation[] }
  | { ok: false; reason: 'DENIED:UNSUPPORTED_OBLIGATION' | 'DEFERRED:INVALID_CONTEXT' | 'DEFERRED:BUDGET_EXCEEDED' };

/**
 * Runtime obligations of a decision over material whose highest transitive
 * effective classification (R25) is `level`, sent to a destination of class
 * `destination` (absent when the decision names none: read, derive, an unnamed
 * recipient). Pure and deterministic.
 *
 * - A tenant without an active policy gets no runtime obligation at all (0.4 behaviour).
 * - Otherwise the decision carries `max_output_classification` = `level`, and a
 *   policy applies when it is active, `classification <= level` and its
 *   `destinationClass` is absent or equals `destination`.
 * - Per domain, among the applicable policies naming a profile for it, the one with
 *   the highest `classification` wins; at equal classification a policy narrowed to
 *   the destination class wins over an unnarrowed one. Two winners that name
 *   different profiles are a conflict: UNSUPPORTED_OBLIGATION (deny), never a guess.
 * - A malformed record of the tenant defers (INVALID_CONTEXT); more than
 *   RUNTIME_PROFILE_LIMIT records defer (BUDGET_EXCEEDED).
 *
 * The rule assumes what the operator must ensure: a higher tier names a profile
 * that is at least as restrictive. AKAC cannot compare opaque profile ids.
 */
export function containment(s: State, tenant: string, level: Level | null, destination?: DestinationClass): Containment {
  const records = Object.entries(s.runtimeProfiles ?? {}).filter(([, p]) => !!p && typeof p === 'object' && (p as { tenant?: unknown }).tenant === tenant);
  if (records.length > RUNTIME_PROFILE_LIMIT) return { ok: false, reason: 'DEFERRED:BUDGET_EXCEEDED' };
  if (records.some(([key, p]) => !validRuntimeProfile(p) || p.id !== key)) return { ok: false, reason: 'DEFERRED:INVALID_CONTEXT' };
  const active = records.map(([, p]) => p).filter(p => p.active === true);
  if (!active.length) return { ok: true, obligations: [] };
  if (!level || !LEVELS.includes(level)) return { ok: false, reason: 'DEFERRED:INVALID_CONTEXT' };
  const top = LEVELS.indexOf(level);
  const applicable = active.filter(p => LEVELS.indexOf(p.classification) <= top && (p.destinationClass === undefined || p.destinationClass === destination));
  const obligations: Obligation[] = [];
  for (const domain of RUNTIME_DOMAINS) {
    let best: { key: number; profile: string } | undefined, conflict = false;
    for (const p of applicable) {
      const profile = p.profiles[domain];
      if (profile === undefined) continue;
      const key = LEVELS.indexOf(p.classification) * 2 + (p.destinationClass !== undefined ? 1 : 0);
      if (!best || key > best.key) { best = { key, profile }; conflict = false; }
      else if (key === best.key && profile !== best.profile) conflict = true;
    }
    if (conflict) return { ok: false, reason: 'DENIED:UNSUPPORTED_OBLIGATION' };
    if (best) obligations.push({ type: 'runtime_profile', domain, profile: best.profile });
  }
  obligations.push({ type: 'max_output_classification', value: level });
  return { ok: true, obligations };
}

/**
 * Runtime obligations of a share/export whose destination class is not known
 * (R109): an evaluation naming no Destination, or a release to a principal
 * without a Destination profile. The content may reach any of `classes` (the
 * destination classes the run allows; every class for an unrestricted run), so
 * the derivation runs once per class and the results are merged: the decision
 * is never weaker than for any single class it could reach. Two classes whose
 * winners name different profiles for one domain are a conflict
 * (UNSUPPORTED_OBLIGATION, R110): name the destination instead.
 */
export function containmentAcross(s: State, tenant: string, level: Level | null, classes: readonly DestinationClass[]): Containment {
  if (!classes.length) return containment(s, tenant, level);
  const merged = new Map<string, Obligation>();
  let label: Obligation | undefined;
  for (const d of classes) {
    const c = containment(s, tenant, level, d);
    if (!c.ok) return c;
    for (const o of c.obligations) {
      if (o.type === 'max_output_classification') { label = o; continue; }
      if (o.type !== 'runtime_profile') continue;
      const prior = merged.get(o.domain);
      if (prior && prior.type === 'runtime_profile' && prior.profile !== o.profile) return { ok: false, reason: 'DENIED:UNSUPPORTED_OBLIGATION' };
      merged.set(o.domain, o);
    }
  }
  return { ok: true, obligations: [...RUNTIME_DOMAINS.flatMap(d => merged.get(d) ?? []), ...(label ? [label] : [])] };
}

/**
 * Digest of the tenant's active runtime profile policy set (JCS over the valid
 * active records sorted by id), or undefined when it has none. Engine decisions
 * that loaded the set add it to the policy digest input, so the digest of a
 * 0.5 decision identifies the containment policy it was derived under; a tenant
 * without an active policy keeps the 0.4 digest.
 */
export function runtimeSetDigest(s: State, tenant: string): string | undefined {
  const active = Object.values(s.runtimeProfiles ?? {}).filter(p => validRuntimeProfile(p) && p.tenant === tenant && p.active === true)
    .sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  return active.length ? 'runtime-profiles:' + createHash('sha256').update(canonicalize(active)).digest('hex') : undefined;
}
