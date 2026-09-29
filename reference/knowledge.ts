import { containerChain, effectiveLabel, LIMITS } from './policy.ts';
import type { DestinationTarget } from './policy.ts';
import { KNOWLEDGE, LEVELS, MODALITIES, RESIDENCY_CODE } from './types.ts';
import type { CombinationRule, Ephemeral, Knowledge, KnowledgeMeta, Level, ModelRef, State } from './types.ts';
import { exactKeys, safeNumber, validId } from './validation.ts';

/**
 * Knowledge semantics of AKAC 0.6 (ADR-022, spec/AKAC-0.6.md R182-R196): pure
 * functions over one tenant snapshot, used by the engine and the control plane. None of
 * them can allow anything: each either computes an attribute or adds a condition.
 */

const get = <T>(records: Record<string, T> | undefined, id: unknown): T | undefined =>
  records && typeof id === 'string' && Object.hasOwn(records, id) ? records[id] : undefined;
const unique = (x: readonly unknown[]) => new Set(x).size === x.length;
/** 0..KNOWLEDGE.tags distinct ids. */
export const validTags = (x: unknown): x is string[] => Array.isArray(x) && x.length <= KNOWLEDGE.tags && x.every(validId) && unique(x);
/** 0..KNOWLEDGE.residency distinct residency codes (an empty list admits no destination). */
export const validResidency = (x: unknown): x is string[] => Array.isArray(x) && x.length <= KNOWLEDGE.residency
  && x.every(c => typeof c === 'string' && RESIDENCY_CODE.test(c)) && unique(x);
export const validRegion = (x: unknown): x is string => typeof x === 'string' && RESIDENCY_CODE.test(x);
export const validModality = (x: unknown): x is Knowledge['modality'] => (MODALITIES as readonly unknown[]).includes(x);
export const validModel = (x: unknown): x is ModelRef => exactKeys(x, ['id', 'version']) && validId(x.id) && validId(x.version);
export const validEphemeral = (x: unknown): x is Ephemeral => exactKeys(x, ['sessionId', 'run', 'expiresAt'])
  && validId(x.sessionId) && validId(x.run) && safeNumber(x.expiresAt);

/**
 * Facts over a record, its container chain and every transitive source (and their
 * chains): the highest effective classification (a LEVELS index), the union of tags,
 * the intersection of every residency that is set (undefined: none is set), the
 * derivation generation (0 without sources, else 1 + the highest source generation)
 * and the session scopes of ephemeral records in the closure.
 */
export type Facts = { level: number; tags: Set<string>; residency: Set<string> | undefined; generation: number; ephemeral: Ephemeral[] };
const intersect = (a: Set<string> | undefined, b: ReadonlySet<string> | undefined): Set<string> | undefined =>
  a === undefined ? (b === undefined ? undefined : new Set(b)) : b === undefined ? a : new Set([...a].filter(x => b.has(x)));
function join(into: Facts, from: Facts, generation: number): void {
  into.level = Math.max(into.level, from.level);
  for (const t of from.tags) into.tags.add(t);
  into.residency = intersect(into.residency, from.residency);
  into.generation = Math.max(into.generation, generation);
  for (const e of from.ephemeral) if (!into.ephemeral.some(x => x.sessionId === e.sessionId && x.run === e.run && x.expiresAt === e.expiresAt)) into.ephemeral.push(e);
}
/**
 * lineageFacts() is bounded exactly like transitiveClassification() (nodes, edges, path
 * of LIMITS; cycles fail): null when anything cannot be established, including a
 * malformed tag, residency or session scope anywhere in the closure (fail closed).
 */
export function lineageFacts(state: State, root: KnowledgeMeta): Facts | null {
  const done = new Map<string, Facts>(), visiting = new Set<string>();
  let nodes = 0, edges = 0;
  const visit = (k: KnowledgeMeta, depth: number): Facts => {
    if (depth >= LIMITS.path || visiting.has(k.id)) throw new Error('cycle');
    const known = done.get(k.id);
    if (known) return known;
    const label = ++nodes <= LIMITS.nodes ? effectiveLabel(state, k) : null;
    const chain = label ? containerChain(state, k) : null;
    if (!label || !chain || !Array.isArray(k.sources)) throw new Error('label');
    const facts: Facts = { level: LEVELS.indexOf(label.classification), tags: new Set(), residency: undefined, generation: 0, ephemeral: [] };
    for (const x of [k, ...chain]) {
      if (x.tags !== undefined) { if (!validTags(x.tags)) throw new Error('tags'); for (const t of x.tags) facts.tags.add(t); }
      if (x.residency !== undefined) { if (!validResidency(x.residency)) throw new Error('residency'); facts.residency = intersect(facts.residency, new Set(x.residency)); }
    }
    if (k.ephemeral !== undefined) { if (!validEphemeral(k.ephemeral)) throw new Error('ephemeral'); facts.ephemeral.push(k.ephemeral); }
    visiting.add(k.id);
    for (const ref of k.sources) {
      if (++edges > LIMITS.edges || !validId(ref?.id)) throw new Error('budget');
      const source = get(state.knowledge, ref.id);
      if (!source || source.tenant !== k.tenant || source.version !== ref.version) throw new Error('source');
      const f = visit(source, depth + 1);
      join(facts, f, f.generation + 1);
    }
    visiting.delete(k.id); done.set(k.id, facts); return facts;
  };
  try { return visit(root, 0); } catch { return null; }
}
/** lineageFacts() over several records joined (generation: the highest); null when any cannot be established or an id is unknown. */
export function factsOf(state: State, ids: Iterable<string>): Facts | null {
  const out: Facts = { level: 0, tags: new Set(), residency: undefined, generation: 0, ephemeral: [] };
  for (const id of ids) {
    const k = get(state.knowledge, id);
    const f = k ? lineageFacts(state, k) : null;
    if (!f) return null;
    join(out, f, f.generation);
  }
  return out;
}
export const sortedTags = (tags: ReadonlySet<string>) => [...tags].sort();
export const sortedResidency = (residency: ReadonlySet<string> | undefined) => residency === undefined ? undefined : [...residency].sort();

/**
 * R182: the tenant's derivation depth limit (settings.lineageDepth, default
 * KNOWLEDGE.defaultDepth); null when the configured value is malformed (fail closed).
 */
export function lineageDepthOf(state: State, tenant: string): number | null {
  const s = get(state.settings, tenant);
  const v = s?.tenant === tenant ? s.lineageDepth : undefined;
  if (v === undefined) return KNOWLEDGE.defaultDepth;
  return Number.isSafeInteger(v) && v >= 1 && v <= KNOWLEDGE.maxDepth ? v : null;
}

/** A well-formed combination rule (R188). */
export const validCombinationRule = (r: unknown): r is CombinationRule => exactKeys(r, ['id', 'tenant', 'tagsA', 'tagsB', 'effect', 'active'], ['upliftTo'])
  && validId(r.id) && validId(r.tenant) && validTags(r.tagsA) && (r.tagsA as string[]).length >= 1 && validTags(r.tagsB) && (r.tagsB as string[]).length >= 1
  && (r.effect === 'deny' ? r.upliftTo === undefined : r.effect === 'uplift' && (r.upliftTo === undefined || LEVELS.includes(r.upliftTo as Level)))
  && typeof r.active === 'boolean';
/**
 * Combination verdict (R188) of a run whose accumulated sources carry `tags`: `deny`
 * when an active deny rule matches; `level` the classification an uplift raises a
 * derivation of level `level` to (never lower). A rule matches when the tags contain a tag
 * of `tagsA` and a tag of `tagsB`. Null when a rule of the tenant is malformed or the
 * tenant holds more than KNOWLEDGE.combinationRules (fail closed).
 */
export function combination(state: State, tenant: string, tags: ReadonlySet<string>, level: number): { deny: boolean; level: number } | null {
  let deny = false, out = level, count = 0;
  for (const r of Object.values(state.combinationRules ?? {})) {
    if (r?.tenant !== tenant) continue;
    if (++count > KNOWLEDGE.combinationRules || !validCombinationRule(r)) return null;
    if (!r.active || !r.tagsA.some(t => tags.has(t)) || !r.tagsB.some(t => tags.has(t))) continue;
    if (r.effect === 'deny') deny = true;
    else out = Math.max(out, r.upliftTo !== undefined ? LEVELS.indexOf(r.upliftTo) : Math.min(level + 1, LEVELS.length - 1));
  }
  return { deny, level: out };
}

/**
 * R187: a release to `target` of content whose effective residency is `residency`.
 * Without residency (none set anywhere in the closure) nothing is added. Otherwise the
 * target must be an active Destination profile of the tenant whose region is in the set;
 * an implicit user, a principal without profile and a destination without region fail.
 */
export function residencyAdmits(state: State, target: DestinationTarget, tenant: string, residency: ReadonlySet<string> | undefined): boolean {
  if (residency === undefined) return true;
  if (target.kind !== 'profile') return false;
  const d = get(state.destinations, target.id);
  return !!d && d.id === target.id && d.tenant === tenant && d.active === true && validRegion(d.region) && residency.has(d.region);
}

/** Audience clause: a principal satisfies it when listed as a reader or holding a reader role. */
type Clause = { readers: readonly string[]; readerRoles: readonly string[] };
const narrower = (d: Clause, c: Clause) => d.readers.every(x => c.readers.includes(x)) && d.readerRoles.every(x => c.readerRoles.includes(x));
/**
 * R192 (no write-down): placing derived content with its own audience `own` and
 * classification `classification` into `container` must not produce a static label that
 * admits a principal the static label of a source does not admit. For every source S and
 * every audience clause c of S's effective label (its own ACL and each ancestor
 * container's), some clause of the placed record (its own ACL or an ancestor container's)
 * must be at least as narrow as c (readers and reader roles subsets of c's); the placed
 * record's classification and projects must be at least S's. True when the placement is
 * allowed; false when it would write down or a label cannot be established.
 */
export function placementAllowed(state: State, tenant: string, sources: readonly KnowledgeMeta[], own: Clause & { projects: readonly string[] }, classification: Level, container: string): boolean {
  const chain = containerChain(state, { tenant, container });
  if (!chain || !chain.length) return false;
  const clauses: Clause[] = [own, ...chain];
  const level = Math.max(LEVELS.indexOf(classification), ...chain.map(c => LEVELS.indexOf(c.classification)));
  const projects = new Set([...own.projects, ...chain.flatMap(c => c.projects)]);
  for (const s of sources) {
    const label = effectiveLabel(state, s);
    if (!label || LEVELS.indexOf(label.classification) > level || !label.projects.every(p => projects.has(p))) return false;
    if (!label.audiences.every(c => clauses.some(d => narrower(d, c)))) return false;
  }
  return true;
}

/**
 * R190: the session scope of a derivation. Every ephemeral record in the closure of
 * the sources must belong to one session of this run; a requested session must be that
 * session. The result expires at the earliest of the sources' expiry, the requested
 * lifetime and the run's expiry. `ok: false` carries the audited reason.
 */
export function sessionOf(facts: Facts, run: string, now: number, runExpiresAt: number, requested?: { sessionId: string; ttlMs?: number }):
  { ok: true; ephemeral?: Ephemeral } | { ok: false; reason: string } {
  if (requested !== undefined && (!validId(requested.sessionId) || (requested.ttlMs !== undefined
    && !(Number.isSafeInteger(requested.ttlMs) && requested.ttlMs >= 1000 && requested.ttlMs <= KNOWLEDGE.ephemeralMaxTtlMs)))) return { ok: false, reason: 'DEFERRED:INVALID_REQUEST' };
  const sessions = new Set(facts.ephemeral.map(e => e.sessionId));
  if (requested) sessions.add(requested.sessionId);
  if (!sessions.size) return { ok: true };
  if (sessions.size > 1 || facts.ephemeral.some(e => e.run !== run)) return { ok: false, reason: 'DENIED:OUT_OF_SCOPE' };
  const expiresAt = Math.min(runExpiresAt, ...facts.ephemeral.map(e => e.expiresAt), ...(requested ? [now + (requested.ttlMs ?? KNOWLEDGE.ephemeralTtlMs)] : []));
  if (!safeNumber(expiresAt) || expiresAt <= now) return { ok: false, reason: 'DENIED:EXPIRED' };
  return { ok: true, ephemeral: { sessionId: [...sessions][0]!, run, expiresAt } };
}

/**
 * Numeric-aware version order for model recalls (R191): dot- or dash-separated
 * segments, numeric segments compared as numbers, others as strings; a numeric segment
 * sorts before a non-numeric one; a prefix sorts first.
 */
export function compareVersions(a: string, b: string): number {
  const x = a.split(/[.-]/), y = b.split(/[.-]/);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i], q = y[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const m = /^\d{1,15}$/.test(p), n = /^\d{1,15}$/.test(q);
    if (m && n) { if (Number(p) !== Number(q)) return Number(p) < Number(q) ? -1 : 1; continue; }
    if (m !== n) return m ? -1 : 1;
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}
/** A model version range: inclusive bounds, either may be absent (open). */
export type VersionRange = { from?: string; to?: string };
export const validRange = (r: unknown): r is VersionRange => exactKeys(r, [], ['from', 'to']) && (r.from === undefined || validId(r.from)) && (r.to === undefined || validId(r.to))
  && (r.from === undefined || r.to === undefined || compareVersions(r.from as string, r.to as string) <= 0);
export const inRange = (version: string, r: VersionRange) => (r.from === undefined || compareVersions(version, r.from) >= 0) && (r.to === undefined || compareVersions(version, r.to) <= 0);

/** Combination window bounds (0.6b, R188), ms: default and minimum = the maximum context lifetime. */
export const COMBINATION_WINDOW = { defaultMs: 300_000, maxMs: 30 * 86_400_000 } as const;
