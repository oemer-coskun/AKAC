// Generators of random AKAC worlds for differential testing (tests/differential-fuzz.test.ts).
import fc from 'fast-check';
import { ACTIONS, DESTINATION_CLASSES, LEVELS, emptyState } from '../reference/types.ts';
import type { State } from '../reference/types.ts';
import { RUNTIME_DOMAINS } from '../reference/decision.ts';
import { json } from './differential-harness.ts';
import type { J } from './differential-harness.ts';

export const NOW = 1_800_000_000_000;
const R = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5'], P = ['p1', 'p2'], K = ['k0', 'k1', 'k2', 'k3', 'k4', 'k5'];
// Knowledge semantics (0.6, ADR-022): tags, residency codes, modalities, session scopes.
const T = ['t1', 't2', 't3'];
/** Mostly well-formed; a malformed value is rare, since one anywhere in a closure denies the whole closure. */
const pickBy = <V>(table: [number, V][]) => fc.integer({ min: 0, max: 99 }).map(n => { let acc = 0; for (const [p, v] of table) { acc += p; if (n < acc) return v; } return table.at(-1)![1]; });
const tags = pickBy<unknown>([[55, undefined], [12, ['t1']], [10, ['t2']], [8, ['t1', 't3']], [8, ['t3']], [5, ['t2', 't3']], [1, ['bad tag']], [1, 't1']]);
const residency = pickBy<unknown>([[75, undefined], [10, ['DE']], [7, ['DE', 'FR']], [5, ['US']], [2, []], [1, ['de']]]);
const ephemeral = fc.constantFrom<unknown>(undefined, undefined, undefined, undefined, undefined, undefined,
  { sessionId: 's1', run: 'g0', expiresAt: NOW + 60_000 }, { sessionId: 's2', run: 'g0', expiresAt: NOW + 60_000 }, { sessionId: 's1', run: 'g1', expiresAt: NOW + 60_000 },
  { sessionId: 's1', run: 'g0', expiresAt: NOW }, { sessionId: 's1', run: 'g0' });
const ACTORS = ['u', 'a', 'u2', 'a2', 'svc', 'adm'], D = ['d1', 'd2', 'd3'], PURPOSES = ['work', 'other'];
const likely = (p: number) => fc.integer({ min: 0, max: 99 }).map(n => n < p);
const tenant = fc.integer({ min: 0, max: 99 }).map(n => n < 90 ? 'acme' : 'other');
const level = fc.constantFrom(...LEVELS);
const weird = fc.constantFrom<unknown>(null, 'x', 7, 1.5, [], {}, true, 'r0', ['r0', 7], -1);
const maybe = <T>(arb: fc.Arbitrary<T>, p = 50) => fc.tuple(likely(p), arb).map(([on, v]) => on ? v : undefined);

const role = fc.record({ tenant, inherits: fc.subarray(R, { maxLength: 3 }), active: likely(90), acyclic: likely(85) });
const actor = fc.record({ tenant, roles: fc.subarray(R, { maxLength: 4 }), clearance: level, projects: fc.subarray(P), active: likely(92),
  destination: maybe(fc.constantFrom(...D, 'missing', 'tool'), 25) });
const group = fc.record({ tenant, members: fc.subarray(ACTORS), roles: fc.subarray(R, { maxLength: 3 }), active: likely(70) });
const constraint = fc.record({ tenant, kind: fc.constantFrom('static', 'dynamic', 'dynamic', 'static', 'bogus'), roles: fc.subarray(R, { minLength: 1, maxLength: 4 }),
  cardinality: fc.constantFrom(2, 2, 3, 1), keep: likely(35) });
const container = fc.record({ tenant, classification: level, readerRoles: fc.subarray(R, { maxLength: 3 }), readers: fc.subarray(['u', 'a', 'u2'], { maxLength: 2 }),
  projects: fc.subarray(P, { maxLength: 1 }), active: likely(90), clean: likely(80), parent: fc.constantFrom('default', 'default', 'default', 'none', 'self', 'missing', 'f3'),
  tags, residency });
const knowledge = fc.record({ tenant, kind: fc.constantFrom('document', 'memory', 'artifact'), origin: fc.constantFrom('system', 'human', 'model', 'model', 'bogus'),
  classification: level, projects: fc.subarray(P, { maxLength: 1 }), readerRoles: fc.subarray(R, { maxLength: 3 }), readers: fc.subarray(['u', 'a', 'u2', 'svc'], { maxLength: 2 }),
  sources: fc.subarray(K, { maxLength: 3 }), staleSource: likely(8), forward: likely(4), active: likely(92), version: fc.constantFrom(1, 1, 1, 2, 0),
  container: fc.constantFrom(undefined, undefined, 'kb', 'f1', 'f2', 'f3', 'missing'),
  // '#unreadable' (0.6b): the internal flag of a record whose content could not be opened, instead of a lifecycle.
  lifecycle: fc.constantFrom(undefined, undefined, undefined, undefined, undefined, 'quarantined', 'erased', 'bogus', '#unreadable'),
  accessExpiresAt: fc.constantFrom(undefined, undefined, undefined, NOW + 1000, NOW, NOW - 1), clean: likely(75),
  tags, residency, ephemeral, modality: fc.constantFrom<unknown>(undefined, undefined, 'text', 'image') });
const grant = fc.record({ actions: fc.subarray([...ACTIONS], { maxLength: 6 }), resources: fc.constantFrom(['*'], ['*'], ['k0', 'k1', 'k2'], ['k3'], []),
  purposes: fc.constantFrom(['work'], ['work', 'other'], ['*'], ['other']), notBefore: fc.constantFrom(NOW - 1000, NOW - 1000, NOW - 2000, NOW + 1),
  expiresAt: fc.constantFrom(NOW + 3_600_000, NOW + 3_600_000, NOW + 1_000_000, NOW), active: likely(93),
  activeRoles: maybe(fc.subarray([...R, 'missing'], { maxLength: 3 }), 25),
  destinations: maybe(fc.subarray([...DESTINATION_CLASSES, ...D, 'missing'], { minLength: 1, maxLength: 3 }), 35),
  maxResults: maybe(fc.constantFrom(1, 2, 3, 64, 0, 65), 15), agent: fc.constantFrom('a', 'a', 'a', 'a2'), inherit: likely(70), clean: likely(75) });
const destination = fc.record({ tenant, class: fc.constantFrom(...DESTINATION_CLASSES), maxClassification: level, purposes: fc.subarray(PURPOSES), active: likely(85),
  region: fc.constantFrom<unknown>(undefined, 'DE', 'DE', 'FR', 'US', 'de') });
const combinationRule = fc.record({ tagsA: fc.subarray(T, { minLength: 1, maxLength: 2 }), tagsB: fc.subarray(T, { minLength: 1, maxLength: 2 }),
  effect: pickBy([[45, 'deny'], [53, 'uplift'], [2, 'bogus']]), upliftTo: fc.constantFrom<unknown>(undefined, undefined, 'confidential', 'restricted', 'public'), active: likely(80) });
const runtimeProfile = fc.record({ tenant, classification: level, destinationClass: maybe(fc.constantFrom(...DESTINATION_CLASSES), 35),
  profiles: fc.record(Object.fromEntries(RUNTIME_DOMAINS.map(d => [d, maybe(fc.constantFrom('deny-all', 'internal-only', 'read-only'), 45)])) as Record<string, fc.Arbitrary<string | undefined>>),
  active: likely(85), malformed: likely(4) });
const corruption = fc.tuple(fc.constantFrom('actors', 'grants', 'knowledge', 'roles', 'groups', 'containers', 'constraints', 'destinations', 'runtimeProfiles'),
  fc.nat(5), fc.constantFrom('tenant', 'roles', 'active', 'readerRoles', 'readers', 'projects', 'sources', 'classification', 'parent', 'inherits', 'members',
    'actions', 'resources', 'kind', 'version', 'cardinality', 'destinations', 'activeRoles', 'profiles', 'purposes', 'id', 'maxResults', 'clearance'), weird);

export const worldArb = fc.record({
  roles: fc.array(role, { maxLength: 5 }), actors: fc.array(actor, { minLength: 6, maxLength: 6 }), kinds: fc.integer({ min: 0, max: 99 }).map(n => n < 94 ? 0 : n < 97 ? 1 : 2),
  groups: fc.array(group, { maxLength: 3 }), constraints: fc.array(constraint, { maxLength: 2 }), containers: fc.array(container, { minLength: 4, maxLength: 4 }),
  knowledge: fc.array(knowledge, { minLength: 3, maxLength: 6 }), grants: fc.array(grant, { minLength: 1, maxLength: 4 }),
  destinations: fc.array(destination, { maxLength: 3 }), runtimeProfiles: fc.array(runtimeProfile, { maxLength: 3 }),
  combinationRules: fc.array(combinationRule, { maxLength: 2 }).chain(r => pickBy([[50, []], [50, r]])),
  /** Half of the worlds carry no 0.6 knowledge attributes at all, so the 0.5 rules keep their share of allows. */
  semantic: likely(50), lineageDepth: pickBy<unknown>([[55, undefined], [12, 1], [12, 2], [8, 3], [10, 16], [3, 0]]),
  corruptions: fc.array(corruption, { maxLength: 2 }).map(x => x), corrupt: likely(15),
  epoch: fc.constantFrom(0, 0, 1), benign: likely(60), tidyContainers: likely(85),
  request: fc.record({ grant: fc.constantFrom(0, 0, 0, 0, 0, 1, 1, 2, 3), action: fc.constantFrom(...ACTIONS), resource: fc.constantFrom('k0', 'k1', 'k2', 'k0', 'k1', 'k2', 'k3', 'k4', 'missing'),
    purpose: fc.constantFrom('work', 'work', 'other') }),
  evaluateDestination: fc.constantFrom<string | undefined>(undefined, undefined, 'd1', 'd2', 'd3', 'tool', 'missing', 'Bad id!'),
  steps: fc.record({ extra: maybe(fc.constantFrom(...K), 40), then: fc.constantFrom('derive', 'memory', 'release', 'release', 'delegate', 'open'),
    recipient: fc.constantFrom('u', 'u2', 'svc', 'adm', 'a', 'missing'), action: fc.constantFrom<'share' | 'export'>('share', 'export'), child: grant,
    unenforceable: fc.constantFrom<unknown>(undefined, undefined, undefined, ['runtime_profile'], ['no_persist'], ['bogus']),
    options: fc.record({ modality: fc.constantFrom<unknown>(undefined, undefined, 'code', 'hologram'),
      session: fc.constantFrom<unknown>(undefined, undefined, { id: 's1' }, { id: 's2', ttlMs: 5000 }, { id: 'bad id!' }),
      container: fc.constantFrom<unknown>(undefined, undefined, undefined, 'kb', 'f1', 'f2', 'missing') }),
    close: fc.constantFrom<unknown>(undefined, undefined, undefined, 's1', 's2') })
});
export type World = typeof worldArb extends fc.Arbitrary<infer T> ? T : never;

/** The generated world as an AKAC state (tenant acme, principals u/a, delegation chain g0..gN). */
export function build(w: World): State {
  const s = emptyState();
  s.epochs = { acme: w.epoch };
  w.roles.forEach(({ acyclic, ...r }, i) => { s.roles[`r${i}`] = { id: `r${i}`, ...r, inherits: acyclic ? r.inherits.filter(x => R.indexOf(x) > i) : r.inherits }; });
  ACTORS.forEach((id, i) => {
    const a = w.actors[i]!;
    const kind = id === 'a' || id === 'a2' ? 'agent' : id === 'svc' ? 'service' : 'user';
    s.actors[id] = { id, tenant: id === 'u' || id === 'a' ? 'acme' : a.tenant, kind: w.kinds === 1 && id === 'a' ? 'user' : w.kinds === 2 && id === 'u' ? 'service' : kind,
      roles: id === 'adm' ? ['security-admin'] : a.roles, clearance: a.clearance, projects: a.projects, active: a.active,
      ...(a.destination !== undefined && id !== 'u' && id !== 'a' ? { destination: a.destination } : {}) };
  });
  w.groups.forEach((g, i) => { s.groups[`grp${i}`] = { id: `grp${i}`, ...g }; });
  w.constraints.forEach(({ keep, ...c }, i) => { if (keep || !w.benign) s.constraints[`sod${i}`] = { id: `sod${i}`, ...(c as J) }; });
  const ids = ['kb', 'f1', 'f2', 'f3'];
  w.containers.forEach((c, i) => {
    const id = ids[i]!;
    const parent = c.parent === 'none' ? undefined : c.parent === 'self' ? id : c.parent === 'default' ? (i === 0 ? undefined : ids[i - 1]) : c.parent;
    const { parent: _p, clean: _c, tags: t, residency: res, ...rest } = c;
    s.containers[id] = { id, kind: i === 0 ? 'knowledge-base' : 'folder', ...rest, ...(parent !== undefined ? { parent } : {}),
      ...(t !== undefined ? { tags: t } : {}), ...(res !== undefined ? { residency: res } : {}) } as J;
  });
  w.knowledge.forEach((k, i) => {
    const id = K[i]!;
    const earlier = k.sources.filter(src => K.indexOf(src) < i || (k.forward && K.indexOf(src) < w.knowledge.length));
    const { staleSource, forward: _f, lifecycle, accessExpiresAt, container: box, clean: _c, tags: t, residency: res, ephemeral: e, modality: m, ...rest } = k;
    s.knowledge[id] = { id, ...rest, content: `Synthetic note ${id}.`, sources: earlier.map(src => ({ id: src, version: staleSource ? 2 : 1 })),
      ...(box !== undefined ? { container: box } : {}), ...(lifecycle === '#unreadable' ? { unreadable: true } : lifecycle !== undefined ? { lifecycle } : {}),
      ...(accessExpiresAt !== undefined ? { accessExpiresAt } : {}), ...(t !== undefined ? { tags: t } : {}), ...(res !== undefined ? { residency: res } : {}),
      ...(e !== undefined ? { ephemeral: e } : {}), ...(m !== undefined ? { modality: m } : {}) } as J;
  });
  w.grants.forEach((g, i) => {
    const { activeRoles, destinations, maxResults, agent, inherit, clean: _c, ...rest } = g;
    // Mostly a well-formed attenuation of the parent (same scope and time), so that the narrowing rules decide.
    const parent = i > 0 ? s.grants[`g${i - 1}`] : undefined;
    if (parent && inherit) Object.assign(rest, { actions: [...parent.actions], resources: [...parent.resources], purposes: [...parent.purposes],
      notBefore: parent.notBefore, expiresAt: parent.expiresAt });
    s.grants[`g${i}`] = { id: `g${i}`, tenant: 'acme', subject: 'u', agent: i === 0 ? 'a' : agent, ...rest,
      ...(i > 0 ? { parent: `g${i - 1}` } : {}), ...(activeRoles !== undefined ? { activeRoles } : {}),
      ...(destinations !== undefined ? { destinations } : {}), ...(maxResults !== undefined ? { maxResults } : {}) } as J;
  });
  w.destinations.forEach(({ region, ...d }, i) => { s.destinations![D[i]!] = { id: D[i]!, ...d, ...(region !== undefined ? { region } : {}) } as J; });
  s.combinationRules = {};
  if (!w.semantic) {
    for (const k of Object.values(s.knowledge) as J[]) { delete k.tags; delete k.residency; delete k.ephemeral; delete k.modality; }
    for (const c of Object.values(s.containers) as J[]) { delete c.tags; delete c.residency; }
    for (const d of Object.values(s.destinations ?? {}) as J[]) delete d.region;
  }
  if (w.semantic) w.combinationRules.forEach(({ upliftTo, ...r }, i) => { s.combinationRules![`cr${i}`] = { id: `cr${i}`, tenant: 'acme', ...r, ...(upliftTo !== undefined ? { upliftTo } : {}) } as J; });
  s.settings = w.semantic && w.lineageDepth !== undefined ? { acme: { id: 'acme', tenant: 'acme', lineageDepth: w.lineageDepth } as J } : {};
  w.runtimeProfiles.forEach((p, i) => {
    const { malformed, destinationClass, profiles, ...rest } = p;
    const named = Object.fromEntries(Object.entries(profiles).filter(([, v]) => v !== undefined));
    s.runtimeProfiles![`rp${i}`] = { id: `rp${i}`, ...rest, profiles: Object.keys(named).length ? named : { network: 'deny-all' },
      ...(destinationClass !== undefined ? { destinationClass } : {}), ...(malformed ? { extra: true } : {}) } as J;
  });
  // Benign worlds: the principals can read most records, so the rules decide rather than a missing role.
  if (w.benign) {
    for (const id of ['u', 'a']) Object.assign(s.actors[id]!, { roles: [...new Set(['r0', ...s.actors[id]!.roles])], clearance: 'restricted', projects: [...P], active: true });
    if (s.roles.r0) Object.assign(s.roles.r0, { tenant: 'acme', active: true });
    for (const k of Object.values(s.knowledge)) { k.readerRoles = [...new Set(['r0', ...k.readerRoles])]; if (k.tenant !== 'acme' && k.id < 'k3') k.tenant = 'acme'; }
    for (const c of Object.values(s.containers)) Object.assign(c, { readerRoles: [...new Set(['r0', ...c.readerRoles])], active: true, tenant: 'acme' });
    // Most records of a benign world are well-formed; the rest keep their generated defects.
    w.knowledge.forEach((k, i) => {
      if (!k.clean) return;
      const r = s.knowledge[K[i]!] as J;
      Object.assign(r, { active: true, version: 1, origin: r.kind === 'document' ? 'system' : 'model', tenant: 'acme' });
      delete r.lifecycle; delete r.unreadable; delete r.accessExpiresAt;
      r.sources = r.sources.map((x: J) => ({ id: x.id, version: 1 }));
    });
    w.containers.forEach((c, i) => {
      const r = s.containers[['kb', 'f1', 'f2', 'f3'][i]!] as J;
      if (c.clean || w.tidyContainers) { if (i === 0) delete r.parent; else r.parent = ['kb', 'f1', 'f2'][i - 1]; }
    });
    w.grants.forEach((g, i) => {
      const r = s.grants[`g${i}`] as J;
      if (!g.clean) return;
      if (r.activeRoles) r.activeRoles = r.activeRoles.filter((x: string) => s.actors.u!.roles.includes(x));
      if (r.maxResults !== undefined && (r.maxResults < 1 || r.maxResults > 64)) delete r.maxResults;
      r.agent = 'a';
    });
    const g0 = s.grants.g0!;
    Object.assign(g0, { resources: ['*'], purposes: ['work', 'other'], active: true, notBefore: NOW - 1000, expiresAt: NOW + 3_600_000,
      actions: [...new Set([...g0.actions, w.request.action, 'read', ...(w.steps.then === 'derive' ? ['derive'] : w.steps.then === 'memory' ? ['derive', 'write_memory']
        : w.steps.then === 'release' ? [w.steps.action] : [])])] });
    w.grants.forEach((g, i) => {
      const parent = s.grants[`g${i - 1}`], r = s.grants[`g${i}`]!;
      if (i > 0 && g.inherit && parent) Object.assign(r, { actions: [...parent.actions], resources: [...parent.resources], purposes: [...parent.purposes],
        notBefore: parent.notBefore, expiresAt: parent.expiresAt });
    });
  }
  if (w.corrupt) {
    for (const [collection, n, field, value] of w.corruptions) {
      const records = Object.values((s as unknown as Record<string, Record<string, J>>)[collection] ?? {});
      if (records.length) records[n % records.length][field] = value;
    }
  }
  return s;
}

/**
 * A gateway holds session-scoped records in memory only while they are well-formed, of its tenant and unexpired (R190):
 * the step sequence starts from that view, so both implementations see the same records.
 */
function live(state: J): J {
  const s = json(state);
  for (const [id, k] of Object.entries(s.knowledge as Record<string, J>)) {
    const e = k?.ephemeral;
    if (e === undefined) continue;
    if (k.tenant !== 'acme' || !e || typeof e !== 'object' || typeof e.sessionId !== 'string' || typeof e.run !== 'string'
      || !Number.isSafeInteger(e.expiresAt) || e.expiresAt <= NOW) delete s.knowledge[id];
  }
  return s;
}
/** Three runner-contract cases per world: decide, evaluate (optionally naming a destination) and a gateway sequence. */
export function casesOf(w: World): J[] {
  const state = json(build(w));
  const binding = { tenant: 'acme', subject: 'u', agent: 'a', grant: `g${w.request.grant % w.grants.length}` };
  const resource = w.benign && !Object.hasOwn(state.knowledge, w.request.resource) ? 'k0' : w.request.resource;
  const request = { binding, action: w.request.action, resource, purpose: w.request.purpose, now: NOW };
  const st = w.steps, resources = [resource, ...(st.extra !== undefined ? [st.extra] : [])];
  const { inherit, clean: _c, ...fields } = st.child;
  const parent = state.grants[binding.grant] as J;
  // A benign delegation keeps the parent's scope and time; the generated run fields still widen or narrow it.
  const scope = w.benign && inherit && parent ? { actions: parent.actions, resources: parent.resources, purposes: parent.purposes,
    notBefore: parent.notBefore, expiresAt: parent.expiresAt } : {};
  const child = { id: 'child', tenant: 'acme', subject: 'u', parent: binding.grant, ...fields, ...scope, agent: w.benign ? 'a' : 'a2' };
  const options = w.semantic ? Object.fromEntries(Object.entries(st.options).filter(([, v]) => v !== undefined)) : {};
  const next = st.then === 'derive' ? { op: 'derive', binding, context: '$c', content: 'Synthetic derived text.', kind: 'artifact', options, save: 'd' }
    : st.then === 'memory' ? { op: 'derive', binding, context: '$c', content: 'Synthetic memory.', kind: 'memory', options, save: 'd' }
    : st.then === 'release' ? { op: 'release', binding, context: '$c', recipient: st.recipient, content: 'Synthetic answer.', action: st.action }
    : st.then === 'delegate' ? { op: 'delegate', binding, child: json(child) }
    : { op: 'open', binding, resources: [...K].reverse().slice(0, 2), purpose: w.request.purpose };
  return [
    { op: 'decide', state, request },
    { op: 'evaluate', state: live(state), request, ...(w.evaluateDestination !== undefined ? { destination: w.evaluateDestination } : {}) },
    { op: 'steps', state: live(state), now: NOW, ...(st.unenforceable !== undefined ? { unenforceable: st.unenforceable } : {}), steps: [
      { op: 'open', binding, resources, purpose: w.request.purpose, save: 'c' }, next,
      ...(st.close !== undefined && w.semantic ? [{ op: 'close', binding, session: st.close }] : []),
      ...(st.then === 'derive' || st.then === 'memory' ? [{ op: 'open', binding, resources: ['$d'], purpose: w.request.purpose }] : [])] }
  ];
}

