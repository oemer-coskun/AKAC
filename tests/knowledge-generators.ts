// Generators of knowledge-semantics worlds over the kbFixture company (0.6, ADR-022): used by the
// differential fuzz (tests/differential-knowledge.test.ts) and the monotonicity property (tests/knowledge-monotonicity.test.ts).
import fc from 'fast-check';
import { json } from './differential-harness.ts';
import type { J } from './differential-harness.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';

export const NOW = 1_800_000_000_000;
export const DOCS = ['handbook', 'strategy', 'project-alpha', 'staff-faq', 'board-notes', 'm1', 'm2', 'm3'];
const tagSet = fc.constantFrom<unknown>(undefined, undefined, ['fin'], ['audit'], ['fin', 'hr'], ['hr'], ['bad tag']);
const codes = fc.constantFrom<unknown>(undefined, undefined, undefined, ['DE'], ['DE', 'FR'], ['US'], []);
export const world = fc.record({
  docTags: fc.array(tagSet, { minLength: 8, maxLength: 8 }), docResidency: fc.array(codes, { minLength: 8, maxLength: 8 }),
  kbTags: tagSet, kbResidency: codes,
  rules: fc.array(fc.record({ tagsA: fc.subarray(['fin', 'hr'], { minLength: 1 }), tagsB: fc.subarray(['audit', 'hr'], { minLength: 1 }),
    effect: fc.constantFrom('deny', 'uplift', 'uplift'), upliftTo: fc.constantFrom<unknown>(undefined, 'restricted', 'internal'), active: fc.boolean() }), { maxLength: 2 }),
  depth: fc.constantFrom<unknown>(undefined, 1, 2, 3, 0),
  regions: fc.array(fc.constantFrom<unknown>(undefined, 'DE', 'FR', 'US'), { minLength: 3, maxLength: 3 }),
  who: fc.constantFrom<'chief' | 'lead' | 'intern'>('chief', 'chief', 'lead', 'intern'),
  first: fc.subarray(DOCS, { minLength: 1, maxLength: 3 }), second: fc.subarray(DOCS, { maxLength: 2 }),
  kind: fc.constantFrom('memory', 'artifact'),
  modality: fc.constantFrom<unknown>(undefined, 'image', 'text'), session: fc.constantFrom<unknown>(undefined, undefined, { id: 's1' }, { id: 's2', ttlMs: 60_000 }),
  container: fc.constantFrom<unknown>(undefined, undefined, 'kb-corporate', 'f-executive', 'f-vault'),
  recipient: fc.constantFrom('r-de', 'r-fr', 'r-us', 'intern', 'chief'), close: fc.boolean(), derivedAgain: fc.boolean()
});
export type World = typeof world extends fc.Arbitrary<infer T> ? T : never;

export function caseOf(w: World): J {
  const s = kbFixture(NOW) as J;
  const mem = (id: string, src: string) => ({ id, tenant: 'acme', version: 1, kind: 'memory', origin: 'model', content: `Synthetic ${id}.`, classification: 'public',
    projects: [], readerRoles: ['staff'], readers: [], sources: [{ id: src, version: 1 }], active: true });
  s.knowledge.m1 = mem('m1', 'handbook'); s.knowledge.m2 = mem('m2', 'm1'); s.knowledge.m3 = mem('m3', 'm2');
  DOCS.forEach((id, i) => {
    if (w.docTags[i] !== undefined) s.knowledge[id].tags = w.docTags[i];
    if (w.docResidency[i] !== undefined) s.knowledge[id].residency = w.docResidency[i];
  });
  if (w.kbTags !== undefined) s.containers['kb-corporate'].tags = w.kbTags;
  if (w.kbResidency !== undefined) s.containers['kb-corporate'].residency = w.kbResidency;
  s.combinationRules = Object.fromEntries(w.rules.map((r, i) => [`cr${i}`, { id: `cr${i}`, tenant: 'acme', tagsA: r.tagsA, tagsB: r.tagsB, effect: r.effect, active: r.active,
    ...(r.effect === 'uplift' && r.upliftTo !== undefined ? { upliftTo: r.upliftTo } : {}) }]));
  s.settings = w.depth === undefined ? {} : { acme: { id: 'acme', tenant: 'acme', lineageDepth: w.depth } };
  ['r-de', 'r-fr', 'r-us'].forEach((id, i) => {
    s.destinations[`d-${id}`] = { id: `d-${id}`, tenant: 'acme', class: 'internal-user', maxClassification: 'restricted', purposes: ['work'], active: true,
      ...(w.regions[i] !== undefined ? { region: w.regions[i] } : {}) };
    s.actors[id] = { id, tenant: 'acme', kind: 'user', roles: ['staff', 'executive', 'project'], clearance: 'restricted', projects: ['alpha'], active: true, destination: `d-${id}` };
  });
  const binding = bindings[w.who];
  const options = { ...(w.modality !== undefined ? { modality: w.modality } : {}), ...(w.session !== undefined ? { session: w.session } : {}),
    ...(w.container !== undefined ? { container: w.container } : {}) };
  const steps: J[] = [
    { op: 'open', binding, resources: w.first, purpose: 'work', save: 'c' },
    ...(w.second.length ? [{ op: 'open', binding, resources: w.second, purpose: 'work', save: 'c' }] : []),
    { op: 'derive', binding, context: '$c', content: 'Synthetic derived text.', kind: w.kind, options, save: 'd' },
    { op: 'release', binding, context: '$c', recipient: w.recipient, content: 'Synthetic answer.', action: 'share' },
    ...(w.close && w.session !== undefined ? [{ op: 'close', binding, session: (w.session as { id: string }).id }] : []),
    { op: 'open', binding, resources: ['$d'], purpose: 'work', save: 'e' },
    ...(w.derivedAgain ? [{ op: 'derive', binding, context: '$e', content: 'Synthetic second generation.', kind: 'artifact', options: {} }] : [])
  ];
  return { op: 'steps', state: json(s), now: NOW, model: { id: 'synthetic-model', version: '1.0' }, steps };
}

