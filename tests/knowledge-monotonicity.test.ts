// R196 (0.6, ADR-022): adding a restriction never turns a denial into an allow. For random
// knowledge worlds and a random added restriction (a tag, a residency, a combination rule, a narrower
// container audience, a lower depth limit, a risk cap), every decide() that denied before still denies,
// and a gateway sequence is never allowed further than before: at the first step whose effect differs,
// the restricted world denies and the original allowed.
import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { decide } from '../reference/policy.ts';
import { ACTIONS } from '../reference/types.ts';
import type { State } from '../reference/types.ts';
import { bindings } from '../examples/fixture.ts';
import { evaluateTs } from './differential-harness.ts';
import type { J } from './differential-harness.ts';
import { DOCS, NOW, caseOf, world } from './knowledge-generators.ts';

const RUNS = Number(process.env.AKAC_MONOTONE_RUNS ?? 300);
const SEED = Number(process.env.AKAC_FUZZ_SEED ?? 20260929);
const TARGETS = [...DOCS, 'kb-corporate', 'f-executive', 'f-vault'];
const restriction = fc.oneof(
  fc.record({ kind: fc.constant('tag' as const), target: fc.constantFrom(...TARGETS), tag: fc.constantFrom('fin', 'audit', 'hr') }),
  fc.record({ kind: fc.constant('residency' as const), target: fc.constantFrom(...TARGETS), codes: fc.subarray(['DE', 'FR', 'US']) }),
  fc.record({ kind: fc.constant('rule' as const), tagsA: fc.subarray(['fin', 'hr'], { minLength: 1 }), tagsB: fc.subarray(['audit', 'hr'], { minLength: 1 }),
    effect: fc.constantFrom('deny', 'uplift'), upliftTo: fc.constantFrom<undefined | string>(undefined, 'confidential', 'restricted') }),
  fc.record({ kind: fc.constant('activate' as const) }),
  fc.record({ kind: fc.constant('audience' as const), container: fc.constantFrom('kb-corporate', 'f-executive', 'f-vault'), drop: fc.constantFrom('staff', 'executive'),
    project: fc.boolean() }),
  fc.record({ kind: fc.constant('depth' as const), by: fc.integer({ min: 1, max: 3 }) }),
  fc.record({ kind: fc.constant('risk' as const), principal: fc.constantFrom('chief', 'lead', 'intern', 'chief-agent'), level: fc.constantFrom('medium', 'high', 'critical') })
);
type Restriction = typeof restriction extends fc.Arbitrary<infer T> ? T : never;

/** Applies one restriction to a snapshot (in place). Only ever narrows. */
function restrict(s: J, r: Restriction): void {
  const record = (id: string) => s.knowledge[id] ?? s.containers[id];
  switch (r.kind) {
    case 'tag': { const x = record(r.target); if (Array.isArray(x.tags) && x.tags.includes('bad tag')) return; x.tags = [...new Set([...(Array.isArray(x.tags) ? x.tags : []), r.tag])]; return; }
    case 'residency': { const x = record(r.target); x.residency = Array.isArray(x.residency) ? x.residency.filter((c: string) => r.codes.includes(c)) : [...r.codes]; return; }
    case 'rule': s.combinationRules.added = { id: 'added', tenant: 'acme', tagsA: r.tagsA, tagsB: r.tagsB, effect: r.effect, active: true,
      ...(r.effect === 'uplift' && r.upliftTo ? { upliftTo: r.upliftTo } : {}) }; return;
    case 'activate': for (const rule of Object.values(s.combinationRules) as J[]) rule.active = true; return;
    case 'audience': { const c = s.containers[r.container]; c.readerRoles = c.readerRoles.filter((x: string) => x !== r.drop); if (r.project) c.projects = [...new Set([...c.projects, 'alpha'])]; return; }
    case 'depth': { const current = s.settings.acme?.lineageDepth ?? 16; if (typeof current !== 'number' || current < 1) return;
      s.settings.acme = { id: 'acme', tenant: 'acme', lineageDepth: Math.max(1, current - r.by) }; return; }
    case 'risk': (s.riskSignals ??= {})[`sig-${r.principal}`] = { id: `sig-${r.principal}`, tenant: 'acme', principal: r.principal, level: r.level, source: 'admin',
      issuedAt: NOW - 1000, expiresAt: NOW + 3_600_000 }; return;
  }
}

test('R196: an added restriction never turns a denial into an allow (random worlds; decide and gateway sequences)', { timeout: 600_000 }, async () => {
  let narrowed = 0, compared = 0, targetNarrowed = 0;
  await fc.assert(fc.asyncProperty(world, restriction, async (w, r) => {
    const base = caseOf(w), narrow = structuredClone(base);
    restrict(narrow.state, r);
    // decide(): every principal, record and action.
    for (const who of ['chief', 'lead', 'intern'] as const) for (const resource of DOCS) for (const action of ACTIONS) {
      const q = { binding: bindings[who], resource, action, purpose: 'work', now: NOW };
      const before = decide(base.state as State, q), after = decide(narrow.state as State, q);
      compared++;
      if (after.effect === 'allow' && before.effect !== 'allow') throw new Error(`decide widened by ${JSON.stringify(r)}: ${who} ${action} ${resource}`);
      if (before.effect === 'allow' && after.effect !== 'allow') narrowed++;
    }
    // Gateway sequence: up to the first difference the restricted world may only deny more.
    const a = await evaluateTs(base) as J[], b = await evaluateTs(narrow) as J[];
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i].effect === b[i].effect) continue;
      // The one intended exception (R196): narrowing the audience of a placement's TARGET container can make the placement
      // admissible (R192); the placed record then admits fewer principals, so no one gains access.
      const step = base.steps[i];
      if (b[i].effect === 'allow' && r.kind === 'audience' && step.op === 'derive' && step.options?.container !== undefined && a[i].code === 'WRITE_DOWN') { targetNarrowed++; break; }
      if (b[i].effect === 'allow') throw new Error(`step ${i} widened by ${JSON.stringify(r)}`);
      narrowed++; break;
    }
    // A uplift only raises the stored classification of what is derived.
    const levels = ['public', 'internal', 'confidential', 'restricted'];
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i].record && b[i].record && a[i].effect === 'allow' && b[i].effect === 'allow') {
        assert.ok(levels.indexOf(b[i].record.classification) >= levels.indexOf(a[i].record.classification), `classification lowered by ${JSON.stringify(r)}`);
      }
      if (a[i].effect !== b[i].effect) break;
    }
  }), { seed: SEED, numRuns: RUNS });
  // The property must have bite: restrictions actually turned allows into denials.
  assert.ok(compared > RUNS * 100 && narrowed > RUNS / 20, `restrictions narrowed too little (${narrowed})`);
});
