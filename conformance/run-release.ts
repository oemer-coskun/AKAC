import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { kbFixture, bindings } from '../examples/fixture.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryStore } from '../reference/store.ts';
import { MemoryRateLimits } from '../reference/limits.ts';
import { DecisionCache } from '../reference/decision-cache.ts';
import { VolumeBudget } from '../reference/protection.ts';
import { classify, parseObligations } from '../reference/decision.ts';
import type { DeriveSanitizer, ReleaseFilter } from '../reference/hooks.ts';
import type { PolicyHook } from '../reference/types.ts';
import type { Level } from '../reference/types.ts';
import { apply } from './patch.ts';
import type { Patch } from './patch.ts';
import { outcomeOf } from './outcome.ts';
import type { Row } from './outcome.ts';

/**
 * Release and retrieval protection vectors (0.6, ADR-020, spec/AKAC-0.6.md, profile AKAC-Release/0.6-draft).
 * - obligations: parseObligations() over `input`; expected the merged list or null.
 * - reason: classify() of `input`; expected {code, category?} or null.
 * - release: openContext over `sources`, then release to `recipient` with the configured filters; expected {effect, code?,
 *   content?, findings?, returned?} where `returned` lists the obligation types the caller receives.
 * - derive: openContext over `sources`, then derive with the configured sanitizers; expected {effect, code?, stored?, findings?}.
 * - hint: the same denied request for each of `resources` with hints requested; every answer MUST carry `hint` (null: none).
 * - volume: consecutive openContext calls under a volume budget; expected the sequence of effects and the last code.
 * - cache: a sequence of evaluate/revoke steps with the decision cache on; expected the sequence of decisions.
 *
 * A vector that expects a denial and observes an allow is UNSAFE_SUCCESS (a filter, budget or cache that failed open).
 */
type Behavior = { id: string; behavior: 'pass' | 'redact' | 'clean' | 'deny' | 'throw' | 'hang' | 'invalid' | 'grow'; from?: string; to?: string; findings?: string[] };
type Expected = { effect?: 'allow' | 'deny'; code?: string; content?: string; stored?: string; findings?: string[]; returned?: string[]; hint?: string | null;
  sequence?: ('allow' | 'deny')[]; decisions?: boolean[]; ok?: unknown };
type Vector = { id: string; kind: 'obligations' | 'reason' | 'release' | 'derive' | 'hint' | 'volume' | 'cache'; description?: string; patch?: Patch[]; tags?: string[];
  input?: unknown; binding?: keyof typeof bindings; sources?: string[]; recipient?: string; content?: string; action?: 'share' | 'export'; derive?: 'memory' | 'artifact';
  filters?: Behavior[]; sanitizers?: Behavior[]; failure?: 'deny' | 'skip'; required?: string[]; policyRequires?: string[];
  resources?: string[]; purpose?: string; clockOffset?: number;
  limits?: Partial<Record<Level, { bytes?: number; documents?: number }>>; onExceed?: 'deny' | 'approval'; calls?: string[][];
  steps?: string[]; resource?: string; expected: Expected | unknown };
/** Test-only: a deliberately wrong oracle proves the runner sees a leak (tests/release-protection-vectors.test.ts). */
export type ReleaseMutant = 'ignore-required-filters' | 'ignore-volume';
const behave = (b: Behavior) => async (input: { content: string }): Promise<unknown> => {
  switch (b.behavior) {
    case 'pass': return { action: 'pass' };
    case 'redact': return { action: 'redact', content: input.content.replace(b.from ?? '', b.to ?? '') };
    case 'clean': return { action: 'clean', content: input.content.replace(b.from ?? '', b.to ?? ''), findings: b.findings ?? [] };
    case 'deny': return b.findings ? { action: 'deny', findings: b.findings } : { action: 'deny', reason: 'policy-match' };
    case 'throw': throw new Error('hook failure');
    case 'hang': return new Promise(() => {});
    case 'grow': return { action: 'redact', content: input.content + 'x'.repeat(input.content.length * 2 + 300) };
    default: return { action: 'unknown' };
  }
};
const filters = (list: Behavior[] = []): ReleaseFilter[] => list.map(b => ({ id: b.id, filter: behave(b) as ReleaseFilter['filter'] }));
const sanitizers = (list: Behavior[] = []): DeriveSanitizer[] => list.map(b => ({ id: b.id, sanitize: behave(b) as DeriveSanitizer['sanitize'] }));
const pick = (actual: Record<string, unknown>, expected: Record<string, unknown>) => Object.fromEntries(Object.keys(expected).map(k => [k, actual[k]]));

export async function runReleaseVectors(mutant?: ReleaseMutant): Promise<Row[]> {
  const data = JSON.parse(readFileSync(new URL('./vectors-0.6-release.json', import.meta.url), 'utf8')) as { clock: number; cases: Vector[] };
  const rows: Row[] = [];
  for (const v of data.cases) {
    let actual: unknown, expected = v.expected as Record<string, unknown>;
    try {
      const state = kbFixture(data.clock); apply(state, v.patch ?? []);
      const binding = bindings[v.binding ?? 'chief'], clock = () => data.clock + (v.clockOffset ?? 0);
      const store = new MemoryStore(state);
      const last = async () => (await store.auditLog(binding.tenant)).at(-1);
      const purpose = v.purpose ?? 'work';
      const policy: PolicyHook | undefined = v.policyRequires && mutant !== 'ignore-required-filters' ? { revision: 'vectors', check: async () => true,
        verdict: async i => ({ allow: true, obligations: i.action === 'share' || i.action === 'export' ? [{ type: 'release_filter', value: v.policyRequires }] : [] }) } : undefined;
      const options = { clock, ...(policy ? { policy } : {}), hooks: { timeoutMs: 30, failure: v.failure ?? 'deny' as const } };
      if (v.kind === 'obligations') actual = parseObligations(v.input);
      else if (v.kind === 'reason') actual = classify(v.input as string);
      else if (v.kind === 'release') {
        const engine = new Engine(store, { ...options, releaseFilters: filters(v.filters), ...(v.required && mutant !== 'ignore-required-filters' ? { requiredFilters: () => v.required! } : {}) });
        const ctx = await engine.openContext(binding, v.sources!, purpose);
        const r = ctx.ok ? await engine.release(binding, ctx.value.context, v.recipient!, v.content!, v.action ?? 'share') : ctx;
        const entry = await last();
        actual = pick({ effect: r.ok ? 'allow' : 'deny', code: entry?.reasonCode, content: r.ok ? (r.value as { content: string }).content : undefined, findings: entry?.findings,
          returned: r.ok ? r.obligations.map(o => o.type) : undefined }, expected);
      } else if (v.kind === 'derive') {
        const engine = new Engine(store, { ...options, deriveSanitizers: sanitizers(v.sanitizers) });
        const ctx = await engine.openContext(binding, v.sources!, purpose);
        const r = ctx.ok ? await engine.derive(binding, ctx.value.context, v.content!, v.derive ?? 'artifact') : ctx;
        const entry = await last();
        const stored = r.ok ? await new Promise<string>((resolve, reject) => { store.transaction(binding.tenant, async tx => { await tx.load({ knowledge: [(r.value as { id: string }).id] }); resolve(tx.state.knowledge[(r.value as { id: string }).id]!.content); }).catch(reject); }) : undefined;
        actual = pick({ effect: r.ok ? 'allow' : 'deny', code: entry?.reasonCode, stored, findings: entry?.findings }, expected);
      } else if (v.kind === 'hint') {
        const engine = new Engine(store, options);
        const seen = new Set<string | null>(); let denied = true;
        for (const resource of v.resources!) {
          const r = await engine.openContext(binding, [resource], purpose, { hints: true });
          if (r.ok) denied = false; else seen.add(r.hint ?? null);
        }
        actual = { hint: seen.size === 1 ? [...seen][0] : [...seen].sort().join('|'), denied };
        expected = { hint: (expected as { hint: string | null }).hint, denied: true };
      } else if (v.kind === 'volume') {
        const limiter = new MemoryRateLimits({ clock });
        const volume = new VolumeBudget({ limiter, windowMs: 3_600_000, limits: v.limits!, ...(v.onExceed ? { onExceed: v.onExceed } : {}) });
        const engine = new Engine(store, { ...options, ...(mutant === 'ignore-volume' ? {} : { volume }) });
        const sequence: string[] = [];
        for (const resources of v.calls!) sequence.push((await engine.openContext(binding, resources, purpose)).ok ? 'allow' : 'deny');
        actual = pick({ sequence, code: (await last())?.reasonCode }, expected);
      } else {
        const cache = new DecisionCache({ ttlMs: 60_000, clock });
        const engine = new Engine(store, { ...options, decisionCache: cache });
        const decisions: boolean[] = [];
        for (const step of v.steps!) {
          if (step === 'evaluate') decisions.push((await engine.evaluate(binding, v.resource!, 'read', purpose)).decision);
          else if (step.startsWith('revoke:')) {
            const [, type, id] = step.split(':') as [string, 'grant' | 'knowledge' | 'actor', string];
            await engine.revoke(binding.tenant, 'admin', type, id);
          }
        }
        actual = { decisions };
      }
    } catch (error) { actual = `error: ${(error as Error).message}`; }
    const pass = isDeepStrictEqual(actual, expected);
    const wantAllow = v.kind === 'obligations' || v.kind === 'reason' ? true : v.kind === 'cache' ? (expected.decisions as boolean[]).at(-1) === true
      : v.kind === 'volume' ? (expected.sequence as string[]).at(-1) === 'allow' : v.kind === 'hint' ? false : expected.effect === 'allow';
    const gotAllow = v.kind === 'obligations' || v.kind === 'reason' ? pass : v.kind === 'cache' ? (actual as { decisions?: boolean[] })?.decisions?.at(-1) === true
      : v.kind === 'volume' ? (actual as { sequence?: string[] })?.sequence?.at(-1) === 'allow' : v.kind === 'hint' ? (actual as { denied?: boolean })?.denied === false : (actual as { effect?: string })?.effect === 'allow';
    rows.push({ id: v.id, kind: `release-${v.kind}`, expected: wantAllow ? 'allow' : 'deny', actual: gotAllow ? 'allow' : 'deny', pass, outcome: outcomeOf(wantAllow, gotAllow, pass), ...(v.tags ? { tags: v.tags } : {}) });
  }
  return rows;
}
