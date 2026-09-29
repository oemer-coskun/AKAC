import { readFileSync, writeFileSync } from 'node:fs';
import { contextFresh, decide } from '../reference/policy.ts';
import { fixture, kbFixture, bindings } from '../examples/fixture.ts';
import type { Action, Audit, Context, PolicyInput, State } from '../reference/types.ts';
import { isDeepStrictEqual } from 'node:util';
import { canonicalize } from '../reference/jcs.ts';
import { consistencyRanges, inclusionRanges, leafHash, leafLookup, rangeHash, rootOf, verifyConsistency, verifyInclusion } from '../reference/merkle.ts';
import { auditLeaf, entryHash, verifyAudit } from '../reference/audit.ts';
import { classify, parseObligations } from '../reference/decision.ts';
import { verifyCheckpointV2 } from '../reference/checkpoint.ts';
import type { CheckpointV2 } from '../reference/checkpoint.ts';
import { runAuthzenVectors } from './run-authzen.ts';
import { runScenarios } from './scenarios.ts';
import { runDestinationVectors } from './run-destinations.ts';
import type { Mutant } from './scenarios.ts';
import { apply } from './patch.ts';
import type { Patch } from './patch.ts';
import { exitCode, outcomeOf, summarize, table } from './outcome.ts';
import type { Outcome, Row } from './outcome.ts';
import { createHash, createPublicKey } from 'node:crypto';
import { readdirSync } from 'node:fs';
type Decision = { id: string; kind?: 'decision'; binding: keyof typeof bindings; grant?: string; resource: string; action: Action; purpose: string;
  patch: Patch[]; expected: 'allow' | 'deny'; code?: string; tags?: string[] };
type Freshness = { id: string; kind: 'context'; context: Context; revision: string; patch: Patch[]; expected: 'valid' | 'invalid'; tags?: string[] };
const FILES = ['./vectors.json', './vectors-0.3.json'];

/** Decision vectors as portable {state, request} cases, for differential runs against other evaluators. */
export function vectorCases(): { id: string; state: State; request: PolicyInput }[] {
  return FILES.flatMap(file => {
    const data = JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8')) as { clock: number; fixture?: 'kbFixture'; cases: (Decision | Freshness)[] };
    return data.cases.filter((v): v is Decision => v.kind !== 'context').map(vector => {
      const state = data.fixture === 'kbFixture' ? kbFixture(data.clock) : fixture(data.clock);
      apply(state, vector.patch);
      const binding = { ...bindings[vector.binding], ...(vector.grant ? { grant: vector.grant } : {}) };
      return { id: vector.id, state, request: { binding, action: vector.action, resource: vector.resource, purpose: vector.purpose, now: data.clock } };
    });
  });
}
/**
 * Test-only injection points: a deliberately wrong oracle proves the runner can see a leak
 * (see tests/conformance-mutation.test.ts). Production runs never pass hooks.
 */
export type Hooks = { decide?: typeof decide; contextFresh?: typeof contextFresh;
  verifyInclusion?: typeof verifyInclusion; verifyConsistency?: typeof verifyConsistency; verifyCheckpointV2?: typeof verifyCheckpointV2 };
export function runVectors(hooks: Hooks = {}): Row[] {
  const decideFn = hooks.decide ?? decide, freshFn = hooks.contextFresh ?? contextFresh;
  return FILES.flatMap(file => {
    const data = JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8')) as { clock: number; fixture?: 'kbFixture'; cases: (Decision | Freshness)[] };
    return data.cases.map(vector => {
      const state = data.fixture === 'kbFixture' ? kbFixture(data.clock) : fixture(data.clock);
      apply(state, vector.patch);
      if (vector.kind === 'context') {
        const actual = freshFn(state, vector.context, data.clock, vector.revision) ? 'valid' : 'invalid';
        const pass = actual === vector.expected;
        return { id: vector.id, kind: 'context', expected: vector.expected, actual, pass, outcome: outcomeOf(vector.expected === 'valid', actual === 'valid', pass), ...(vector.tags ? { tags: vector.tags } : {}) };
      }
      const binding = { ...bindings[vector.binding], ...(vector.grant ? { grant: vector.grant } : {}) };
      const result = decideFn(state, { binding, action: vector.action, resource: vector.resource, purpose: vector.purpose, now: data.clock });
      const pass = result.effect === vector.expected && (vector.code === undefined || result.code === vector.code);
      return { id: vector.id, kind: 'decision', expected: vector.expected, actual: result.effect, ...(vector.code ? { code: result.code } : {}), pass,
        outcome: outcomeOf(vector.expected === 'allow', result.effect === 'allow', pass), ...(vector.tags ? { tags: vector.tags } : {}) };
    });
  });
}
type Evidence = { id: string; kind: 'merkle-root' | 'inclusion' | 'consistency' | 'jcs' | 'audit-hash' | 'audit-leaf' | 'audit-chain' | 'obligations' | 'reason' | 'decision'
    | 'verify-inclusion' | 'verify-consistency' | 'checkpoint-v2';
  expected: unknown; [key: string]: unknown };
/** Decision and audit evidence vectors (0.4): pure functions over the published formats. */
export function runEvidenceVectors(hooks: Hooks = {}): Row[] {
  const decideFn = hooks.decide ?? decide;
  const inclusionFn = hooks.verifyInclusion ?? verifyInclusion, consistencyFn = hooks.verifyConsistency ?? verifyConsistency;
  const checkpointFn = hooks.verifyCheckpointV2 ?? verifyCheckpointV2;
  const data = JSON.parse(readFileSync(new URL('./vectors-0.4.json', import.meta.url), 'utf8')) as { cases: Evidence[] };
  return data.cases.map(v => {
    let actual: unknown;
    try {
      const leaves = () => (v.leaves as string[]).map(h => leafHash(Buffer.from(h, 'hex')));
      switch (v.kind) {
        case 'merkle-root': actual = rootOf(leaves().slice(0, v.size as number)); break;
        case 'inclusion': { const l = leaves().slice(0, v.size as number), look = leafLookup(l);
          actual = inclusionRanges(v.index as number, v.size as number).map(r => rangeHash(look, r));
          if (!verifyInclusion(l[v.index as number]!, v.index as number, v.size as number, actual as string[], rootOf(l))) actual = 'unverifiable'; break; }
        case 'consistency': { const l = leaves().slice(0, v.second as number), look = leafLookup(l);
          actual = consistencyRanges(v.first as number, v.second as number).map(r => rangeHash(look, r));
          if (!verifyConsistency(v.first as number, v.second as number, rootOf(l.slice(0, v.first as number)), rootOf(l), actual as string[])) actual = 'unverifiable'; break; }
        case 'jcs': try { actual = canonicalize(v.input); } catch { actual = null; } break;
        case 'audit-hash': actual = entryHash(v.entry as Omit<Audit, 'hash'>); break;
        case 'audit-leaf': actual = auditLeaf(v.entry as Audit); break;
        case 'audit-chain': actual = verifyAudit(v.entries as Audit[]); break;
        case 'obligations': actual = parseObligations(v.input); break;
        case 'reason': actual = classify(v.reason as string); break;
        // Verification vectors: a verifier MUST accept the controls and reject every forged, resized, tampered or rolled-back variant.
        case 'verify-inclusion': actual = inclusionFn(leafHash(Buffer.from(v.leaf as string, 'hex')), v.index as number, v.size as number, v.path as string[], v.root as string); break;
        case 'verify-consistency': actual = consistencyFn(v.first as number, v.second as number, v.firstRoot as string, v.secondRoot as string, v.path as string[]); break;
        case 'checkpoint-v2': {
          const pem = createPublicKey({ key: v.publicKey as import('node:crypto').JsonWebKey, format: 'jwk' }).export({ type: 'spki', format: 'pem' }).toString();
          actual = checkpointFn(v.checkpoint as CheckpointV2, pem, v.stream as string, v.keyId as string, v.minimumSize !== undefined ? { minimumSize: v.minimumSize as number } : {}); break;
        }
        // Lifecycle decisions (0.4): decide() over the kbFixture with patches; expected { effect, code }.
        case 'decision': { const state = kbFixture(v.clock as number); apply(state, v.patch as Patch[]);
          const d = decideFn(state, { binding: bindings[v.binding as keyof typeof bindings], resource: v.resource as string, action: v.action as Action, purpose: v.purpose as string, now: v.clock as number });
          actual = { effect: d.effect, code: d.code }; break; }
        default: actual = 'unknown vector kind';
      }
    } catch (error) { actual = `error: ${(error as Error).message}`; }
    const pass = isDeepStrictEqual(actual, v.expected);
    if (v.kind === 'decision') {
      const want = (v.expected as { effect?: string }).effect, got = (actual as { effect?: string } | undefined)?.effect;
      return { id: v.id, kind: 'lifecycle-decision', expected: want, actual: got ?? actual, pass, outcome: outcomeOf(want === 'allow', got === 'allow', pass) };
    }
    // Accepting a proof or checkpoint is an allow: accepting a forged one is an unsafe success.
    if (v.kind === 'verify-inclusion' || v.kind === 'verify-consistency' || v.kind === 'checkpoint-v2') {
      return { id: v.id, kind: v.kind, expected: v.expected ? 'accept' : 'reject', actual: actual === true ? 'accept' : actual === false ? 'reject' : actual, pass,
        outcome: outcomeOf(v.expected === true, actual === true, pass) };
    }
    // Pure-function vectors have no allow/deny meaning: a match is SUCCESS, a mismatch FAILURE.
    return { id: v.id, kind: v.kind, expected: 'match', actual: pass ? 'match' : 'mismatch', pass, outcome: (pass ? 'SUCCESS' : 'FAILURE') as Outcome };
  });
}
export const RUNNER_VERSION = 'akac-conformance-runner/0.4.0';
export const PROFILES = ['AKAC-Core/0.1-draft', 'AKAC-KB/0.3-draft', 'AKAC-Evidence/0.4-draft', 'AKAC-Lifecycle/0.4-draft', 'AKAC-AuthZEN/0.4-draft', 'AKAC-RedTeam/0.4-draft', 'AKAC-Destinations/0.4-draft'];
const sha256 = (path: URL) => createHash('sha256').update(readFileSync(path)).digest('hex');
/** Reproducibility manifest: digests of everything the result depends on (repository-relative names, no host paths). */
export function manifest() {
  const root = new URL('../', import.meta.url);
  const list = (dir: string, keep: (name: string) => boolean) => Object.fromEntries(readdirSync(new URL(dir, root)).filter(keep).sort().map(name => [`${dir}${name}`, sha256(new URL(`${dir}${name}`, root))]));
  return { runner: RUNNER_VERSION, node: process.version, packageLock: sha256(new URL('package-lock.json', root)),
    spec: list('spec/', n => n.endsWith('.md')), vectors: list('conformance/', n => /^vectors.*\.json$/.test(n)) };
}
/** Every portable vector with its four-way outcome. `hooks` and `mutant` are test-only. */
export async function runAll(options: { hooks?: Hooks; mutant?: Mutant } = {}): Promise<Row[]> {
  return [...runVectors(options.hooks), ...runEvidenceVectors(options.hooks), ...runAuthzenVectors(options.hooks), ...runDestinationVectors(), ...await runScenarios(options.mutant)];
}
export function report(results: Row[]) {
  const summary = summarize(results);
  return { summary, out: { runner: RUNNER_VERSION, profiles: PROFILES, independentCertification: false, manifest: manifest(), summary, results } };
}
if (/[\\/]conformance[\\/]run\.ts$/.test(process.argv[1] ?? '')) {
  const results = await runAll();
  const { summary, out } = report(results);
  const flag = process.argv.find(a => a === '--json' || a.startsWith('--json='));
  const byKind: Record<string, Record<Outcome, number>> = {};
  for (const r of results) { const c = byKind[r.kind ?? 'other'] ??= { SUCCESS: 0, SAFE_BLOCK: 0, FAILURE: 0, UNSAFE_SUCCESS: 0 }; c[r.outcome]++; }
  if (flag?.startsWith('--json=')) writeFileSync(flag.slice(7), JSON.stringify(out, null, 2) + '\n');
  if (flag === '--json') console.log(JSON.stringify(out, null, 2)); else console.log(table(summary, byKind));
  for (const r of results.filter(r => r.outcome === 'FAILURE' || r.outcome === 'UNSAFE_SUCCESS')) console.error(`${r.outcome} ${r.id} expected=${String(r.expected)} actual=${String(r.actual)}`);
  process.exitCode = exitCode(summary);
}
