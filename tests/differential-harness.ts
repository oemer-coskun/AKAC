// Differential harness: the same JSON case through the TypeScript reference and the Python
// implementation (implementations/python, runner contract in docs/IMPLEMENTATIONS.md).
import { spawn, spawnSync } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { contextFresh, decide, destinationGate, evaluationTargetNamed, targetOf, transitiveClassification } from '../reference/policy.ts';
import { containment, containmentAcross } from '../reference/containment.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryStore } from '../reference/store.ts';
import { EphemeralPartition, EphemeralStore } from '../reference/ephemeral.ts';
import { mapEvaluation } from '../reference/authzen.ts';
import { canonicalize } from '../reference/jcs.ts';
import { consistencyRanges, inclusionRanges, leafHash, leafLookup, rangeHash, rootOf, verifyConsistency, verifyInclusion } from '../reference/merkle.ts';
import { auditLeaf, entryHash, verifyAudit } from '../reference/audit.ts';
import { classify, parseObligations } from '../reference/decision.ts';
import { verifyCheckpointV2 } from '../reference/checkpoint.ts';
import type { CheckpointV2 } from '../reference/checkpoint.ts';
import { LEVELS } from '../reference/types.ts';
import type { Audit, Binding, Level, State, Store, Tx } from '../reference/types.ts';
import { bindings, fixture, kbFixture } from '../examples/fixture.ts';
import { apply } from '../conformance/patch.ts';
import type { Patch } from '../conformance/patch.ts';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type J = any;
export const PYTHON_DIR = fileURLToPath(new URL('../implementations/python/', import.meta.url));

/** Python 3.10+ interpreter: AKAC_PYTHON, else python3, else python; null when none is available. */
export const python: string | null = (() => {
  for (const cmd of [process.env.AKAC_PYTHON, 'python3', 'python'].filter((x): x is string => !!x)) {
    const r = spawnSync(cmd, ['-c', 'import sys; print(sys.version_info >= (3, 10))'], { encoding: 'utf8', timeout: 20000 });
    if (r.status === 0 && r.stdout.trim() === 'True') return cmd;
  }
  return null;
})();
export const skipReason = python ? false : 'no Python 3.10+ interpreter (set AKAC_PYTHON)';
/** True when the optional `cryptography` dependency is importable (checkpoint signature verification). */
export const pythonCrypto = !!python && spawnSync(python, ['-c', 'import cryptography'], { timeout: 20000 }).status === 0;

/** Batch mode: `python -m akac eval` with {cases} on stdin. */
export function evalPython(cases: unknown[]): unknown[] {
  const r = spawnSync(python!, ['-m', 'akac', 'eval'], { cwd: PYTHON_DIR, input: JSON.stringify({ cases }), encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, timeout: 300_000 });
  if (r.status !== 0) throw new Error(`python -m akac eval failed: ${r.stderr || r.error?.message}`);
  return JSON.parse(r.stdout) as unknown[];
}
/** Line mode: one long-lived `python -m akac serve` process, one JSON case per line. */
export class PythonWorker {
  private child: ChildProcessWithoutNullStreams;
  private pending: ((line: string) => void)[] = [];
  constructor() {
    this.child = spawn(python!, ['-m', 'akac', 'serve'], { cwd: PYTHON_DIR });
    this.child.stdout.setEncoding('utf8');
    createInterface({ input: this.child.stdout }).on('line', line => this.pending.shift()?.(line));
  }
  call(c: unknown): Promise<unknown> {
    return new Promise(resolve => { this.pending.push(line => resolve(JSON.parse(line))); this.child.stdin.write(JSON.stringify(c) + '\n'); });
  }
  close() { this.child.stdin.end(); }
}

/** JSON round trip: both implementations see exactly the same data (no undefined members, no shared references). */
export const json = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

/**
 * Deterministic UUIDs (decision, context and record ids) while `fn` runs, in the same
 * sequence the Python implementation uses, so both sides order generated ids alike.
 */
export async function withIds<T>(fn: () => Promise<T>): Promise<T> {
  const original = crypto.randomUUID;
  let n = 0;
  crypto.randomUUID = (() => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`) as typeof crypto.randomUUID;
  syncBuiltinESMExports();
  try { return await fn(); } finally { crypto.randomUUID = original; syncBuiltinESMExports(); }
}

/**
 * A store over one whole-state snapshot (no tenant partitioning), as the Python operations receive it.
 * Transactions work on a copy and commit it only when they complete (a failed or refused one leaves nothing).
 */
class WholeStore implements Store {
  state: State;
  constructor(state: State) { this.state = state; }
  async transaction<T>(_tenant: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    this.state.destinations ??= {}; this.state.runtimeProfiles ??= {};
    const draft = structuredClone(this.state);
    const result = await fn({ state: draft, complete: true, load: async () => {} });
    for (const key of Object.keys(this.state)) delete (this.state as Record<string, unknown>)[key];
    Object.assign(this.state, draft);
    return result;
  }
  async ready() { return true; }
  async auditLog(tenant: string): Promise<Audit[]> { return this.state.audits.filter(a => a.tenant === tenant); }
  async close() {}
}

const pick = (r: J, keys: string[]) => Object.fromEntries(keys.filter(k => r[k] !== undefined).map(k => [k, r[k]]));
const RECORD = ['classification', 'projects', 'readerRoles', 'readers', 'sources', 'retainUntil', 'lifecycle', 'quarantineReason',
  // Knowledge semantics (0.6, ADR-022): inherited attributes, placement and session scope.
  'tags', 'residency', 'modality', 'container', 'ephemeral'];
const categoryOf = (entry?: Audit) => entry && entry.decision === 'deny' ? { category: entry.reason.startsWith('DEFERRED:') ? 'defer' : 'deny' } : {};
const subst = (value: J, saved: Map<string, string>): J => {
  if (typeof value === 'string' && value.startsWith('$') && saved.has(value.slice(1))) return saved.get(value.slice(1));
  if (Array.isArray(value)) return value.map(v => subst(v, saved));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, subst(v, saved)]));
  return value;
};
const top = (s: State, ids: string[]): Level | null => {
  let t = 0;
  for (const id of ids) {
    const l = Object.hasOwn(s.knowledge, id) ? transitiveClassification(s, s.knowledge[id]!) : null;
    if (!l) return null;
    t = Math.max(t, LEVELS.indexOf(l));
  }
  return LEVELS[t]!;
};
const leaves = (c: J) => (c.leaves as string[]).map(h => leafHash(Buffer.from(h, 'hex')));

/** The reference result of one runner-contract case (the Python side computes the same from the same JSON). */
export async function evaluateTs(input: J): Promise<J> {
  const c = json(input);
  const s = c.state as State;
  switch (c.op ?? 'decide') {
    case 'decide': return decide(s, c.request);
    case 'evaluate': {
      const q = c.request, store = new WholeStore(s), before = s.audits.length;
      return withIds(async () => {
        const v = await new Engine(store, { clock: () => q.now }).evaluate(q.binding, q.resource, q.action, q.purpose, c.destination !== undefined ? { destination: c.destination } : {});
        const entry = s.audits.length > before ? s.audits.at(-1) : undefined;
        return { effect: v.decision ? 'allow' : 'deny', code: v.code, obligations: v.obligations, audited: !!entry, ...categoryOf(entry) };
      });
    }
    case 'steps': return withIds(async () => {
      // Session-scoped records (R190) live in the engine's partition; the Python side keeps them in its snapshot.
      const partition = new EphemeralPartition(() => c.now);
      const store = new EphemeralStore(new WholeStore(s), partition, () => c.now);
      const engine = new Engine(store, { clock: () => c.now, ...(c.memoryReview ? { memoryReview: c.memoryReview } : {}), ...(c.model ? { model: c.model } : {}),
        ...(c.candidates ? { candidates: { candidates: async () => [...c.candidates] } } : {}) });
      const saved = new Map<string, string>(), results: J[] = [];
      const call = c.unenforceable !== undefined ? { unenforceable: c.unenforceable } : undefined;
      for (const raw of c.steps) {
        const step = subst(raw, saved), before = s.audits.length;
        let r: J;
        try {
          switch (step.op) {
            case 'open': r = await engine.openContext(step.binding, step.resources, step.purpose, call); break;
            case 'retrieve': r = await engine.retrieve(step.binding, step.query, step.purpose, step.limit ?? 5, call); break;
            case 'derive': r = await engine.derive(step.binding, step.context, step.content, step.kind ?? 'artifact', call, step.options ?? {}); break;
            case 'close': r = await engine.closeSession(step.binding, step.session, call); break;
            case 'release': r = await engine.release(step.binding, step.context, step.recipient, step.content, step.action ?? 'share', call); break;
            case 'delegate': r = await engine.delegate(step.binding, step.child, call); break;
            case 'revoke': r = await engine.revoke(step.tenant, step.admin, step.type, step.id); break;
            default: throw new Error('unknown operation');
          }
        } catch { results.push({ thrown: true }); break; }
        const entry = s.audits.length > before ? s.audits.at(-1) : undefined;
        const out: J = { effect: r.ok ? 'allow' : 'deny', code: entry?.reasonCode ?? r.code, obligations: r.ok ? r.obligations : [], audited: !!entry, ...categoryOf(entry) };
        if (r.ok && (step.op === 'open' || step.op === 'retrieve')) out.documents = r.value.documents.map((d: J) => d.id);
        if (r.ok && step.op === 'derive') {
          out.record = pick(s.knowledge[r.value.id] ?? partition.records('acme').find(k => k.id === r.value.id), RECORD);
          if (r.value.quarantined) out.quarantined = true;
        }
        if (r.ok && step.op === 'release' && r.value.destination) out.destination = r.value.destination;
        results.push(out);
        if (r.ok && step.save) saved.set(step.save, step.op === 'open' || step.op === 'retrieve' ? r.value.context : r.value.id);
      }
      return results;
    });
    case 'gate': {
      const b = c.binding as Binding;
      const target = c.recipient === null || c.recipient === undefined ? { kind: 'unspecified' as const } : targetOf(s.actors[c.recipient]!);
      const g = destinationGate(s, s.grants[b.grant]!, target, b.tenant, top(s, c.sources), c.purpose);
      return g.ok ? { ok: true, ...(g.restrict ? { restrict: g.restrict } : {}) } : { ok: false };
    }
    case 'containment': {
      const level = c.sources ? top(s, c.sources) : c.level;
      return c.classes !== undefined ? containmentAcross(s, c.tenant, level, c.classes) : containment(s, c.tenant, level, c.destinationClass);
    }
    case 'fresh': return contextFresh(s, c.context, c.now, c.revision);
    case 'classification': return transitiveClassification(s, s.knowledge[c.id]!);
    case 'authzen': {
      const mapped = mapEvaluation(c.tenant, c.request);
      if (!mapped.ok) return { mapped: mapped.kind };
      let d: J = decide(s, { binding: mapped.binding, resource: mapped.resource, action: mapped.action, purpose: mapped.purpose, now: c.now });
      if (!evaluationTargetNamed(mapped.action, mapped.destination)) d = { effect: 'deny', code: 'RECIPIENT', category: 'deny' };
      const evaluate = await evaluateTs({ op: 'evaluate', state: s, request: { binding: mapped.binding, resource: mapped.resource, action: mapped.action, purpose: mapped.purpose, now: c.now },
        ...(mapped.destination !== undefined ? { destination: mapped.destination } : {}) });
      return { mapped: 'ok', binding: mapped.binding, decision: d, evaluate };
    }
    case 'scenario': return runScenarioTs(c.scenario);
    case 'jcs': try { return canonicalize(c.input); } catch { return null; }
    case 'merkleRoot': return rootOf(leaves(c).slice(0, c.size));
    case 'inclusionProof': { const l = leaves(c).slice(0, c.size), look = leafLookup(l); return inclusionRanges(c.index, c.size).map(r => rangeHash(look, r)); }
    case 'consistencyProof': { const l = leaves(c).slice(0, c.second), look = leafLookup(l); return consistencyRanges(c.first, c.second).map(r => rangeHash(look, r)); }
    case 'verifyInclusion': return verifyInclusion(leafHash(Buffer.from(c.leaf, 'hex')), c.index, c.size, c.path, c.root);
    case 'verifyConsistency': return verifyConsistency(c.first, c.second, c.firstRoot, c.secondRoot, c.path);
    case 'auditHash': return entryHash(c.entry);
    case 'auditLeaf': return auditLeaf(c.entry);
    case 'auditChain': return verifyAudit(c.entries);
    case 'obligations': return parseObligations(c.input);
    case 'reason': return classify(c.reason);
    case 'checkpointV2': {
      const pem = crypto.createPublicKey({ key: c.publicKey, format: 'jwk' }).export({ type: 'spki', format: 'pem' }).toString();
      return verifyCheckpointV2(c.checkpoint as CheckpointV2, pem, c.stream, c.keyId, c.minimumSize !== undefined ? { minimumSize: c.minimumSize } : {});
    }
    default: throw new Error(`unknown op ${String(c.op)}`);
  }
}

/** A red-team scenario (conformance/scenarios.ts semantics) with every step's effect and audited code. */
export async function runScenarioTs(v: J): Promise<J> {
  const clockSubst = (value: J, saved: Map<string, string>): J => {
    if (typeof value === 'string') {
      if (value.startsWith('$')) { const x = saved.get(value.slice(1)); if (x === undefined) throw new Error(`Unknown variable ${value}`); return x; }
      const m = /^clock([+-]\d+)?$/.exec(value);
      return m ? v.clock + Number(m[1] ?? 0) : value;
    }
    if (Array.isArray(value)) return value.map(x => clockSubst(x, saved));
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, x]) => [k, clockSubst(x, saved)]));
    return value;
  };
  return withIds(async () => {
    const store = new MemoryStore((v.fixture === 'fixture' ? fixture : kbFixture)(v.clock));
    const engine = new Engine(store, { clock: () => v.clock, ...(v.memoryReview ? { memoryReview: v.memoryReview } : {}),
      ...(v.candidates ? { candidates: { candidates: async () => [...v.candidates] } } : {}) });
    const saved = new Map<string, string>(), steps: J[] = [];
    const done = (outcome: string) => ({ outcome, steps });
    for (const raw of v.steps) {
      const step = clockSubst(raw, saved);
      const who: Binding = typeof step.as === 'string' ? bindings[step.as as keyof typeof bindings] : step.as;
      const tenant = step.op === 'revoke' ? step.tenant : step.op === 'patch' ? 'acme' : who.tenant;
      const before = (await store.auditLog(tenant)).length;
      let r: J, allowed: boolean;
      try {
        switch (step.op) {
          case 'open': r = await engine.openContext(who, step.resources, step.purpose); allowed = r.ok && (!step.target || r.value.documents.some((d: J) => step.target.includes(d.id))); break;
          case 'retrieve': r = await engine.retrieve(who, step.query, step.purpose);
            allowed = r.ok && (step.target ? r.value.documents.some((d: J) => step.target.includes(d.id)) : r.value.documents.length > 0); break;
          case 'derive': r = await engine.derive(who, step.context, step.content, step.kind); allowed = r.ok; break;
          case 'release': r = await engine.release(who, step.context, step.recipient, step.content, step.action); allowed = r.ok; break;
          case 'delegate': r = await engine.delegate(who, step.child); allowed = r.ok; break;
          case 'revoke': r = await engine.revoke(step.tenant, step.admin, step.type, step.id); allowed = r.ok; break;
          case 'patch': await store.transaction('acme', async tx => { apply(tx.state, step.patch as Patch[]); }); r = { ok: true }; allowed = true; break;
          default: throw new Error('Unknown step');
        }
      } catch { return done('FAILURE'); }
      const log = await store.auditLog(tenant);
      steps.push({ op: step.op, allowed, code: step.op === 'patch' ? null : log.length > before ? log.at(-1)!.reasonCode : r.code });
      if (r.ok && step.save) saved.set(step.save, step.op === 'open' || step.op === 'retrieve' ? r.value.context : r.value.id);
      const expectAllow = v.expected === 'allow';
      if (step.probe) return done(expectAllow ? (allowed ? 'SUCCESS' : 'FAILURE') : (allowed ? 'UNSAFE_SUCCESS' : 'SAFE_BLOCK'));
      if (step.expect && (step.expect === 'allow') !== allowed) return done('FAILURE');
    }
    return done('FAILURE');
  });
}

/** First differing path between two JSON values, for readable failure messages. */
export function firstDifference(a: unknown, b: unknown, path = '$'): string | null {
  if (isDeepStrictEqual(a, b)) return null;
  if (a && b && typeof a === 'object' && typeof b === 'object' && Array.isArray(a) === Array.isArray(b)) {
    const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])];
    for (const k of keys) {
      const d = firstDifference((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], `${path}.${k}`);
      if (d) return d;
    }
  }
  return `${path}: typescript=${JSON.stringify(a)} python=${JSON.stringify(b)}`;
}
