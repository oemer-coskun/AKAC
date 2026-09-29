import { readFileSync } from 'node:fs';
import { Engine } from '../reference/engine.ts';
import type { CandidateSource, EngineOptions } from '../reference/engine.ts';
import { MemoryStore } from '../reference/store.ts';
import { bindings, fixture, kbFixture } from '../examples/fixture.ts';
import type { Binding, Grant, State, Tx } from '../reference/types.ts';
import { apply } from './patch.ts';
import type { Patch } from './patch.ts';
import { outcomeOf } from './outcome.ts';
import type { Row } from './outcome.ts';

/**
 * Scenario vectors (red-team practice): multi-step attacks driven through the Engine over a
 * MemoryStore, because they need state that only earlier operations create (derived memory,
 * delegated grants, epoch changes). Every step may assert `expect` ('allow' | 'deny') to prove the
 * setup did what the attack assumes; the single step marked `probe` carries the vector's expectation.
 * String arguments `$name` are replaced by an id saved from an earlier step (`save`), and
 * `clock`, `clock+N`, `clock-N` by the scenario clock.
 */
type Step = { op: 'open' | 'retrieve' | 'derive' | 'release' | 'delegate' | 'revoke' | 'patch'; as?: string | Binding;
  resources?: string[]; purpose?: string; query?: string; context?: string; kind?: 'memory' | 'artifact'; content?: string; recipient?: string; action?: 'share' | 'export';
  child?: Grant; tenant?: string; admin?: string; type?: 'grant' | 'knowledge' | 'actor'; id?: string; patch?: Patch[];
  /** retrieve/open probes: ids whose disclosure is a leak (allow when any is present). Without it, any disclosure counts. */
  target?: string[]; save?: string; expect?: 'allow' | 'deny'; probe?: boolean };
type Scenario = { id: string; kind: 'scenario'; description?: string; tags?: string[]; fixture?: 'fixture' | 'kbFixture'; clock: number;
  memoryReview?: 'none' | 'quarantine'; candidates?: string[]; steps: Step[]; expected: 'allow' | 'deny' };

/**
 * A deliberately broken implementation, for meta-tests only: `state` rewrites the tenant state at the
 * start of every transaction (a wrong data model), `engine` overrides operations (a wrong engine).
 */
export type Mutant = { name: string; state?: (state: State) => void; engine?: (engine: Engine, store: MemoryStore) => void };

class MutantStore extends MemoryStore {
  private mutate?: (state: State) => void;
  constructor(initial: State, mutate?: (state: State) => void) { super(initial); this.mutate = mutate; }
  override async transaction<T>(tenant: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    return super.transaction(tenant, tx => { this.mutate?.(tx.state); return fn(tx); });
  }
}

const subst = (value: unknown, saved: Map<string, string>, clock: number): unknown => {
  if (typeof value === 'string') {
    if (value.startsWith('$')) { const v = saved.get(value.slice(1)); if (v === undefined) throw new Error(`Unknown variable ${value}`); return v; }
    const m = /^clock([+-]\d+)?$/.exec(value);
    return m ? clock + Number(m[1] ?? 0) : value;
  }
  if (Array.isArray(value)) return value.map(v => subst(v, saved, clock));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, subst(v, saved, clock)]));
  return value;
};

async function execute(v: Scenario, mutant?: Mutant): Promise<Row> {
  const state = (v.fixture === 'fixture' ? fixture : kbFixture)(v.clock);
  const store = new MutantStore(state, mutant?.state);
  const source: CandidateSource | undefined = v.candidates ? { candidates: async () => [...v.candidates!] } : undefined;
  const options: EngineOptions = { clock: () => v.clock, ...(v.memoryReview ? { memoryReview: v.memoryReview } : {}), ...(source ? { candidates: source } : {}) };
  const engine = new Engine(store, options);
  mutant?.engine?.(engine, store);
  const saved = new Map<string, string>();
  const row = (actual: string, pass: boolean, allowed: boolean): Row => ({ id: v.id, kind: 'scenario', expected: v.expected, actual, pass,
    outcome: outcomeOf(v.expected === 'allow', allowed, pass), ...(v.tags ? { tags: v.tags } : {}) });
  for (const raw of v.steps) {
    const step = subst(raw, saved, v.clock) as Step;
    const who = typeof step.as === 'string' ? bindings[step.as as keyof typeof bindings] : step.as;
    let allowed: boolean;
    try {
      switch (step.op) {
        case 'open': { const r = await engine.openContext(who!, step.resources!, step.purpose!);
          allowed = r.ok && (!step.target || r.value.documents.some(d => step.target!.includes(d.id))); if (r.ok && step.save) saved.set(step.save, r.value.context); break; }
        case 'retrieve': { const r = await engine.retrieve(who!, step.query!, step.purpose!);
          allowed = r.ok && (step.target ? r.value.documents.some(d => step.target!.includes(d.id)) : r.value.documents.length > 0); if (r.ok && step.save) saved.set(step.save, r.value.context); break; }
        case 'derive': { const r = await engine.derive(who!, step.context!, step.content!, step.kind); allowed = r.ok; if (r.ok && step.save) saved.set(step.save, r.value.id); break; }
        case 'release': { const r = await engine.release(who!, step.context!, step.recipient!, step.content!, step.action); allowed = r.ok; break; }
        case 'delegate': { const r = await engine.delegate(who!, step.child!); allowed = r.ok; break; }
        case 'revoke': { const r = await engine.revoke(step.tenant!, step.admin!, step.type!, step.id!); allowed = r.ok; break; }
        case 'patch': await store.transaction('acme', async tx => { apply(tx.state, step.patch!); }); allowed = true; break;
        default: throw new Error('Unknown step');
      }
    } catch (error) { return row(`error: ${(error as Error).message}`, false, false); }
    if (step.probe) return row(allowed ? 'allow' : 'deny', true, allowed);
    if (step.expect && (step.expect === 'allow') !== allowed) return row(`setup: ${step.op} ${allowed ? 'allowed' : 'denied'}`, false, false);
  }
  return row('no probe', false, false);
}

/** Runs every scenario of vectors-redteam.json. */
export async function runScenarios(mutant?: Mutant): Promise<Row[]> {
  const data = JSON.parse(readFileSync(new URL('./vectors-redteam.json', import.meta.url), 'utf8')) as { cases: Scenario[] };
  const rows: Row[] = [];
  for (const v of data.cases) rows.push(await execute(v, mutant));
  return rows;
}
