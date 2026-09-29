import { createHash } from 'node:crypto';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import type { Embedder } from './embedding.ts';

/**
 * Embedding anchors (0.6, ADR-020): a few operator-chosen anchor texts are embedded at start-up and
 * periodically. A hosted embedding model can change behind a stable name; the vectors then drift away from the
 * ones the index was built with, and similarity ranking degrades silently (or, after a poisoned model, on
 * purpose). The monitor compares each anchor's fresh vector with its baseline vector: when the cosine of any
 * anchor falls below `threshold`, or the model, dimensions or anchor set changed, vector retrieval is disabled
 * (DEFERRED:RETRIEVAL_DISABLED) until an administrator re-baselines. Disabled means the vector candidate source
 * throws before any index is queried; there is no silent fallback to another mode.
 *
 * The baseline is never created implicitly (0.6 review): a missing or unreadable baseline leaves the monitor
 * `pending` (retrieval disabled) until an administrator re-baselines (rebaseline(), POST
 * /admin/v1/index/anchors/rebaseline), or, once, when the operator starts with `bootstrap` (AKAC_ANCHOR_BOOTSTRAP=true)
 * and no baseline exists yet. Otherwise a restart that lost the baseline, or a model swapped while the gateway was down,
 * would silently accept the current embedder as the reference.
 *
 * What it does and does not do: it detects a changed embedding function on fixed probe texts. It does not prove
 * the embedder is honest, and it does not replace re-embedding the corpus after a deliberate model change.
 */
export class RetrievalDisabled extends Error {
  constructor() { super('Vector retrieval is disabled'); this.name = 'RetrievalDisabled'; }
}
export type AnchorBaseline = { model: string; dimensions: number; createdAt: number; anchors: string[]; vectors: number[][] };
/** Where the baseline lives so that it survives a restart (the file store), or nowhere (baseline per process). */
export interface AnchorBaselineStore { load(): Promise<AnchorBaseline | undefined>; save(baseline: AnchorBaseline): Promise<void> }
export type AnchorState = 'pending' | 'ok' | 'drifted';
export type AnchorOptions = {
  embedder: Embedder; anchors: readonly string[];
  /** Minimum cosine of every anchor against its baseline (default 0.98). */
  threshold?: number; store?: AnchorBaselineStore; clock?: () => number;
  /**
   * One-time bootstrap (AKAC_ANCHOR_BOOTSTRAP=true): start() may create the first baseline when the store reports none.
   * It never replaces an existing or unreadable baseline, and applies to the first start() of this monitor only.
   * Remove the flag after the first start: otherwise a later loss of the baseline file would be re-baselined silently.
   */
  bootstrap?: boolean;
  /** State changes and every check (never carries text or vectors). */
  onCheck?: (result: { state: AnchorState; minCosine?: number; failed?: boolean }) => void;
};
export const ANCHORS = { threshold: 0.98, maxAnchors: 32, maxText: 4096 } as const;
const digest = (text: string) => createHash('sha256').update(text).digest('hex');
export const cosine = (a: ArrayLike<number>, b: ArrayLike<number>): number => {
  if (a.length !== b.length || !a.length) return -1;
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) { dot += a[i]! * b[i]!; na += a[i]! * a[i]!; nb += b[i]! * b[i]!; }
  return na > 0 && nb > 0 ? dot / Math.sqrt(na * nb) : -1;
};
export class AnchorMonitor {
  private embedder: Embedder; private anchors: string[]; private threshold: number; private store?: AnchorBaselineStore; private clock: () => number;
  private onCheck?: AnchorOptions['onCheck']; private baseline?: AnchorBaseline; private current: AnchorState = 'pending';
  private timer?: ReturnType<typeof setInterval>; private running?: Promise<unknown>; private bootstrap: boolean;
  constructor(o: AnchorOptions) {
    this.embedder = o.embedder; this.anchors = [...o.anchors]; this.threshold = o.threshold ?? ANCHORS.threshold; this.store = o.store; this.clock = o.clock ?? Date.now; this.onCheck = o.onCheck;
    this.bootstrap = o.bootstrap === true;
    if (o.bootstrap !== undefined && typeof o.bootstrap !== 'boolean') throw new Error('Invalid embedding anchor configuration');
    if (!this.anchors.length || this.anchors.length > ANCHORS.maxAnchors || this.anchors.some(a => typeof a !== 'string' || !a.trim() || a.length > ANCHORS.maxText) || new Set(this.anchors).size !== this.anchors.length
      || !(this.threshold > 0 && this.threshold <= 1)) throw new Error('Invalid embedding anchor configuration');
  }
  get state(): AnchorState { return this.current; }
  /** Throws RetrievalDisabled unless the last check found the embedder consistent with its baseline. */
  assertEnabled(): void { if (this.current !== 'ok') throw new RetrievalDisabled(); }
  private async embed(): Promise<number[][]> {
    const vectors = await this.embedder.embed(this.anchors);
    if (vectors.length !== this.anchors.length || vectors.some(v => !(v instanceof Float32Array) || v.length !== this.embedder.dimensions)) throw new Error('Embedder shape');
    return vectors.map(v => [...v]);
  }
  private fresh(vectors: number[][]): AnchorBaseline {
    return { model: this.embedder.model, dimensions: this.embedder.dimensions, createdAt: this.clock(), anchors: this.anchors.map(digest), vectors };
  }
  private report(state: AnchorState, minCosine?: number, failed?: boolean) {
    this.current = state;
    try { this.onCheck?.({ state, ...(minCosine !== undefined ? { minCosine } : {}), ...(failed ? { failed } : {}) }); } catch { /* metrics never affect decisions */ }
  }
  /** Compares fresh vectors with the held baseline; a differing model, dimension count or anchor set is drift. */
  private compare(vectors: number[][]): { drifted: boolean; min: number } {
    const b = this.baseline!;
    if (b.model !== this.embedder.model || b.dimensions !== this.embedder.dimensions || b.anchors.length !== this.anchors.length || this.anchors.some((a, i) => b.anchors[i] !== digest(a))) return { drifted: true, min: -1 };
    const min = Math.min(...vectors.map((v, i) => cosine(v, b.vectors[i]!)));
    return { drifted: !(min >= this.threshold), min };
  }
  /**
   * Start-up: adopts the stored baseline and checks against it. Without a stored baseline (none, or unreadable) the monitor
   * stays `pending` and vector retrieval disabled, unless `bootstrap` is set and the store reports none at all: then, once,
   * the current vectors become the baseline (persisted before retrieval is enabled). An unreadable baseline is never replaced.
   */
  async start(): Promise<AnchorState> {
    const vectors = await this.embed();
    const bootstrap = this.bootstrap; this.bootstrap = false;
    let stored: AnchorBaseline | undefined;
    try { stored = await this.store?.load(); } catch { this.report('pending', undefined, true); return 'pending'; }
    if (!stored) {
      if (!bootstrap) { this.report('pending'); return 'pending'; }
      const created = this.fresh(vectors);
      await this.store?.save(created); // a failed save leaves the monitor pending (fail closed)
      this.baseline = created; this.report('ok', 1); return 'ok';
    }
    this.baseline = stored;
    const { drifted, min } = this.compare(vectors);
    this.report(drifted ? 'drifted' : 'ok', min); return this.current;
  }
  /**
   * One periodic check. A failure to embed is reported and leaves the state as it was (a down embedder also fails every
   * query); a drifted or pending monitor stays so until re-baselined, either here (rebaseline()) or by an administrator
   * who replaced the stored baseline, which is adopted on the next check. A check never creates a baseline.
   */
  async check(): Promise<AnchorState> {
    if (this.running) { await this.running; return this.current; }
    const work = (async () => {
      let vectors: number[][];
      try { vectors = await this.embed(); } catch { this.report(this.current, undefined, true); return; }
      if (!this.baseline || this.current === 'drifted') {
        let stored: AnchorBaseline | undefined;
        try { stored = this.store ? await this.store.load() : undefined; } catch { this.report(this.current, undefined, true); return; }
        if (!stored || (this.baseline && stored.createdAt === this.baseline.createdAt)) {
          this.report(this.current, this.baseline ? this.compare(vectors).min : undefined); return;
        }
        this.baseline = stored; // an administrator replaced (or provided) the baseline: adopt it and compare against it
      }
      const { drifted, min } = this.compare(vectors);
      this.report(drifted ? 'drifted' : 'ok', min);
    })();
    this.running = work;
    try { await work; } finally { this.running = undefined; }
    return this.current;
  }
  /** Administrator action: takes the current vectors as the new baseline and re-enables vector retrieval. */
  async rebaseline(): Promise<void> {
    const next = this.fresh(await this.embed());
    await this.store?.save(next); // persisted first: a failed save changes nothing
    this.baseline = next; this.report('ok', 1);
  }
  /** Checks every `intervalMs` (at least 1 s); the timer does not keep the process alive. */
  schedule(intervalMs: number): void {
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 1000) throw new Error('Invalid anchor interval');
    this.stop(); this.timer = setInterval(() => { void this.check().catch(() => {}); }, intervalMs); this.timer.unref();
  }
  stop(): void { if (this.timer) clearInterval(this.timer); this.timer = undefined; }
}
/** A baseline in one JSON file, replaced atomically. Operator-owned: whoever can write it can re-baseline. */
export class FileAnchorBaseline implements AnchorBaselineStore {
  private path: string;
  constructor(path: string) { this.path = path; }
  async load(): Promise<AnchorBaseline | undefined> {
    let raw: string;
    // Only a missing file is "no baseline"; any other read failure is an unreadable baseline (the monitor stays pending).
    try { raw = readFileSync(this.path, 'utf8'); } catch (error) { if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return undefined; throw error; }
    const b = JSON.parse(raw) as AnchorBaseline;
    if (!b || typeof b.model !== 'string' || !Number.isSafeInteger(b.dimensions) || !Number.isSafeInteger(b.createdAt) || !Array.isArray(b.anchors) || !Array.isArray(b.vectors)
      || b.vectors.length !== b.anchors.length || b.vectors.some(v => !Array.isArray(v) || v.length !== b.dimensions || v.some(x => typeof x !== 'number' || !Number.isFinite(x)))) throw new Error('Invalid anchor baseline file');
    return b;
  }
  async save(baseline: AnchorBaseline): Promise<void> {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(baseline), { mode: 0o600 }); renameSync(tmp, this.path);
  }
}
