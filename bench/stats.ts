import { execFileSync } from 'node:child_process';
import os from 'node:os';

/** Seeded PRNG (mulberry32): the same seed always yields the same synthetic data set. */
export function prng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  return { next, int, pick: <T>(xs: readonly T[]): T => xs[int(xs.length)]!, chance: (p: number) => next() < p };
}
export type Rng = ReturnType<typeof prng>;

export type Summary = {
  n: number; errors: number; concurrency: number; seconds: number; throughput: number;
  p50: number; p95: number; p99: number; mean: number; max: number;
  /** Outcome counts (allow, deny, or a reason code). */
  outcomes: Record<string, number>;
};
/** Nearest-rank percentile of a sorted sample, milliseconds. */
export function percentile(sorted: readonly number[], p: number): number {
  if (!sorted.length) return NaN;
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))]!;
}
const round = (x: number) => Number.isFinite(x) ? Math.round(x * 1000) / 1000 : x;
/**
 * Built-in closed-loop load generator: `concurrency` workers each call `fn(i)`
 * until `iterations` calls are done. Latency is measured per call with
 * performance.now(); `warmup` calls run first and are not recorded.
 */
export async function load(fn: (i: number) => Promise<string>, o: { iterations: number; concurrency: number; warmup?: number }): Promise<Summary> {
  for (let i = 0; i < (o.warmup ?? 0); i++) await fn(-1 - i).catch(() => 'error');
  const times: number[] = [], outcomes: Record<string, number> = {};
  let next = 0, errors = 0;
  const started = performance.now();
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= o.iterations) return;
      const t = performance.now();
      let outcome: string;
      try { outcome = await fn(i); } catch { outcome = 'error'; errors++; }
      times.push(performance.now() - t);
      outcomes[outcome] = (outcomes[outcome] ?? 0) + 1;
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, o.concurrency) }, worker));
  const seconds = (performance.now() - started) / 1000;
  times.sort((a, b) => a - b);
  return { n: times.length, errors, concurrency: o.concurrency, seconds: round(seconds), throughput: round(times.length / seconds),
    p50: round(percentile(times, 50)), p95: round(percentile(times, 95)), p99: round(percentile(times, 99)),
    mean: round(times.reduce((a, b) => a + b, 0) / (times.length || 1)), max: round(times.at(-1) ?? NaN), outcomes };
}
/** Synchronous micro-benchmark: median and p99 of `repeat` calls, microseconds. */
export function micro(fn: () => unknown, repeat: number): { p50us: number; p99us: number; result: unknown } {
  let result: unknown;
  for (let i = 0; i < Math.min(20, repeat); i++) result = fn();
  const times: number[] = [];
  for (let i = 0; i < repeat; i++) { const t = performance.now(); result = fn(); times.push((performance.now() - t) * 1000); }
  times.sort((a, b) => a - b);
  return { p50us: round(percentile(times, 50)), p99us: round(percentile(times, 99)), result };
}

export type Machine = { os: string; kernel: string; arch: string; cpu: string; cores: number; memoryGiB: number; node: string; gitSha: string; runner: string; postgres?: string; pgvector?: string };
export function machine(): Machine {
  let gitSha = process.env.GITHUB_SHA ?? 'unknown';
  if (gitSha === 'unknown') { try { gitSha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { /* not a checkout */ } }
  const cpus = os.cpus();
  return { os: `${os.type()} ${os.release()}`, kernel: os.version(), arch: os.arch(), cpu: cpus[0]?.model.trim() ?? 'unknown', cores: cpus.length,
    memoryGiB: Math.round(os.totalmem() / 2 ** 30 * 10) / 10, node: process.version, gitSha,
    runner: process.env.GITHUB_ACTIONS ? `github-actions ${process.env.RUNNER_OS ?? ''} ${process.env.ImageOS ?? ''} ${process.env.ImageVersion ?? ''}`.trim() : 'local' };
}
