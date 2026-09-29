import { FINDING, FINDINGS_LIMIT } from './decision.ts';
import type { Level } from './types.ts';
import { validId } from './validation.ts';

/**
 * Release and derive extension points (0.6, ADR-020, spec/AKAC-0.6.md).
 *
 * AKAC ships the interfaces, the ordering and the fail-closed handling; implementations
 * (PII redaction, content sanitizers, semantic filters) are supplied by the operator or a
 * separate module. A hook runs only after decide(), the supplemental policy and the
 * destination gate allowed the operation, so it can only NARROW the outcome: redact or
 * clean what is released or stored, or deny. It cannot allow anything that was denied
 * and cannot widen content (bounded growth, see HOOK_LIMITS). Its result is untrusted
 * input: it is validated strictly, and an error, a timeout or a malformed result is a
 * denial unless the operator explicitly configured `failure: 'skip'` (never for a filter
 * that a policy requires through the release_filter obligation).
 */
export type ReleaseFilterInput = { tenant: string; content: string; classification: Level; recipient: string; purpose: string };
export type ReleaseFilterResult = { action: 'pass' } | { action: 'redact'; content: string } | { action: 'deny'; reason: string };
export interface ReleaseFilter {
  /** Stable identifier (validId); named by the release_filter obligation. */
  readonly id: string;
  filter(input: ReleaseFilterInput): Promise<ReleaseFilterResult>;
}
export type DeriveSanitizerInput = { tenant: string; content: string; kind: 'memory' | 'artifact' };
export type DeriveSanitizerResult = { action: 'pass' } | { action: 'clean'; content: string; findings: string[] } | { action: 'deny'; findings: string[] };
export interface DeriveSanitizer {
  readonly id: string;
  sanitize(input: DeriveSanitizerInput): Promise<DeriveSanitizerResult>;
}
/** 'deny' (default): a hook error, timeout or malformed result denies. 'skip': it is ignored for hooks no policy requires. */
export type HookFailure = 'deny' | 'skip';
export type HookOptions = { timeoutMs?: number; failure?: HookFailure };
/** `growth`: a redacted or cleaned text may be at most `growth`x the original plus `slack` characters (markers), and never above `content`. */
export const HOOK_LIMITS = { timeoutMs: 2000, maxTimeoutMs: 10_000, maxHooks: 16, content: 100_000, growth: 2, slack: 256 } as const;

/** Outcome of a hook chain. `findings` are closed, content-free strings for the audit entry. */
export type HookOutcome = { ok: true; content: string; findings: string[] } | { ok: false; findings: string[] };

export function checkHooks(hooks: readonly { id: string }[] | undefined, what: string): void {
  if (hooks === undefined) return;
  if (!Array.isArray(hooks) || hooks.length > HOOK_LIMITS.maxHooks || !hooks.every(h => !!h && validId(h.id)) || new Set(hooks.map(h => h.id)).size !== hooks.length)
    throw new Error(`Invalid ${what} configuration`);
}
export function checkHookOptions(o: HookOptions): { timeoutMs: number; failure: HookFailure } {
  const timeoutMs = o.timeoutMs ?? HOOK_LIMITS.timeoutMs, failure = o.failure ?? 'deny';
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > HOOK_LIMITS.maxTimeoutMs || (failure !== 'deny' && failure !== 'skip')) throw new Error('Invalid hook configuration');
  return { timeoutMs, failure };
}
const plain = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const only = (x: Record<string, unknown>, keys: string[]) => Object.keys(x).length === keys.length && keys.every(k => Object.hasOwn(x, k));
const validText = (out: unknown, original: string): out is string => typeof out === 'string' && out.length > 0 && out.length <= HOOK_LIMITS.content
  && out.length <= original.length * HOOK_LIMITS.growth + HOOK_LIMITS.slack;
const closed = (list: unknown): list is string[] => Array.isArray(list) && list.length <= FINDINGS_LIMIT && Object.keys(list).length === list.length && list.every(f => typeof f === 'string' && FINDING.test(f));
const clip = (s: string) => s.slice(0, 128);
class Bad extends Error {}

/** Runs one hook call under a deadline; a rejection, a timeout or a hook that is not a function is an error. */
async function call<T>(work: () => Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([Promise.resolve().then(work), new Promise<never>((_r, reject) => { timer = setTimeout(() => reject(new Bad('timeout')), ms); })]);
  } finally { if (timer) clearTimeout(timer); }
}
const failed = (error: unknown) => error instanceof Bad ? 'timeout' : 'error';
const push = (findings: string[], ...items: string[]) => { for (const f of items) { if (findings.length < FINDINGS_LIMIT - 1) findings.push(clip(f)); else if (findings[findings.length - 1] !== 'findings_truncated') findings.push('findings_truncated'); } };

/**
 * Runs the configured release filters in order over `input.content`; each sees the previous
 * one's redaction. `required` names filters a policy requires: they never fail open.
 * Precondition (checked by the caller): every required id is configured.
 */
export async function runReleaseFilters(filters: readonly ReleaseFilter[], input: ReleaseFilterInput, options: { timeoutMs: number; failure: HookFailure }, required: ReadonlySet<string>): Promise<HookOutcome> {
  let content = input.content; const findings: string[] = [];
  for (const f of filters) {
    let result: unknown;
    try { result = await call(() => f.filter({ ...input, content }), options.timeoutMs); }
    catch (error) {
      push(findings, `${f.id}:${failed(error)}`);
      if (options.failure === 'skip' && !required.has(f.id)) continue;
      return { ok: false, findings };
    }
    if (plain(result) && result.action === 'pass' && only(result, ['action'])) continue;
    if (plain(result) && result.action === 'redact' && only(result, ['action', 'content']) && validText(result.content, content)) { content = result.content; push(findings, `${f.id}:redact`); continue; }
    if (plain(result) && result.action === 'deny' && only(result, ['action', 'reason']) && typeof result.reason === 'string' && FINDING.test(result.reason)) {
      push(findings, `${f.id}:deny`, `reason:${result.reason}`); return { ok: false, findings };
    }
    push(findings, `${f.id}:invalid`);
    if (options.failure === 'skip' && !required.has(f.id)) continue;
    return { ok: false, findings };
  }
  return { ok: true, content, findings };
}

/** Runs the configured derive sanitizers in order over the content about to be stored. */
export async function runSanitizers(sanitizers: readonly DeriveSanitizer[], input: DeriveSanitizerInput, options: { timeoutMs: number; failure: HookFailure }): Promise<HookOutcome> {
  let content = input.content; const findings: string[] = [];
  for (const s of sanitizers) {
    let result: unknown;
    try { result = await call(() => s.sanitize({ ...input, content }), options.timeoutMs); }
    catch (error) {
      push(findings, `${s.id}:${failed(error)}`);
      if (options.failure === 'skip') continue;
      return { ok: false, findings };
    }
    if (plain(result) && result.action === 'pass' && only(result, ['action'])) continue;
    if (plain(result) && result.action === 'clean' && only(result, ['action', 'content', 'findings']) && validText(result.content, content) && closed(result.findings)) {
      content = result.content; push(findings, `${s.id}:clean`, ...result.findings.map(f => `finding:${f}`)); continue;
    }
    if (plain(result) && result.action === 'deny' && only(result, ['action', 'findings']) && closed(result.findings)) {
      push(findings, `${s.id}:deny`, ...result.findings.map(f => `finding:${f}`)); return { ok: false, findings };
    }
    push(findings, `${s.id}:invalid`);
    if (options.failure === 'skip') continue;
    return { ok: false, findings };
  }
  return { ok: true, content, findings };
}
