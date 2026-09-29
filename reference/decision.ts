import { createHash, randomUUID } from 'node:crypto';
import { canonicalize } from './jcs.ts';
import { LEVELS } from './types.ts';
import type { Category, Level } from './types.ts';
import { validId } from './validation.ts';

/**
 * Structured decisions (AKAC 0.4, ADR-006). The decision shape is aligned with the
 * OpenID AuthZEN Authorization API 1.0 (a decision plus context) and with the
 * AuthZEN working-group draft on obligations; it is "draft-aligned", not a claim
 * of conformance to either.
 */

/** Closed, stable reason codes. Allow codes first; every other code is a denial. */
export const ALLOW_CODES = ['AUTHORIZED', 'PROTECTED_DERIVATION', 'AUTHORIZED_RECIPIENT', 'ATTENUATED', 'IDEMPOTENT_REPLAY'] as const;
export const REASON_CODES = [...ALLOW_CODES,
  // decide() (R29), in evaluation order
  'INVALID_REQUEST', 'NOT_AUTHORIZED', 'INVALID_CONTEXT', 'IDENTITY_BOUNDARY', 'INVALID_DELEGATION', 'OUT_OF_SCOPE',
  'UNSUPPORTED_OBLIGATION', 'SOD_VIOLATION', 'KNOWLEDGE_BOUNDARY',
  // supplemental policy
  'POLICY_DENIED', 'POLICY_UNAVAILABLE',
  // operation level (engine)
  'STALE_CONTEXT', 'STALE_SOURCE', 'EXPIRED', 'RECIPIENT', 'CANDIDATES_UNAVAILABLE', 'BUDGET_EXCEEDED', 'STORE_ERROR',
  // control plane
  'NOT_ADMIN', 'CONFLICT', 'IDEMPOTENCY_KEY_REUSED'] as const;
export type ReasonCode = typeof REASON_CODES[number];

/**
 * Closed obligation set. A policy enforcement point that cannot enforce every
 * obligation of an allow decision MUST treat the decision as a deny.
 * - audit_level full: record the decision id with every downstream use of the result.
 * - max_context_ttl_ms: do not use the disclosed content after this many ms.
 * - no_persist: do not persist the content (or content derived from it) outside AKAC.
 * - destination_restricted: only the listed destination profiles may receive the content (ADR-008).
 * - runtime_profile (0.5, ADR-012): the runtime that holds the content MUST
 *   confine it with the operator-reviewed profile `profile` for `domain`. At most
 *   one profile per domain; two different profiles for one domain are unsatisfiable.
 * - max_output_classification (0.5, ADR-012): every output derived from the
 *   content MUST carry at least this classification outside AKAC.
 */
export const OBLIGATION_TYPES = ['audit_level', 'max_context_ttl_ms', 'no_persist', 'destination_restricted', 'runtime_profile', 'max_output_classification'] as const;
export type ObligationType = typeof OBLIGATION_TYPES[number];
/** Runtime containment domains (0.5), in their canonical obligation order. */
export const RUNTIME_DOMAINS = ['network', 'filesystem', 'tool', 'credential'] as const;
export type RuntimeDomain = typeof RUNTIME_DOMAINS[number];
export type Obligation =
  | { type: 'audit_level'; value: 'full' }
  | { type: 'max_context_ttl_ms'; value: number }
  | { type: 'no_persist' }
  | { type: 'destination_restricted'; value: string[] }
  | { type: 'runtime_profile'; domain: RuntimeDomain; profile: string }
  | { type: 'max_output_classification'; value: Level };
export const OBLIGATION_LIMIT = 16;
const plain = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
/** No holes and no extra members: `every` skips holes, so a sparse array would otherwise validate. */
const dense = (x: unknown[]) => Object.keys(x).length === x.length;
const only = (x: Record<string, unknown>, keys: string[]) => Object.keys(x).every(k => keys.includes(k)) && keys.every(k => Object.hasOwn(x, k));
export function validObligation(x: unknown): x is Obligation {
  if (!plain(x)) return false;
  switch (x.type) {
    case 'audit_level': return only(x, ['type', 'value']) && x.value === 'full';
    case 'max_context_ttl_ms': return only(x, ['type', 'value']) && Number.isSafeInteger(x.value) && (x.value as number) >= 1;
    case 'no_persist': return only(x, ['type']);
    case 'destination_restricted': return only(x, ['type', 'value']) && Array.isArray(x.value) && x.value.length >= 1 && x.value.length <= 64
      && dense(x.value) && x.value.every(validId) && new Set(x.value).size === x.value.length;
    case 'runtime_profile': return only(x, ['type', 'domain', 'profile']) && (RUNTIME_DOMAINS as readonly unknown[]).includes(x.domain) && validId(x.profile);
    case 'max_output_classification': return only(x, ['type', 'value']) && (LEVELS as readonly unknown[]).includes(x.value);
    default: return false;
  }
}
/**
 * True when no enforcement point can satisfy the list: a destination_restricted
 * with no destination left, or two different runtime profiles for one domain.
 */
export function unsatisfiable(obligations: readonly Obligation[]): boolean {
  const profiles = new Map<string, string>();
  for (const o of obligations) {
    if (o.type === 'destination_restricted' && !o.value.length) return true;
    if (o.type === 'runtime_profile') {
      const prior = profiles.get(o.domain);
      if (prior !== undefined && prior !== o.profile) return true;
      profiles.set(o.domain, o.profile);
    }
  }
  return false;
}
/**
 * Strict: an array of at most 16 known, well-formed obligations without holes, or
 * null (the caller denies UNSUPPORTED_OBLIGATION). Conflicting destination_restricted
 * obligations whose intersection is empty, and different runtime profiles for one
 * domain, are unsatisfiable and also null.
 */
export function parseObligations(x: unknown): Obligation[] | null {
  if (!Array.isArray(x) || x.length > OBLIGATION_LIMIT || !dense(x) || !x.every(validObligation)) return null;
  const merged = merge(structuredClone(x));
  return unsatisfiable(merged) ? null : merged;
}
/**
 * Combines obligations restrictively: shortest TTL, intersection of destinations,
 * highest output classification, one entry per type (runtime_profile: per domain),
 * stable order. Two different profiles for one domain are both kept, in order, as an
 * unsatisfiable pair (see unsatisfiable()): no enforcement point can apply both.
 */
export function merge(...lists: Obligation[][]): Obligation[] {
  const byType = new Map<ObligationType, Obligation>();
  const profiles = new Map<RuntimeDomain, Obligation[]>();
  for (const o of lists.flat()) {
    if (o.type === 'runtime_profile') {
      const list = profiles.get(o.domain) ?? [];
      if (!list.some(p => p.type === 'runtime_profile' && p.profile === o.profile)) list.push(structuredClone(o));
      profiles.set(o.domain, list); continue;
    }
    const prior = byType.get(o.type);
    if (!prior) { byType.set(o.type, structuredClone(o)); continue; }
    if (o.type === 'max_context_ttl_ms' && prior.type === o.type) prior.value = Math.min(prior.value, o.value);
    // An empty intersection is kept as an impossible restriction, which no PEP can satisfy: deny.
    if (o.type === 'destination_restricted' && prior.type === o.type) prior.value = prior.value.filter(d => o.value.includes(d));
    if (o.type === 'max_output_classification' && prior.type === o.type && LEVELS.indexOf(o.value) > LEVELS.indexOf(prior.value)) prior.value = o.value;
  }
  return OBLIGATION_TYPES.flatMap(t => t === 'runtime_profile' ? RUNTIME_DOMAINS.flatMap(d => profiles.get(d) ?? []) : byType.has(t) ? [byType.get(t)!] : []);
}
/** True when every obligation type is in `supported`, every obligation is well-formed and the list is satisfiable. A PEP denies otherwise. */
export const enforceable = (obligations: readonly unknown[], supported: readonly ObligationType[]) =>
  Array.isArray(obligations) && obligations.every(o => validObligation(o) && supported.includes(o.type)) && !unsatisfiable(obligations as Obligation[]);

export const newDecisionId = (): string => randomUUID();
export const validDecisionId = (x: unknown): x is string => typeof x === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(x);
/** W3C Trace Context trace-id: 32 lowercase hex digits, not all zero. */
export const validTraceId = (x: unknown): x is string => typeof x === 'string' && /^[0-9a-f]{32}$/.test(x) && !/^0+$/.test(x);
/**
 * Per-call options of engine and control-plane entry points: correlation only, never
 * authority. An invalid trace id, execution id or runtime revision is ignored (never
 * recorded). `executionId` (0.5) names the agent execution (for example a
 * sandbox or job id; `x-akac-execution-id` over HTTP). `runtimeRevision` (0.5)
 * identifies the runtime policy revision a trusted runtime enforcer applied; only
 * trusted in-process callers (ProtectedRuntime) set it, never an agent over HTTP.
 */
export type Call = { trace?: { traceId?: string; executionId?: string; runtimeRevision?: string } };
export const traceOf = (call?: Call): string | undefined => validTraceId(call?.trace?.traceId) ? call!.trace!.traceId : undefined;
export const executionOf = (call?: Call): string | undefined => validId(call?.trace?.executionId) ? call!.trace!.executionId : undefined;
export const runtimeRevisionOf = (call?: Call): string | undefined => validId(call?.trace?.runtimeRevision) ? call!.trace!.runtimeRevision : undefined;
/** SHA-256 over the JCS array of the active policy material (core version, state policy version, hook or bundle revision). */
export const policyDigest = (parts: readonly string[]): string => createHash('sha256').update(canonicalize([...parts])).digest('hex');

/** `DENIED:X` / `DEFERRED:X` / allow reason -> closed code and category; null for anything outside the enum. */
export function classify(reason: string): { code: ReasonCode; category?: Category } | null {
  const match = /^(DENIED|DEFERRED):([A-Z_]+)$/.exec(reason);
  const code = (match ? match[2] : reason) as ReasonCode;
  if (!REASON_CODES.includes(code)) return null;
  const allow = (ALLOW_CODES as readonly string[]).includes(code);
  if (match ? allow : !allow) return null;
  return match ? { code, category: match[1] === 'DENIED' ? 'deny' : 'defer' } : { code };
}
/** The structured decision record: returned in-process (events), recorded in audit, never in HTTP failure bodies. */
export type DecisionRecord = {
  decisionId: string; effect: 'allow' | 'deny'; code: ReasonCode; category?: Category;
  policyRevision: string; policyDigest: string; obligations: Obligation[];
};
