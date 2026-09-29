import { createHash } from 'node:crypto';
import type { Audit, State } from './types.ts';
import { safeNumber, validId } from './validation.ts';
import { canonicalBytes } from './jcs.ts';
import { classify, validDecisionId, validFindings, validObligation, validTraceId } from './decision.ts';
import type { Obligation, ReasonCode } from './decision.ts';
import { leafHash } from './merkle.ts';

export const GENESIS = '0'.repeat(64);
/** Current audit entry format. Format 1 entries have no `formatVersion`. */
export const AUDIT_FORMAT = 2;
/** Format 1: SHA-256 over JSON with top-level keys sorted (0.1-0.3). Kept verbatim for old entries. */
export function auditHash(entry: Omit<Audit, 'hash'>): string {
  const ordered = Object.fromEntries(Object.entries(entry).sort(([a], [b]) => a.localeCompare(b, 'en')));
  return createHash('sha256').update(JSON.stringify(ordered)).digest('hex');
}
const V1 = ['sequence', 'time', 'tenant', 'actor', 'operation', 'decision', 'reason', 'policyVersion', 'epoch', 'previous'];
const V2 = [...V1, 'formatVersion', 'decisionId', 'reasonCode', 'policyDigest', 'obligations'];
/**
 * Optional format 2 members. `executionId` and `runtimeRevision` (0.5, ADR-012)
 * are absent from every earlier entry, so earlier entries hash and verify unchanged;
 * a verifier that predates them rejects an entry carrying them (closed shape, fail closed).
 */
const V2_OPTIONAL = ['runId', 'traceId', 'executionId', 'runtimeRevision', 'actorChain', 'breakGlass', 'findings'];
/** RFC 8693 actor chain (0.6, R145): 1..MAX_ACTOR_CHAIN printable ASCII identifiers of at most 256 characters. */
export const MAX_ACTOR_CHAIN = 5;
export const validActorId = (x: unknown): x is string => typeof x === 'string' && /^[!-~]{1,256}$/.test(x);
export const validActorChain = (x: unknown): x is string[] => Array.isArray(x) && x.length >= 1 && x.length <= MAX_ACTOR_CHAIN
  && Object.keys(x).length === x.length && x.every(validActorId);
/** Closed shape of a format 2 body (without `hash`). */
function v2Shape(body: Record<string, unknown>): boolean {
  const keys = Object.keys(body);
  const code = typeof body.reason === 'string' ? classify(body.reason) : null;
  return V2.every(k => Object.hasOwn(body, k)) && keys.every(k => V2.includes(k) || V2_OPTIONAL.includes(k))
    && body.formatVersion === 2 && validDecisionId(body.decisionId) && !!code && code.code === body.reasonCode
    && (body.decision === 'allow') === !code.category && ['allow', 'deny'].includes(body.decision as string)
    && typeof body.policyDigest === 'string' && /^[a-f0-9]{64}$/.test(body.policyDigest)
    && Array.isArray(body.obligations) && body.obligations.length <= 16 && body.obligations.every(validObligation)
    && (body.decision === 'allow' || body.obligations.length === 0)
    && (body.runId === undefined || validId(body.runId)) && (body.traceId === undefined || validTraceId(body.traceId))
    && (body.executionId === undefined || validId(body.executionId)) && (body.runtimeRevision === undefined || validId(body.runtimeRevision))
    && (body.actorChain === undefined || validActorChain(body.actorChain)) && (body.breakGlass === undefined || body.breakGlass === true)
    && (body.findings === undefined || (validFindings(body.findings) && body.findings.length >= 1));
}
/** Format 2: SHA-256 over the RFC 8785 (JCS) form of the body, which includes `formatVersion: 2`. */
export function auditHashV2(entry: Omit<Audit, 'hash'>): string {
  return createHash('sha256').update(canonicalBytes(entry)).digest('hex');
}
/** Hash of an entry body under its own format, or null for an unknown format or a malformed format 2 body. */
export function entryHash(body: Omit<Audit, 'hash'>): string | null {
  try {
    if (!Object.hasOwn(body, 'formatVersion')) return auditHash(body);
    return v2Shape(body as Record<string, unknown>) ? auditHashV2(body) : null;
  } catch { return null; }
}
/**
 * RFC 9162 leaf of an entry (format 1 or 2): H(0x00 || JCS(entry including `hash`)).
 * The leaf index of an entry is `sequence - 1` in its tenant stream.
 */
export const auditLeaf = (entry: Audit): string => leafHash(canonicalBytes(entry));
/**
 * Each tenant is an independent stream starting at sequence 1 (or, with
 * `window`, at its first supplied entry). Entries of one tenant must be in order.
 * The hash chain continues across the format change: a format 2 entry's
 * `previous` is the hash of the preceding entry, whatever its format. A format 1
 * entry after a format 2 entry of the same stream is a downgrade and fails.
 */
export function verifyAudit(entries: Audit[], options: { window?: boolean } = {}): boolean {
  const heads = new Map<string, { sequence: number; hash: string; v2: boolean }>();
  return entries.every(entry => {
    if (!entry || typeof entry !== 'object') return false;
    const { hash, ...body } = entry;
    const head = heads.get(entry.tenant);
    const sequence = head ? head.sequence + 1 : options.window ? entry.sequence : 1;
    const previous = head ? head.hash : options.window ? entry.previous : GENESIS;
    const v2 = Object.hasOwn(entry, 'formatVersion');
    const valid = safeNumber(entry.sequence) && entry.sequence >= 1 && entry.sequence === sequence
      && entry.previous === previous && !(head?.v2 && !v2) && entryHash(body) === hash;
    heads.set(entry.tenant, { sequence: entry.sequence, hash, v2: v2 || !!head?.v2 }); return valid;
  });
}
/** The 0.1 format: one global chain across all tenants. */
export function verifyLegacyAudit(entries: Audit[]): boolean {
  let previous = GENESIS;
  return entries.every((entry, index) => {
    const { hash, ...body } = entry;
    const valid = entry.sequence === index + 1 && entry.previous === previous && auditHash(body) === hash;
    previous = hash; return valid;
  });
}
export type AuditFields = {
  time: number; tenant: string; actor: string; operation: string; decision: 'allow' | 'deny'; reason: string;
  policyVersion: string; epoch: number; decisionId: string; reasonCode: ReasonCode; policyDigest: string;
  obligations: Obligation[]; runId?: string; traceId?: string; executionId?: string; runtimeRevision?: string;
  actorChain?: string[]; breakGlass?: true;
};
/**
 * Appends a format 2 entry to the tenant stream. A partial snapshot MUST contain
 * the tenant head (Need.audit). A malformed entry throws (the transaction fails).
 */
export function appendAudit(s: State, fields: AuditFields): Audit {
  let head: Audit | undefined;
  for (let i = s.audits.length - 1; i >= 0; i--) if (s.audits[i]!.tenant === fields.tenant) { head = s.audits[i]; break; }
  const { runId, traceId, executionId, runtimeRevision, actorChain, breakGlass, ...required } = fields;
  const entry: Omit<Audit, 'hash'> = { ...required, obligations: structuredClone(fields.obligations),
    ...(runId !== undefined ? { runId } : {}), ...(traceId !== undefined ? { traceId } : {}),
    ...(executionId !== undefined ? { executionId } : {}), ...(runtimeRevision !== undefined ? { runtimeRevision } : {}),
    ...(actorChain !== undefined ? { actorChain: [...actorChain] } : {}), ...(breakGlass === true ? { breakGlass } : {}),
    formatVersion: AUDIT_FORMAT, sequence: (head?.sequence ?? 0) + 1, previous: head?.hash ?? GENESIS };
  const hash = entryHash(entry);
  if (!hash) throw new Error('Malformed audit entry');
  const audit = { ...entry, hash };
  s.audits.push(audit); return audit;
}
