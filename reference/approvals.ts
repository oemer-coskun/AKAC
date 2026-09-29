import { createHash } from 'node:crypto';
import { canonicalize } from './jcs.ts';
import { APPROVAL_CLASSES, DEFAULT_RISK_CAPS, KNOWLEDGE, LEVELS, RISK_LEVELS } from './types.ts';
import type { ApprovalClass, RiskCap, RiskLevel, TenantSettings } from './types.ts';
import { exactKeys, validId } from './validation.ts';

/**
 * Approval quorum for sensitive administrative operations (0.6, R153..R157).
 *
 * A quorum of N means N distinct standing security-admins: the requester and N-1
 * approvers who are not the requester. Quorum 1 is the requester alone (the 0.5
 * behaviour, the default for every class except break-glass). Break-glass needs at
 * least 2 (four eyes) and cannot be configured lower.
 */
export const DEFAULT_QUORUM: Readonly<Record<ApprovalClass, number>> = {
  break_glass: 2, label_widening: 1, role_widening: 1, sod_relaxation: 1, runtime_profile: 1, destination_widening: 1, settings: 1
};
/** Lowest configurable quorum per class; the highest quorum; approval lifetime bounds (ms). */
export const APPROVAL = { maxQuorum: 8, minimum: { break_glass: 2 } as Partial<Record<ApprovalClass, number>>,
  defaultTtlMs: 86_400_000, minTtlMs: 300_000, maxTtlMs: 7 * 86_400_000, list: 256, gateTimeoutMs: 2000 } as const;

/**
 * Structural hook for an external approval workflow (for example an IGA or ticketing
 * system in an enterprise edition). It can only require more: a quorum below the
 * tenant's is ignored, and satisfied() is consulted only after the internal quorum is
 * met, so it can never approve an operation on its own. Errors and timeouts fail
 * closed: an unanswered requirements() call requires the external workflow, an
 * unanswered satisfied() call is not satisfied.
 */
export interface ApprovalGate {
  requirements?(input: { tenant: string; class: ApprovalClass; operation: string; requester: string; digest: string }): Promise<{ quorum?: number; external?: boolean }>;
  satisfied?(input: { tenant: string; approval: string; class: ApprovalClass; operation: string; digest: string; requester: string; approvers: readonly string[] }): Promise<boolean>;
}

/** SHA-256 over the RFC 8785 (JCS) form of an operation's arguments. */
export const approvalDigest = (payload: unknown): string => createHash('sha256').update(canonicalize(jsonValue(payload))).digest('hex');
/** The JSON value of the arguments (undefined members dropped), as stored and as executed. */
export const jsonValue = (payload: unknown): unknown => JSON.parse(JSON.stringify(payload ?? null));
/** Tenant quorum of a class: the configured value, never below the class minimum or 1. */
export function quorumOf(settings: TenantSettings | undefined, cls: ApprovalClass): number {
  const configured = settings?.approvalQuorum?.[cls];
  const value = Number.isSafeInteger(configured) ? configured! : DEFAULT_QUORUM[cls];
  return Math.min(APPROVAL.maxQuorum, Math.max(value, APPROVAL.minimum[cls] ?? 1, 1));
}
/** Approval lifetime of a tenant (ms). */
export const approvalTtl = (settings: TenantSettings | undefined): number =>
  Number.isSafeInteger(settings?.approvalTtlMs) ? settings!.approvalTtlMs! : APPROVAL.defaultTtlMs;

const capRank = (cap: RiskCap) => cap === 'deny' ? -1 : LEVELS.indexOf(cap);
/** Well-formed settings of `tenant`: quorums within bounds, TTL within bounds, caps monotone (a higher risk never caps above a lower one). */
export function validSettings(x: unknown, tenant: string): x is TenantSettings {
  if (!exactKeys(x, ['id', 'tenant'], ['approvalQuorum', 'approvalTtlMs', 'riskCaps', 'lineageDepth']) || x.id !== tenant || x.tenant !== tenant || !validId(tenant)) return false;
  // Derivation depth limit (0.6, R182): 1..KNOWLEDGE.maxDepth.
  if (x.lineageDepth !== undefined && !(Number.isSafeInteger(x.lineageDepth) && (x.lineageDepth as number) >= 1 && (x.lineageDepth as number) <= KNOWLEDGE.maxDepth)) return false;
  const q = x.approvalQuorum, ttl = x.approvalTtlMs, caps = x.riskCaps;
  if (q !== undefined && !(exactKeys(q, [], [...APPROVAL_CLASSES]) && Object.entries(q).every(([k, v]) =>
    Number.isSafeInteger(v) && (v as number) >= (APPROVAL.minimum[k as ApprovalClass] ?? 1) && (v as number) <= APPROVAL.maxQuorum))) return false;
  if (ttl !== undefined && !(Number.isSafeInteger(ttl) && (ttl as number) >= APPROVAL.minTtlMs && (ttl as number) <= APPROVAL.maxTtlMs)) return false;
  if (caps !== undefined) {
    if (!exactKeys(caps, [], RISK_LEVELS.filter(l => l !== 'critical'))) return false;
    if (!Object.values(caps).every(v => v === 'deny' || LEVELS.includes(v as never))) return false;
    let previous = Infinity;
    for (const level of RISK_LEVELS) {
      const cap = (caps as Record<string, RiskCap>)[level];
      if (cap === undefined) continue;
      if (capRank(cap) > previous) return false;
      previous = capRank(cap);
    }
  }
  return true;
}
/** Effective cap per level under a settings record (missing levels take the default). */
function caps(settings: TenantSettings | undefined): Record<RiskLevel, number> {
  const out = {} as Record<RiskLevel, number>;
  let limit = LEVELS.length - 1;
  for (const level of RISK_LEVELS) {
    const cap = level === 'critical' ? 'deny' : settings?.riskCaps?.[level] ?? DEFAULT_RISK_CAPS[level];
    limit = Math.min(limit, capRank(cap)); out[level] = limit;
  }
  return out;
}
/** True when `next` relaxes anything of `current`: a lower quorum, a longer approval lifetime, a higher risk cap or a deeper derivation limit. */
export function settingsRelax(current: TenantSettings | undefined, next: TenantSettings): boolean {
  if (APPROVAL_CLASSES.some(c => quorumOf(next, c) < quorumOf(current, c))) return true;
  if ((next.lineageDepth ?? KNOWLEDGE.defaultDepth) > (current?.lineageDepth ?? KNOWLEDGE.defaultDepth)) return true;
  if (approvalTtl(next) > approvalTtl(current)) return true;
  const before = caps(current), after = caps(next);
  return RISK_LEVELS.some(l => after[l] > before[l]);
}
/**
 * Roles whose holders count towards an approval quorum (R154): only standing security-admins approve.
 * Any change that makes a principal newly hold one of them (an elevation, 0.6b R158) passes the approval gate
 * at settingsQuorum(): otherwise a single administrator could mint the second approver of a four-eyes rule.
 */
export const APPROVER_ROLES: readonly string[] = ['security-admin'];
/** Quorum of a settings relaxation: the highest quorum of any class (a single admin can never lower a multi-person rule). */
export const settingsQuorum = (current: TenantSettings | undefined): number => Math.max(...APPROVAL_CLASSES.map(c => quorumOf(current, c)));
