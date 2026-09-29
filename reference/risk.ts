import { createHash } from 'node:crypto';
import { RISK_LEVELS } from './types.ts';
import type { RiskLevel, RiskSignal, State } from './types.ts';

/**
 * Risk-based authorization (0.6, R151, R152). Risk signals lower a
 * principal's effective clearance (policy.ts riskLimit); they never raise it.
 *
 * Community core: signals ingested through the administrative API
 * (POST /admin/v1/risk-signals, security-admin or risk-ingest) and the structural
 * RiskProvider hook. Receivers for the OpenID Shared Signals Framework 1.0
 * (Final Specification, 2025) and connectors for identity-provider risk engines are
 * enterprise connectors: they verify SSF Security Event Tokens (RFC 8417) from
 * a configured transmitter and call the ingestion route or implement RiskProvider.
 * Mapping of CAEP 1.0 `risk-level-change` (current_level LOW, MEDIUM, HIGH) to AKAC
 * levels: caepRiskLevel(). `critical` has no CAEP counterpart: it is set by an
 * operator or a RISC/incident rule (for example account compromise).
 */
export interface RiskProvider {
  /**
   * Current risk level of a principal from an external source. It can only add
   * restrictions: the engine takes the higher of this and the stored signals. A
   * failure, a timeout or a value outside RISK_LEVELS denies (POLICY_UNAVAILABLE).
   */
  level(input: { tenant: string; principal: string; kind: 'user' | 'agent' }): Promise<RiskLevel>;
}
/** Stored signal id: one record per (source, principal) (SHA-256, hex). */
export const riskSignalId = (source: string, principal: string): string =>
  createHash('sha256').update(`${source}\u0000${principal}`).digest('hex');
/** CAEP 1.0 risk-level-change `current_level` to an AKAC risk level; null for anything else. */
export function caepRiskLevel(currentLevel: unknown): RiskLevel | null {
  return currentLevel === 'LOW' ? 'low' : currentLevel === 'MEDIUM' ? 'medium' : currentLevel === 'HIGH' ? 'high' : null;
}
/** OpenID CAEP/RISC event type URIs accepted as the `event` of a stored signal. */
export const SSF_EVENT = /^https:\/\/schemas\.openid\.net\/secevent\/(caep|risc)\/event-type\/[a-z][a-z-]{0,63}$/;
/** Longest lifetime of a stored risk signal (30 days) and the default (24 hours). */
export const RISK_SIGNAL = { maxTtlMs: 30 * 86_400_000, defaultTtlMs: 86_400_000 } as const;
/**
 * A view of `state` with one additional, transient signal per principal (from a
 * RiskProvider), valid until `now + 1`. Adding a signal can only raise the risk
 * level, so decide() over the view never allows what it denied over `state`.
 */
export function withRisk(state: State, tenant: string, now: number, levels: { principal: string; level: RiskLevel }[]): State {
  const riskSignals: Record<string, RiskSignal> = { ...(state.riskSignals ?? {}) };
  for (const { principal, level } of levels) {
    if (!RISK_LEVELS.includes(level) || level === 'none') continue;
    const id = `provider:${riskSignalId('risk-provider', principal)}`;
    riskSignals[id] = { id, tenant, principal, level, source: 'risk-provider', issuedAt: now, expiresAt: now + 1 };
  }
  return { ...state, riskSignals };
}
