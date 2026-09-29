import { ALGORITHMS, hasPostQuantum, isAlgorithm } from './algorithms.ts';
import type { AlgorithmId } from './algorithms.ts';
import { exactKeys, safeNumber } from '../validation.ts';

/**
 * Verifier policy (0.6, ADR-021): what THIS verifier accepts, decided by its operator and never by the
 * document being verified. `algorithms` is an allowlist. `allowClassicalAfterPq` is the explicit, default-off
 * downgrade permission (see AlgorithmFloor).
 */
export type VerifierPolicy = { algorithms: readonly AlgorithmId[]; allowClassicalAfterPq?: boolean };
/** Every registered algorithm; classical-after-PQ refused. */
export const DEFAULT_POLICY: VerifierPolicy = Object.freeze({ algorithms: ALGORITHMS });
/** Only classical Ed25519: the 0.4-0.5 verifier behaviour. */
export const CLASSICAL_ONLY_POLICY: VerifierPolicy = Object.freeze({ algorithms: Object.freeze(['ed25519'] as AlgorithmId[]) });
export function parsePolicy(value: unknown): VerifierPolicy {
  if (!exactKeys(value, ['algorithms'], ['allowClassicalAfterPq']) || !Array.isArray(value.algorithms) || !value.algorithms.length || !value.algorithms.every(isAlgorithm)
    || (value.allowClassicalAfterPq !== undefined && typeof value.allowClassicalAfterPq !== 'boolean')) throw new Error('Invalid verifier policy');
  return { algorithms: [...new Set(value.algorithms as AlgorithmId[])], ...(value.allowClassicalAfterPq ? { allowClassicalAfterPq: true } : {}) };
}
export const allows = (policy: VerifierPolicy, alg: AlgorithmId): boolean => policy.algorithms.includes(alg);

/** The earliest verified checkpoint of a stream that carried a post-quantum component. */
export type PqSince = { issuedAt: number; treeSize: number };
export type AlgorithmVerdict = 'ok' | 'algorithm_not_allowed' | 'downgrade';
type Head = { stream: string; alg: AlgorithmId; issuedAt: number; treeSize: number };
/**
 * No-downgrade rule. Once a stream has a verified checkpoint with a post-quantum component (pq or hybrid), a
 * classical-only checkpoint of that stream is refused unless it is provably older (issuedAt before AND treeSize
 * not beyond that first post-quantum checkpoint) or the policy sets `allowClassicalAfterPq`. An attacker who can
 * forge only Ed25519 (a quantum adversary, or a stolen classical key) therefore cannot present a fresh classical
 * checkpoint for a stream that migrated. A backdated forgery is still bound by append-only history: it must be a
 * prefix of the later stream (verifyCheckpointExtension). Only signature-verified checkpoints may be passed to
 * `observe`; the floor is verifier state and can be persisted with `snapshot()` (a claim inside an unverified
 * document never raises or lowers it).
 */
export class AlgorithmFloor {
  private since = new Map<string, PqSince>();
  private policy: VerifierPolicy;
  constructor(policy: VerifierPolicy = DEFAULT_POLICY, snapshot: Record<string, PqSince> = {}) {
    this.policy = policy;
    for (const [stream, s] of Object.entries(snapshot)) if (safeNumber(s?.issuedAt) && safeNumber(s?.treeSize)) this.since.set(stream, { issuedAt: s.issuedAt, treeSize: s.treeSize });
  }
  check(head: Head): AlgorithmVerdict {
    if (!allows(this.policy, head.alg)) return 'algorithm_not_allowed';
    const since = this.since.get(head.stream);
    if (!hasPostQuantum(head.alg) && since && !this.policy.allowClassicalAfterPq && (head.issuedAt >= since.issuedAt || head.treeSize > since.treeSize)) return 'downgrade';
    return 'ok';
  }
  observe(head: Head): void {
    if (!hasPostQuantum(head.alg)) return;
    const s = this.since.get(head.stream);
    if (!s || head.issuedAt < s.issuedAt) this.since.set(head.stream, { issuedAt: head.issuedAt, treeSize: head.treeSize });
  }
  snapshot(): Record<string, PqSince> { return Object.fromEntries(this.since); }
}
