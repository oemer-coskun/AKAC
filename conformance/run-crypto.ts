import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { verifyCheckpointHistory, verifyCheckpointV3 } from '../reference/checkpoint.ts';
import type { AuditCheckpoint, CheckpointV3 } from '../reference/checkpoint.ts';
import { isAlgorithm, runtimeSupports } from '../reference/crypto/algorithms.ts';
import { parsePolicy } from '../reference/crypto/policy.ts';
import { outcomeOf } from './outcome.ts';
import type { Row } from './outcome.ts';

/**
 * Crypto agility vectors (AKAC 0.6, ADR-021, R159..R164). Verification-only known answers with public keys and
 * signatures; see the description in conformance/vectors-0.6-crypto.json.
 * - checkpoint-v3: verifyCheckpointV3(checkpoint, publicKey, stream, keyId, {minimumSize?, policy?}) must equal `expected`.
 * - checkpoint-history: verifyCheckpointHistory over items {checkpoint, publicKey} with the policy must equal `expected`.
 * Accepting a forged, relabelled, partial-hybrid or downgraded checkpoint is an allow of something that must be denied:
 * UNSAFE_SUCCESS. A runtime that cannot execute an algorithm is a FAILURE for the reference (Node 24 with OpenSSL 3.5 is
 * required); other implementations report NOT_APPLICABLE for algorithms they lack (Python runner), never a pass.
 */
type Vector = { id: string; kind: 'checkpoint-v3' | 'checkpoint-history'; expected: boolean; tags?: string[]; alg?: string; policy?: unknown;
  checkpoint?: unknown; publicKey?: string; stream: string; keyId?: string; minimumSize?: number; items?: { checkpoint: AuditCheckpoint; publicKey: string }[] };
export function runCryptoVectors(): Row[] {
  const data = JSON.parse(readFileSync(new URL('./vectors-0.6-crypto.json', import.meta.url), 'utf8')) as { cases: Vector[] };
  return data.cases.map(v => {
    let actual: unknown;
    try {
      const policy = v.policy ? parsePolicy(v.policy) : undefined;
      const algs = v.kind === 'checkpoint-v3' ? [v.alg] : v.items!.map(i => (i.checkpoint as { alg?: string }).alg ?? 'ed25519');
      if (!algs.every(a => isAlgorithm(a) && runtimeSupports(a))) actual = 'unsupported-runtime';
      else if (v.kind === 'checkpoint-v3') actual = verifyCheckpointV3(v.checkpoint as CheckpointV3, v.publicKey!, v.stream, v.keyId!, { ...(v.minimumSize !== undefined ? { minimumSize: v.minimumSize } : {}), ...(policy ? { policy } : {}) });
      else actual = verifyCheckpointHistory(v.items!.map(i => ({ checkpoint: i.checkpoint, publicPem: i.publicKey })), v.stream, policy);
    } catch (error) { actual = `error: ${(error as Error).message}`; }
    const pass = isDeepStrictEqual(actual, v.expected);
    return { id: v.id, kind: v.kind, expected: v.expected ? 'accept' : 'reject', actual: actual === true ? 'accept' : actual === false ? 'reject' : actual, pass,
      outcome: outcomeOf(v.expected === true, actual === true, pass), ...(v.tags ? { tags: v.tags } : {}) };
  });
}
