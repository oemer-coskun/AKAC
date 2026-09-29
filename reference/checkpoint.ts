import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import type { Audit } from './types.ts';
import { auditLeaf, verifyAudit } from './audit.ts';
import { canonicalBytes } from './jcs.ts';
import { isHash, rootOf, verifyConsistency } from './merkle.ts';
import type { TreeHead } from './evidence.ts';
import { isAlgorithm, keyIdMatches, parsePrivateKeys, parsePublicKeys, signBytes, signatureLength, verifyBytes } from './crypto/algorithms.ts';
import type { AlgorithmId } from './crypto/algorithms.ts';
import { AlgorithmFloor, DEFAULT_POLICY, allows } from './crypto/policy.ts';
import type { VerifierPolicy } from './crypto/policy.ts';
/** A checkpoint covers exactly one tenant stream, in order, from sequence 1. */
const single = (entries: Audit[]) => entries.every(e => e.tenant === entries[0]!.tenant);
import { exactKeys, safeNumber, safeText } from './validation.ts';

/** Format 1 (0.2-0.3): signs the hash of the last entry. Still verified; new checkpoints use format 2. */
export type Checkpoint = {
  format: 'akac-audit-checkpoint/1'; stream: string; sequence: number;
  hash: string; issuedAt: number; keyId: string; signature: string;
};
/**
 * Format 2 (0.4): an Ed25519 signature over the RFC 8785 (JCS) form of every
 * other member, i.e. {format, stream, treeSize, rootHash, issuedAt, keyId}, where
 * rootHash is the RFC 9162 root of the first treeSize entries of the stream. Two
 * format 2 checkpoints of one stream are checked for append-only history with an
 * RFC 9162 consistency proof, which detects rewritten, reordered and rolled-back
 * streams without holding the entries.
 */
export type CheckpointV2 = {
  format: 'akac-audit-checkpoint/2'; stream: string; treeSize: number;
  rootHash: string; issuedAt: number; keyId: string; signature: string;
};
/**
 * Format 3 (0.6, ADR-021): the format 2 content plus `alg`, an identifier from the algorithm registry
 * (reference/crypto/algorithms.ts). The signature covers the RFC 8785 (JCS) form of every other member, i.e.
 * {format, alg, stream, treeSize, rootHash, issuedAt, keyId}, so the algorithm cannot be swapped without invalidating
 * the signature and a v3 signature is never valid as a v2 one. `keyId` is `<alg>:<label>`. `signature` is the
 * base64url of the component signatures in registry order; the hybrid `ed25519+ml-dsa-65` is Ed25519 (64 bytes)
 * followed by ML-DSA-65 (3309 bytes) over the same bytes and is valid only if BOTH verify. Which algorithms a
 * verifier accepts is its own policy (reference/crypto/policy.ts), not something the record decides.
 */
export type CheckpointV3 = {
  format: 'akac-audit-checkpoint/3'; alg: AlgorithmId; stream: string; treeSize: number;
  rootHash: string; issuedAt: number; keyId: string; signature: string;
};
/** Any checkpoint format that signs a tree head (2 and 3). */
export type AuditCheckpoint = CheckpointV2 | CheckpointV3;
function bytes(record: Omit<Checkpoint, 'signature'>): Buffer {
  return Buffer.from(JSON.stringify([record.format, record.stream, record.sequence, record.hash, record.issuedAt, record.keyId]));
}
const signingKey = (privatePem: string) => {
  const key = createPrivateKey(privatePem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Ed25519 checkpoint key required');
  return key;
};
export function signCheckpoint(entries: Audit[], privatePem: string, stream: string, keyId: string, issuedAt = Date.now()): Checkpoint {
  if (!verifyAudit(entries) || !single(entries) || !safeText(stream, 128) || !safeText(keyId, 128) || !safeNumber(issuedAt)) throw new Error('Invalid checkpoint input');
  const key = signingKey(privatePem);
  const body: Omit<Checkpoint, 'signature'> = { format: 'akac-audit-checkpoint/1', stream,
    sequence: entries.length, hash: entries.at(-1)?.hash ?? '0'.repeat(64), issuedAt, keyId };
  return { ...body, signature: sign(null, bytes(body), key).toString('base64url') };
}
/** The caller obtains this checkpoint/public key from an independent trusted location. */
export function verifyCheckpoint(entries: Audit[], record: Checkpoint, publicPem: string, expectedStream: string, expectedKeyId: string, minimumSequence: number): boolean {
  try {
    if (!exactKeys(record, ['format', 'stream', 'sequence', 'hash', 'issuedAt', 'keyId', 'signature'])
      || record.format !== 'akac-audit-checkpoint/1' || record.stream !== expectedStream || record.keyId !== expectedKeyId
      || !safeNumber(record.sequence) || !safeNumber(record.issuedAt) || !safeNumber(minimumSequence)
      || record.sequence < minimumSequence || record.sequence > entries.length
      || !safeText(record.stream, 128) || !safeText(record.keyId, 128)
      || typeof record.hash !== 'string' || !/^[a-f0-9]{64}$/.test(record.hash)
      || typeof record.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(record.signature)
      || !verifyAudit(entries) || !single(entries)) return false;
    const key = createPublicKey(publicPem);
    if (key.asymmetricKeyType !== 'ed25519') return false;
    const hash = record.sequence ? entries[record.sequence - 1]!.hash : '0'.repeat(64);
    return hash === record.hash && verify(null, bytes(record), key, Buffer.from(record.signature, 'base64url'));
  } catch { return false; }
}

const unsigned = (r: Omit<CheckpointV2, 'signature'>) => canonicalBytes({ format: r.format, stream: r.stream, treeSize: r.treeSize,
  rootHash: r.rootHash, issuedAt: r.issuedAt, keyId: r.keyId });
/** The exact bytes a format 2 checkpoint signature covers (JCS of every member but `signature`); for external signers (reference/custody.ts). */
export const checkpointSigningInput = (r: Omit<CheckpointV2, 'signature'>): Buffer => unsigned(r);
/** Signs a tree head (for example from reference/evidence.ts treeHead) as a format 2 checkpoint. */
export function signTreeHead(head: TreeHead, privatePem: string, keyId: string, issuedAt = Date.now()): CheckpointV2 {
  if (!safeText(head?.stream, 128) || !safeText(keyId, 128) || !safeNumber(issuedAt) || !safeNumber(head.treeSize) || !isHash(head.rootHash)) throw new Error('Invalid checkpoint input');
  const body: Omit<CheckpointV2, 'signature'> = { format: 'akac-audit-checkpoint/2', stream: head.stream, treeSize: head.treeSize,
    rootHash: head.rootHash, issuedAt, keyId };
  return { ...body, signature: sign(null, unsigned(body), signingKey(privatePem)).toString('base64url') };
}
/** Signs a format 2 checkpoint over a complete, verified stream (root recomputed from the entries). */
export function signCheckpointV2(entries: Audit[], privatePem: string, stream: string, keyId: string, issuedAt = Date.now()): CheckpointV2 {
  // The stream of a format 2 checkpoint is the tenant whose audit stream it covers.
  if (!verifyAudit(entries) || !single(entries) || (entries.length && entries[0]!.tenant !== stream)) throw new Error('Invalid checkpoint input');
  return signTreeHead({ stream, treeSize: entries.length, rootHash: rootOf(entries.map(auditLeaf)) }, privatePem, keyId, issuedAt);
}
/**
 * Verifies a format 2 checkpoint: closed shape, expected stream and key, Ed25519
 * signature and, with `minimumSize`, no rollback below a size already trusted.
 * With `entries` (the stream from sequence 1), also the chain and that the root of
 * the first treeSize entries equals rootHash.
 */
export function verifyCheckpointV2(record: CheckpointV2, publicPem: string, expectedStream: string, expectedKeyId: string,
  options: { entries?: Audit[]; minimumSize?: number } = {}): boolean {
  try {
    const minimum = options.minimumSize ?? 0;
    if (!exactKeys(record, ['format', 'stream', 'treeSize', 'rootHash', 'issuedAt', 'keyId', 'signature'])
      || record.format !== 'akac-audit-checkpoint/2' || record.stream !== expectedStream || record.keyId !== expectedKeyId
      || !safeText(record.stream, 128) || !safeText(record.keyId, 128) || !safeNumber(record.treeSize) || !safeNumber(record.issuedAt)
      || !safeNumber(minimum) || record.treeSize < minimum || !isHash(record.rootHash)
      || typeof record.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(record.signature)) return false;
    const key = createPublicKey(publicPem);
    if (key.asymmetricKeyType !== 'ed25519' || !verify(null, unsigned(record), key, Buffer.from(record.signature, 'base64url'))) return false;
    if (!options.entries) return true;
    const entries = options.entries;
    return verifyAudit(entries) && single(entries) && entries.length >= record.treeSize && (!entries.length || entries[0]!.tenant === expectedStream)
      && rootOf(entries.slice(0, record.treeSize).map(auditLeaf)) === record.rootHash;
  } catch { return false; }
}
/**
 * Append-only check between two independently verified format 2 checkpoints of the
 * same stream: `newer` must extend `older` (RFC 9162 §2.1.4.2). A rolled-back,
 * truncated or rewritten stream cannot produce a valid proof.
 */
export function verifyCheckpointExtension(older: AuditCheckpoint, newer: AuditCheckpoint, path: readonly string[]): boolean {
  const tree = (r: AuditCheckpoint) => r.format === 'akac-audit-checkpoint/2' || r.format === 'akac-audit-checkpoint/3';
  return older.stream === newer.stream && tree(older) && tree(newer)
    && verifyConsistency(older.treeSize, newer.treeSize, older.rootHash, newer.rootHash, path);
}

const unsignedV3 = (r: Omit<CheckpointV3, 'signature'>) => canonicalBytes({ format: r.format, alg: r.alg, stream: r.stream, treeSize: r.treeSize,
  rootHash: r.rootHash, issuedAt: r.issuedAt, keyId: r.keyId });
/** The exact bytes a format 3 checkpoint signature covers; for external signers (reference/custody.ts). */
export const checkpointSigningInputV3 = (r: Omit<CheckpointV3, 'signature'>): Buffer => unsignedV3(r);
/** Format 3 record without a signature; validates the identifiers a signer must not get wrong. */
export function checkpointBodyV3(head: TreeHead, alg: AlgorithmId, keyId: string, issuedAt: number): Omit<CheckpointV3, 'signature'> {
  if (!isAlgorithm(alg) || !safeText(head?.stream, 128) || !keyIdMatches(keyId, alg) || !safeNumber(issuedAt) || !safeNumber(head.treeSize) || !isHash(head.rootHash)) throw new Error('Invalid checkpoint input');
  return { format: 'akac-audit-checkpoint/3', alg, stream: head.stream, treeSize: head.treeSize, rootHash: head.rootHash, issuedAt, keyId };
}
/** Signs a tree head as a format 3 checkpoint. `privatePem` holds PKCS#8 PEM (the hybrid: an Ed25519 block then an ML-DSA-65 block). */
export function signTreeHeadV3(head: TreeHead, alg: AlgorithmId, privatePem: string, keyId: string, issuedAt = Date.now()): CheckpointV3 {
  const body = checkpointBodyV3(head, alg, keyId, issuedAt);
  return { ...body, signature: signBytes(alg, unsignedV3(body), parsePrivateKeys(alg, privatePem)).toString('base64url') };
}
/** Signs a format 3 checkpoint over a complete, verified stream (root recomputed from the entries). */
export function signCheckpointV3(entries: Audit[], alg: AlgorithmId, privatePem: string, stream: string, keyId: string, issuedAt = Date.now()): CheckpointV3 {
  if (!verifyAudit(entries) || !single(entries) || (entries.length && entries[0]!.tenant !== stream)) throw new Error('Invalid checkpoint input');
  return signTreeHeadV3({ stream, treeSize: entries.length, rootHash: rootOf(entries.map(auditLeaf)) }, alg, privatePem, keyId, issuedAt);
}
/** Canonical, exact-length base64url signature of `alg` as bytes, or undefined. */
function decodeSignature(alg: AlgorithmId, text: unknown): Buffer | undefined {
  if (typeof text !== 'string' || text.length > 40000 || !/^[A-Za-z0-9_-]+$/.test(text)) return undefined;
  const raw = Buffer.from(text, 'base64url');
  return raw.length === signatureLength(alg) && raw.toString('base64url') === text ? raw : undefined;
}
/**
 * Verifies a format 3 checkpoint: closed shape, a registered algorithm the `policy` allows (default: every registered
 * algorithm), key id `<alg>:<label>` equal to the expected one, key material of that algorithm, every component
 * signature, and with `minimumSize` no rollback. With `entries` also the chain and the root. Downgrade across several
 * checkpoints of one stream is a separate check (AlgorithmFloor, verifyCheckpointHistory).
 */
export function verifyCheckpointV3(record: CheckpointV3, publicPem: string, expectedStream: string, expectedKeyId: string,
  options: { entries?: Audit[]; minimumSize?: number; policy?: VerifierPolicy } = {}): boolean {
  try {
    const minimum = options.minimumSize ?? 0;
    if (!exactKeys(record, ['format', 'alg', 'stream', 'treeSize', 'rootHash', 'issuedAt', 'keyId', 'signature'])
      || record.format !== 'akac-audit-checkpoint/3' || !isAlgorithm(record.alg) || !allows(options.policy ?? DEFAULT_POLICY, record.alg)
      || record.stream !== expectedStream || record.keyId !== expectedKeyId || !keyIdMatches(record.keyId, record.alg)
      || !safeText(record.stream, 128) || !safeNumber(record.treeSize) || !safeNumber(record.issuedAt)
      || !safeNumber(minimum) || record.treeSize < minimum || !isHash(record.rootHash)) return false;
    const signature = decodeSignature(record.alg, record.signature);
    if (!signature || !verifyBytes(record.alg, unsignedV3(record), parsePublicKeys(record.alg, publicPem), signature)) return false;
    if (!options.entries) return true;
    const entries = options.entries;
    return verifyAudit(entries) && single(entries) && entries.length >= record.treeSize && (!entries.length || entries[0]!.tenant === expectedStream)
      && rootOf(entries.slice(0, record.treeSize).map(auditLeaf)) === record.rootHash;
  } catch { return false; }
}
/** Verifies a format 2 or 3 checkpoint (any other format is refused). Format 3 honours `policy`; format 2 is Ed25519, allowed unless the policy excludes it. */
export function verifyAuditCheckpoint(record: AuditCheckpoint, publicPem: string, expectedStream: string, expectedKeyId: string,
  options: { entries?: Audit[]; minimumSize?: number; policy?: VerifierPolicy } = {}): boolean {
  if (record?.format === 'akac-audit-checkpoint/3') return verifyCheckpointV3(record, publicPem, expectedStream, expectedKeyId, options);
  if (record?.format === 'akac-audit-checkpoint/2' && allows(options.policy ?? DEFAULT_POLICY, 'ed25519')) return verifyCheckpointV2(record, publicPem, expectedStream, expectedKeyId, options);
  return false;
}
/** The algorithm a format 2 or 3 checkpoint claims (format 2 is always Ed25519). */
export const checkpointAlgorithm = (r: AuditCheckpoint): AlgorithmId => (r.format === 'akac-audit-checkpoint/3' ? r.alg : 'ed25519');
export type HistoryItem = { checkpoint: AuditCheckpoint; publicPem: string };
/**
 * No-downgrade verification of several checkpoints of ONE stream, each with the trusted public key for its key id.
 * Every checkpoint must verify under `policy`; then no classical-only checkpoint may be newer or larger than the
 * earliest verified checkpoint that had a post-quantum component, unless `policy.allowClassicalAfterPq`. Returns
 * false for the whole set on any failure (fail closed). Consistency of the roots is checked separately
 * (verifyCheckpointExtension) because it needs proofs.
 */
export function verifyCheckpointHistory(items: HistoryItem[], expectedStream: string, policy: VerifierPolicy = DEFAULT_POLICY, floor = new AlgorithmFloor(policy)): boolean {
  try {
    if (!Array.isArray(items) || !items.length) return false;
    const head = (c: AuditCheckpoint) => ({ stream: c.stream, alg: checkpointAlgorithm(c), issuedAt: c.issuedAt, treeSize: c.treeSize });
    for (const { checkpoint, publicPem } of items) {
      if (!verifyAuditCheckpoint(checkpoint, publicPem, expectedStream, checkpoint.keyId, { policy })) return false;
      floor.observe(head(checkpoint));
    }
    return items.every(({ checkpoint }) => floor.check(head(checkpoint)) === 'ok');
  } catch { return false; }
}
