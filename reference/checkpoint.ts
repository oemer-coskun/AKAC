import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import type { Audit } from './types.ts';
import { auditLeaf, verifyAudit } from './audit.ts';
import { canonicalBytes } from './jcs.ts';
import { isHash, rootOf, verifyConsistency } from './merkle.ts';
import type { TreeHead } from './evidence.ts';
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
export function verifyCheckpointExtension(older: CheckpointV2, newer: CheckpointV2, path: readonly string[]): boolean {
  return older.stream === newer.stream && older.format === 'akac-audit-checkpoint/2' && newer.format === 'akac-audit-checkpoint/2'
    && verifyConsistency(older.treeSize, newer.treeSize, older.rootHash, newer.rootHash, path);
}
