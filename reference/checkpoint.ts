import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import type { Audit } from './types.ts';
import { verifyAudit } from './audit.ts';
/** A checkpoint covers exactly one tenant stream, in order, from sequence 1. */
const single = (entries: Audit[]) => entries.every(e => e.tenant === entries[0]!.tenant);
import { exactKeys, safeNumber, safeText } from './validation.ts';

export type Checkpoint = {
  format: 'akac-audit-checkpoint/1'; stream: string; sequence: number;
  hash: string; issuedAt: number; keyId: string; signature: string;
};
function bytes(record: Omit<Checkpoint, 'signature'>): Buffer {
  return Buffer.from(JSON.stringify([record.format, record.stream, record.sequence, record.hash, record.issuedAt, record.keyId]));
}
export function signCheckpoint(entries: Audit[], privatePem: string, stream: string, keyId: string, issuedAt = Date.now()): Checkpoint {
  if (!verifyAudit(entries) || !single(entries) || !safeText(stream, 128) || !safeText(keyId, 128) || !safeNumber(issuedAt)) throw new Error('Invalid checkpoint input');
  const key = createPrivateKey(privatePem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Ed25519 checkpoint key required');
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
