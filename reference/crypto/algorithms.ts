import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

/**
 * Signature algorithm registry (0.6, ADR-021). Every algorithm is a NIST-standardised or
 * IETF-standardised primitive that node:crypto provides (OpenSSL 3.5+): Ed25519 (RFC 8032),
 * ML-DSA (FIPS 204), SLH-DSA (FIPS 205) and one hybrid that requires an Ed25519 and an ML-DSA-65
 * signature over the same bytes. Adding an algorithm is a registry entry plus a vector, never a
 * free-form string from a document: an unregistered identifier is refused.
 */
export type AlgorithmId = 'ed25519' | 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87' | 'slh-dsa-sha2-128s' | 'slh-dsa-sha2-256s' | 'ed25519+ml-dsa-65';
export type AlgorithmInfo = {
  id: AlgorithmId;
  /** classical: broken by a cryptographically relevant quantum computer (Shor); pq: no such known attack; hybrid: both components must verify. */
  kind: 'classical' | 'pq' | 'hybrid';
  /** node:crypto asymmetricKeyType of each component key, in signature order. */
  components: readonly string[];
  /** Exact byte length of each component signature (fixed-size schemes only). */
  lengths: readonly number[];
  standard: string;
};
const INFO: readonly AlgorithmInfo[] = [
  { id: 'ed25519', kind: 'classical', components: ['ed25519'], lengths: [64], standard: 'RFC 8032' },
  { id: 'ml-dsa-44', kind: 'pq', components: ['ml-dsa-44'], lengths: [2420], standard: 'NIST FIPS 204 (category 2)' },
  { id: 'ml-dsa-65', kind: 'pq', components: ['ml-dsa-65'], lengths: [3309], standard: 'NIST FIPS 204 (category 3)' },
  { id: 'ml-dsa-87', kind: 'pq', components: ['ml-dsa-87'], lengths: [4627], standard: 'NIST FIPS 204 (category 5)' },
  { id: 'slh-dsa-sha2-128s', kind: 'pq', components: ['slh-dsa-sha2-128s'], lengths: [7856], standard: 'NIST FIPS 205 (category 1)' },
  { id: 'slh-dsa-sha2-256s', kind: 'pq', components: ['slh-dsa-sha2-256s'], lengths: [29792], standard: 'NIST FIPS 205 (category 5)' },
  { id: 'ed25519+ml-dsa-65', kind: 'hybrid', components: ['ed25519', 'ml-dsa-65'], lengths: [64, 3309], standard: 'RFC 8032 + NIST FIPS 204; AKAC-specific composition (both signatures required)' }
];
export const ALGORITHMS: readonly AlgorithmId[] = INFO.map(i => i.id);
const BY_ID = new Map<string, AlgorithmInfo>(INFO.map(i => [i.id, i]));
export const isAlgorithm = (value: unknown): value is AlgorithmId => typeof value === 'string' && BY_ID.has(value);
export const algorithmInfo = (id: AlgorithmId): AlgorithmInfo => BY_ID.get(id)!;
/** True when the algorithm has a post-quantum component (pq or hybrid). */
export const hasPostQuantum = (id: AlgorithmId): boolean => algorithmInfo(id).kind !== 'classical';
/** Length in bytes of a signature of `id`. */
export const signatureLength = (id: AlgorithmId): number => algorithmInfo(id).lengths.reduce((a, b) => a + b, 0);
/** Key ids carry the algorithm as their prefix (`ml-dsa-65:prod-2026`); an id without a registered prefix is the legacy Ed25519 form. */
export function algorithmOfKeyId(keyId: string): AlgorithmId | undefined {
  const i = typeof keyId === 'string' ? keyId.indexOf(':') : -1;
  const prefix = i > 0 ? keyId.slice(0, i) : '';
  return isAlgorithm(prefix) ? prefix : undefined;
}
export const KEY_ID_PATTERN = /^[A-Za-z0-9._:+-]{1,128}$/;
/** Key id rule of format 3: `<alg>:<label>` with the checkpoint's own algorithm. */
export const keyIdMatches = (keyId: string, alg: AlgorithmId): boolean => KEY_ID_PATTERN.test(keyId) && keyId.startsWith(`${alg}:`) && keyId.length > alg.length + 1;

const PEM = /-----BEGIN ([A-Z ]+)-----[A-Za-z0-9+/=\s]+?-----END \1-----/g;
const blocks = (text: string): string[] => text.match(PEM) ?? [];
/** Overwrites a Buffer in place. Strings and KeyObjects cannot be erased (docs/CRYPTO-AGILITY.md, key-material hygiene). */
export const zeroize = (buffer: Uint8Array): void => { buffer.fill(0); };
function ordered<T extends KeyObject>(alg: AlgorithmId, keys: T[]): T[] {
  const want = algorithmInfo(alg).components;
  if (keys.length !== want.length || keys.some((k, i) => k.asymmetricKeyType !== want[i])) throw new Error(`Key material does not match ${alg}`);
  return keys;
}
/** Public keys of `alg` from PEM text: one SPKI block, or for the hybrid an Ed25519 block followed by an ML-DSA-65 block. */
export function parsePublicKeys(alg: AlgorithmId, pem: string): KeyObject[] {
  if (typeof pem !== 'string' || pem.length > 16384) throw new Error('Invalid public key');
  const found = blocks(pem);
  if (found.some(b => !b.startsWith('-----BEGIN PUBLIC KEY-----'))) throw new Error('Public key must be SPKI PEM');
  return ordered(alg, found.map(b => createPublicKey(b)));
}
/** Private keys of `alg` (PKCS#8 PEM blocks, same order as public keys). A Buffer input is erased after parsing. */
export function parsePrivateKeys(alg: AlgorithmId, pem: string | Buffer): KeyObject[] {
  const text = typeof pem === 'string' ? pem : pem.toString('latin1');
  try {
    const found = blocks(text);
    if (found.some(b => !b.startsWith('-----BEGIN PRIVATE KEY-----'))) throw new Error('Private key must be PKCS#8 PEM');
    return ordered(alg, found.map(b => createPrivateKey(b)));
  } finally { if (typeof pem !== 'string') zeroize(pem); }
}
/** The registered algorithm that PEM key material belongs to (public or private), or undefined. Does not erase a Buffer. */
export function detectAlgorithm(pem: string | Buffer): AlgorithmId | undefined {
  const found = blocks(typeof pem === 'string' ? pem : pem.toString('latin1'));
  try {
    const types = found.map(b => (b.includes('PRIVATE KEY') ? createPrivateKey(b) : createPublicKey(b)).asymmetricKeyType);
    return INFO.find(i => i.components.length === types.length && i.components.every((c, n) => c === types[n]))?.id;
  } catch { return undefined; }
}
/** node:crypto in this runtime can create and use keys of `alg` (ML-DSA and SLH-DSA need OpenSSL 3.5+, Node 24.x). */
export function runtimeSupports(alg: AlgorithmId): boolean {
  try { for (const c of algorithmInfo(alg).components) generateKeyPairSync(c as 'ed25519'); return true; } catch { return false; }
}
/** Fresh key pair as PEM text (the hybrid: two concatenated blocks). For tests, `keygen` and offline ceremonies. */
export function generateKeyMaterial(alg: AlgorithmId): { privatePem: string; publicPem: string } {
  const pairs = algorithmInfo(alg).components.map(c => generateKeyPairSync(c as 'ed25519'));
  return { privatePem: pairs.map(p => p.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()).join(''),
    publicPem: pairs.map(p => p.publicKey.export({ type: 'spki', format: 'pem' }).toString()).join('') };
}
/** Signature of `message`: the component signatures concatenated in registry order (the hybrid: Ed25519 || ML-DSA-65). */
export function signBytes(alg: AlgorithmId, message: Uint8Array, keys: KeyObject[]): Buffer {
  const info = algorithmInfo(alg);
  ordered(alg, keys);
  const out = keys.map(k => sign(null, message, k));
  if (out.some((s, i) => s.length !== info.lengths[i])) throw new Error(`Unexpected ${alg} signature length`);
  return Buffer.concat(out);
}
/** Every component signature must verify: a hybrid with one bad or missing half is invalid. False, never a throw, on malformed input. */
export function verifyBytes(alg: AlgorithmId, message: Uint8Array, keys: KeyObject[], signature: Uint8Array): boolean {
  try {
    const info = algorithmInfo(alg);
    ordered(alg, keys);
    if (signature.length !== signatureLength(alg)) return false;
    let offset = 0;
    const results = keys.map((k, i) => { const part = signature.subarray(offset, offset += info.lengths[i]!); return verify(null, message, k, part); });
    return results.every(Boolean);
  } catch { return false; }
}
