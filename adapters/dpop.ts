import { createHash } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import type { JWK } from 'jose';
import type { ProofBinding } from './jwt.ts';

/**
 * Optional sender-constrained access tokens: OAuth 2.0 DPoP (RFC 9449) at the resource server.
 * Proof of possession narrows replay of a stolen access token; it does not replace token validation,
 * grants or revocation. Server-provided nonces (`DPoP-Nonce`, RFC 9449 section 8) are not supported.
 */
export const DPOP_ALGORITHMS = ['ES256', 'EdDSA', 'PS256'] as const;
export type DpopAlgorithm = typeof DPOP_ALGORITHMS[number];
export type DpopMode = 'optional' | 'required';
export const DPOP_LIMITS = { proof: 8192, jti: 256, defaultSkewSeconds: 60, maxSkewSeconds: 300, replayEntries: 100_000 } as const;

/** Single-use registry for proof identifiers, keyed by (jti, key thumbprint). */
export interface DpopReplayCache {
  /** Resolves true when the pair was new (now recorded until `expiresAt`, Unix seconds) and false for a replay. Rejects when the decision cannot be made; callers fail closed. */
  consume(jti: string, jkt: string, expiresAt: number): Promise<boolean>;
  close?(): Promise<void>;
}
/**
 * Per-instance replay cache. A replica does not see another replica's proofs: use the PostgreSQL cache for
 * more than one instance. Unexpired entries are never evicted (that would reopen a replay window); when the
 * bound is reached the cache refuses, so requests fail closed until entries expire.
 */
export class MemoryReplayCache implements DpopReplayCache {
  private seen = new Map<string, number>();
  private swept = 0;
  private max: number; private clock: () => number;
  constructor(max: number = DPOP_LIMITS.replayEntries, clock: () => number = () => Date.now()) { this.max = max; this.clock = clock; }
  async consume(jti: string, jkt: string, expiresAt: number): Promise<boolean> {
    const now = Math.floor(this.clock() / 1000), key = `${jkt}.${jti}`;
    if (now !== this.swept) { this.swept = now; for (const [k, exp] of this.seen) if (exp <= now) this.seen.delete(k); }
    const existing = this.seen.get(key);
    if (existing !== undefined && existing > now) return false;
    if (existing === undefined && this.seen.size >= this.max) throw new Error('DPoP replay cache is full');
    this.seen.set(key, expiresAt);
    return true;
  }
}

const plain = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const b64 = /^[A-Za-z0-9_-]+$/;
const sha256b64 = (s: string) => createHash('sha256').update(s).digest('base64url');
// Only public members: any private (d, p, q, dp, dq, qi, oth, k) or key-reference (x5c, x5u, ...) member is refused.
const PUBLIC_MEMBERS = new Set(['kty', 'crv', 'x', 'y', 'n', 'e', 'use', 'alg', 'kid']);
function publicJwk(value: unknown, alg: DpopAlgorithm): JWK | null {
  if (!plain(value)) return null;
  const j = value;
  if (Object.keys(j).some(k => !PUBLIC_MEMBERS.has(k) || typeof j[k] !== 'string')) return null;
  if ((j.alg !== undefined && j.alg !== alg) || (j.use !== undefined && j.use !== 'sig')) return null;
  const s = (k: string) => j[k] as string | undefined, coord = (k: string) => typeof s(k) === 'string' && b64.test(s(k)!) && s(k)!.length === 43;
  if (alg === 'ES256' && !(j.kty === 'EC' && j.crv === 'P-256' && coord('x') && coord('y') && !Object.hasOwn(j, 'n'))) return null;
  if (alg === 'EdDSA' && !(j.kty === 'OKP' && j.crv === 'Ed25519' && coord('x') && !Object.hasOwn(j, 'y'))) return null;
  if (alg === 'PS256') {
    if (j.kty !== 'RSA' || !s('n') || !s('e') || !b64.test(s('n')!) || !b64.test(s('e')!) || s('e')!.length > 8 || Object.hasOwn(j, 'crv')) return null;
    const n = Buffer.from(s('n')!, 'base64url');
    if (n[0] === 0 || n.length < 256 || n.length > 512) return null; // 2048-4096 bit modulus
  }
  return j as JWK;
}
const norm = (s: string) => { const u = new URL(s); return `${u.origin}${u.pathname}`; };

export type ProofCheck = { method: string; htu: string; accessToken: string; algorithms: readonly DpopAlgorithm[]; skewSeconds: number; now: number };
export type VerifiedProof = { jkt: string; jti: string; iat: number };
/** Verifies one DPoP proof (RFC 9449 section 4.3). Never throws; null means invalid. Replay and token binding are checked by the caller. */
export async function verifyDpopProof(proof: string, check: ProofCheck): Promise<VerifiedProof | null> {
  try {
    if (proof.length > DPOP_LIMITS.proof || proof.split('.').length !== 3) return null;
    const header = decodeProtectedHeader(proof);
    const alg = header.alg as DpopAlgorithm;
    if (header.typ !== 'dpop+jwt' || !check.algorithms.includes(alg) || header.jku || header.x5u || header.x5c || header.x5t || header['x5t#S256'] || header.crit) return null;
    const jwk = publicJwk(header.jwk, alg);
    if (!jwk) return null;
    const key = await importJWK(jwk, alg);
    const { payload } = await jwtVerify(proof, key, { algorithms: [alg], typ: 'dpop+jwt', requiredClaims: ['jti', 'iat'], clockTolerance: 0 });
    if (typeof payload.jti !== 'string' || !payload.jti || payload.jti.length > DPOP_LIMITS.jti || !Number.isSafeInteger(payload.iat)) return null;
    if (payload.htm !== check.method || typeof payload.htu !== 'string' || payload.ath !== sha256b64(check.accessToken)) return null;
    const htu = new URL(payload.htu);
    if (htu.search || htu.hash || htu.username || htu.password || payload.htu.includes('?') || payload.htu.includes('#') || norm(payload.htu) !== norm(check.htu)) return null;
    if (Math.abs(check.now - payload.iat!) > check.skewSeconds) return null;
    return { jkt: await calculateJwkThumbprint(jwk, 'sha256'), jti: payload.jti, iat: payload.iat! };
  } catch { return null; }
}

export type DpopOptions = {
  mode: DpopMode;
  /** Externally visible base URL of this listener (scheme, host, optional path prefix). The Host header is never trusted. */
  publicUrl: string | (() => string);
  algorithms?: readonly DpopAlgorithm[];
  skewSeconds?: number;
  replay?: DpopReplayCache;
  clock?: () => number;
};
export type DpopOutcome<T> = { ok: true; value: T } | { ok: false; challenge: string[] };
function baseUrl(value: string): URL {
  const u = new URL(value);
  if (!/^https?:$/.test(u.protocol) || u.username || u.password || u.search || u.hash) throw new Error('Invalid DPoP public URL');
  return u;
}
/** Validates a configured public URL; throws on problems. */
export const checkPublicUrl = (value: string) => { baseUrl(value); };

/** Request-level DPoP enforcement shared by the agent and administrative listeners. */
export class DpopGuard {
  readonly mode: DpopMode;
  private publicUrl: () => URL;
  private algorithms: DpopAlgorithm[];
  private skew: number;
  private replay: DpopReplayCache;
  private clock: () => number;
  constructor(options: DpopOptions) {
    if (!['optional', 'required'].includes(options.mode)) throw new Error('Invalid DPoP configuration');
    const algorithms = [...(options.algorithms ?? DPOP_ALGORITHMS)];
    const skew = options.skewSeconds ?? DPOP_LIMITS.defaultSkewSeconds;
    if (!algorithms.length || algorithms.some(a => !DPOP_ALGORITHMS.includes(a)) || !Number.isInteger(skew) || skew < 1 || skew > DPOP_LIMITS.maxSkewSeconds) throw new Error('Invalid DPoP configuration');
    this.mode = options.mode; this.algorithms = algorithms; this.skew = skew;
    this.replay = options.replay ?? new MemoryReplayCache();
    this.clock = options.clock ?? (() => Date.now());
    if (typeof options.publicUrl === 'string') { const fixed = baseUrl(options.publicUrl); this.publicUrl = () => fixed; }
    else { const supply = options.publicUrl; this.publicUrl = () => baseUrl(supply()); }
  }
  private challenge(error?: string): string[] {
    const dpop = `DPoP ${error ? `error="${error}", ` : ''}algs="${this.algorithms.join(' ')}"`;
    return this.mode === 'required' ? [dpop] : ['Bearer', dpop];
  }
  /**
   * Extracts the credential and, for the DPoP scheme, verifies the proof and binds it to the token through
   * `authenticate(token, { jkt })`. A token carrying `cnf` is never accepted as a plain bearer token.
   */
  async authorize<T>(req: IncomingMessage, authenticate: (token: string, proof?: ProofBinding) => Promise<T | null>): Promise<DpopOutcome<T>> {
    const fail = (error?: string): DpopOutcome<T> => ({ ok: false, challenge: this.challenge(error) });
    const header = req.headers.authorization, m = typeof header === 'string' ? /^(Bearer|DPoP) (\S+)$/i.exec(header) : null;
    if (!m) return fail();
    const token = m[2]!;
    if (m[1]!.toLowerCase() === 'bearer') {
      if (this.mode === 'required') return fail();
      const value = await authenticate(token);
      return value === null ? fail() : { ok: true, value };
    }
    const proof = req.headers.dpop;
    if (typeof proof !== 'string') return fail('invalid_dpop_proof');
    const target = req.url?.split(/[?#]/, 1)[0] ?? '';
    if (!target.startsWith('/') || target.startsWith('//')) return fail('invalid_dpop_proof');
    let htu: string;
    try { const base = this.publicUrl(); htu = `${base.origin}${base.pathname.replace(/\/$/, '')}${target}`; } catch { return fail('invalid_dpop_proof'); }
    const now = Math.floor(this.clock() / 1000);
    const verified = await verifyDpopProof(proof, { method: req.method ?? '', htu, accessToken: token, algorithms: this.algorithms, skewSeconds: this.skew, now });
    if (!verified) return fail('invalid_dpop_proof');
    const value = await authenticate(token, { jkt: verified.jkt });
    if (value === null) return fail('invalid_token');
    // Consumed only for an authenticated, correctly bound request; a failure to decide propagates (503).
    if (!await this.replay.consume(verified.jti, verified.jkt, verified.iat + this.skew + 1)) return fail('invalid_dpop_proof');
    return { ok: true, value };
  }
}
