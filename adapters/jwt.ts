import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import type { Binding } from '../reference/types.ts';
import { exactKeys, validId } from '../reference/validation.ts';

export interface Authenticator { authenticate(token: string): Promise<Binding | null> }
export type JwtConfiguration = {
  issuer: string; audience: string; jwksUrl: string;
  algorithms: ('RS256' | 'ES256' | 'EdDSA')[];
  /** Trusted provisioning binds a verified token subject to one bounded agent run. */
  subjects: Record<string, Binding>;
  maxLifetimeSeconds?: number;
};

export class JwtAuthenticator implements Authenticator {
  private config: JwtConfiguration;
  private key: JWTVerifyGetKey;
  constructor(config: JwtConfiguration, trustedKeyResolver?: JWTVerifyGetKey) {
    const jwks = new URL(config.jwksUrl), issuer = new URL(config.issuer);
    if (jwks.protocol !== 'https:' || issuer.protocol !== 'https:' || jwks.username || jwks.password
      || jwks.hash || !config.audience || !config.algorithms.length
      || config.algorithms.some(a => !['RS256', 'ES256', 'EdDSA'].includes(a))
      || !Object.keys(config.subjects).length
      || (config.maxLifetimeSeconds !== undefined && (!Number.isInteger(config.maxLifetimeSeconds)
        || config.maxLifetimeSeconds < 1 || config.maxLifetimeSeconds > 900))) throw new Error('Invalid JWT configuration');
    for (const [subject, binding] of Object.entries(config.subjects)) {
      if (!subject || subject.length > 256 || !exactKeys(binding, ['tenant', 'subject', 'agent', 'grant'])
        || !Object.values(binding).every(validId)) throw new Error('Invalid JWT identity binding');
    }
    this.config = structuredClone(config);
    this.key = trustedKeyResolver ?? createRemoteJWKSet(jwks, { timeoutDuration: 2000, cooldownDuration: 30000, cacheMaxAge: 60000 });
  }
  async authenticate(token: string): Promise<Binding | null> {
    try {
      if (token.length > 16384) return null;
      const header = decodeProtectedHeader(token);
      // Keys and algorithms come from operator configuration, never the token.
      if (header.jku || header.jwk || header.x5u) return null;
      const { payload } = await jwtVerify(token, this.key, {
        issuer: this.config.issuer, audience: this.config.audience,
        algorithms: this.config.algorithms, typ: 'at+jwt', clockTolerance: 0,
        requiredClaims: ['sub', 'iat', 'exp', 'jti'], maxTokenAge: this.config.maxLifetimeSeconds ?? 300
      });
      if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)
        || payload.exp! <= payload.iat! || payload.exp! - payload.iat! > (this.config.maxLifetimeSeconds ?? 300)
        || typeof payload.jti !== 'string' || !payload.jti || payload.jti.length > 256
        || !Object.hasOwn(this.config.subjects, payload.sub!)) return null;
      // Roles, permissions and agent IDs supplied in the token are deliberately ignored.
      return structuredClone(this.config.subjects[payload.sub!]!);
    } catch { return null; }
  }
}
