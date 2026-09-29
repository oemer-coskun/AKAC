import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import type { Binding } from '../reference/types.ts';
import { exactKeys, validId } from '../reference/validation.ts';

/** DPoP key binding verified by the gateway (RFC 7638 thumbprint of the proof key). A token with `cnf.jkt` authenticates only with a matching binding. */
export type ProofBinding = { jkt: string };
export interface Authenticator { authenticate(token: string, proof?: ProofBinding): Promise<Binding | null> }
export type JwtConfiguration = {
  issuer: string; audience: string; jwksUrl: string;
  algorithms: ('RS256' | 'ES256' | 'EdDSA')[];
  /** Trusted provisioning binds a verified token subject to one bounded agent run. */
  subjects: Record<string, Binding>;
  maxLifetimeSeconds?: number;
};

/** Trusted operator identity for the administrative listener: tenant and admin actor, never token claims. */
export type AdminIdentity = { tenant: string; admin: string };
export interface AdminAuthenticator { authenticate(token: string, proof?: ProofBinding): Promise<AdminIdentity | null> }
export type AdminJwtConfiguration = Omit<JwtConfiguration, 'subjects'> & {
  /** Verified token subject -> administrative identity. Use an audience distinct from the agent API. */
  admins: Record<string, AdminIdentity>;
};

/** Shared verification: pinned issuer, audience, algorithms and keys; returns the verified subject only. */
class Verifier {
  private config: Omit<JwtConfiguration, 'subjects'>;
  private key: JWTVerifyGetKey;
  constructor(config: Omit<JwtConfiguration, 'subjects'>, trustedKeyResolver?: JWTVerifyGetKey) {
    const jwks = new URL(config.jwksUrl), issuer = new URL(config.issuer);
    if (jwks.protocol !== 'https:' || issuer.protocol !== 'https:' || jwks.username || jwks.password
      || jwks.hash || !config.audience || !config.algorithms.length
      || config.algorithms.some(a => !['RS256', 'ES256', 'EdDSA'].includes(a))
      || (config.maxLifetimeSeconds !== undefined && (!Number.isInteger(config.maxLifetimeSeconds)
        || config.maxLifetimeSeconds < 1 || config.maxLifetimeSeconds > 900))) throw new Error('Invalid JWT configuration');
    this.config = { issuer: config.issuer, audience: config.audience, jwksUrl: config.jwksUrl, algorithms: [...config.algorithms],
      ...(config.maxLifetimeSeconds !== undefined ? { maxLifetimeSeconds: config.maxLifetimeSeconds } : {}) };
    this.key = trustedKeyResolver ?? createRemoteJWKSet(jwks, { timeoutDuration: 2000, cooldownDuration: 30000, cacheMaxAge: 60000 });
  }
  async subject(token: string, proof?: ProofBinding): Promise<string | null> {
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
        || typeof payload.sub !== 'string') return null;
      // Sender constraint (RFC 9449 section 6): `cnf.jkt` must equal the proof key; other confirmation methods are unsupported and fail closed.
      // A bound token never authenticates as a bearer token, and a DPoP proof never authenticates an unbound token.
      if (payload.cnf === undefined) return proof ? null : payload.sub;
      const cnf = payload.cnf as Record<string, unknown> | null;
      if (!cnf || typeof cnf !== 'object' || Array.isArray(cnf) || typeof cnf.jkt !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(cnf.jkt)
        || Object.keys(cnf).some(k => k !== 'jkt') || !proof || proof.jkt !== cnf.jkt) return null;
      return payload.sub;
    } catch { return null; }
  }
}

export class JwtAuthenticator implements Authenticator {
  private verifier: Verifier;
  private subjects: Record<string, Binding>;
  constructor(config: JwtConfiguration, trustedKeyResolver?: JWTVerifyGetKey) {
    const { subjects, ...base } = config;
    this.verifier = new Verifier(base, trustedKeyResolver);
    if (!Object.keys(subjects).length) throw new Error('Invalid JWT configuration');
    for (const [subject, binding] of Object.entries(subjects)) {
      if (!subject || subject.length > 256 || !exactKeys(binding, ['tenant', 'subject', 'agent', 'grant'])
        || !Object.values(binding).every(validId)) throw new Error('Invalid JWT identity binding');
    }
    this.subjects = structuredClone(subjects);
  }
  async authenticate(token: string, proof?: ProofBinding): Promise<Binding | null> {
    const sub = await this.verifier.subject(token, proof);
    // Roles, permissions and agent IDs supplied in the token are deliberately ignored.
    return sub !== null && Object.hasOwn(this.subjects, sub) ? structuredClone(this.subjects[sub]!) : null;
  }
}

/** Same verification as the agent API with its own audience and an admin identity mapping. Modes never fall back to each other. */
export class AdminJwtAuthenticator implements AdminAuthenticator {
  private verifier: Verifier;
  private admins: Record<string, AdminIdentity>;
  constructor(config: AdminJwtConfiguration, trustedKeyResolver?: JWTVerifyGetKey) {
    const { admins, ...base } = config;
    this.verifier = new Verifier(base, trustedKeyResolver);
    if (!admins || !Object.keys(admins).length) throw new Error('Invalid JWT configuration');
    for (const [subject, identity] of Object.entries(admins)) {
      if (!subject || subject.length > 256 || !exactKeys(identity, ['tenant', 'admin']) || !Object.values(identity).every(validId)) throw new Error('Invalid JWT identity binding');
    }
    this.admins = structuredClone(admins);
  }
  async authenticate(token: string, proof?: ProofBinding): Promise<AdminIdentity | null> {
    const sub = await this.verifier.subject(token, proof);
    return sub !== null && Object.hasOwn(this.admins, sub) ? structuredClone(this.admins[sub]!) : null;
  }
}

/** Trusted identity of a policy enforcement point (a gateway) calling the AuthZEN PDP listener: tenant and PEP id, never token claims. */
export type PepIdentity = { tenant: string; pep: string };
export interface PepAuthenticator { authenticate(token: string, proof?: ProofBinding): Promise<PepIdentity | null> }
export type PepJwtConfiguration = Omit<JwtConfiguration, 'subjects'> & {
  /** Verified token subject -> PEP identity. Use an audience distinct from the agent and administrative APIs. */
  peps: Record<string, PepIdentity>;
};
/** Same verification as the other listeners with its own audience and a PEP identity mapping. Modes never fall back to each other. */
export class PepJwtAuthenticator implements PepAuthenticator {
  private verifier: Verifier;
  private peps: Record<string, PepIdentity>;
  constructor(config: PepJwtConfiguration, trustedKeyResolver?: JWTVerifyGetKey) {
    const { peps, ...base } = config;
    this.verifier = new Verifier(base, trustedKeyResolver);
    if (!peps || !Object.keys(peps).length) throw new Error('Invalid JWT configuration');
    for (const [subject, identity] of Object.entries(peps)) {
      if (!subject || subject.length > 256 || !exactKeys(identity, ['tenant', 'pep']) || !Object.values(identity).every(validId)) throw new Error('Invalid JWT identity binding');
    }
    this.peps = structuredClone(peps);
  }
  async authenticate(token: string, proof?: ProofBinding): Promise<PepIdentity | null> {
    const sub = await this.verifier.subject(token, proof);
    return sub !== null && Object.hasOwn(this.peps, sub) ? structuredClone(this.peps[sub]!) : null;
  }
}
