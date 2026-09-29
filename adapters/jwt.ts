import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import type { Binding } from '../reference/types.ts';
import { exactKeys, validId } from '../reference/validation.ts';
import { MAX_ACTOR_CHAIN, validActorId } from '../reference/audit.ts';
import { attachActorChain } from '../reference/delegation.ts';

/** DPoP key binding verified by the gateway (RFC 7638 thumbprint of the proof key). A token with `cnf.jkt` authenticates only with a matching binding. */
export type ProofBinding = { jkt: string };
export interface Authenticator { authenticate(token: string, proof?: ProofBinding): Promise<Binding | null> }
export type JwtConfiguration = {
  issuer: string; audience: string; jwksUrl: string;
  algorithms: ('RS256' | 'ES256' | 'EdDSA')[];
  /** Trusted provisioning binds a verified token subject to one bounded agent run. */
  subjects: Record<string, Binding>;
  maxLifetimeSeconds?: number;
  /**
   * RFC 8693 delegation (0.6, R143..R146), per token subject: `actor` is the `sub` of
   * the current actor (the outermost `act`) that the mapped binding's agent presents
   * after a token exchange, and `actorIssuer`, when set, the `iss` that `act` must
   * carry. A subject listed here authenticates ONLY with a delegation token whose
   * current actor matches; a subject not listed authenticates only without `act`
   * (the 0.5 mapping, where the operator's mapping itself states that the token
   * subject is the run's delegating user).
   */
  delegation?: Record<string, { actor: string; actorIssuer?: string }>;
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
    return (await this.claims(token, proof))?.sub ?? null;
  }
  /** Verified subject plus the RFC 8693 `act` and `may_act` members (unvalidated beyond being present). */
  async claims(token: string, proof?: ProofBinding): Promise<{ sub: string; act?: unknown; mayAct?: unknown } | null> {
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
      const out = { sub: payload.sub, ...(payload.act !== undefined ? { act: payload.act } : {}), ...(payload.may_act !== undefined ? { mayAct: payload.may_act } : {}) };
      if (payload.cnf === undefined) return proof ? null : out;
      const cnf = payload.cnf as Record<string, unknown> | null;
      if (!cnf || typeof cnf !== 'object' || Array.isArray(cnf) || typeof cnf.jkt !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(cnf.jkt)
        || Object.keys(cnf).some(k => k !== 'jkt') || !proof || proof.jkt !== cnf.jkt) return null;
      return out;
    } catch { return null; }
  }
}

const plainObject = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
/**
 * The RFC 8693 section 4.1 actor chain of `act`: the current actor (outermost) first,
 * then each prior actor (nested `act`). Only identity members are read; `sub` is
 * required in every level and `iss`, when present, must be a string. Null when the
 * claim is malformed or deeper than MAX_ACTOR_CHAIN.
 */
export function actorChain(act: unknown): { chain: string[]; issuer?: string } | null {
  const chain: string[] = [];
  let issuer: string | undefined;
  for (let level: unknown = act; level !== undefined; level = (level as Record<string, unknown>).act) {
    if (!plainObject(level) || chain.length >= MAX_ACTOR_CHAIN || !validActorId(level.sub) || (level.iss !== undefined && typeof level.iss !== 'string')) return null;
    if (!chain.length && typeof level.iss === 'string') issuer = level.iss;
    chain.push(level.sub);
  }
  return chain.length ? { chain, ...(issuer !== undefined ? { issuer } : {}) } : null;
}

export class JwtAuthenticator implements Authenticator {
  private verifier: Verifier;
  private subjects: Record<string, Binding>;
  private delegation: Record<string, { actor: string; actorIssuer?: string }>;
  constructor(config: JwtConfiguration, trustedKeyResolver?: JWTVerifyGetKey) {
    const { subjects, delegation, ...base } = config;
    this.verifier = new Verifier(base, trustedKeyResolver);
    if (!Object.keys(subjects).length) throw new Error('Invalid JWT configuration');
    for (const [subject, binding] of Object.entries(subjects)) {
      if (!subject || subject.length > 256 || !exactKeys(binding, ['tenant', 'subject', 'agent', 'grant'])
        || !Object.values(binding).every(validId)) throw new Error('Invalid JWT identity binding');
    }
    for (const [subject, rule] of Object.entries(delegation ?? {})) {
      if (!Object.hasOwn(subjects, subject) || !exactKeys(rule, ['actor'], ['actorIssuer']) || !validActorId(rule.actor)
        || (rule.actorIssuer !== undefined && (typeof rule.actorIssuer !== 'string' || !rule.actorIssuer || rule.actorIssuer.length > 256))) throw new Error('Invalid JWT delegation mapping');
    }
    this.subjects = structuredClone(subjects);
    this.delegation = structuredClone(delegation ?? {});
  }
  /**
   * Verified token -> binding (R143..R146). Roles, permissions, scopes and agent ids
   * supplied in the token are deliberately ignored: a token exchange can only select
   * a pre-provisioned binding, whose grant still governs every decision, so a
   * delegation never widens anything. With `act`, the current actor must match the
   * subject's delegation mapping (sub and, when configured, iss); `may_act`, when
   * present, must name that same actor. Anything else denies (null).
   */
  async authenticate(token: string, proof?: ProofBinding): Promise<Binding | null> {
    const claims = await this.verifier.claims(token, proof);
    if (!claims || !Object.hasOwn(this.subjects, claims.sub)) return null;
    const rule = Object.hasOwn(this.delegation, claims.sub) ? this.delegation[claims.sub] : undefined;
    const binding = structuredClone(this.subjects[claims.sub]!);
    if (claims.act === undefined) {
      // Impersonation-style token (no act): accepted only where the mapping does not require delegation,
      // and never together with may_act (the presenter would not be the party it authorizes).
      return !rule && claims.mayAct === undefined ? binding : null;
    }
    const chain = actorChain(claims.act);
    if (!rule || !chain || chain.chain[0] !== rule.actor || (rule.actorIssuer !== undefined && chain.issuer !== rule.actorIssuer)) return null;
    if (claims.mayAct !== undefined) {
      const may = claims.mayAct;
      if (!plainObject(may) || may.sub !== rule.actor || (may.iss !== undefined && may.iss !== chain.issuer)) return null;
    }
    return attachActorChain(binding, chain.chain);
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
    const claims = await this.verifier.claims(token, proof);
    // Administrative authority is never delegated through token exchange (R146): act or may_act denies.
    const sub = claims && claims.act === undefined && claims.mayAct === undefined ? claims.sub : null;
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
    const claims = await this.verifier.claims(token, proof);
    // A PEP credential is never a delegation token (R146).
    const sub = claims && claims.act === undefined && claims.mayAct === undefined ? claims.sub : null;
    return sub !== null && Object.hasOwn(this.peps, sub) ? structuredClone(this.peps[sub]!) : null;
  }
}
