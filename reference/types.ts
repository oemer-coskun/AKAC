export const ACTIONS = ['read', 'derive', 'write_memory', 'share', 'export', 'declassify'] as const;
export type Action = typeof ACTIONS[number];
export const LEVELS = ['public', 'internal', 'confidential', 'restricted'] as const;
export type Level = typeof LEVELS[number];
/** Closed enum. Origin is provenance evidence, never authority. */
export const ORIGINS = ['human', 'system', 'model'] as const;
export type Origin = typeof ORIGINS[number];
export const SCHEMA = 'akac-state/0.3';
export const CORE_VERSION = 'akac-reference/0.3.0';
export type Ref = { id: string; version: number };
export type Actor = {
  id: string; tenant: string; kind: 'user' | 'agent' | 'service';
  roles: string[]; projects: string[]; clearance: Level; active: boolean;
};
/** NIST hierarchical RBAC: a role includes every (transitively) inherited junior role. */
export type Role = { id: string; tenant: string; inherits: string[]; active: boolean };
/** SCIM-style group: members receive the group's roles while both are active. */
export type Group = { id: string; tenant: string; members: string[]; roles: string[]; active: boolean };
/** Separation of duty: holding (static) or activating (dynamic) >= cardinality of roles denies. */
export type SodConstraint = { id: string; tenant: string; kind: 'static' | 'dynamic'; roles: string[]; cardinality: number };
/** A container adds a classification floor and an audience every descendant must also satisfy. */
export type Container = {
  id: string; tenant: string; kind: 'knowledge-base' | 'folder'; parent?: string;
  classification: Level; readerRoles: string[]; readers: string[]; projects: string[]; active: boolean;
};
export type Grant = {
  id: string; tenant: string; subject: string; agent: string;
  actions: Action[]; resources: string[]; purposes: string[];
  notBefore: number; expiresAt: number; active: boolean; parent?: string;
  /** Session role activation; must be a subset of the subject's effective roles and of the parent's. */
  activeRoles?: string[];
};
export type Knowledge = {
  id: string; tenant: string; version: number;
  kind: 'document' | 'memory' | 'artifact'; origin: Origin; content: string;
  classification: Level; projects: string[]; readerRoles: string[];
  readers: string[]; sources: Ref[]; active: boolean;
  accessExpiresAt?: number; container?: string;
};
export type Binding = { tenant: string; subject: string; agent: string; grant: string };
export type Context = Binding & {
  id: string; purpose: string; sources: Ref[]; expiresAt: number;
  policyVersion: string; epoch: number; active: boolean;
};
export type Audit = {
  sequence: number; time: number; tenant: string; actor: string;
  operation: string; decision: 'allow' | 'deny'; reason: string;
  policyVersion: string; epoch: number; previous: string; hash: string;
};
/**
 * Stores MAY hand the engine a partial snapshot of one tenant (see Tx). Every
 * record keeps its tenant; decisions never trust the snapshot boundary alone.
 */
export type State = {
  schema: typeof SCHEMA; policyVersion: string;
  /** Per-tenant revocation epochs; absent means 0. */
  epochs: Record<string, number>;
  actors: Record<string, Actor>; grants: Record<string, Grant>;
  knowledge: Record<string, Knowledge>; contexts: Record<string, Context>;
  roles: Record<string, Role>; groups: Record<string, Group>;
  containers: Record<string, Container>; constraints: Record<string, SodConstraint>;
  /** Per-tenant hash-chained streams; a partial snapshot holds only the tenant head. */
  audits: Audit[];
  /** A 0.1 global chain retained verbatim after upgrade; verified with its original rules. */
  legacyAudits?: Audit[];
};
/** `deny`: definite policy denial. `defer`: authorization could not be established. */
export type Category = 'deny' | 'defer';
export type Decision = { effect: 'allow'; code: 'AUTHORIZED' } | { effect: 'deny'; code: string; category: Category };
export type PolicyInput = {
  binding: Binding; action: Action; resource: string; purpose: string; now: number;
};
/**
 * Record ids to hydrate. Stores MAY return more (closures); they MUST NOT return
 * other tenants. A store MUST either load every requested record and the closure
 * it names, or throw `BudgetExceeded` (reference/hydrate.ts); it MUST NOT return a
 * silently truncated result.
 */
export type Need = {
  actors?: string[]; grants?: string[]; knowledge?: string[]; containers?: string[]; roles?: string[];
  /** Groups whose members include any of these actor ids. */
  memberships?: string[];
  /** Groups by id (administrative reads and writes). */
  groups?: string[];
  contexts?: string[]; bindings?: Binding[];
  constraints?: boolean; epoch?: boolean; audit?: boolean;
  /** Up to this many tenant knowledge records, for the bounded lexical fallback. */
  corpus?: number;
  /** With `corpus`: throw BudgetExceeded instead of loading more than this many content bytes (UTF-8). */
  corpusBytes?: number;
  /** Every active actor of the tenant and every group (bounded), for administrative holder checks. */
  principals?: boolean;
};
/** Knowledge without its content: what index maintenance needs to plan work. */
export type KnowledgeMeta = Omit<Knowledge, 'content'>;
/**
 * Holder count without loading principals: how many active principals of the tenant
 * (users, agents and services) hold, through direct roles and active groups closed
 * over the role hierarchy (as `effectiveRoles`), at least `cardinality` of `roles`
 * for ANY listed constraint. `role` replaces the stored record of that id
 * (a hypothetical hierarchy change).
 */
export type HolderQuery = { constraints: { roles: readonly string[]; cardinality: number }[]; role?: Role };
export interface Tx {
  /** Possibly partial snapshot. Mutations are persisted at commit. */
  readonly state: State;
  /** True when `state` already holds every record; hydration is then skipped. */
  readonly complete: boolean;
  load(need: Need): Promise<void>;
  /**
   * Metadata (no content) of up to `limit` tenant documents ordered by id. Partial
   * stores implement it; complete stores read `state` instead.
   */
  catalog?(limit: number): Promise<KnowledgeMeta[]>;
  /**
   * Optional server-side holder count for tenants beyond the principal load budget.
   * 'unknown' when the role closure of some principal cannot be established within
   * its bounds (more than 64 roles, a path longer than 16 roles, a cycle).
   */
  countSodHolders?(query: HolderQuery): Promise<number | 'unknown'>;
}
export interface Store {
  /** Serializable per tenant: tenants proceed in parallel, one tenant's work is linearized. */
  transaction<T>(tenant: string, fn: (tx: Tx) => Promise<T>): Promise<T>;
  /** Bounded integrity check; with a tenant, verifies that tenant's audit tail. */
  ready(tenant?: string): Promise<boolean>;
  /** Ordered audit stream of one tenant, for auditors and checkpoints. */
  auditLog(tenant: string, after?: number, limit?: number): Promise<Audit[]>;
  close(): Promise<void>;
}
export interface PolicyHook {
  readonly revision: string;
  ready?(): Promise<boolean>;
  check(input: { action: Action; tenant: string; classification: Level; purpose: string }): Promise<boolean>;
}
export function emptyState(): State {
  return { schema: SCHEMA, policyVersion: CORE_VERSION, epochs: {},
    actors: {}, grants: {}, knowledge: {}, contexts: {}, roles: {}, groups: {}, containers: {}, constraints: {}, audits: [] };
}
type LegacyState = {
  schema: 'akac-state/0.1'; policyVersion: string; epoch: number; audits: Audit[];
  actors: Record<string, Actor>; grants: Record<string, Grant>;
  knowledge: Record<string, Omit<Knowledge, 'origin'>>; contexts: Record<string, Context>;
};
/**
 * 0.1 -> 0.3. Documents become origin 'system', memory/artifacts 'model'. Every
 * tenant inherits the former global epoch. The global audit chain is retained
 * unchanged as `legacyAudits`; per-tenant streams start empty.
 */
export function upgradeState(old: unknown): State {
  const input = old as { schema?: unknown };
  if (input?.schema === SCHEMA) return old as State;
  if (input?.schema !== 'akac-state/0.1') throw new Error('Unsupported state schema');
  const legacy = structuredClone(old as LegacyState);
  const next = emptyState();
  next.policyVersion = legacy.policyVersion;
  next.actors = legacy.actors; next.grants = legacy.grants; next.contexts = legacy.contexts;
  for (const [id, k] of Object.entries(legacy.knowledge)) {
    next.knowledge[id] = { ...k, origin: k.kind === 'document' ? 'system' : 'model' };
  }
  const tenants = new Set([...Object.values(legacy.actors), ...Object.values(legacy.grants),
    ...Object.values(legacy.knowledge), ...Object.values(legacy.contexts)].map(r => r.tenant));
  for (const tenant of tenants) next.epochs[tenant] = legacy.epoch;
  if (legacy.audits.length) next.legacyAudits = legacy.audits;
  return next;
}
