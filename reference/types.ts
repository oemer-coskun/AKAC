import type { Obligation, RuntimeDomain } from './decision.ts';
import type { NodeKey } from './merkle.ts';
export const ACTIONS = ['read', 'derive', 'write_memory', 'share', 'export', 'declassify'] as const;
export type Action = typeof ACTIONS[number];
export const LEVELS = ['public', 'internal', 'confidential', 'restricted'] as const;
export type Level = typeof LEVELS[number];
/** Closed enum. Origin is provenance evidence, never authority. */
export const ORIGINS = ['human', 'system', 'model'] as const;
export type Origin = typeof ORIGINS[number];
export const SCHEMA = 'akac-state/0.3';
export const CORE_VERSION = 'akac-reference/0.6.0';
export type Ref = { id: string; version: number };
export type Actor = {
  id: string; tenant: string; kind: 'user' | 'agent' | 'service';
  roles: string[]; projects: string[]; clearance: Level; active: boolean;
  /**
   * Runtime binding (0.6b, R147): the agent ids whose heartbeat-bound runs this principal (holding the `runtime`
   * role) may keep alive. Absent or empty: it may heartbeat no grant. Set by a security-admin only.
   */
  runtimeFor?: string[];
  /**
   * Destination profile (0.4, ADR-008) that governs what this principal may receive
   * through share/export: the id of a same-tenant Destination. Absent: a user is the
   * implicit `internal-user` destination; any other principal has no destination
   * profile (legacy recipient rules only; denied wherever a grant restricts destinations).
   */
  destination?: string;
};
/** Destination classes (0.4, ADR-008), from the most to the least trusted. */
export const DESTINATION_CLASSES = ['internal-user', 'internal-service', 'model-provider', 'tool', 'external'] as const;
export type DestinationClass = typeof DESTINATION_CLASSES[number];
/**
 * Destination profile (0.4, ADR-008): a tenant-scoped egress target class with the
 * highest classification it may receive and the purposes it may receive it for.
 * Recipients reference it through `Actor.destination`. An inactive or unknown
 * profile denies every release to its principals.
 */
export type Destination = {
  id: string; tenant: string; class: DestinationClass;
  maxClassification: Level; purposes: string[]; active: boolean;
  /**
   * Jurisdiction or region this destination processes content in (0.6, R187): an
   * ISO 3166-1 alpha-2 code or an operator-defined region code (RESIDENCY_CODE). Content
   * whose effective residency is set is released only to a destination whose region is
   * in that set; a destination without a region receives none of it.
   */
  region?: string;
};
/**
 * Runtime profile policy (0.5, ADR-012): per tenant, which operator-reviewed
 * runtime profile (by id, per domain) a runtime that holds released content must
 * apply. It applies to decisions whose highest transitive classification is at least
 * `classification` and, when `destinationClass` is set, only to decisions whose
 * destination has that class. Profile ids name templates reviewed by the operator;
 * AKAC never generates or interprets runtime policy.
 */
export type RuntimeProfilePolicy = {
  id: string; tenant: string; classification: Level; destinationClass?: DestinationClass;
  profiles: Partial<Record<RuntimeDomain, string>>; active: boolean;
};
/** Most runtime profile policies one tenant may hold (a larger set is refused, and a load beyond it defers). */
export const RUNTIME_PROFILE_LIMIT = 256;
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
  /** Tags every descendant carries (0.6, R186): combination rules and policy extensions read them; they never grant. */
  tags?: string[];
  /** Residency every descendant must respect (0.6, R187): the effective residency is an intersection. */
  residency?: string[];
};
export type Grant = {
  id: string; tenant: string; subject: string; agent: string;
  actions: Action[]; resources: string[]; purposes: string[];
  notBefore: number; expiresAt: number; active: boolean; parent?: string;
  /** Session role activation; must be a subset of the subject's effective roles and of the parent's. */
  activeRoles?: string[];
  /**
   * Destinations of this run (0.4, ADR-008): destination classes or Destination ids
   * that share/export may release to. Absent: no run-level restriction (0.3
   * recipient rules; a recipient's own destination profile still applies). A child
   * grant of a restricted parent MUST restrict to a subset.
   */
  destinations?: string[];
  /** Most documents one disclosure of this run may return (1..MAX_RESULTS); a child may only lower it. */
  maxResults?: number;
  /**
   * Heartbeat binding (0.6, R147): the run is valid only while its trusted runtime
   * reported a heartbeat less than this many ms ago (HEARTBEAT bounds). A child of a
   * heartbeat-bound parent MUST carry a TTL no longer than the parent's; a lapsed
   * parent invalidates every descendant. A lapse is final.
   */
  heartbeatTtlMs?: number;
  /** Time (ms) of the last trusted heartbeat; set by the control plane (issuance, heartbeat) and delegation, never by a caller. */
  lastHeartbeatAt?: number;
  /**
   * Break-glass grant (0.6, R149): issued by the control plane after its approval
   * quorum; read-only, named resources, at most BREAK_GLASS.maxTtlMs, never delegable.
   * Every decision under it is flagged in audit.
   */
  breakGlass?: true;
};
/** Heartbeat TTL bounds of a grant (ms). */
export const HEARTBEAT = { minTtlMs: 1000, maxTtlMs: 86_400_000 } as const;
/** Break-glass grant bounds: lifetime (ms) and named resources. */
export const BREAK_GLASS = { maxTtlMs: 7_200_000, minTtlMs: 60_000, resources: 64 } as const;
/** Risk levels of a principal (0.6, R151), from the lowest to the highest. */
export const RISK_LEVELS = ['none', 'low', 'medium', 'high', 'critical'] as const;
export type RiskLevel = typeof RISK_LEVELS[number];
/** Clearance cap of a risk level: a classification, or `deny` (no knowledge at all). */
export type RiskCap = Level | 'deny';
/**
 * Default risk caps (secure default). A tenant may configure others (TenantSettings.riskCaps);
 * `critical` always denies, and the cap of a level never exceeds the cap of a lower level (riskLimit()).
 */
export const DEFAULT_RISK_CAPS: Readonly<Record<RiskLevel, RiskCap>> = { none: 'restricted', low: 'restricted', medium: 'confidential', high: 'internal', critical: 'deny' };
/**
 * Risk signal (0.6, R151): one per (source, principal). `source` is the ingesting
 * administrative identity (never a request field); `event` optionally names the
 * OpenID CAEP/RISC event type URI it was derived from. Expired signals are ignored.
 */
export type RiskSignal = {
  id: string; tenant: string; principal: string; level: RiskLevel; source: string;
  issuedAt: number; expiresAt: number; event?: string;
};
/** Operation classes that pass the approval gate (0.6, R153). */
export const APPROVAL_CLASSES = ['break_glass', 'label_widening', 'role_widening', 'sod_relaxation', 'runtime_profile', 'destination_widening', 'settings'] as const;
export type ApprovalClass = typeof APPROVAL_CLASSES[number];
/**
 * Pending approval of a sensitive administrative operation (0.6, R153..R157).
 * `approvers` excludes the requester; the operation executes once the requester
 * plus the distinct approvers reach the quorum (and an external gate, when it
 * required one, is satisfied).
 */
export type Approval = {
  id: string; tenant: string; class: ApprovalClass; operation: string; requester: string;
  /** The operation's arguments (JSON), executed verbatim; `digest` is SHA-256 over their JCS form. */
  payload: unknown; digest: string;
  approvers: string[]; required: number; external: boolean;
  createdAt: number; expiresAt: number;
  status: 'pending' | 'executed' | 'rejected';
  executedAt?: number;
};
/**
 * Tenant settings (0.6): the approval quorum per operation class, the approval
 * lifetime and the risk caps. Keyed by tenant (`id` = `tenant`). Absent means the defaults.
 */
export type TenantSettings = {
  id: string; tenant: string;
  approvalQuorum?: Partial<Record<ApprovalClass, number>>;
  approvalTtlMs?: number;
  riskCaps?: Partial<Record<RiskLevel, RiskCap>>;
  /** Most derivation generations (0.6, R182): 1..KNOWLEDGE.maxDepth, default KNOWLEDGE.defaultDepth. */
  lineageDepth?: number;
};
/** Core cap on disclosed documents per openContext/retrieve call (the openContext request bound). */
export const MAX_RESULTS = 64;
/**
 * Knowledge lifecycle beyond `active` (0.4, ADR-007). Absent means normal. Any
 * present value, including an unknown one, makes the record and every record
 * whose provenance includes it invisible to every gate (R-LIFE-1).
 * - quarantined: suspected poisoning or pending review; reversible by release().
 * - erased: content removed (tombstone); terminal, the id is never reused.
 */
export const LIFECYCLES = ['quarantined', 'erased'] as const;
export type Lifecycle = typeof LIFECYCLES[number];
/** Closed, content-free quarantine reasons (free text could carry personal data). */
export const QUARANTINE_REASONS = ['suspected_poisoning', 'scanner', 'scanner_unavailable', 'memory_review', 'incident',
  // 0.6 (R191..R193): confirmed poisoning; set by the lineage sweeper on the descendants of a revoked, erased,
  // quarantined or upward-relabelled record; a model recall (quarantineByModel).
  'poisoned', 'ancestor_revoked', 'model_recall'] as const;
export type QuarantineReason = typeof QUARANTINE_REASONS[number];
/** Content modalities (0.6, R183): descriptive only, never authority; derivation inherits labels whatever the modality. */
export const MODALITIES = ['text', 'image', 'audio', 'video', 'table', 'code', 'other'] as const;
export type Modality = typeof MODALITIES[number];
/** Model identity of derived content (0.6, R191), supplied by a trusted runtime path only. */
export type ModelRef = { id: string; version: string };
/**
 * Session-scoped knowledge (0.6, R190): held only in the gateway's in-memory
 * partition, never in a persistent store, visible only to its run (`run`: the grant id)
 * and only before `expiresAt`.
 */
export type Ephemeral = { sessionId: string; run: string; expiresAt: number };
/**
 * Knowledge semantics bounds (0.6, ADR-022). `defaultDepth`/`maxDepth`: derivation
 * generations (the traversal bound LIMITS.path is 128 nodes, so at most 127
 * generations). `tags`/`residency`: most entries per record or container.
 * `combinationRules`: most rules per tenant (a larger set is refused, a load beyond it
 * defers). `ephemeralTtlMs`/`ephemeralMaxTtlMs`: default and longest session record
 * lifetime. `ephemeralRecords`/`ephemeralTenant`: most in-memory records per session and per tenant.
 */
export const KNOWLEDGE = { defaultDepth: 16, maxDepth: 127, tags: 32, residency: 32, combinationRules: 256,
  ephemeralTtlMs: 3_600_000, ephemeralMaxTtlMs: 86_400_000, ephemeralRecords: 1000, ephemeralTenant: 10_000 } as const;
/** A residency code: ISO 3166-1 alpha-2 (for example `DE`) or an operator-defined region code (for example `EU`, `US-GOV`). Exact match only. */
export const RESIDENCY_CODE = /^[A-Z][A-Z0-9-]{1,15}$/;
/**
 * Combination rule (0.6, R188; Brewer-Nash, aggregation): when one run's accumulated
 * sources carry a tag of `tagsA` and a tag of `tagsB`, `deny` refuses the run's context
 * or derivation (COMBINATION) and `uplift` raises the classification of what the run
 * derives to at least `upliftTo` (absent: one level above what it would have). Never lowers.
 */
export type CombinationRule = {
  id: string; tenant: string; tagsA: string[]; tagsB: string[]; effect: 'deny' | 'uplift'; upliftTo?: Level; active: boolean;
};
export type Knowledge = {
  id: string; tenant: string; version: number;
  kind: 'document' | 'memory' | 'artifact'; origin: Origin; content: string;
  classification: Level; projects: string[]; readerRoles: string[];
  readers: string[]; sources: Ref[]; active: boolean;
  accessExpiresAt?: number; container?: string;
  /** Lifecycle state (0.4); absent is normal. */
  lifecycle?: Lifecycle;
  /** Time (ms) of the last lifecycle transition; for `erased` it is the erasure time. */
  lifecycleAt?: number;
  quarantineReason?: QuarantineReason;
  /**
   * Retention deadline (ms): from then on the record is due for erasure by the
   * retention job. It does not end access (that is accessExpiresAt).
   */
  retainUntil?: number;
  /** Legal hold ids; a non-empty list blocks erasure and retention of this record and of every ancestor, and content changes of this record. */
  legalHolds?: string[];
  /**
   * Time (ms) a security-admin revoked the record (revoke, revokeLineage). While
   * present the record stays inactive across new versions; only reinstate() clears it.
   */
  revokedAt?: number;
  /** Content modality (0.6, R183); descriptive, never authority. */
  modality?: Modality;
  /** Tags (0.6, R186); the effective tags are the union over the record, its containers and every transitive source. */
  tags?: string[];
  /** Residency (0.6, R187); the effective residency is the intersection over the record, its containers and every transitive source. */
  residency?: string[];
  /** Model that produced derived content (0.6, R191); set by the gateway from a trusted runtime path, never by a caller. */
  model?: ModelRef;
  /** Session-scoped record (0.6, R190); never persisted. */
  ephemeral?: Ephemeral;
  /**
   * Time (ms) an erasure of this record was requested while a legal hold blocked it
   * (0.6, R194). The erasure (with cascade) runs once no hold blocks it any more.
   */
  erasureRequestedAt?: number;
  /**
   * Internal, never persisted, never accepted from a caller (0.6b, R195): the stored
   * content could not be opened for a reason other than a key the provider reports as
   * destroyed (key service down, tampered envelope). Every gate hides the record and
   * everything derived from it; a transaction that would write it fails (DEFERRED:STORE_ERROR).
   */
  unreadable?: true;
};
export type Binding = { tenant: string; subject: string; agent: string; grant: string };
export type Context = Binding & {
  id: string; purpose: string; sources: Ref[]; expiresAt: number;
  policyVersion: string; epoch: number; active: boolean;
};
/**
 * One audit entry. Format 1 (0.1-0.3) has only the first line of fields and is
 * hashed over sorted-key JSON; format 2 (0.4, `formatVersion: 2`) adds decision
 * evidence and is hashed over its RFC 8785 (JCS) form (reference/audit.ts).
 */
export type Audit = {
  sequence: number; time: number; tenant: string; actor: string;
  operation: string; decision: 'allow' | 'deny'; reason: string;
  policyVersion: string; epoch: number; previous: string; hash: string;
  formatVersion?: 2;
  /** UUIDv4 of the decision, also returned to the caller. */
  decisionId?: string;
  /** Closed code (reference/decision.ts REASON_CODES). */
  reasonCode?: string;
  /** SHA-256 of the active policy material (reference/decision.ts policyDigest). */
  policyDigest?: string;
  /** Obligations of an allow decision; empty on deny. */
  obligations?: Obligation[];
  /** Run (grant) the decision belongs to, where applicable. */
  runId?: string;
  /** W3C trace-id supplied by the caller, when valid. */
  traceId?: string;
  /** Agent execution (sandbox, job) the decision belongs to, when supplied and valid (0.5). */
  executionId?: string;
  /** Runtime policy revision a trusted runtime enforcer applied before this decision's effect (0.5). */
  runtimeRevision?: string;
  /**
   * RFC 8693 actor chain of the credential (0.6, R145): the current actor first,
   * then prior actors (outermost `act` first), as verified by a trusted authenticator.
   */
  actorChain?: string[];
  /** The decision was taken under (or issues) a break-glass grant (0.6, R150). */
  breakGlass?: true;
  /**
   * Closed, content-free findings of release filters, derive sanitizers and volume budgets (0.6, ADR-020): 1..32 strings of
   * A-Z a-z 0-9 . _ : - (at most 128 characters each), for example `pii:redact` or `volume:confidential`. Never content.
   */
  findings?: string[];
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
  /** Destination profiles (0.4, ADR-008). Optional so that 0.3 snapshots stay valid; absent means none. */
  destinations?: Record<string, Destination>;
  /** Runtime profile policies (0.5, ADR-012). Optional so that 0.4 snapshots stay valid; absent means none. */
  runtimeProfiles?: Record<string, RuntimeProfilePolicy>;
  /** Risk signals (0.6, R151). Optional; absent means none. */
  riskSignals?: Record<string, RiskSignal>;
  /** Tenant settings by tenant id (0.6). Optional; absent means the defaults. */
  settings?: Record<string, TenantSettings>;
  /** Approvals of sensitive administrative operations (0.6, R153). Optional. */
  approvals?: Record<string, Approval>;
  /** Combination rules (0.6, R188). Optional; absent means none. */
  combinationRules?: Record<string, CombinationRule>;
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
  /** Every context of these (subject, agent) pairs, of any grant, expiring after `since` (0.6b, R188; bounded, BudgetExceeded above). */
  pairs?: { subject: string; agent: string; since: number }[];
  constraints?: boolean; epoch?: boolean; audit?: boolean;
  /** Up to this many tenant knowledge records, for the bounded lexical fallback. */
  corpus?: number;
  /** With `corpus`: throw BudgetExceeded instead of loading more than this many content bytes (UTF-8). */
  corpusBytes?: number;
  /** Every active actor of the tenant and every group (bounded), for administrative holder checks. */
  principals?: boolean;
  /** Destination profiles by id (0.4). */
  destinations?: string[];
  /** Every runtime profile policy of the tenant (0.5; bounded by RUNTIME_PROFILE_LIMIT, BudgetExceeded above it). */
  runtimeProfiles?: boolean;
  /** Risk signals of these principals (0.6; bounded, BudgetExceeded above it). */
  risks?: string[];
  /** The tenant settings record (0.6). */
  settings?: boolean;
  /** Approvals by id (0.6). */
  approvals?: string[];
  /** Pending approvals of the tenant that are unexpired at this time (ms), oldest first (0.6; bounded, BudgetExceeded above it). */
  pendingApprovals?: number;
  /** Every combination rule of the tenant (0.6; bounded by KNOWLEDGE.combinationRules, BudgetExceeded above it). */
  combinationRules?: boolean;
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
  /**
   * Optional (partial stores): metadata of tenant records whose provenance
   * (transitively, any version) includes one of `roots`, roots excluded, at most
   * `limit` of them. `truncated` when more exist or the traversal bound was hit.
   * Complete stores are traversed in memory instead (reference/lifecycle.ts).
   */
  descendants?(roots: string[], limit: number): Promise<{ records: KnowledgeMeta[]; truncated: boolean }>;
  /**
   * Optional (partial stores): ids of tenant records with `retainUntil <= now`,
   * not erased and without a legal hold of their own, ordered by id, after `after`.
   */
  retentionDue?(now: number, after: string, limit: number): Promise<string[]>;
  /** Optional (partial stores, 0.6): metadata of tenant records produced by model `id` (any version), ordered by id, after `after`, at most `limit`. */
  modelRecords?(id: string, after: string, limit: number): Promise<KnowledgeMeta[]>;
  /** Optional (partial stores, 0.6): ids of tenant records with a pending erasure request, ordered by id, after `after`, at most `limit`. */
  pendingErasures?(after: string, limit: number): Promise<string[]>;
}
export interface Store {
  /** Serializable per tenant: tenants proceed in parallel, one tenant's work is linearized. */
  transaction<T>(tenant: string, fn: (tx: Tx) => Promise<T>): Promise<T>;
  /** Bounded integrity check; with a tenant, verifies that tenant's audit tail. */
  ready(tenant?: string): Promise<boolean>;
  /** Ordered audit stream of one tenant, for auditors and checkpoints. */
  auditLog(tenant: string, after?: number, limit?: number): Promise<Audit[]>;
  /**
   * Optional: the current size of the tenant's RFC 9162 audit tree (one leaf per
   * entry, leaf index = sequence - 1) and the hashes of the requested perfect
   * subtrees, each of which MUST lie inside the tree (throw otherwise). Without it,
   * proofs are computed from auditLog() in O(n) (reference/evidence.ts).
   */
  auditTree?(tenant: string, keys: NodeKey[]): Promise<{ size: number; hashes: string[] }>;
  close(): Promise<void>;
}
/**
 * Input of the supplemental policy. 0.6 (R189) adds attributes an extension may
 * narrow on (for example sovereignty, aggregation or Chinese-wall policy packs): the
 * effective `tags` and `residency` of the resource over its whole source graph
 * (`residency` absent: none is set) and `sources`, the ids of everything the operation
 * of the run reads (the resource included). They are absent where not computed (health
 * probes); a hook MUST NOT read absence as a permission.
 */
export type PolicyHookInput = { action: Action; tenant: string; classification: Level; purpose: string;
  tags?: string[]; residency?: string[]; sources?: string[] };
export interface PolicyHook {
  readonly revision: string;
  ready?(): Promise<boolean>;
  check(input: PolicyHookInput): Promise<boolean>;
  /**
   * Optional structured verdict, preferred over check() when present. `obligations`
   * are validated by the engine: anything unknown or malformed denies with
   * UNSUPPORTED_OBLIGATION. A hook that only implements check() adds none.
   */
  verdict?(input: PolicyHookInput): Promise<PolicyVerdict>;
}
export type PolicyVerdict = { allow: boolean; obligations?: unknown[] };
export function emptyState(): State {
  return { schema: SCHEMA, policyVersion: CORE_VERSION, epochs: {},
    actors: {}, grants: {}, knowledge: {}, contexts: {}, roles: {}, groups: {}, containers: {}, constraints: {}, destinations: {}, runtimeProfiles: {}, audits: [] };
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
