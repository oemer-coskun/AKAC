import { DatabaseSync } from 'node:sqlite';
import type { Audit, State, Store, Tx } from './types.ts';
import { emptyState, SCHEMA, upgradeState } from './types.ts';
import { verifyAudit, verifyLegacyAudit } from './audit.ts';
import { countSodHolders } from './policy.ts';
import { treeFromEntries } from './evidence.ts';
import type { NodeKey } from './merkle.ts';
import { validId } from './validation.ts';

const COLLECTIONS = ['actors', 'grants', 'knowledge', 'contexts', 'roles', 'groups', 'containers', 'constraints', 'destinations'] as const;
/** A collection of a snapshot; `destinations` (0.4) is absent from 0.3 snapshots. */
const records = (s: State, collection: typeof COLLECTIONS[number]): Record<string, { id?: unknown; tenant?: unknown }> => (s[collection] ?? {}) as Record<string, { id?: unknown; tenant?: unknown }>;
const complete = (state: State, tenant: string): Tx => (state.destinations ??= {}, { state, complete: true, load: async () => {},
  countSodHolders: async query => countSodHolders(state, tenant, query) });
const blank = (policyVersion: string): State => ({ ...emptyState(), policyVersion });
const sound = (shard: State) => shard.schema === SCHEMA && verifyAudit(shard.audits);
const stream = (shard: State | undefined, after: number, limit: number): Audit[] =>
  structuredClone((shard?.audits ?? []).filter(a => a.sequence > after).slice(0, limit));

/**
 * Splits a whole-state snapshot into one snapshot per tenant. Keys are (tenant,
 * id): each tenant sees only its own records, so the same id may exist in two
 * tenants and another tenant's record is indistinguishable from an absent one.
 */
function split(state: State): Map<string, State> {
  const shards = new Map<string, State>();
  const of = (tenant: unknown) => {
    const key = String(tenant);
    let s = shards.get(key); if (!s) { s = blank(state.policyVersion); shards.set(key, s); }
    return s;
  };
  for (const collection of COLLECTIONS) {
    for (const [id, record] of Object.entries(records(state, collection))) ((of(record?.tenant)[collection] ??= {}) as Record<string, unknown>)[id] = record;
  }
  for (const [tenant, epoch] of Object.entries(state.epochs)) of(tenant).epochs[tenant] = epoch;
  for (const audit of state.audits) of(audit.tenant).audits.push(audit);
  return shards;
}
/** A tenant transaction may only write its own tenant (the same rule the PostgreSQL adapter enforces at flush). */
function confine(s: State, tenant: string): void {
  for (const collection of COLLECTIONS) {
    for (const [id, record] of Object.entries(records(s, collection))) {
      if (record?.tenant !== tenant || record.id !== id) throw new Error('Cross-tenant write');
    }
  }
  if (Object.keys(s.epochs).some(t => t !== tenant)) throw new Error('Cross-tenant epoch write');
  if (s.audits.some(a => a.tenant !== tenant)) throw new Error('Cross-tenant audit write');
  if (s.legacyAudits !== undefined) throw new Error('The legacy audit chain is read-only');
}

/**
 * Tenant-partitioned in-process store for tests and single-process use.
 * Transactions are serialized; each receives a complete snapshot of its own
 * tenant (load() is a no-op) and may write only that tenant.
 */
export class MemoryStore implements Store {
  private shards: Map<string, State>;
  private legacy: Audit[] | undefined;
  private policyVersion: string;
  private tail: Promise<void> = Promise.resolve();
  constructor(initial: State = emptyState()) {
    const state = upgradeState(structuredClone(initial));
    this.policyVersion = state.policyVersion; this.legacy = state.legacyAudits; this.shards = split(state);
  }
  async transaction<T>(tenant: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    if (!validId(tenant)) throw new Error('Invalid tenant');
    let release!: () => void;
    const previous = this.tail; this.tail = new Promise(resolve => { release = resolve; });
    await previous;
    const next = structuredClone(this.shards.get(tenant) ?? blank(this.policyVersion));
    try { const result = await fn(complete(next, tenant)); confine(next, tenant); this.shards.set(tenant, next); return result; }
    finally { release(); }
  }
  async ready(): Promise<boolean> {
    return [...this.shards.values()].every(sound) && (!this.legacy || verifyLegacyAudit(this.legacy));
  }
  async auditLog(tenant: string, after = 0, limit = Number.MAX_SAFE_INTEGER): Promise<Audit[]> { return stream(this.shards.get(tenant), after, limit); }
  /** Recomputed from the stream (O(n)); this store is for tests and single-process use. */
  async auditTree(tenant: string, keys: NodeKey[]) { return treeFromEntries(this.shards.get(tenant)?.audits ?? [], keys); }
  async close() { await this.tail; }
}

/**
 * Single-node developer mode: one JSON row per tenant (`akac_tenant_state`) under
 * BEGIN IMMEDIATE. `akac_state` keeps only the policy version and, after an
 * upgrade, the retained 0.1 global audit chain. A whole-state row written by an
 * earlier version is split into tenant rows once, when the file is opened. It does
 * not scale with history; use the PostgreSQL adapter for shared deployments.
 */
export class SqliteStore implements Store {
  private db: DatabaseSync;
  private tail: Promise<void> = Promise.resolve();
  private broken: unknown;
  constructor(path: string) {
    this.db = new DatabaseSync(path, { timeout: 5000 });
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS akac_state (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS akac_tenant_state (tenant TEXT PRIMARY KEY, body TEXT NOT NULL)`);
    this.db.prepare('INSERT OR IGNORE INTO akac_state(id,body) VALUES(1,?)').run(JSON.stringify(emptyState()));
    try { this.partition(); } catch (error) { this.broken = error; }
  }
  /** Moves every record of a whole-state row into tenant rows, leaving only metadata behind. */
  private partition() {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const state = upgradeState(JSON.parse((this.db.prepare('SELECT body FROM akac_state WHERE id=1').get() as { body: string }).body));
      const shards = split(state);
      if (shards.size) {
        const exists = this.db.prepare('SELECT 1 FROM akac_tenant_state WHERE tenant=?'), insert = this.db.prepare('INSERT INTO akac_tenant_state(tenant, body) VALUES(?, ?)');
        for (const [tenant, shard] of shards) {
          if (exists.get(tenant)) throw new Error('Tenant state exists twice');
          insert.run(tenant, JSON.stringify(shard));
        }
      }
      const meta: State = { ...blank(state.policyVersion), ...(state.legacyAudits ? { legacyAudits: state.legacyAudits } : {}) };
      this.db.prepare('UPDATE akac_state SET body=? WHERE id=1').run(JSON.stringify(meta));
      this.db.exec('COMMIT');
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  private meta(): State {
    if (this.broken) throw this.broken;
    return JSON.parse((this.db.prepare('SELECT body FROM akac_state WHERE id=1').get() as { body: string }).body) as State;
  }
  private shard(tenant: string): State | undefined {
    const row = this.db.prepare('SELECT body FROM akac_tenant_state WHERE tenant=?').get(tenant) as { body: string } | undefined;
    return row ? JSON.parse(row.body) as State : undefined;
  }
  async transaction<T>(tenant: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    if (!validId(tenant)) throw new Error('Invalid tenant');
    let release!: () => void;
    const previous = this.tail; this.tail = new Promise(resolve => { release = resolve; });
    await previous;
    let started = false;
    try {
      const meta = this.meta();
      this.db.exec('BEGIN IMMEDIATE'); started = true;
      const state = this.shard(tenant) ?? blank(meta.policyVersion);
      const result = await fn(complete(state, tenant));
      if (state.schema !== SCHEMA) throw new Error('Unsupported state schema');
      confine(state, tenant);
      this.db.prepare('INSERT INTO akac_tenant_state(tenant, body) VALUES(?, ?) ON CONFLICT(tenant) DO UPDATE SET body=excluded.body').run(tenant, JSON.stringify(state));
      this.db.exec('COMMIT'); return result;
    } catch (error) { if (started) this.db.exec('ROLLBACK'); throw error; }
    finally { release(); }
  }
  async ready(): Promise<boolean> {
    try {
      const meta = this.meta();
      if (meta.schema !== SCHEMA || (meta.legacyAudits && !verifyLegacyAudit(meta.legacyAudits))) return false;
      const rows = this.db.prepare('SELECT body FROM akac_tenant_state').all() as { body: string }[];
      return rows.every(r => sound(JSON.parse(r.body) as State));
    } catch { return false; }
  }
  async auditLog(tenant: string, after = 0, limit = Number.MAX_SAFE_INTEGER): Promise<Audit[]> { this.meta(); return stream(this.shard(tenant), after, limit); }
  /** Recomputed from the tenant row (O(n)); developer mode only. */
  async auditTree(tenant: string, keys: NodeKey[]) { this.meta(); return treeFromEntries(this.shard(tenant)?.audits ?? [], keys); }
  async close() { await this.tail; this.db.close(); }
}

/**
 * Trusted bulk import (seeding, tests, migration). One transaction per tenant, so
 * a row-level-security store never sees a cross-tenant write. Audits are not copied.
 */
export async function importState(store: Store, source: State): Promise<void> {
  const state = upgradeState(structuredClone(source));
  const tenants = new Set<string>(Object.keys(state.epochs));
  for (const collection of COLLECTIONS) for (const record of Object.values(records(state, collection))) tenants.add(String(record.tenant));
  for (const tenant of [...tenants].sort()) await store.transaction(tenant, async tx => {
    await tx.load({ epoch: true });
    for (const collection of COLLECTIONS) {
      const target = (tx.state[collection] ??= {}) as Record<string, unknown>;
      for (const [id, record] of Object.entries(records(state, collection))) if (record.tenant === tenant) target[id] = structuredClone(record);
    }
    if (state.epochs[tenant] !== undefined) tx.state.epochs[tenant] = state.epochs[tenant];
  });
}
