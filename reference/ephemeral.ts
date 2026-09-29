import { KNOWLEDGE } from './types.ts';
import type { Knowledge, Need, Store, Tx } from './types.ts';
import { validEphemeral } from './knowledge.ts';
import { validId } from './validation.ts';

/**
 * Session-scoped knowledge (0.6, R190, ADR-022): an in-memory partition of this
 * gateway process. Ephemeral records (derived memory and artifacts carrying
 * `ephemeral`) are held here only: never in SQLite or PostgreSQL, never in a vector
 * index. They are gone when their session is closed, when they expire (at the latest
 * with their run's grant) and when the process restarts. Several gateway instances do
 * not share the partition: a session's records exist on the instance that wrote them.
 */
export class EphemeralPartition {
  private tenants = new Map<string, Map<string, Knowledge>>();
  private clock: () => number;
  constructor(clock: () => number = Date.now) { this.clock = clock; }
  /** Drops every expired record of the tenant (and malformed ones). */
  purge(tenant: string, now = this.clock()): void {
    const records = this.tenants.get(tenant);
    if (!records) return;
    for (const [id, k] of records) if (!validEphemeral(k.ephemeral) || now >= k.ephemeral.expiresAt) records.delete(id);
    if (!records.size) this.tenants.delete(tenant);
  }
  records(tenant: string): Knowledge[] { return [...this.tenants.get(tenant)?.values() ?? []]; }
  size(tenant: string): number { return this.tenants.get(tenant)?.size ?? 0; }
  /** Room for `count` more records of this session (KNOWLEDGE.ephemeralRecords per session, KNOWLEDGE.ephemeralTenant per tenant). */
  room(tenant: string, run: string, sessionId: string, count = 1): boolean {
    const records = this.records(tenant);
    return records.length + count <= KNOWLEDGE.ephemeralTenant
      && records.filter(k => k.ephemeral?.run === run && k.ephemeral.sessionId === sessionId).length + count <= KNOWLEDGE.ephemeralRecords;
  }
  set(tenant: string, record: Knowledge): void {
    if (record.tenant !== tenant || !validId(record.id) || !validEphemeral(record.ephemeral)) throw new Error('Invalid ephemeral record');
    let records = this.tenants.get(tenant);
    if (!records) { records = new Map(); this.tenants.set(tenant, records); }
    records.set(record.id, structuredClone(record));
  }
  delete(tenant: string, id: string): void { this.tenants.get(tenant)?.delete(id); }
  /** Removes every record of one session of one run; returns how many. */
  closeSession(tenant: string, run: string, sessionId: string): number {
    const records = this.tenants.get(tenant);
    let n = 0;
    for (const [id, k] of records ?? []) if (k.ephemeral?.run === run && k.ephemeral.sessionId === sessionId) { records!.delete(id); n++; }
    return n;
  }
}

/**
 * A Store view that overlays the partition on every transaction: requested ephemeral
 * records (and, for complete snapshots, all of the tenant's) appear in the snapshot so
 * decide() treats them like any record; ephemeral records present when the operation
 * ends are taken out of the snapshot before the underlying store commits, and enter the
 * partition only once it did (a rolled-back operation leaves nothing behind).
 */
export class EphemeralStore implements Store {
  readonly inner: Store;
  readonly partition: EphemeralPartition;
  readonly auditTree?: Store['auditTree'];
  private clock: () => number;
  constructor(inner: Store, partition: EphemeralPartition, clock: () => number = Date.now) {
    this.inner = inner; this.partition = partition; this.clock = clock;
    if (inner.auditTree) this.auditTree = inner.auditTree.bind(inner);
  }
  async transaction<T>(tenant: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    const staged: { set: Knowledge[]; update: Knowledge[]; drop: string[] } = { set: [], update: [], drop: [] };
    const result = await this.inner.transaction(tenant, async tx => {
      this.partition.purge(tenant, this.clock());
      /** Injected records and their serialized form, to tell a change from an unchanged copy. */
      const injected = new Map<string, string>();
      const inject = (ids?: readonly string[]) => {
        const wanted = ids ? new Set(ids) : undefined;
        for (const k of this.partition.records(tenant)) {
          if (wanted && !wanted.has(k.id)) continue;
          if (Object.hasOwn(tx.state.knowledge, k.id)) continue;
          tx.state.knowledge[k.id] = structuredClone(k); injected.set(k.id, JSON.stringify(k));
        }
      };
      if (tx.complete) inject();
      const view: Tx = {
        get state() { return tx.state; },
        complete: tx.complete,
        load: async (need: Need) => { await tx.load(need); if (need.knowledge?.length) inject(need.knowledge); if (need.corpus) inject(); },
        ...(tx.catalog ? { catalog: tx.catalog.bind(tx) } : {}),
        ...(tx.countSodHolders ? { countSodHolders: tx.countSodHolders.bind(tx) } : {}),
        ...(tx.descendants ? { descendants: tx.descendants.bind(tx) } : {}),
        ...(tx.retentionDue ? { retentionDue: tx.retentionDue.bind(tx) } : {}),
        ...(tx.modelRecords ? { modelRecords: tx.modelRecords.bind(tx) } : {}),
        ...(tx.pendingErasures ? { pendingErasures: tx.pendingErasures.bind(tx) } : {})
      };
      const value = await fn(view);
      const knowledge = tx.state.knowledge;
      for (const [id, k] of Object.entries(knowledge)) {
        if (k?.ephemeral !== undefined) {
          // A new record enters the partition; a changed copy updates it only if it is still there (a session closed meanwhile stays closed).
          // A malformed or foreign session scope is never kept (it would be invisible anyway): the record is dropped.
          if (k.tenant !== tenant || !validEphemeral(k.ephemeral) || k.id !== id || !validId(id)) { if (injected.has(id)) staged.drop.push(id); }
          else if (!injected.has(id)) staged.set.push(structuredClone(k)); else if (injected.get(id) !== JSON.stringify(k)) staged.update.push(structuredClone(k));
          delete knowledge[id];
        }
        else if (injected.has(id)) {
          // An injected record that lost its session scope would become persistent: never; it is dropped instead.
          staged.drop.push(id); delete knowledge[id];
        }
      }
      return value;
    });
    for (const id of staged.drop) this.partition.delete(tenant, id);
    for (const k of staged.set) this.partition.set(tenant, k);
    for (const k of staged.update) if (this.partition.records(tenant).some(x => x.id === k.id)) this.partition.set(tenant, k);
    return result;
  }
  ready(tenant?: string) { return this.inner.ready(tenant); }
  auditLog(tenant: string, after?: number, limit?: number) { return this.inner.auditLog(tenant, after, limit); }
  close() { return this.inner.close(); }
}
/** The ephemeral-aware store of an engine: an EphemeralStore is used as is, any other store is wrapped. */
export const withEphemeral = (store: Store, clock: () => number): EphemeralStore => store instanceof EphemeralStore ? store : new EphemeralStore(store, new EphemeralPartition(clock), clock);
