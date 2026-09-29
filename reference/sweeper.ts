import type { ControlPlane, ControlResult } from './control.ts';
import type { VersionRange } from './knowledge.ts';
import { MemoryJobLock } from './limits.ts';
import type { JobLock } from './limits.ts';
import type { Knowledge } from './types.ts';
import type { VectorIndex } from './vector.ts';

/**
 * Cascade sweeper (0.6, R193, ADR-022). Denial of a record derived from revoked,
 * erased or quarantined knowledge is lazy and authoritative: every gate traverses the
 * provenance (R-LIFE-2). The sweeper makes it explicit and removes stale index entries:
 * it quarantines the descendants of such a record (`ancestor_revoked`, or `poisoned`
 * below a record quarantined as poisoned), raises the stored classification of the
 * descendants of a record that was relabelled upward, and drops or re-indexes the
 * affected documents. It works in bounded, audited batches (ControlPlane.sweepLineage,
 * at most 100 records per transaction), resumes by id, and runs under the `sweep` job
 * lock, so that several gateway instances and CronJob pods never sweep one tenant at
 * once (the PostgreSQL job lock of ADR-016 across instances). A sweep that did not run
 * (lock held), failed or stopped at its bound changes nothing that a gate relies on.
 */
export type SweepResult = { ran: boolean; batches: number; changed: number; truncated: boolean; indexPending: number;
  /** Set when the sweep stopped at `maxBatches`: pass it as `after` to continue. */
  next?: string;
  /** The first refusal (for example NOT_AUTHORIZED), when a batch was refused. */
  refused?: string };
export type SweeperOptions = {
  control: ControlPlane;
  /** Job lock shared by every instance (adapters/postgres-ha.ts PostgresJobLock); default per process. */
  lock?: JobLock;
  /** The vector index to drop quarantined documents from. Without it the index is left to reconcile(). */
  index?: VectorIndex;
  /**
   * Re-checks one document against the index (for example Ingestor.relabel, which drops a document that may no longer be
   * indexed and re-indexes one whose label changed). Preferred over `index` when both are given.
   */
  reindex?: (tenant: string, id: string) => Promise<unknown>;
  /** Repairs the index of a tenant after erasures (for example Ingestor.reconcile). */
  reconcile?: (tenant: string) => Promise<unknown>;
  /** Most batches one call runs (default 100: 10 000 records). */
  maxBatches?: number;
};
export class Sweeper {
  private control: ControlPlane;
  private lock: JobLock;
  private index?: VectorIndex;
  private reindex?: SweeperOptions['reindex'];
  private reconcile?: SweeperOptions['reconcile'];
  private maxBatches: number;
  constructor(options: SweeperOptions) {
    this.control = options.control; this.lock = options.lock ?? new MemoryJobLock(); this.index = options.index;
    this.reindex = options.reindex; this.reconcile = options.reconcile; this.maxBatches = options.maxBatches ?? 100;
    if (!Number.isSafeInteger(this.maxBatches) || this.maxBatches < 1 || this.maxBatches > 10_000) throw new Error('Invalid sweeper options');
  }
  /** Sweeps the lineage of one record (see ControlPlane.sweepLineage) under the job lock. */
  async sweep(tenant: string, adminId: string, id: string, options: { after?: string } = {}): Promise<SweepResult> {
    const locked = await this.lock.run('sweep', tenant, () => this.lineage(tenant, adminId, id, options.after));
    return locked.ran ? locked.value : { ran: false, batches: 0, changed: 0, truncated: false, indexPending: 0 };
  }
  /**
   * Model recall (R191): quarantines the records of `model` in `range`
   * (ControlPlane.quarantineByModel) and sweeps the lineage of each, under the job lock.
   */
  async recallModel(tenant: string, adminId: string, model: string, range: VersionRange): Promise<SweepResult & { recalled: number }> {
    const locked = await this.lock.run('sweep', tenant, async () => {
      const out: SweepResult & { recalled: number } = { ran: true, batches: 0, changed: 0, truncated: false, indexPending: 0, recalled: 0 };
      let after: string | undefined;
      do {
        if (out.batches >= this.maxBatches) { out.next = after; break; }
        const r = await this.control.quarantineByModel(tenant, adminId, model, range, after ? { after } : {});
        out.batches++;
        if (!r.ok) { out.refused = r.code; break; }
        out.recalled += r.value.quarantined.length; out.changed += r.value.quarantined.length;
        for (const root of r.value.quarantined) {
          out.indexPending += await this.drop(tenant, root);
          const swept = await this.lineage(tenant, adminId, root);
          out.batches += swept.batches; out.changed += swept.changed; out.indexPending += swept.indexPending;
          out.truncated ||= swept.truncated || swept.next !== undefined;
          if (swept.refused) { out.refused = swept.refused; return out; }
        }
        after = r.value.next;
      } while (after);
      return out;
    });
    return locked.ran ? locked.value : { ran: false, batches: 0, changed: 0, truncated: false, indexPending: 0, recalled: 0 };
  }
  /**
   * Pending erasures (R194): runs every erasure a legal hold no longer blocks
   * (ControlPlane.applyPendingErasures) under the `erasure` job lock, then repairs the index.
   */
  async applyPendingErasures(tenant: string, adminId: string): Promise<{ ran: boolean; erased: number; held: number; deferred: number; refused?: string }> {
    const locked = await this.lock.run('erasure', tenant, async () => {
      const out = { ran: true, erased: 0, held: 0, deferred: 0 } as { ran: boolean; erased: number; held: number; deferred: number; refused?: string };
      let after: string | undefined, batches = 0;
      do {
        if (++batches > this.maxBatches) break;
        const r: ControlResult<{ erased: number; held: number; deferred: number; next?: string }> = await this.control.applyPendingErasures(tenant, adminId, after ? { after } : {});
        if (!r.ok) { out.refused = r.code; break; }
        out.erased += r.value.erased; out.held += r.value.held; out.deferred += r.value.deferred;
        after = r.value.next;
      } while (after);
      if (out.erased && this.reconcile) { try { await this.reconcile(tenant); } catch { out.deferred++; } }
      return out;
    });
    return locked.ran ? locked.value : { ran: false, erased: 0, held: 0, deferred: 0 };
  }
  private async lineage(tenant: string, adminId: string, id: string, start?: string): Promise<SweepResult> {
    const out: SweepResult = { ran: true, batches: 0, changed: 0, truncated: false, indexPending: 0 };
    let after = start;
    do {
      if (out.batches >= this.maxBatches) { out.next = after; break; }
      const r = await this.control.sweepLineage(tenant, adminId, id, after ? { after } : {});
      out.batches++;
      if (!r.ok) { out.refused = r.code; break; }
      out.truncated ||= r.value.truncated;
      out.changed += r.value.changed.length;
      for (const c of r.value.changed) out.indexPending += await this.follow(tenant, c);
      after = r.value.next;
    } while (after);
    return out;
  }
  /** Index follow-up of one changed record: documents are re-checked (or dropped); derived records are never indexed. */
  private async follow(tenant: string, c: { id: string; kind: Knowledge['kind'] }): Promise<number> {
    return c.kind === 'document' ? this.drop(tenant, c.id) : 0;
  }
  /** Re-checks (reindex) or drops (index) one document; a failure counts as pending (reconcile() repairs it). */
  private async drop(tenant: string, id: string): Promise<number> {
    try {
      if (this.reindex) { const r = await this.reindex(tenant, id) as { ok?: unknown } | undefined; return r && r.ok === false ? 1 : 0; }
      if (this.index) await this.index.removeDocument(tenant, id);
      return 0;
    } catch { return 1; }
  }
}
