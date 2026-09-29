import { LIMITS } from './policy.ts';
import type { Knowledge, KnowledgeMeta, Tx } from './types.ts';
import { safeNumber, validId } from './validation.ts';

/**
 * Knowledge lifecycle bounds (ADR-007).
 * - list: most descendants one descendants() read returns.
 * - cascade: most records one erase() or revokeLineage() changes (target included);
 *   a larger lineage is a deferred denial (BUDGET_EXCEEDED) that changes nothing.
 * - rows: traversal rows a store may visit before it reports truncation.
 * - retentionBatch: most due records one applyRetention() call processes.
 * - loadChunk: record ids per load while materializing a cascade.
 */
export const LIFECYCLE = { list: 1000, cascade: 1000, rows: 8192, retentionBatch: 100, loadChunk: 64 } as const;

/** Metadata of one descendant, as returned to auditors (no content, no ACL). */
export type LineageRecord = Pick<KnowledgeMeta, 'id' | 'version' | 'kind' | 'classification' | 'active'> & Pick<KnowledgeMeta, 'lifecycle'>;
export const lineageRecord = (k: KnowledgeMeta): LineageRecord =>
  ({ id: k.id, version: k.version, kind: k.kind, classification: k.classification, active: k.active, ...(k.lifecycle !== undefined ? { lifecycle: k.lifecycle } : {}) });

/**
 * Every tenant record whose provenance includes one of `roots` (transitively, at
 * any referenced version), roots excluded, sorted by id. Traversal is bounded by
 * LIMITS.path in depth and LIFECYCLE.rows in visited edges; `truncated` reports
 * that more than `limit` descendants exist or that a bound was hit. Callers that
 * act on the lineage (erasure, revocation) MUST treat truncation as a failure.
 */
export async function lineage(tx: Tx, tenant: string, roots: string[], limit: number): Promise<{ records: KnowledgeMeta[]; truncated: boolean }> {
  if (!roots.every(validId) || !Number.isSafeInteger(limit) || limit < 0) throw new Error('Invalid lineage request');
  if (!tx.complete) {
    if (!tx.descendants) throw new Error('Store cannot traverse provenance');
    const found = await tx.descendants(roots, limit);
    // Stores never return other tenants; a record of another tenant is dropped, not trusted.
    const records = found.records.filter(k => k.tenant === tenant && !roots.includes(k.id));
    return { records: records.slice(0, limit).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0), truncated: found.truncated || records.length > limit };
  }
  const children = new Map<string, Knowledge[]>();
  for (const k of Object.values(tx.state.knowledge)) {
    if (k.tenant !== tenant || !Array.isArray(k.sources)) continue;
    for (const ref of k.sources) {
      if (!validId(ref?.id)) continue;
      const list = children.get(ref.id); if (list) list.push(k); else children.set(ref.id, [k]);
    }
  }
  const seen = new Set(roots), out: Knowledge[] = [];
  let frontier = [...roots], depth = 0, rows = 0, truncated = false;
  while (frontier.length && !truncated) {
    if (++depth > LIMITS.path) { truncated = true; break; }
    const next: string[] = [];
    for (const id of frontier) {
      for (const child of children.get(id) ?? []) {
        if (++rows > LIFECYCLE.rows) { truncated = true; break; }
        if (seen.has(child.id)) continue;
        seen.add(child.id); out.push(child); next.push(child.id);
        if (out.length > limit) { truncated = true; break; }
      }
      if (truncated) break;
    }
    frontier = next;
  }
  const records = out.slice(0, limit).map(k => { const { content: _content, ...meta } = k; return structuredClone(meta); });
  return { records: records.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0), truncated };
}

/** Loads full records of a lineage into a partial snapshot (bounded chunks; BudgetExceeded above the store bound). */
export async function materialize(tx: Tx, ids: string[]): Promise<void> {
  if (tx.complete) return;
  for (let i = 0; i < ids.length; i += LIFECYCLE.loadChunk) await tx.load({ knowledge: ids.slice(i, i + LIFECYCLE.loadChunk) });
}

/** Ids of records due for retention erasure (see Tx.retentionDue), ordered by id after `after`. */
export async function retentionDue(tx: Tx, tenant: string, now: number, after: string, limit: number): Promise<string[]> {
  if (!safeNumber(now) || !Number.isSafeInteger(limit) || limit < 1) throw new Error('Invalid retention request');
  if (!tx.complete) {
    if (!tx.retentionDue) throw new Error('Store cannot list retention');
    return (await tx.retentionDue(now, after, limit)).filter(validId).slice(0, limit);
  }
  return Object.values(tx.state.knowledge)
    .filter(k => k.tenant === tenant && k.id > after && k.lifecycle !== 'erased' && safeNumber(k.retainUntil) && k.retainUntil <= now && !held(k))
    .map(k => k.id).sort().slice(0, limit);
}

/** A record under at least one legal hold. A malformed hold list counts as held (fail closed). */
export const held = (k: Pick<Knowledge, 'legalHolds'>): boolean => k.legalHolds !== undefined && (!Array.isArray(k.legalHolds) || k.legalHolds.length > 0);

/**
 * Replaces a record by its tombstone: content removed, reader list cleared,
 * inactive, lifecycle `erased`. Identity, version, kind, origin, classification
 * and provenance ids stay (pseudonymous; needed to keep denying descendants and to
 * explain the audit trail). Returns false when it already was a tombstone.
 */
export function tombstone(k: Knowledge, now: number): boolean {
  if (k.lifecycle === 'erased' && k.content === '') return false;
  k.content = ''; k.readers = []; k.active = false; k.lifecycle = 'erased'; k.lifecycleAt = now;
  delete k.quarantineReason; delete k.retainUntil; delete k.legalHolds;
  return true;
}
