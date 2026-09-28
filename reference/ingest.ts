import { defaultChunker } from './chunking.ts';
import type { Chunker } from './chunking.ts';
import { ControlPlane } from './control.ts';
import type { ControlResult } from './control.ts';
import type { Embedder } from './embedding.ts';
import { hydrate } from './hydrate.ts';
import { effectiveLabel } from './policy.ts';
import type { Knowledge, KnowledgeMeta, Level, Store } from './types.ts';
import { labelDigest } from './vector.ts';
import type { IndexedChunk, VectorIndex } from './vector.ts';
import { validId } from './validation.ts';

/** The authoritative write succeeded but the index could not be updated; `reconcile()` repairs it. */
export type Pending = { ok: false; code: 'INDEX_PENDING'; id: string; version: number };
export type IngestResult<T> = ControlResult<T> | Pending;
export type IngestEvent =
  | { type: 'indexed'; tenant: string; chunks: number }
  | { type: 'index_removed'; tenant: string }
  | { type: 'index_pending'; tenant: string; reason: 'embed' | 'index' | 'chunk' | 'unreadable' }
  | { type: 'reconciled'; tenant: string; indexed: number; removed: number; failed: number; truncated: boolean };
/**
 * `reconcileDocuments`: documents examined per run. `reconcileBatch`: documents whose
 * content one reconcile transaction loads. `containerChunk`: container ids per load,
 * so a chunk's ancestry (depth <= 33) stays within the store's container bound.
 */
export const INGEST = { embedBatch: 32, reconcileDocuments: 5000, reconcileBatch: 32, containerChunk: 7 } as const;

type Labels = { id: string; version: number; compartment: Level; readTokens: string[]; requiredProjects: string[]; containerTokens: string[][] };
type Plan = Labels & { texts: string[]; ids: string[] };
const tokens = (a: { readers: string[]; readerRoles: string[] }) => [...a.readers.map(x => `user:${x}`), ...a.readerRoles.map(x => `role:${x}`)];

/**
 * Keeps the vector index consistent with the authoritative store. Authorization
 * and audit happen in ControlPlane; chunk metadata is derived from the effective
 * label (never from model output). If embedding or indexing fails after the
 * authoritative write, the document stays authoritative but unindexed
 * (INDEX_PENDING) and reconcile() repairs it. Nothing here grants access: the
 * index is a pre-filter and every hit is re-checked by the engine.
 */
export class Ingestor {
  private control: ControlPlane;
  private store: Store;
  private index: VectorIndex;
  private embedder: Embedder;
  private chunker: Chunker;
  private clock: () => number;
  private emit: (event: IngestEvent) => void;
  constructor(o: { control: ControlPlane; store: Store; index: VectorIndex; embedder: Embedder; chunker?: Chunker; clock?: () => number; onEvent?: (event: IngestEvent) => void }) {
    this.control = o.control; this.store = o.store; this.index = o.index; this.embedder = o.embedder; this.chunker = o.chunker ?? defaultChunker;
    this.clock = o.clock ?? Date.now;
    const listener = o.onEvent; this.emit = event => { try { listener?.(event); } catch { /* metrics never affect indexing */ } };
  }

  /** Label metadata for one document (no content needed); null means it must not be indexed. */
  private labels(k: KnowledgeMeta | undefined, tenant: string, label: ReturnType<typeof effectiveLabel> | null): Labels | null {
    if (!k || k.tenant !== tenant || k.kind !== 'document' || !k.active || !label) return null;
    if (k.accessExpiresAt !== undefined && k.accessExpiresAt <= this.clock()) return null;
    const [own, ...ancestors] = label.audiences;
    return { id: k.id, version: k.version, compartment: label.classification,
      readTokens: own ? tokens(own) : [], requiredProjects: label.projects, containerTokens: ancestors.map(tokens) };
  }
  /** Label metadata and chunk texts for one document; null means it must not be indexed. */
  private plan(k: Knowledge | undefined, tenant: string, label: ReturnType<typeof effectiveLabel> | null): Plan | null {
    const labels = this.labels(k, tenant, label);
    if (!labels) return null;
    const chunks = this.chunker(k!.id, k!.version, k!.content);
    return { ...labels, texts: chunks.map(c => c.text), ids: chunks.map(c => c.id) };
  }
  private async embed(texts: string[]): Promise<Float32Array[]> {
    const out: Float32Array[] = [];
    for (let i = 0; i < texts.length; i += INGEST.embedBatch) out.push(...await this.embedder.embed(texts.slice(i, i + INGEST.embedBatch)));
    if (out.length !== texts.length || out.some(v => v.length !== this.embedder.dimensions)) throw new Error('Embedder shape');
    return out;
  }
  private async write(tenant: string, plan: Plan): Promise<void> {
    const vectors = await this.embed(plan.texts);
    await this.index.upsert(plan.ids.map((chunkId, ordinal): IndexedChunk => ({ tenant, docId: plan.id, docVersion: plan.version, chunkId, ordinal,
      compartment: plan.compartment, readTokens: plan.readTokens, requiredProjects: plan.requiredProjects, containerTokens: plan.containerTokens,
      model: this.embedder.model, vector: vectors[ordinal]! })));
    this.emit({ type: 'indexed', tenant, chunks: plan.ids.length });
  }
  /** Reads the document and its container chain in one store transaction, then indexes it. */
  private async sync(tenant: string, docId: string): Promise<{ id: string; version: number; chunks: number } | 'pending'> {
    let version = 0, plan: Plan | null;
    try {
      const read = await this.store.transaction(tenant, async tx => {
        await hydrate(tx, { knowledge: [docId] });
        const k = Object.hasOwn(tx.state.knowledge, docId) ? tx.state.knowledge[docId] : undefined;
        return { k: k && structuredClone(k), label: k && effectiveLabel(tx.state, k) };
      });
      version = read.k?.version ?? 0;
      try { plan = this.plan(read.k, tenant, read.label ?? null); }
      catch { this.emit({ type: 'index_pending', tenant, reason: 'chunk' }); return 'pending'; }
    } catch { this.emit({ type: 'index_pending', tenant, reason: 'unreadable' }); return 'pending'; }
    try {
      if (!plan) { await this.index.removeDocument(tenant, docId); this.emit({ type: 'index_removed', tenant }); return { id: docId, version, chunks: 0 }; }
      await this.write(tenant, plan);
      return { id: docId, version, chunks: plan.ids.length };
    } catch { this.emit({ type: 'index_pending', tenant, reason: plan ? 'embed' : 'index' }); return 'pending'; }
  }

  /** Authorized upsert (kb-admin) followed by indexing. */
  async ingest(tenant: string, adminId: string, document: Knowledge): Promise<IngestResult<{ id: string; version: number; chunks: number }>> {
    const result = await this.control.upsertKnowledge(tenant, adminId, document);
    if (!result.ok) return result;
    const done = await this.sync(tenant, result.value.id);
    return done === 'pending' ? { ok: false, code: 'INDEX_PENDING', ...result.value } : { ok: true, value: { ...result.value, chunks: done.chunks } };
  }
  /** Authorized removal: retires the document (kb-admin, audited, advances the tenant epoch), then drops its chunks. */
  async remove(tenant: string, adminId: string, docId: string): Promise<IngestResult<{ id: string; epoch: number }>> {
    const result = await this.control.removeKnowledge(tenant, adminId, docId);
    if (!result.ok) return result;
    try { await this.index.removeDocument(tenant, docId); this.emit({ type: 'index_removed', tenant }); }
    catch { this.emit({ type: 'index_pending', tenant, reason: 'index' }); return { ok: false, code: 'INDEX_PENDING', id: docId, version: 0 }; }
    return { ok: true, value: { id: docId, epoch: result.value.epoch } };
  }
  /**
   * Recomputes one document's labels and re-indexes it, moving it between
   * compartments if its effective classification changed. Use after editing a
   * container; reconcile() does the same for a whole tenant.
   */
  async relabel(tenant: string, docId: string): Promise<{ ok: true; value: { id: string; version: number; chunks: number } } | { ok: false; code: 'INVALID_REQUEST' | 'INDEX_PENDING' }> {
    if (!validId(tenant) || !validId(docId)) return { ok: false, code: 'INVALID_REQUEST' };
    const done = await this.sync(tenant, docId);
    return done === 'pending' ? { ok: false, code: 'INDEX_PENDING' } : { ok: true, value: done };
  }
  /**
   * Repairs drift between the authoritative store and the index: re-indexes
   * documents whose indexed version, label digest or embedding model differs, and
   * removes chunks of documents that are inactive, expired, unlabelable or gone.
   * Removal is skipped when the tenant exceeds the scan cap (`truncated`).
   *
   * Memory is bounded: the first pass reads document metadata only (no content)
   * and container labels; content is then loaded only for documents that need
   * (re)indexing, `reconcileBatch` documents per transaction.
   */
  async reconcile(tenant: string): Promise<{ indexed: number; removed: number; failed: number; truncated: boolean }> {
    if (!validId(tenant)) throw new Error('Invalid tenant');
    const cap = INGEST.reconcileDocuments;
    const catalog = new Map<string, Labels | null>();
    let truncated = false, failed = 0;
    await this.store.transaction(tenant, async tx => {
      let docs: KnowledgeMeta[];
      if (tx.complete) docs = Object.values(tx.state.knowledge).filter(k => k.tenant === tenant && k.kind === 'document').sort((a, b) => a.id < b.id ? -1 : 1).slice(0, cap + 1);
      else if (tx.catalog) docs = await tx.catalog(cap + 1);
      else throw new Error('Store cannot list documents');
      truncated = docs.length > cap;
      const chosen = docs.slice(0, cap);
      const containers = [...new Set(chosen.map(k => k.container).filter(validId))];
      for (let i = 0; i < containers.length; i += INGEST.containerChunk) await tx.load({ containers: containers.slice(i, i + INGEST.containerChunk) });
      for (const k of chosen) {
        try { catalog.set(k.id, this.labels(k, tenant, effectiveLabel(tx.state, k))); } catch { failed++; }
      }
    });
    const indexed = await this.index.state(tenant);
    let written = 0, removed = 0;
    const stale: string[] = [];
    for (const [id, labels] of catalog) {
      const current = indexed.get(id);
      if (labels) {
        if (!(current && current.version === labels.version && current.digest === labelDigest(labels) && current.model === this.embedder.model)) stale.push(id);
      } else if (current) {
        try { await this.index.removeDocument(tenant, id); removed++; } catch { failed++; }
      }
    }
    for (let i = 0; i < stale.length; i += INGEST.reconcileBatch) {
      const batch = stale.slice(i, i + INGEST.reconcileBatch);
      let plans: Map<string, Plan | null> | null = null;
      try {
        plans = await this.store.transaction(tenant, async tx => {
          await hydrate(tx, { knowledge: batch });
          const out = new Map<string, Plan | null>();
          for (const id of batch) {
            const k = Object.hasOwn(tx.state.knowledge, id) ? tx.state.knowledge[id] : undefined;
            try { out.set(id, this.plan(k, tenant, k ? effectiveLabel(tx.state, k) : null)); } catch { failed++; }
          }
          return out;
        });
      } catch { /* the batch closure did not fit: fall back to one document per transaction */ }
      for (const id of batch) {
        if (!plans) {
          const done = await this.sync(tenant, id);
          if (done === 'pending') failed++; else if (done.chunks) written++; else if (indexed.has(id)) removed++;
          continue;
        }
        if (!plans.has(id)) continue;
        const plan = plans.get(id)!;
        if (!plan) {
          if (indexed.has(id)) { try { await this.index.removeDocument(tenant, id); removed++; } catch { failed++; } }
          continue;
        }
        try { await this.write(tenant, plan); written++; } catch { failed++; this.emit({ type: 'index_pending', tenant, reason: 'embed' }); }
      }
    }
    if (!truncated) {
      for (const id of indexed.keys()) {
        if (catalog.has(id)) continue;
        try { await this.index.removeDocument(tenant, id); removed++; } catch { failed++; }
      }
    }
    this.emit({ type: 'reconciled', tenant, indexed: written, removed, failed, truncated });
    return { indexed: written, removed, failed, truncated };
  }
}
