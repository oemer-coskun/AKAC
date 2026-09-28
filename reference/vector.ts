import { createHash } from 'node:crypto';
import { LEVELS } from './types.ts';
import type { Level } from './types.ts';
import { validId } from './validation.ts';

/**
 * One embedded chunk plus the label metadata used to pre-filter it (ADR-004).
 * The index never stores chunk text and never authorizes: decide() re-checks every hit.
 */
export type IndexedChunk = {
  tenant: string; docId: string; docVersion: number; chunkId: string; ordinal: number;
  /** Classification compartment: the effective classification of the document. */
  compartment: Level;
  /** Document ACL tokens (`user:`, `role:`): the caller needs any one. */
  readTokens: string[];
  /** Union of project requirements: the caller needs all of them. */
  requiredProjects: string[];
  /** One token list per ancestor container: the caller needs any one of EACH list. */
  containerTokens: string[][];
  /** Embedder identity, so a model change is detected and re-embedded. */
  model: string;
  vector: Float32Array;
};
export type VectorQuery = {
  tenant: string;
  /** Compartments the caller may see. Others MUST NOT be queried. */
  compartments: Level[];
  tokens: string[]; projects: string[]; vector: Float32Array; k: number;
};
export type VectorHit = { docId: string; chunkId: string; score: number };
export type IndexedDocument = { version: number; model: string; digest: string };
export interface VectorIndex {
  /** Replaces every stored chunk of each document in the batch (in any compartment). A lower version than stored is ignored. */
  upsert(chunks: IndexedChunk[]): Promise<void>;
  removeDocument(tenant: string, docId: string): Promise<void>;
  /** Pre-filter first, then rank only the admitted chunks; best score first. */
  query(q: VectorQuery): Promise<VectorHit[]>;
  /** What is indexed for a tenant, for reconciliation. */
  state(tenant: string): Promise<Map<string, IndexedDocument>>;
}
export const QUERY_LIMIT = 1000;

/** Digest of everything that decides pre-filter admission, used to detect stale metadata. */
export function labelDigest(c: Pick<IndexedChunk, 'compartment' | 'readTokens' | 'requiredProjects' | 'containerTokens'>): string {
  const sorted = (x: readonly string[]) => [...x].sort();
  return createHash('sha256').update(JSON.stringify([c.compartment, sorted(c.readTokens), sorted(c.requiredProjects), c.containerTokens.map(sorted)])).digest('hex');
}
const anyOf = (need: readonly string[], have: ReadonlySet<string>) => need.some(t => have.has(t));
/** The pre-filter as a pure predicate. Empty ACL lists match nobody. */
export function admits(c: IndexedChunk, q: { tenant: string; compartments: readonly Level[]; tokens: ReadonlySet<string>; projects: ReadonlySet<string> }): boolean {
  return c.tenant === q.tenant && q.compartments.includes(c.compartment) && anyOf(c.readTokens, q.tokens)
    && c.containerTokens.every(level => anyOf(level, q.tokens)) && c.requiredProjects.every(p => q.projects.has(p));
}
export function checkQuery(q: VectorQuery): void {
  if (!q || !validId(q.tenant) || !Array.isArray(q.compartments) || q.compartments.some(l => !LEVELS.includes(l)) || !Array.isArray(q.tokens)
    || !Array.isArray(q.projects) || !(q.vector instanceof Float32Array) || !Number.isInteger(q.k) || q.k < 1 || q.k > QUERY_LIMIT) throw new Error('Invalid vector query');
}
export function checkChunk(c: IndexedChunk): void {
  if (!validId(c.tenant) || !validId(c.docId) || !Number.isSafeInteger(c.docVersion) || c.docVersion < 1 || typeof c.chunkId !== 'string' || !c.chunkId
    || !Number.isInteger(c.ordinal) || c.ordinal < 0 || !LEVELS.includes(c.compartment) || !(c.vector instanceof Float32Array)
    || ![c.readTokens, c.requiredProjects].every(x => Array.isArray(x) && x.every(t => typeof t === 'string'))
    || !Array.isArray(c.containerTokens) || c.containerTokens.some(l => !Array.isArray(l) || l.some(t => typeof t !== 'string'))
    || typeof c.model !== 'string' || c.vector.some(x => !Number.isFinite(x))) throw new Error('Invalid indexed chunk');
}
function cosine(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length) throw new Error('Vector dimension mismatch');
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) { dot += a[i]! * b[i]!; na += a[i]! * a[i]!; nb += b[i]! * b[i]!; }
  return na && nb ? dot / Math.sqrt(na * nb) : 0;
}
/** Best score first; ties by chunk id so results are deterministic. */
export const byScore = (a: VectorHit, b: VectorHit) => b.score - a.score || (a.chunkId < b.chunkId ? -1 : a.chunkId > b.chunkId ? 1 : 0);
/** Groups chunks by document; a document's chunks must share one version. */
export function byDocument(chunks: IndexedChunk[]): Map<string, IndexedChunk[]> {
  const docs = new Map<string, IndexedChunk[]>();
  for (const c of chunks) { const k = `${c.tenant}\n${c.docId}`; docs.set(k, [...docs.get(k) ?? [], c]); }
  for (const list of docs.values()) if (list.some(c => c.docVersion !== list[0]!.docVersion)) throw new Error('Mixed document versions');
  return docs;
}

/**
 * Exact in-process index. Chunks live in one physical Map per (tenant,
 * compartment); a query touches only the partitions it names, and scores only
 * chunks that pass the pre-filter.
 */
export class MemoryVectorIndex implements VectorIndex {
  private partitions = new Map<string, Map<string, IndexedChunk>>();
  private key = (tenant: string, compartment: Level) => `${tenant}|${compartment}`;
  private versionOf(tenant: string, docId: string): number {
    let v = 0;
    for (const level of LEVELS) for (const c of this.partitions.get(this.key(tenant, level))?.values() ?? []) if (c.docId === docId) v = Math.max(v, c.docVersion);
    return v;
  }
  async removeDocument(tenant: string, docId: string): Promise<void> {
    for (const level of LEVELS) {
      const p = this.partitions.get(this.key(tenant, level));
      if (p) for (const [id, c] of p) if (c.docId === docId) p.delete(id);
    }
  }
  async upsert(chunks: IndexedChunk[]): Promise<void> {
    chunks.forEach(checkChunk);
    for (const list of byDocument(chunks).values()) {
      const { tenant, docId, docVersion } = list[0]!;
      if (this.versionOf(tenant, docId) > docVersion) continue;
      await this.removeDocument(tenant, docId);
      for (const c of list) {
        const k = this.key(c.tenant, c.compartment);
        if (!this.partitions.has(k)) this.partitions.set(k, new Map());
        this.partitions.get(k)!.set(c.chunkId, { ...c, readTokens: [...c.readTokens], requiredProjects: [...c.requiredProjects],
          containerTokens: c.containerTokens.map(l => [...l]), vector: Float32Array.from(c.vector) });
      }
    }
  }
  async query(q: VectorQuery): Promise<VectorHit[]> {
    checkQuery(q);
    const filter = { tenant: q.tenant, compartments: q.compartments, tokens: new Set(q.tokens), projects: new Set(q.projects) };
    const hits: VectorHit[] = [];
    for (const level of new Set(q.compartments)) {
      for (const c of this.partitions.get(this.key(q.tenant, level))?.values() ?? []) {
        if (admits(c, filter)) hits.push({ docId: c.docId, chunkId: c.chunkId, score: cosine(q.vector, c.vector) });
      }
    }
    return hits.sort(byScore).slice(0, q.k);
  }
  async state(tenant: string): Promise<Map<string, IndexedDocument>> {
    const out = new Map<string, IndexedDocument>();
    for (const level of LEVELS) for (const c of this.partitions.get(this.key(tenant, level))?.values() ?? []) {
      const next = { version: c.docVersion, model: c.model, digest: labelDigest(c) };
      const seen = out.get(c.docId);
      out.set(c.docId, seen && (seen.digest !== next.digest || seen.model !== next.model) ? { ...next, digest: 'conflict' } : next);
    }
    return out;
  }
}

/**
 * Routes compartments to different indexes, for example the restricted tier to a
 * dedicated database (ADR-004). Each backend only ever sees its own compartments.
 */
export class RoutedVectorIndex implements VectorIndex {
  private backends: VectorIndex[];
  private route: Record<Level, VectorIndex>;
  constructor(routes: { default: VectorIndex } & Partial<Record<Level, VectorIndex>>) {
    this.route = Object.fromEntries(LEVELS.map(l => [l, routes[l] ?? routes.default])) as Record<Level, VectorIndex>;
    this.backends = [...new Set(Object.values(this.route))];
  }
  async upsert(chunks: IndexedChunk[]): Promise<void> {
    chunks.forEach(checkChunk);
    const docs = [...byDocument(chunks).values()];
    for (const backend of this.backends) {
      const own = docs.flatMap(list => list.filter(c => this.route[c.compartment] === backend));
      // A backend that no longer holds any of a document's chunks must drop the old ones.
      for (const list of docs) if (!list.some(c => this.route[c.compartment] === backend)) await backend.removeDocument(list[0]!.tenant, list[0]!.docId);
      if (own.length) await backend.upsert(own);
    }
  }
  async removeDocument(tenant: string, docId: string) { for (const b of this.backends) await b.removeDocument(tenant, docId); }
  async query(q: VectorQuery): Promise<VectorHit[]> {
    checkQuery(q);
    const hits: VectorHit[] = [];
    for (const backend of this.backends) {
      const compartments = q.compartments.filter(l => this.route[l] === backend);
      if (compartments.length) hits.push(...await backend.query({ ...q, compartments }));
    }
    return hits.sort(byScore).slice(0, q.k);
  }
  async state(tenant: string): Promise<Map<string, IndexedDocument>> {
    const out = new Map<string, IndexedDocument>();
    for (const backend of this.backends) for (const [id, s] of await backend.state(tenant)) out.set(id, out.has(id) ? { ...s, digest: 'conflict' } : s);
    return out;
  }
}
