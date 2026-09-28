import type { CandidateSource } from './engine.ts';
import type { Embedder } from './embedding.ts';
import { LEVELS } from './types.ts';
import type { Level } from './types.ts';
import type { VectorIndex } from './vector.ts';

export type VectorSourceOptions = {
  index: VectorIndex; embedder: Embedder;
  /** Hits at or below this cosine score are dropped. Scores exist only for admitted chunks. */
  minScore?: number;
  /** Chunk over-fetch per requested document, since several chunks can belong to one document. */
  overfetch?: number;
};
const prefixed = (tokens: string[], prefix: string) => tokens.filter(t => t.startsWith(prefix)).map(t => t.slice(prefix.length));

/**
 * Permission-aware vector candidate source (ADR-004). It queries only the
 * classification compartments up to the caller's effective clearance, passes the
 * principal tokens as an in-index pre-filter, and returns document ids ranked by
 * their best chunk. The result is a hint: the Engine re-checks every id with
 * decide(), and a failing id is dropped and counted as a filter mismatch.
 * Embedder or index failures throw, which the Engine turns into a denial.
 */
export class VectorCandidateSource implements CandidateSource {
  private index: VectorIndex;
  private embedder: Embedder;
  private minScore: number;
  private overfetch: number;
  constructor(o: VectorSourceOptions) {
    this.index = o.index; this.embedder = o.embedder; this.minScore = o.minScore ?? 0; this.overfetch = o.overfetch ?? 4;
    if (!Number.isFinite(this.minScore) || !Number.isInteger(this.overfetch) || this.overfetch < 1 || this.overfetch > 20) throw new Error('Invalid retrieval options');
  }
  async candidates(input: { tenant: string; maxClassification: Level; tokens: string[]; query: string; limit: number }): Promise<string[]> {
    const top = LEVELS.indexOf(input.maxClassification);
    if (top < 0 || !Number.isInteger(input.limit) || input.limit < 1) return [];
    const [vector] = await this.embedder.embed([input.query]);
    if (!vector || vector.length !== this.embedder.dimensions) throw new Error('Embedder shape');
    const hits = await this.index.query({ tenant: input.tenant, compartments: LEVELS.slice(0, top + 1), vector,
      tokens: input.tokens.filter(t => t.startsWith('user:') || t.startsWith('role:')), projects: prefixed(input.tokens, 'project:'),
      k: Math.min(1000, input.limit * this.overfetch) });
    const best = new Map<string, number>();
    for (const h of hits) if (h.score > this.minScore && !(best.get(h.docId)! >= h.score)) best.set(h.docId, h.score);
    return [...best].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, input.limit).map(([id]) => id);
  }
}
