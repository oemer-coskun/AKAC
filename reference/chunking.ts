export type Chunk = { id: string; ordinal: number; text: string };
export type ChunkOptions = { maxChars?: number; overlap?: number; maxChunks?: number };
export type Chunker = (docId: string, version: number, content: string) => Chunk[];
export const CHUNKING = { maxChars: 1200, overlap: 150, maxChunks: 2000 } as const;
export const chunkId = (docId: string, version: number, ordinal: number) => `${docId}#${version}#${ordinal}`;

/** Splits into sentence-like units; a unit longer than `max` is cut at whitespace. */
function units(content: string, max: number): string[] {
  const out: string[] = [];
  for (const paragraph of content.replace(/\r\n?/g, '\n').split(/\n\s*\n/)) {
    for (const sentence of paragraph.split(/(?<=[.!?])\s+/)) {
      let rest = sentence.trim();
      while (rest.length > max) {
        let cut = rest.lastIndexOf(' ', max);
        if (cut < max / 2) cut = max;
        out.push(rest.slice(0, cut).trim()); rest = rest.slice(cut).trim();
      }
      if (rest) out.push(rest);
    }
  }
  return out;
}
/** Word-aligned tail of a chunk, at most `n` characters. */
function tail(text: string, n: number): string {
  if (n <= 0 || text.length <= n) return n > 0 ? text : '';
  const from = text.indexOf(' ', text.length - n);
  return from < 0 ? '' : text.slice(from + 1);
}
/**
 * Deterministic paragraph- and sentence-aware chunker with overlap. The same
 * input always yields the same ids and texts. More than `maxChunks` throws
 * instead of silently truncating: unindexed text would be unsearchable.
 */
export function chunkText(docId: string, version: number, content: string, options: ChunkOptions = {}): Chunk[] {
  const max = options.maxChars ?? CHUNKING.maxChars, overlap = options.overlap ?? CHUNKING.overlap, cap = options.maxChunks ?? CHUNKING.maxChunks;
  if (!Number.isInteger(max) || max < 64 || !Number.isInteger(overlap) || overlap < 0 || overlap > max / 2 || !Number.isInteger(cap) || cap < 1) throw new Error('Invalid chunk options');
  const texts: string[] = [];
  let current = '', fresh = false;
  const flush = () => { if (fresh) texts.push(current); current = fresh ? tail(current, overlap) : ''; fresh = false; };
  for (const unit of units(content, max - overlap)) {
    if (current && current.length + 1 + unit.length > max) flush();
    current = current ? `${current} ${unit}` : unit; fresh = true;
    if (texts.length >= cap) throw new Error('Document exceeds the chunk limit');
  }
  flush();
  if (texts.length > cap) throw new Error('Document exceeds the chunk limit');
  return texts.map((text, ordinal) => ({ id: chunkId(docId, version, ordinal), ordinal, text }));
}
export const defaultChunker: Chunker = (docId, version, content) => chunkText(docId, version, content);
