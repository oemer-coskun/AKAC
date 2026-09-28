/**
 * Embedding providers. An embedder sees document text and query text, so it sits
 * inside the trust boundary of the most sensitive compartment it is used for:
 * use a local model (or HashEmbedder) for restricted content unless the provider
 * is approved for it. Vectors are protected derivatives of their source.
 */
export interface Embedder {
  readonly model: string;
  readonly dimensions: number;
  embed(texts: string[], signal?: AbortSignal): Promise<Float32Array[]>;
}

const FNV_OFFSET = 0x811c9dc5, FNV_PRIME = 0x01000193;
function fnv1a(text: string): number {
  let h = FNV_OFFSET;
  for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, FNV_PRIME) >>> 0; }
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b) >>> 0; h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35) >>> 0; h ^= h >>> 16;
  return h >>> 0;
}
/** Lower-cased NFKC word tokens: letters and digits only. */
export const words = (text: string): string[] => text.normalize('NFKC').toLocaleLowerCase('en').split(/[^\p{L}\p{N}]+/u).filter(Boolean);

/**
 * Deterministic feature hashing of word unigrams and bigrams, L2-normalized.
 * Lexical, not semantic; for tests, air-gapped development and as a dependency-free
 * default. Feature counts are non-negative, so unrelated texts score exactly 0.
 */
export class HashEmbedder implements Embedder {
  readonly model: string;
  readonly dimensions: number;
  constructor(dimensions = 256) {
    if (!Number.isInteger(dimensions) || dimensions < 8 || dimensions > 4096) throw new Error('Invalid dimensions');
    this.dimensions = dimensions; this.model = `akac-hash-v1-${dimensions}`;
  }
  async embed(texts: string[], signal?: AbortSignal): Promise<Float32Array[]> {
    signal?.throwIfAborted();
    return texts.map(text => {
      const v = new Float32Array(this.dimensions), w = words(text);
      const add = (feature: string) => { v[fnv1a(feature) % this.dimensions]! += 1; };
      for (let i = 0; i < w.length; i++) { add(`1|${w[i]}`); if (i + 1 < w.length) add(`2|${w[i]} ${w[i + 1]}`); }
      let norm = 0; for (const x of v) norm += x * x;
      norm = Math.sqrt(norm);
      if (norm > 0) for (let i = 0; i < v.length; i++) v[i]! /= norm;
      return v;
    });
  }
}

const loopback = (host: string) => host === 'localhost' || host === '[::1]' || /^127(\.\d{1,3}){3}$/.test(host);
export type HttpEmbedderOptions = {
  baseUrl: string; model: string; dimensions: number; apiKey?: string;
  timeoutMs?: number; maxBatch?: number;
  /** Send `dimensions` in the request (OpenAI text-embedding-3 family). Off by default: many servers reject it. */
  requestDimensions?: boolean;
  fetch?: typeof fetch;
};
/**
 * OpenAI-compatible `POST {baseUrl}/v1/embeddings`. HTTPS is required unless the
 * host is loopback. The response shape and every vector are validated strictly;
 * errors never include request text or the response body.
 */
export class HttpEmbedder implements Embedder {
  readonly model: string;
  readonly dimensions: number;
  private endpoint: string;
  private key?: string;
  private timeout: number;
  private batch: number;
  private send: boolean;
  private fetcher: typeof fetch;
  constructor(o: HttpEmbedderOptions) {
    let url: URL;
    try { url = new URL(o.baseUrl); } catch { throw new Error('Invalid embedding base URL'); }
    if (url.username || url.password || url.search || url.hash) throw new Error('Invalid embedding base URL');
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback(url.hostname))) throw new Error('Embedding endpoint must use https unless loopback');
    if (typeof o.model !== 'string' || !o.model || o.model.length > 256) throw new Error('Invalid model');
    if (!Number.isInteger(o.dimensions) || o.dimensions < 1 || o.dimensions > 16_000) throw new Error('Invalid dimensions');
    if (o.apiKey !== undefined && (typeof o.apiKey !== 'string' || !o.apiKey || /[\r\n]/.test(o.apiKey))) throw new Error('Invalid API key');
    const timeout = o.timeoutMs ?? 10_000, batch = o.maxBatch ?? 64;
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 120_000 || !Number.isInteger(batch) || batch < 1 || batch > 2048) throw new Error('Invalid limits');
    this.endpoint = `${url.origin}${url.pathname.replace(/\/+$/, '')}/v1/embeddings`;
    this.model = o.model; this.dimensions = o.dimensions; this.key = o.apiKey; this.timeout = timeout; this.batch = batch;
    this.send = o.requestDimensions ?? false; this.fetcher = o.fetch ?? fetch;
  }
  async embed(texts: string[], signal?: AbortSignal): Promise<Float32Array[]> {
    if (!Array.isArray(texts) || texts.some(t => typeof t !== 'string' || !t)) throw new Error('Invalid embedding input');
    const out: Float32Array[] = [];
    for (let i = 0; i < texts.length; i += this.batch) out.push(...await this.request(texts.slice(i, i + this.batch), signal));
    return out;
  }
  private async request(input: string[], signal?: AbortSignal): Promise<Float32Array[]> {
    const timer = AbortSignal.timeout(this.timeout);
    const response = await this.fetcher(this.endpoint, {
      method: 'POST', redirect: 'error', signal: signal ? AbortSignal.any([signal, timer]) : timer,
      headers: { 'content-type': 'application/json', accept: 'application/json', ...(this.key ? { authorization: `Bearer ${this.key}` } : {}) },
      body: JSON.stringify({ model: this.model, input, encoding_format: 'float', ...(this.send ? { dimensions: this.dimensions } : {}) })
    });
    if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new Error(`Embedding service returned ${response.status}`); }
    const declared = Number(response.headers.get('content-length') ?? 0);
    if (declared > MAX_RESPONSE) { await response.body?.cancel().catch(() => {}); throw new Error('Embedding response too large'); }
    const text = await boundedText(response);
    let body: unknown;
    try { body = JSON.parse(text); } catch { throw new Error('Embedding response is not JSON'); }
    const data = (body as { data?: unknown })?.data;
    if (!Array.isArray(data) || data.length !== input.length) throw new Error('Embedding response shape');
    const vectors: (Float32Array | undefined)[] = new Array(input.length).fill(undefined);
    for (const item of data as { index?: unknown; embedding?: unknown }[]) {
      const index = item?.index, e = item?.embedding;
      if (!Number.isInteger(index) || (index as number) < 0 || (index as number) >= input.length || vectors[index as number]) throw new Error('Embedding response index');
      if (!Array.isArray(e) || e.length !== this.dimensions || e.some(x => typeof x !== 'number' || !Number.isFinite(x))) throw new Error('Embedding response dimensions');
      vectors[index as number] = Float32Array.from(e as number[]);
    }
    return vectors as Float32Array[];
  }
}
const MAX_RESPONSE = 64 * 1024 * 1024;
/** Reads the body incrementally and aborts (cancelling the stream) once it exceeds MAX_RESPONSE bytes. */
async function boundedText(response: Response, max = MAX_RESPONSE): Promise<string> {
  if (!response.body) return '';
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) { await reader.cancel().catch(() => {}); throw new Error('Embedding response too large'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return new TextDecoder().decode(Buffer.concat(chunks));
}
