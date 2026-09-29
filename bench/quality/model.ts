import { createHash } from 'node:crypto';
import { createReadStream, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Embedder } from '../../reference/embedding.ts';

/** Pinned model: id, Hugging Face commit, licence, dimension and the sha256 of every file used. */
export type ModelLock = { model: string; baseModel: string; revision: string; license: string; dimensions: number; pooling: 'mean'; normalize: boolean; dtype: 'fp32'; files: Record<string, string> };
export const HERE = dirname(fileURLToPath(import.meta.url));
export const lock = (): ModelLock => JSON.parse(readFileSync(join(HERE, 'model.lock'), 'utf8')) as ModelLock;
export const cacheDir = () => process.env.AKAC_QUALITY_CACHE ?? join(HERE, '.cache');
const modelDir = (l: ModelLock) => join(cacheDir(), 'models', ...l.model.split('/'));

const sha256 = (path: string) => new Promise<string>((resolve, reject) => {
  const h = createHash('sha256');
  createReadStream(path).on('data', d => h.update(d)).on('error', reject).on('end', () => resolve(h.digest('hex')));
});
/**
 * Downloads each locked file at the pinned revision (never `main`) into the cache
 * unless an identical file is already there, and verifies every sha256. A mismatch
 * deletes nothing and throws: the evaluation never runs on unverified weights.
 */
export async function fetchModel(options: { offline?: boolean; log?: (m: string) => void } = {}): Promise<string> {
  const l = lock(), dir = modelDir(l), log = options.log ?? (() => {});
  if (!/^[0-9a-f]{40}$/.test(l.revision)) throw new Error('model.lock revision must be a full commit hash');
  for (const [file, want] of Object.entries(l.files)) {
    const path = join(dir, ...file.split('/'));
    if (existsSync(path) && await sha256(path) === want) continue;
    if (options.offline) throw new Error(`${file} missing or modified in the model cache`);
    const url = `https://huggingface.co/${l.model}/resolve/${l.revision}/${file}`;
    log(`downloading ${file}`);
    const response = await fetch(url, { redirect: 'follow' });
    if (!response.ok || !response.body) throw new Error(`download ${file}: HTTP ${response.status}`);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(`${path}.part`, Buffer.from(await response.arrayBuffer()));
    const got = await sha256(`${path}.part`);
    if (got !== want) throw new Error(`${file}: sha256 ${got} does not match model.lock`);
    renameSync(`${path}.part`, path);
  }
  return dir;
}

/**
 * Embedder (reference/embedding.ts interface) backed by transformers.js running the
 * pinned ONNX model on onnxruntime-node (CPU). Remote model loading is disabled: the
 * files must be the verified ones in the cache. Mean pooling, L2 normalization.
 */
export async function transformersEmbedder(options: { batch?: number } = {}): Promise<Embedder> {
  const l = lock();
  await fetchModel({ offline: true });
  // A variable specifier: the root type check never needs this optional dependency installed.
  const specifier = '@huggingface/transformers';
  const tf = await import(specifier) as { env: Record<string, unknown>; pipeline: (task: string, model: string, o: Record<string, unknown>) => Promise<(texts: string[], o: Record<string, unknown>) => Promise<{ dims: number[]; data: Float32Array }>> };
  tf.env.allowRemoteModels = false; tf.env.allowLocalModels = true;
  tf.env.localModelPath = join(cacheDir(), 'models') + '/';
  const extract = await tf.pipeline('feature-extraction', l.model, { dtype: l.dtype });
  const batch = options.batch ?? 32;
  return {
    model: `${l.model}@${l.revision.slice(0, 12)}`, dimensions: l.dimensions,
    async embed(texts: string[], signal?: AbortSignal): Promise<Float32Array[]> {
      const out: Float32Array[] = [];
      for (let i = 0; i < texts.length; i += batch) {
        signal?.throwIfAborted();
        const t = await extract(texts.slice(i, i + batch), { pooling: l.pooling, normalize: l.normalize });
        const [n, d] = t.dims;
        if (d !== l.dimensions || n !== Math.min(batch, texts.length - i)) throw new Error('Embedding shape');
        for (let j = 0; j < n!; j++) out.push(Float32Array.from(t.data.subarray(j * d, (j + 1) * d)));
      }
      return out;
    }
  };
}
