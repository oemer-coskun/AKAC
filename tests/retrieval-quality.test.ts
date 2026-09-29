import test from 'node:test';
import assert from 'node:assert/strict';
import { HashEmbedder } from '../reference/embedding.ts';
import { buildCorpus, TOPICS } from '../bench/quality/corpus.ts';
import { cappedRecall, evaluateQuality, exactTopK, overlapRecall } from '../bench/quality/quality.ts';

// Fast check of the retrieval-quality harness (bench/quality) with the hash embedder only;
// the real-model run is bench/quality/ci.sh (no model download in tests).
test('quality metrics: exact top-k, overlap recall and capped relevance recall', () => {
  const v = (...x: number[]) => Float32Array.from(x);
  const chunks = new Map([['a', { vectors: [v(1, 0)] }], ['b', { vectors: [v(0.6, 0.8), v(0, 1)] }], ['c', { vectors: [v(-1, 0)] }]]);
  assert.deepEqual(exactTopK(v(1, 0), ['a', 'b', 'c'], chunks, 5), ['a', 'b'], 'best chunk per document, score floor 0 drops c');
  assert.deepEqual(exactTopK(v(0, 1), ['b', 'c'], chunks, 1), ['b'], 'only the given (authorized) documents are ranked');
  assert.equal(overlapRecall(['a', 'x'], ['a', 'b'], 2), 0.5);
  assert.equal(overlapRecall([], [], 5), undefined);
  assert.equal(cappedRecall(['a', 'b', 'x'], new Set(['a', 'b', 'c', 'd']), 2), 1, 'capped at min(k, |relevant|)');
  assert.equal(cappedRecall(['x'], new Set(), 5), undefined);
});

test('quality corpus is deterministic and carries the documented permission mix', () => {
  const a = buildCorpus({ documents: 300 }), b = buildCorpus({ documents: 300 });
  assert.deepEqual(a.state, b.state);
  assert.equal(a.docs.length, 300);
  const acme = Object.values(a.state.knowledge).filter(k => k.tenant === 'acme');
  const share = (l: string) => acme.filter(k => k.classification === l).length / acme.length;
  assert.ok(share('restricted') > 0.05 && share('public') > 0.1 && share('internal') > 0.25, 'classification mix');
  assert.ok(acme.some(k => k.sources.length) && acme.some(k => k.projects.length) && acme.some(k => k.readers.length), 'derived, project-scoped and named-reader documents');
  assert.ok(Object.values(a.state.knowledge).some(k => k.tenant === 'globex'));
  assert.equal(a.queries.length, TOPICS.length * 4);
});

test('permission-aware retrieval matches the exact authorized baseline and discloses nothing unauthorized (hash embedder)', async () => {
  const corpus = buildCorpus({ documents: 90, queriesPerTopic: 1 });
  const r = await evaluateQuality(corpus, new HashEmbedder(256));
  assert.equal(r.overall.disclosures, 0);
  assert.equal(r.overall.crossTenant, 0);
  assert.ok(r.byKind.all.recallVsExact['@10']! >= 0.95, `recall@10 vs exact ${r.byKind.all.recallVsExact['@10']}`);
  assert.ok(r.byKind.keyword.relevanceAkac['@5']! > r.byKind.paraphrase.relevanceAkac['@5']!, 'the lexical embedder needs shared vocabulary');
  // Only the principal whose agent holds fewer roles than its user produces pre-filter false positives.
  for (const p of r.principals) if (p.principal !== 'counsel-narrow-agent') assert.ok(p.filterMismatches <= p.candidates * 0.01, p.principal);
});
