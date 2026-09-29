import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { check, requirements, testTitles, vectorIds } from '../scripts/coverage-matrix.ts';
import type { Matrix } from '../scripts/coverage-matrix.ts';

const matrixFile = new URL('../conformance/coverage/matrix.json', import.meta.url);
const load = () => JSON.parse(readFileSync(matrixFile, 'utf8')) as Matrix;
function withMatrix(change: (m: Matrix) => void): string[] {
  const dir = mkdtempSync(join(tmpdir(), 'akac-matrix-'));
  try {
    const m = load(); change(m);
    const file = join(dir, 'matrix.json'); writeFileSync(file, JSON.stringify(m));
    return check(file).errors;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('the specifications define R01 to R196 without gaps, and the matrix covers every requirement', () => {
  const ids = requirements().map(r => r.id);
  const numbered = ids.filter(id => /^R\d+$/.test(id)).sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
  assert.deepEqual(numbered, Array.from({ length: 196 }, (_, i) => `R${String(i + 1).padStart(2, '0')}`));
  assert.ok(!ids.some(id => id.startsWith('R-')), 'merged drafts are not read twice: their identifiers resolve through the mapping table');
  assert.deepEqual(check().errors, []);
});

test('the requirement level is read from the RFC 2119 keywords outside code spans', () => {
  const byId = new Map(requirements().map(r => [r.id, r.level]));
  assert.equal(byId.get('R01'), 'MUST');
  assert.equal(byId.get('R54'), 'none', 'a requirement that states no keyword is reported as such, and still needs evidence');
  assert.equal(byId.get('R129'), 'SHOULD');
  assert.ok([...byId.values()].filter(l => l === 'MUST').length >= 120);
});

test('negative controls: the gate fails on a missing entry, a stale entry, an unknown vector, an unknown test and an unresolved procedure', () => {
  assert.ok(withMatrix(m => { delete m.requirements.R07; }).some(e => e.startsWith('R07: no matrix entry')));
  assert.ok(withMatrix(m => { m.requirements.R99999 = { vectors: ['AKAC-001-positive-public'] }; }).some(e => e.includes('R99999') && e.includes('stale')));
  assert.ok(withMatrix(m => { m.requirements.R01!.vectors = ['NO-SUCH-VECTOR']; }).some(e => e.includes('vector NO-SUCH-VECTOR does not exist')));
  assert.ok(withMatrix(m => { m.requirements.R01!.tests = [{ file: 'tests/core.test.ts', name: 'a test that does not exist' }]; }).some(e => e.includes('no test named')));
  assert.ok(withMatrix(m => { m.requirements.R01!.tests = [{ file: 'tests/nothing.test.ts', name: 'x' }]; }).some(e => e.includes('does not exist')));
  assert.ok(withMatrix(m => { m.requirements.R91 = { operator: { procedure: 'docs/CONFORMANCE-COVERAGE.md#no-such-anchor', reason: 'x' } }; }).some(e => e.startsWith('R91') && e.includes('does not resolve')));
  assert.ok(withMatrix(m => { m.requirements['R132']!.artifacts = ['formal/none.tla']; }).some(e => e.includes('artifact formal/none.tla does not exist')));
  const gap = withMatrix(m => { m.requirements.R02 = {}; });
  assert.ok(gap.some(e => e.startsWith('R02') && e.includes('without a vector, a test, an artifact or an operator procedure')));
  assert.ok(withMatrix(m => { m.requirements.R91 = { operator: { procedure: 'docs/CONFORMANCE-COVERAGE.md#op-cache-partitioning', reason: '' } }; }).some(e => e.includes('without a reason')));
});

test('test titles are read from test(), it() and describe(); templated titles cannot be referenced', () => {
  const titles = testTitles('tests/kb.test.ts');
  assert.ok(titles.has('per-tenant epochs: revocation invalidates only the revoking tenant'));
  assert.ok(!testTitles('tests/regressions.test.ts').has('${kind} store: the same id may exist in two tenants'));
});

test('vector ids are unique across the vector files', () => {
  const duplicates: string[] = [];
  const ids = vectorIds(duplicates);
  assert.deepEqual(duplicates, []);
  assert.ok(ids.size >= 230);
});
