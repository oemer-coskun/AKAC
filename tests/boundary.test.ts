import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const dirs = ['reference', 'adapters', 'scripts'];
function* sources(dir: string): Generator<string> {
  let names: string[];
  try { names = readdirSync(dir); } catch { return; }
  for (const name of names) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* sources(path);
    else if (/\.(ts|mts|cts|js|mjs|cjs)$/.test(name)) yield path;
  }
}
/** Module specifiers: static/type imports, re-exports, dynamic import() and require(). */
const specifiers = (code: string) => [...code.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)(['"`])([^'"`]+)\1/g)].map(m => m[2]!);

test('core never imports an enterprise edition (ADR-023): no enterprise module specifier, no enterprise dependency', () => {
  const offenders: string[] = [];
  for (const dir of [...dirs, 'conformance']) for (const file of sources(join(root, dir))) {
    for (const spec of specifiers(readFileSync(file, 'utf8'))) if (/enterprise/i.test(spec)) offenders.push(`${file}: ${spec}`);
  }
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as Record<string, Record<string, string> | undefined>;
  for (const kind of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const name of Object.keys(pkg[kind] ?? {})) if (/enterprise/i.test(name)) offenders.push(`package.json ${kind}: ${name}`);
  }
  assert.deepEqual(offenders, []);
});
