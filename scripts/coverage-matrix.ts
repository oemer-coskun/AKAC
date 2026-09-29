// Rule coverage matrix check: every normative requirement of the published specifications (R01-R196) and of any
// draft not yet merged (spec/drafts/0.6-*.md, R-<TOPIC>-n) maps to conformance vectors and/or tests, or to an operator obligation with a written
// test procedure. Fails (exit 1) on any gap, stale entry, unknown vector id, unknown test name or missing procedure.
// Usage: node scripts/coverage-matrix.ts [--matrix=<file>] [--verbose] [--json]
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export type Level = 'MUST' | 'SHOULD' | 'MAY' | 'none';
export type Requirement = { id: string; file: string; line: number; level: Level; title: string };
export type TestRef = { file: string; name: string };
export type Entry = { vectors?: string[]; tests?: TestRef[]; artifacts?: string[]; operator?: { procedure: string; reason: string }; note?: string };
export type Matrix = { format: string; requirements: Record<string, Entry> };

const rel = (p: string) => relative(root, p).split(sep).join('/');
function walk(dir: string, keep: (name: string) => boolean): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p, keep));
    else if (keep(name)) out.push(p);
  }
  return out.sort();
}

const STRONG = /\b(MUST NOT|MUST|SHALL NOT|SHALL|REQUIRED)\b/;
const LEVELS: [RegExp, Level][] = [[STRONG, 'MUST'], [/\b(SHOULD NOT|SHOULD|RECOMMENDED|NOT RECOMMENDED)\b/, 'SHOULD'], [/\b(MAY|OPTIONAL)\b/, 'MAY']];

/** Requirements of the published specs (spec/AKAC-x.y.md) and of the 0.6 drafts not yet merged (a merged draft starts
 *  with "Merged into spec/AKAC-..."; its identifiers resolve through the mapping table of that spec); keywords are read
 *  outside code spans. */
let requirementsCache: Requirement[] | undefined;
export function requirements(): Requirement[] {
  if (requirementsCache) return requirementsCache;
  const files = [
    ...walk(join(root, 'spec'), n => /^AKAC-\d+\.\d+\.md$/.test(n)),
    ...walk(join(root, 'spec', 'drafts'), n => /^0\.6-.*\.md$/.test(n)).filter(f => !/^Merged into spec\//.test(readFileSync(f, 'utf8')))
  ];
  const out: Requirement[] = [];
  for (const f of files) {
    let fence = false;
    let cur: { id: string; line: number; text: string } | null = null;
    const close = () => {
      if (!cur) return;
      const level = LEVELS.find(([re]) => re.test(cur!.text))?.[1] ?? 'none';
      const title = cur.text.replace(/\*\*/g, '').replace(/^\s*R[\w-]+\s*[—:-]\s*/, '').replace(/\s+/g, ' ').trim();
      out.push({ id: cur.id, file: rel(f), line: cur.line, level, title: (/^(.*?[.:;])(\s|$)/.exec(title)?.[1] ?? title).slice(0, 90) });
      cur = null;
    };
    readFileSync(f, 'utf8').split(/\r?\n/).forEach((raw, i) => {
      if (/^\s*(```|~~~)/.test(raw)) { fence = !fence; return; }
      if (fence) return;
      const masked = raw.replace(/`[^`]*`/g, m => ' '.repeat(m.length));
      const table = /^\|\s*(R\d{2,3})\s*\|(.*)$/.exec(masked);
      const para = /^\*\*(R(?:\d{2,3}|-[A-Z]+-\d+))\b(.*)$/.exec(masked);
      const m = table ?? para;
      if (m) {
        close();
        cur = { id: m[1]!, line: i + 1, text: m[2]! };
        if (table) close();
        return;
      }
      if (cur && (masked.trim() === '' || /^#/.test(masked))) { close(); return; }
      if (cur) cur.text += ' ' + masked;
    });
    close();
  }
  return (requirementsCache = out);
}

/** Ids of every conformance vector (conformance/vectors*.json). */
export function vectorIds(duplicates: string[] = []): Map<string, string> {
  const ids = new Map<string, string>();
  for (const f of walk(join(root, 'conformance'), n => /^vectors.*\.json$/.test(n))) {
    const data = JSON.parse(readFileSync(f, 'utf8')) as { cases?: { id?: unknown }[] };
    for (const c of data.cases ?? []) if (typeof c.id === 'string') { if (ids.has(c.id)) duplicates.push(c.id); ids.set(c.id, rel(f)); }
  }
  return ids;
}

/** Literal test titles of a node:test file: test(), it() and describe() with a plain string first argument. */
export function testTitles(file: string): Set<string> {
  const src = readFileSync(join(root, file), 'utf8');
  const re = new RegExp('^\\s*(?:test|it|describe)(?:\\.\\w+)?\\(\\s*([\'"`])((?:\\\\.|(?!\\1)[^\\\\])*)\\1', 'gm');
  const titles = new Set<string>();
  for (const m of src.matchAll(re)) if (!m[2]!.includes('${')) titles.add(m[2]!.replace(/\\(['"`\\])/g, '$1'));
  return titles;
}

const stripTags = (t: string): string => { let p: string; do { p = t; t = t.replace(/<[^>]*>/g, ''); } while (t !== p); return t; };
const slug = (h: string) => stripTags(h.trim().toLowerCase())
  .replace(/[`*_~]/g, '').replace(/[^\p{L}\p{N}\s-]/gu, '').replace(/\s/g, '-');
/** A heading whose slug is the anchor, or an explicit `<a id="anchor"></a>` marker outside code fences. */
function hasAnchor(file: string, anchor: string): boolean {
  let fence = false;
  for (const l of readFileSync(join(root, file), 'utf8').split(/\r?\n/)) {
    if (/^\s*(```|~~~)/.test(l)) { fence = !fence; continue; }
    if (!fence && l.includes(`<a id="${anchor}"></a>`)) return true;
    const m = !fence && /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(l);
    if (m && slug(m[1]!) === anchor) return true;
  }
  return false;
}

export type Row = { id: string; file: string; level: Level; title: string; vectors: number; tests: number; artifacts: number; operator: boolean; status: 'vector' | 'test' | 'artifact' | 'operator' | 'gap' };
export type Report = { rows: Row[]; errors: string[]; vectorsUnmapped: string[] };

export function check(matrixPath = join(root, 'conformance', 'coverage', 'matrix.json')): Report {
  const errors: string[] = [];
  const matrix = JSON.parse(readFileSync(matrixPath, 'utf8')) as Matrix;
  const reqs = requirements();
  const known = new Set(reqs.map(r => r.id));
  const vectors = vectorIds();
  const titleCache = new Map<string, Set<string> | null>();
  const titlesOf = (file: string) => {
    if (!titleCache.has(file)) titleCache.set(file, existsSync(join(root, file)) && /^(tests|bonus)\/.*\.test\.ts$/.test(file) ? testTitles(file) : null);
    return titleCache.get(file)!;
  };
  const used = new Set<string>();
  const rows: Row[] = [];
  for (const id of Object.keys(matrix.requirements)) if (!known.has(id)) errors.push(`${id}: matrix entry for a requirement that no specification defines (stale)`);
  for (const r of reqs) {
    const e = matrix.requirements[r.id];
    if (!e) { errors.push(`${r.id}: no matrix entry (${r.file}:${r.line})`); rows.push({ id: r.id, file: r.file, level: r.level, title: r.title, vectors: 0, tests: 0, artifacts: 0, operator: false, status: 'gap' }); continue; }
    const v = e.vectors ?? [], t = e.tests ?? [], a = e.artifacts ?? [];
    for (const file of a) if (!existsSync(join(root, file)) || !statSync(join(root, file)).isFile()) errors.push(`${r.id}: artifact ${file} does not exist`);
    for (const id of v) {
      const hits = id.includes('*') ? [...vectors.keys()].filter(k => new RegExp('^' + id.split('*').map(s => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$').test(k)) : vectors.has(id) ? [id] : [];
      if (!hits.length) errors.push(`${r.id}: vector ${id} does not exist`);
      for (const h of hits) used.add(h);
    }
    for (const ref of t) {
      const titles = titlesOf(ref.file);
      if (!titles) errors.push(`${r.id}: test file ${ref.file} does not exist or is not tests/**/*.test.ts`);
      else if (!titles.has(ref.name)) errors.push(`${r.id}: no test named "${ref.name}" in ${ref.file}`);
    }
    if (e.operator) {
      const [file, anchor] = e.operator.procedure.split('#') as [string, string | undefined];
      if (!e.operator.reason?.trim()) errors.push(`${r.id}: operator entry without a reason`);
      if (!file || !anchor || !existsSync(join(root, file)) || !hasAnchor(file, anchor)) errors.push(`${r.id}: operator procedure ${e.operator.procedure} does not resolve to a heading`);
    }
    const status: Row['status'] = v.length ? 'vector' : t.length ? 'test' : a.length ? 'artifact' : e.operator ? 'operator' : 'gap';
    if (status === 'gap') errors.push(`${r.id}: ${r.level} requirement without a vector, a test, an artifact or an operator procedure (${r.file}:${r.line})`);
    rows.push({ id: r.id, file: r.file, level: r.level, title: r.title, vectors: v.length, tests: t.length, artifacts: a.length, operator: !!e.operator, status });
  }
  return { rows, errors, vectorsUnmapped: [...vectors.keys()].filter(k => !used.has(k)) };
}

function summary(rows: Row[]) {
  const groups = new Map<string, Row[]>();
  for (const r of rows) groups.set(r.file.replace(/^spec\//, ''), [...(groups.get(r.file.replace(/^spec\//, '')) ?? []), r]);
  const line = (name: string, rs: Row[]) => {
    const n = (f: (r: Row) => boolean) => String(rs.filter(f).length).padStart(5);
    return `${name.padEnd(32)}${String(rs.length).padStart(6)}${n(r => r.level === 'MUST')}${n(r => r.vectors > 0)}${n(r => r.tests > 0)}${n(r => r.artifacts > 0)}${n(r => r.operator)}${n(r => r.status === 'gap')}`;
  };
  const out = [`${'specification'.padEnd(32)}${'reqs'.padStart(6)}${'MUST'.padStart(5)}${'vec'.padStart(5)}${'test'.padStart(5)}${'art'.padStart(5)}${'oper'.padStart(5)}${'gap'.padStart(5)}`];
  for (const [name, rs] of groups) out.push(line(name, rs));
  out.push(line('total', rows));
  return out;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const arg = process.argv.find(a => a.startsWith('--matrix='));
  const report = check(arg ? resolve(arg.slice('--matrix='.length)) : undefined);
  if (process.argv.includes('--json')) console.log(JSON.stringify({ rows: report.rows, errors: report.errors, vectorsWithoutRequirement: report.vectorsUnmapped }, null, 2));
  else {
    if (process.argv.includes('--verbose')) for (const r of report.rows) console.log(`${r.id.padEnd(10)}${r.level.padEnd(7)}${String(r.vectors).padStart(3)} vec ${String(r.tests).padStart(3)} test ${String(r.artifacts).padStart(2)} art ${r.operator ? 'operator' : '        '} ${r.status === 'gap' ? 'GAP ' : ''}${r.title}`);
    console.log(summary(report.rows).join('\n'));
    const must = report.rows.filter(r => r.level === 'MUST');
    console.log(`\nMUST-level requirements: ${must.length}; with a vector ${must.filter(r => r.vectors > 0).length}, with a test ${must.filter(r => r.tests > 0).length}, `
      + `with an artifact ${must.filter(r => r.artifacts > 0).length}, with an operator procedure ${must.filter(r => r.operator).length}, evidence only from an operator procedure ${must.filter(r => r.status === 'operator').length}, uncovered ${must.filter(r => r.status === 'gap').length}`);
    if (report.vectorsUnmapped.length) console.log(`vectors not mapped to any requirement (informational): ${report.vectorsUnmapped.length}${process.argv.includes('--verbose') ? ` (${report.vectorsUnmapped.join(', ')})` : ''}`);
    for (const e of report.errors) console.error(`ERROR ${e}`);
  }
  if (report.errors.length) { console.error(`\ncoverage matrix: ${report.errors.length} problem(s)`); process.exit(1); }
  if (!process.argv.includes('--json')) console.log('coverage matrix: ok');
}
