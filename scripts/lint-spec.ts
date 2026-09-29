// Specification lint: RFC 2119/8174 keyword use, requirement ID uniqueness/continuity, relative links.
// Usage: node scripts/lint-spec.ts [--warnings-as-errors]. Exit 1 on any error.
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname, resolve, relative, sep, posix } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const strict = process.argv.includes('--warnings-as-errors');
type Finding = { level: 'error' | 'warn'; file: string; line: number; msg: string };
const findings: Finding[] = [];
const add = (level: Finding['level'], file: string, line: number, msg: string) => findings.push({ level, file, line, msg });

function walk(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (name.endsWith('.md')) out.push(p);
  }
  return out;
}
const rel = (p: string) => relative(root, p).split(sep).join('/');

// Lines with fenced code blocks and inline code masked out (line count preserved).
function prose(text: string): string[] {
  let fence = false;
  return text.split(/\r?\n/).map((l) => {
    if (/^\s*(```|~~~)/.test(l)) { fence = !fence; return ''; }
    return fence ? '' : l.replace(/`[^`]*`/g, (m) => ' '.repeat(m.length));
  });
}

const UPPER = /\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED|RECOMMENDED|NOT RECOMMENDED|MAY|OPTIONAL)\b/;
const LOWER_MODAL = /\b(must not|must|shall not|shall|should not|should)\b/;
const MIXED_CASE = /\b(Must|Must not|Shall|Should|Should not)\b/;

const specDir = join(root, 'spec');
const published = walk(specDir).filter((f) => /AKAC-\d+\.\d+\.md$/.test(f));
const all = [...walk(specDir), ...walk(join(root, 'docs'))];

// ---- 1. Requirement definitions -------------------------------------------------------------
const defs = new Map<number, { file: string; line: number }[]>();
const define = (n: number, file: string, line: number) => {
  const a = defs.get(n) ?? [];
  a.push({ file, line });
  defs.set(n, a);
};
for (const f of published) {
  const lines = prose(readFileSync(f, 'utf8'));
  const name = rel(f);
  let cur: { n: number; line: number; kw: boolean } | null = null;
  const close = () => { if (cur && !cur.kw) add('warn', name, cur.line, `requirement R${String(cur.n).padStart(2, '0')} has no RFC 2119 keyword`); cur = null; };
  lines.forEach((l, i) => {
    const table = /^\|\s*R(\d{2,3})\s*\|/.exec(l);
    const para = /^\*\*R(\d{2,3})/.exec(l);
    const m = table ?? para;
    if (m) {
      close();
      define(Number(m[1]), name, i + 1);
      cur = { n: Number(m[1]), line: i + 1, kw: false };
      if (table) { check(l.replace(/^\|\s*R\d+\s*\|/, ''), i + 1); close(); return; }
    } else if (cur && (l.trim() === '' || /^#/.test(l))) { close(); return; }
    if (cur) check(l, i + 1);
  });
  close();
  function check(body: string, line: number) {
    if (UPPER.test(body)) cur!.kw = true;
    const lm = LOWER_MODAL.exec(body);
    if (lm) add('error', name, line, `lowercase "${lm[1]}" in requirement line (use RFC 2119 uppercase keyword or rephrase)`);
    const mc = MIXED_CASE.exec(body);
    if (mc) add('error', name, line, `mixed-case "${mc[1]}" in requirement line`);
  }
}
const ids = [...defs.keys()].sort((a, b) => a - b);
for (const [n, where] of defs) {
  if (where.length > 1) for (const w of where) add('error', w.file, w.line, `requirement R${String(n).padStart(2, '0')} defined ${where.length} times (${where.map((x) => `${x.file}:${x.line}`).join(', ')})`);
}
if (ids.length) {
  const max = ids[ids.length - 1]!;
  for (let n = 1; n <= max; n++) if (!defs.has(n)) add('error', 'spec/', 0, `requirement R${String(n).padStart(2, '0')} is not defined (gap in R01-R${max})`);
}

// ---- 2. Keyword use outside requirement lines (all spec files, including drafts) -------------
for (const f of walk(specDir)) {
  const name = rel(f);
  if (name === 'spec/ERRATA.md' || name === 'spec/CHANGE-CONTROL.md') continue;
  const text = readFileSync(f, 'utf8');
  const lines = prose(text);
  const hasBoilerplate = /RFC\s*2119/.test(text) && /8174/.test(text);
  let usesKeywords = false;
  lines.forEach((l, i) => {
    if (/^#{1,6}\s/.test(l) && UPPER.test(l.replace(/\b(MAY|OPTIONAL|REQUIRED)\b/g, ''))) add('warn', name, i + 1, 'normative keyword in a heading');
    if (UPPER.test(l)) usesKeywords = true;
  });
  if (usesKeywords && !hasBoilerplate && !/^spec\/drafts\//.test(name)) add('warn', name, 0, 'uses uppercase keywords without the RFC 2119 and RFC 8174 statement');
}

// ---- 3. Relative links (spec/ and docs/) ----------------------------------------------------
const stripTags = (t: string): string => { let p: string; do { p = t; t = t.replace(/<[^>]*>/g, ''); } while (t !== p); return t; };
const slug = (h: string) => stripTags(h.trim().toLowerCase())
  .replace(/[`*_~]/g, '').replace(/[^\p{L}\p{N}\s-]/gu, '').replace(/\s/g, '-');
const anchors = new Map<string, Set<string>>();
function anchorsOf(file: string): Set<string> {
  let s = anchors.get(file);
  if (s) return s;
  s = new Set();
  const seen = new Map<string, number>();
  for (const l of prose(readFileSync(file, 'utf8'))) {
    const m = /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(l);
    if (!m) continue;
    const base = slug(m[1]!);
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    s.add(n ? `${base}-${n}` : base);
  }
  anchors.set(file, s);
  return s;
}
for (const f of all) {
  const name = rel(f);
  const lines = prose(readFileSync(f, 'utf8'));
  const re = /\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
  lines.forEach((l, i) => {
    for (const m of l.matchAll(re)) {
      const target = m[1]!;
      if (/^([a-z][a-z0-9+.-]*:|#|\/\/)/i.test(target) && !target.startsWith('#')) continue; // absolute URL / mailto
      const [pathPart, frag] = target.split('#') as [string, string | undefined];
      const dest = pathPart === '' ? f : resolve(dirname(f), decodeURIComponent(pathPart));
      const inRepo = !relative(root, dest).startsWith('..');
      if (!inRepo) { add('error', name, i + 1, `link leaves the repository: ${target}`); continue; }
      if (!existsSync(dest)) { add('error', name, i + 1, `broken relative link: ${target}`); continue; }
      if (frag && statSync(dest).isFile() && dest.endsWith('.md') && !anchorsOf(dest).has(decodeURIComponent(frag).toLowerCase())) {
        add('warn', name, i + 1, `anchor not found: ${posix.normalize(target)}`);
      }
    }
  });
}

// ---- report ---------------------------------------------------------------------------------
findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
for (const f of findings) console.log(`${f.level.toUpperCase().padEnd(5)} ${f.file}${f.line ? `:${f.line}` : ''}  ${f.msg}`);
const errors = findings.filter((f) => f.level === 'error').length;
const warns = findings.length - errors;
console.log(`lint-spec: ${published.length} published spec files, ${ids.length} requirements (R${ids[0] ?? '-'}..R${ids[ids.length - 1] ?? '-'}), ${all.length} markdown files scanned, ${errors} error(s), ${warns} warning(s)`);
process.exit(errors > 0 || (strict && warns > 0) ? 1 : 0);
