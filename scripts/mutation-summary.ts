// Summarizes a StrykerJS JSON report: mutation score per file and in total, survivors listed. Survivors documented as
// equivalent in conformance/coverage/equivalent-mutants.json (by rule or by file, line, mutator and replacement) are
// reported separately; the raw score, which is what the break threshold uses, is never lowered by them.
// Usage: node scripts/mutation-summary.ts [report.json] [--markdown] [--survivors]   (default: reports/mutation/mutation.json)
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
type Mutant = { id: string; mutatorName: string; replacement?: string; status: string; location: { start: { line: number; column: number } } };
type Report = { files: Record<string, { source: string; mutants: Mutant[] }> };
type Equivalent = { file: string; line: number; mutator: string; replacement: string; reason: string };
type Rule = { id: string; mutators: string[]; linePattern: string; reason: string; files?: string[] };

const args = process.argv.slice(2);
const path = resolve(args.find(a => !a.startsWith('--')) ?? resolve(root, 'reports/mutation/mutation.json'));
const markdown = args.includes('--markdown'), survivors = args.includes('--survivors');
const report = JSON.parse(readFileSync(path, 'utf8')) as Report;
const config = JSON.parse(readFileSync(resolve(root, 'conformance/coverage/equivalent-mutants.json'), 'utf8')) as { rules?: Rule[]; mutants?: Equivalent[] };
const rules = (config.rules ?? []).map(r => ({ ...r, re: new RegExp(r.linePattern) }));
const listed = config.mutants ?? [];
const lineOf = (file: string, m: Mutant) => report.files[file]!.source.split('\n')[m.location.start.line - 1] ?? '';
const isEquivalent = (file: string, m: Mutant) => listed.some(e => e.file === file && e.line === m.location.start.line && e.mutator === m.mutatorName && e.replacement === (m.replacement ?? ''))
  || rules.some(r => r.mutators.includes(m.mutatorName) && (!r.files || r.files.includes(file)) && r.re.test(lineOf(file, m)));
const undetected = (m: Mutant) => m.status === 'Survived' || m.status === 'NoCoverage';

type Tally = { detected: number; undetected: number; equivalent: number };
const tally = (file: string, mutants: Mutant[]): Tally => {
  const t: Tally = { detected: 0, undetected: 0, equivalent: 0 };
  for (const m of mutants) {
    if (m.status === 'Killed' || m.status === 'Timeout') t.detected++;
    else if (undetected(m)) { t.undetected++; if (isEquivalent(file, m)) t.equivalent++; }
  }
  return t;
};
const pct = (a: number, b: number) => (b === 0 ? 100 : (100 * a) / b);
const rows = Object.entries(report.files).map(([file, f]) => ({ file, ...tally(file, f.mutants) }));
const sum = rows.reduce((a, r) => ({ detected: a.detected + r.detected, undetected: a.undetected + r.undetected, equivalent: a.equivalent + r.equivalent }), { detected: 0, undetected: 0, equivalent: 0 });
const all = [...rows, { file: 'total', ...sum }];
const hash = (file: string) => createHash('sha256').update(report.files[file]!.source).digest('hex').slice(0, 12);
const cells = (r: (typeof all)[number]) => [r.file, String(r.detected + r.undetected), String(r.detected), String(r.undetected), String(r.equivalent), pct(r.detected, r.detected + r.undetected).toFixed(2) + '%',
  pct(r.detected, r.detected + r.undetected - r.equivalent).toFixed(2) + '%'];
const head = ['file', 'valid mutants', 'killed or timed out', 'survived or uncovered', 'documented equivalent', 'mutation score', 'score excluding documented equivalents'];

if (markdown) {
  console.log('### Mutation score of the reference decision core\n');
  console.log(`| ${head.join(' | ')} |\n|${head.map(() => '---').join('|')}|`);
  for (const r of all) console.log(`| ${cells(r).join(' | ')} |`);
  console.log(`\nMutated sources (sha256 prefix): ${Object.keys(report.files).map(f => `${f} ${hash(f)}`).join(', ')}.`);
} else {
  const w = [28, 7, 7, 8, 6, 8, 8];
  console.log(['file', 'valid', 'killed', 'surv', 'equiv', 'score', 'excl.'].map((h, i) => h.padEnd(w[i]!)).join(' '));
  for (const r of all) console.log(cells(r).map((c, i) => (i ? c.padStart(w[i]!) : c.padEnd(w[i]!))).join(' '));
}
if (markdown || survivors) {
  console.log('\nSurvivors that are not documented as equivalent:\n');
  const cap = survivors ? Infinity : 150;
  let shown = 0, more = 0;
  for (const [file, f] of Object.entries(report.files)) for (const m of f.mutants) if (undetected(m) && !isEquivalent(file, m)) {
    if (shown++ >= cap) { more++; continue; }
    console.log(`- \`${file}:${m.location.start.line}\` ${m.mutatorName} -> \`${(m.replacement ?? '').replace(/\s+/g, ' ').slice(0, 80)}\` (${m.status})`);
  }
  if (more) console.log(`\n... and ${more} more; the JSON and HTML reports list every mutant.`);
}
