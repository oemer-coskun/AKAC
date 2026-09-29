import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import type { Results } from './run.ts';

const cell = (v: unknown) => String(v ?? '').replace(/[\\|]/g, '\\$&').replace(/\r?\n/g, ' ');
const table = (head: string[], rows: unknown[][]) => [`| ${head.join(' | ')} |`, `|${head.map(() => ' --- ').join('|')}|`, ...rows.map(r => `| ${r.map(cell).join(' | ')} |`)].join('\n');
const outcomes = (o: Record<string, number>) => Object.entries(o).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(', ');

/** Markdown report of one results file: machine, data set, latency tables, cost curves. */
export function toMarkdown(r: Results): string {
  const m = r.machine, out: string[] = [];
  out.push(`## AKAC benchmark: scale \`${r.scale.name}\``, '');
  out.push(`Run ${r.startedAt}, commit \`${m.gitSha.slice(0, 12)}\`, seed ${r.seed}.`, '');
  out.push(table(['Machine', ''], [['Runner', m.runner], ['OS', `${m.os} (${m.arch})`], ['CPU', `${m.cpu}, ${m.cores} logical cores`], ['Memory', `${m.memoryGiB} GiB`],
    ['Node.js', m.node], ['PostgreSQL', m.postgres ?? 'not used'], ['pgvector', m.pgvector ?? 'not used']]), '');
  out.push(table(['Data set', 'count'], Object.entries(r.dataset).map(([k, v]) => [k, v])), '');
  out.push(`Per tenant: ${r.scale.roles} roles in chains of depth ${r.scale.roleDepth}, ${r.scale.knowledgeBases} knowledge bases with folder chains of depth ${r.scale.containerDepth}, `
    + `${r.scale.usersPerTenant} users (one agent and one grant each), derivation chains of depth ${r.scale.dagDepth}. Tenant \`tlex\` holds ${r.scale.lexicalDocs} documents (the lexical corpus bound is 1000) for the lexical workload.`, '');
  for (const b of r.backends) {
    out.push(`### ${b.name} (setup ${b.setupSeconds} s)`, '');
    out.push(table(['Workload', 'Callers', 'Calls', 'p50 ms', 'p95 ms', 'p99 ms', 'max ms', 'Calls/s', 'Filter mismatches', 'Outcomes'],
      b.rows.map(x => [x.workload, x.concurrency, x.n, x.p50, x.p95, x.p99, x.max, x.throughput, x.filterMismatches, outcomes(x.outcomes)])), '');
  }
  if (r.curves.length) {
    out.push('### Cost of the documented bounds (pure decide(), in-memory snapshot)', '');
    for (const c of r.curves) {
      out.push(`**${c.name}** (${c.boundName} = ${c.bound}; parameter: ${c.parameter})`, '');
      out.push(table(['Parameter', 'p50 us', 'p99 us', 'Effect', 'Code'], c.points.map(p => [p.parameter === c.bound + 1 ? `${p.parameter} (bound + 1)` : p.parameter, p.p50us, p.p99us, p.effect, p.code])), '');
    }
  }
  out.push('Notes:', '', ...r.notes.map(n => `- ${n}`), '');
  return out.join('\n');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const [input, output] = process.argv.slice(2);
  if (!input) { console.error('Usage: node bench/render.ts RESULTS.json [OUTPUT.md]'); process.exit(2); }
  const md = toMarkdown(JSON.parse(readFileSync(input, 'utf8')) as Results);
  if (output) writeFileSync(output, md); else console.log(md);
}
