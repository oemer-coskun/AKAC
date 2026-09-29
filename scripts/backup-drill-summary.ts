import { readFileSync } from 'node:fs';

// Renders the backup/restore drill evidence as a job-summary table.
type Evidence = {
  ok: boolean;
  tenants: { tenant: string; checkpoint: { treeSize: number }; rootEqualsCheckpoint: boolean }[];
  negativeControl: { verificationFailed: boolean };
  timingsMs: { lossToServing: number };
};
const e = JSON.parse(readFileSync(process.argv[2] ?? 'backup-drill-evidence.json', 'utf8')) as Evidence;
const lines = [
  `### Backup/restore drill: ${e.ok ? 'passed' : 'FAILED'}`,
  '',
  '| tenant | pre-backup treeSize | restored root equals checkpoint |',
  '|---|---|---|',
  ...e.tenants.map(t => `| ${t.tenant} | ${t.checkpoint.treeSize} | ${t.rootEqualsCheckpoint} |`),
  '',
  `Negative control (altered row detected): ${e.negativeControl.verificationFailed}. Loss to serving: ${e.timingsMs.lossToServing} ms (CI runner, synthetic data).`
];
console.log(lines.join('\n'));
