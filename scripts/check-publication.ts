// Public publication boundary. This is a pattern/path gate, not an IP classifier or secret scanner.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, lstatSync } from 'node:fs';
import { dirname, extname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const roots = new Set(['.github', '.well-known', 'adapters', 'bench', 'conformance', 'deploy', 'docs',
  'examples', 'formal', 'governance', 'implementations', 'legal', 'migrations', 'policies', 'reference', 'schemas', 'scripts', 'spec', 'tests']);
const rootFiles = new Set(['.dockerignore', '.env.example', '.gitattributes', '.gitignore', '.gitleaks.toml',
  '.pre-commit-config.yaml', 'CHANGELOG.md', 'CONTACT.md', 'CONTRIBUTING.md', 'Dockerfile', 'GOVERNANCE.md',
  'LICENSE', 'MAINTAINERS.md', 'README.md', 'SECURITY.md', 'compose.yaml', 'package.json', 'package-lock.json',
  'stryker.config.json', 'stryker.vectors.config.json', 'tsconfig.json']);
const textExtensions = new Set(['.md', '.ts', '.py', '.json', '.yaml', '.yml', '.sql', '.rego', '.sh',
  '.tla', '.cfg', '.toml', '.txt', '.lock', '.xml', '.example']);
const publicAssets = new Set(['docs/assets/akac-hero.png', 'docs/assets/akac-social-preview.jpg']);
const specialTextFiles = new Set(['.github/CODEOWNERS']);
const privatePath = /(?:^|\/)(?:private|internal-docs|commercial|customer-data|enterprise|industry-profiles|roadmap|node_modules|secrets|data|\.git)(?:\/|$)|(?:\.env(?!\.example$)|\.(?:pem|key|p12|pfx|zip|tar|gz|tgz|bundle|bak|pdf|docx|xlsx))$/i;

// General patterns avoid putting actual private identifiers or revision anchors in this file.
const privateMetadata = [
  /\bakac[-_](?:enterprise|industry[-_]profiles|mirror)\b/i,
  /(?:verified|reviewed)\s+(?:enterprise\s+module|industry\s+profiles|repository\s+mirror\s+backup)/i,
  /(?:private|internal|proprietary)\s+(?:repository|repo|module|component|mirror)[^\r\n]{0,100}\b[0-9a-f]{40}\b/i,
  /https?:\/\/[^\s/]+\/[^\s/]+\/(?:akac[-_])?(?:enterprise|industry[-_]profiles|mirror)(?:[\s/#?)"']|$)/i,
  /\b(?:BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY)\b[\s\S]{0,160}\r?\n[A-Za-z0-9+/]{32}/,
];

/** Reports categories and paths only, never the matching private text. */
export function inspectPublication(path: string, bytes: Uint8Array): string[] {
  const findings: string[] = [];
  const parts = path.split('/');
  if (path.startsWith('/') || parts.some(p => p === '..' || p === '.') || path.includes('\\')) {
    return ['invalid publication path'];
  }
  if (privatePath.test(path)) findings.push('private material or archive path');
  if (parts.length === 1 ? !rootFiles.has(path) : !roots.has(parts[0]!)) findings.push('unreviewed publication root');
  if (publicAssets.has(path)) return findings;
  if (path.startsWith('docs/assets/')) findings.push('asset requires explicit publication review');
  if (!rootFiles.has(path) && !specialTextFiles.has(path) && !textExtensions.has(extname(path)) && !['.gitignore', '.dockerignore', 'LICENSE'].includes(parts.at(-1)!)) {
    findings.push('unreviewed file type');
  }
  let text: string;
  try {
    if (bytes.includes(0)) throw new Error('binary');
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch { return [...findings, 'opaque file requires explicit publication review']; }
  if (privateMetadata.some(pattern => pattern.test(text))) findings.push('private metadata or key material');
  return findings;
}

export function checkPublication(staged = false, repositoryRoot = root): number {
  const root = repositoryRoot;
  const args = staged ? ['ls-files', '--cached', '-z'] : ['ls-files', '--cached', '--others', '--exclude-standard', '-z'];
  const paths = [...new Set(execFileSync('git', args, { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean))].sort();
  let count = 0, checked = 0;
  for (const path of paths) {
    let bytes: Buffer;
    if (staged) {
      const entry = execFileSync('git', ['ls-files', '--stage', '--', path], { cwd: root, encoding: 'utf8' });
      if (!entry.startsWith('100644 ') && !entry.startsWith('100755 ')) {
        console.error(`${path}: symlink, submodule or unmerged index entry is not allowed`); count++; continue;
      }
      bytes = execFileSync('git', ['show', `:${path}`], { cwd: root, maxBuffer: 16 * 1024 * 1024 });
    } else {
      const file = resolve(root, path);
      if (!existsSync(file)) {
        try { lstatSync(file); }
        catch { continue; } // tracked deletion being prepared
      }
      if (!lstatSync(file).isFile()) {
        console.error(`${path}: symlink or non-regular file is not allowed`); count++; continue;
      }
      bytes = readFileSync(file);
    }
    checked++;
    for (const finding of inspectPublication(path, bytes)) { console.error(`${path}: ${finding}`); count++; }
  }
  console.log(`publication-boundary: ${checked} files checked (${staged ? 'Git index' : 'working tree'}), ${count} finding(s)`);
  return count ? 1 : 0;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  process.exitCode = checkPublication(process.argv.includes('--staged'));
}
