import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { inspectPublication, checkPublication } from '../scripts/check-publication.ts';

const bytes = (text: string) => Buffer.from(text);
test('publication gate allows Community contracts and limits with synthetic data', () => {
  for (const path of ['reference/decision.ts', 'docs/THREAT-MODEL.md', '.env.example', 'spec/AKAC-0.6.md', 'formal/AKAC.tla']) {
    assert.deepEqual(inspectPublication(path, bytes('Public hook contract; HSM custody is an operator obligation.')), []);
  }
});
test('publication gate rejects private roots, credentials and archives regardless of textual content', () => {
  for (const path of ['private/design.md', 'docs/commercial/terms.md', 'customer-data/example.json', '.env', 'docs/dump.zip', 'reference/signing.pem']) {
    assert.ok(inspectPublication(path, bytes('innocuous')).length, path);
  }
});
test('publication gate catches private repository references in public prose and generated source', () => {
  const identifier = ['akac', 'enterprise'].join('-');
  for (const path of ['README.md', 'examples/generated.ts', 'docs/REVIEW.md']) {
    assert.ok(inspectPublication(path, bytes(`See ${identifier}`)).includes('private metadata or key material'));
  }
});
test('publication gate catches private revision anchors without storing actual anchors', () => {
  const revision = 'a'.repeat(40);
  assert.ok(inspectPublication('docs/REVIEW.md', bytes(`Private repository revision: ${revision}`)).length);
  assert.deepEqual(inspectPublication('docs/VERIFICATION.md', bytes(`Public code revision: ${revision}`)), []);
});
test('publication gate allows only reviewed branding images and rejects new screenshots or invalid UTF-8', () => {
  assert.deepEqual(inspectPublication('docs/assets/akac-hero.png', new Uint8Array([0, 255])), []);
  assert.ok(inspectPublication('docs/assets/review.png', new Uint8Array([0, 255])).length);
  assert.ok(inspectPublication('docs/review.md', new Uint8Array([255])).length);
});
test('publication gate rejects traversal and unreviewed roots or file types', () => {
  for (const path of ['../private.md', '/tmp/file.md', 'docs/../private.md', 'docs\\review.md', 'deliveries/code.ts', 'docs/review.exe']) {
    assert.ok(inspectPublication(path, bytes('text')).length, path);
  }
});

test('staged scan detects private index content concealed by a clean working-tree edit', () => {
  const dir = mkdtempSync(join(tmpdir(), 'akac-publication-'));
  const log = console.log, error = console.error;
  const output: string[] = [];
  console.log = console.error = (...args: unknown[]) => { output.push(args.join(' ')); };
  try {
    execFileSync('git', ['init', '-q', dir]);
    const identifier = ['akac', 'enterprise'].join('-');
    writeFileSync(join(dir, 'README.md'), `Private component ${identifier}`);
    execFileSync('git', ['add', 'README.md'], { cwd: dir });
    writeFileSync(join(dir, 'README.md'), 'Community contract');
    assert.equal(checkPublication(false, dir), 0);
    assert.equal(checkPublication(true, dir), 1);
    assert.ok(!output.join('\n').includes(identifier), 'report must not repeat removed content');
  } finally { console.log = log; console.error = error; rmSync(dir, { recursive: true, force: true }); }
});

test('publication gate rejects symlinks before reading their external content', () => {
  const dir = mkdtempSync(join(tmpdir(), 'akac-publication-'));
  const log = console.log, error = console.error;
  console.log = console.error = () => {};
  try {
    execFileSync('git', ['init', '-q', dir]);
    symlinkSync('/nonexistent-publication-target', join(dir, 'README.md'));
    execFileSync('git', ['add', 'README.md'], { cwd: dir });
    assert.equal(checkPublication(true, dir), 1);
  } finally { console.log = log; console.error = error; rmSync(dir, { recursive: true, force: true }); }
});
