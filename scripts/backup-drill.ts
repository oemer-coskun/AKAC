import { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { PostgresStore } from '../adapters/postgres.ts';
import { ControlPlane } from '../reference/control.ts';
import { Engine } from '../reference/engine.ts';
import { importState } from '../reference/store.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';

// Backup and restore drill (0.6, ADR-016). Evidence that a logical PostgreSQL backup
// restores an audit history that still verifies against a checkpoint signed BEFORE
// the backup:
//   1. create a scratch database, migrate, seed synthetic data and produce audit
//      history in two tenants;
//   2. sign a format 2 checkpoint per tenant with a throwaway Ed25519 key
//      (scripts/checkpoint.ts sign) and anchor it in a directory outside the database;
//   3. pg_dump (custom format), DROP the database, CREATE it again, pg_restore;
//   4. scripts/checkpoint.ts verify on the restored database: full hash chain, RFC 9162
//      root recomputed from the entries, stored tree head, and the anchored pre-backup
//      checkpoint (signature through a keyring and prefix root); the restored tree size
//      and root must EQUAL the checkpoint (no writes happened after it);
//   5. the restored gateway store must pass ready() and decide again; a negative control
//      alters one restored audit row and requires the same verification to fail;
//   6. write the evidence JSON (timings, dump digest, per-tenant roots) and drop the database.
//
// Usage: node scripts/backup-drill.ts [--evidence FILE]
//   AKAC_DRILL_DATABASE_URL  server connection with CREATEDB (the scratch database is
//                            created next to the one in the URL; it is always dropped).
//   AKAC_PG_TOOL             command prefix for pg_dump/pg_restore, e.g. a pinned
//                            PostgreSQL image: "docker run --rm -i --network host IMAGE@DIGEST"
//                            or "docker exec -i CONTAINER". Default: the local binaries.
//   AKAC_PG_TOOL_HOST        host:port of the server as the tool sees it (default: the URL's).
// Synthetic data only; the key is generated at run time and deleted afterwards.
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const argv = process.argv.slice(2);
const evidenceFile = argv[0] === '--evidence' && argv[1] ? argv[1] : join(root, 'backup-drill-evidence.json');
const base = process.env.AKAC_DRILL_DATABASE_URL ?? process.env.AKAC_TEST_DATABASE_URL;
if (!base) { console.error('Set AKAC_DRILL_DATABASE_URL (server connection with CREATEDB)'); process.exit(2); }
const prefix = (process.env.AKAC_PG_TOOL ?? '').split(/\s+/).filter(Boolean);
const dbName = `akac_drill_${randomBytes(4).toString('hex')}`;
const urlFor = (db: string, forTool = false) => {
  const u = new URL(base!); u.pathname = `/${db}`;
  if (forTool && process.env.AKAC_PG_TOOL_HOST) u.host = process.env.AKAC_PG_TOOL_HOST;
  return u.toString();
};
const log = (msg: string, extra: Record<string, unknown> = {}) => console.log(JSON.stringify({ level: 'info', time: new Date().toISOString(), msg, ...extra }));
const ms = (start: number) => Math.round(performance.now() - start);

async function admin(sql: string) {
  const c = new pg.Client({ connectionString: base }); await c.connect();
  try { await c.query(sql); } finally { await c.end(); }
}
/** Runs a command; stdin/stdout optionally streamed from/to files. Rejects on a non-zero exit. */
function run(cmd: string[], opts: { env?: Record<string, string>; stdinFile?: string; stdoutFile?: string } = {}): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(cmd[0]!, cmd.slice(1), { cwd: root, env: { ...process.env, ...opts.env }, stdio: [opts.stdinFile ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    if (opts.stdoutFile) child.stdout!.pipe(createWriteStream(opts.stdoutFile)); else child.stdout!.on('data', d => { out += d; });
    child.stderr!.on('data', d => { err += d; });
    if (opts.stdinFile) createReadStream(opts.stdinFile).pipe(child.stdin!);
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolvePromise(out) : reject(new Error(`${cmd.slice(0, prefix.length + 1).join(' ')} exited ${code}: ${err.slice(-2000)}`)));
  });
}
const node = (script: string, args: string[], env: Record<string, string>) => run([process.execPath, join(root, 'scripts', script), ...args], { env });

const work = mkdtempSync(join(tmpdir(), 'akac-drill-'));
const tenants = ['acme', 'beta'];
const evidence: Record<string, unknown> = { format: 'akac-backup-drill/1', time: new Date().toISOString(), database: dbName, tool: prefix.length ? 'container' : 'local' };
let ok = false;
try {
  await admin(`CREATE DATABASE ${dbName}`);
  const url = urlFor(dbName);
  // 1. Schema, synthetic data and audit history in two tenants.
  const store = new PostgresStore(url, { migrate: true, requireRls: false });
  try {
    const state = kbFixture();
    for (const [id, tenant, role] of [['drill-sec', 'acme', 'security-admin'], ['drill-aud', 'acme', 'auditor'], ['beta-sec', 'beta', 'security-admin']] as const)
      state.actors[id] = { id, tenant, kind: 'user', roles: [role], projects: [], clearance: 'restricted', active: true };
    await importState(store, state);
    const engine = new Engine(store), control = new ControlPlane(store);
    for (let i = 0; i < 20; i++) {
      await engine.openContext(bindings.intern, ['handbook'], 'work');
      await engine.openContext(bindings.intern, ['strategy'], 'work'); // denied, audited
      await control.upsertActor('acme', 'drill-sec', { id: `drill-user-${i}`, tenant: 'acme', kind: 'user', roles: [], projects: [], clearance: 'public', active: true });
      await control.upsertActor('beta', 'beta-sec', { id: `beta-user-${i}`, tenant: 'beta', kind: 'user', roles: [], projects: [], clearance: 'public', active: true });
    }
  } finally { await store.close(); }
  const env = { DATABASE_URL: url, AKAC_AUTO_MIGRATE: 'false', AKAC_PG_ALLOW_BYPASS_RLS: 'true' };

  // 2. Pre-backup checkpoints, anchored outside the database, with a throwaway key.
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const keyFile = join(work, 'checkpoint-key.pem'), keyringFile = join(work, 'keyring.json'), anchors = join(work, 'anchors');
  writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), { mode: 0o600 });
  writeFileSync(keyringFile, JSON.stringify({ keys: [{ keyId: 'drill-key', publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), status: 'active' }] }));
  mkdirSync(anchors, { mode: 0o700 });
  const before: Record<string, { treeSize: number; rootHash: string }> = {};
  for (const tenant of tenants) {
    const out = join(work, `${tenant}.checkpoint.json`);
    await node('checkpoint.ts', ['sign', '--tenant', tenant, '--out', out, '--anchor-dir', anchors], { ...env, AKAC_CHECKPOINT_KEY_FILE: keyFile, AKAC_CHECKPOINT_KEY_ID: 'drill-key' });
    const cp = JSON.parse(readFileSync(out, 'utf8'));
    before[tenant] = { treeSize: cp.treeSize, rootHash: cp.rootHash };
  }
  log('pre-backup checkpoints signed', { tenants: before });

  // 3. Backup, total loss, restore.
  const dump = join(work, 'akac.dump');
  let t = performance.now();
  await run([...(prefix.length ? prefix : []), 'pg_dump', '--format=custom', '--no-owner', '--no-privileges', `--dbname=${urlFor(dbName, true)}`], { stdoutFile: dump });
  const dumpMs = ms(t), dumpBytes = statSync(dump).size, dumpSha256 = createHash('sha256').update(readFileSync(dump)).digest('hex');
  if (dumpBytes < 1024) throw new Error('dump is implausibly small');
  const lost = performance.now();
  await admin(`DROP DATABASE ${dbName} WITH (FORCE)`);
  await admin(`CREATE DATABASE ${dbName}`);
  t = performance.now();
  await run([...(prefix.length ? prefix : []), 'pg_restore', '--no-owner', '--no-privileges', '--exit-on-error', `--dbname=${urlFor(dbName, true)}`], { stdinFile: dump });
  const restoreMs = ms(t);

  // 4. Verify the restored history against the anchored pre-backup checkpoints.
  t = performance.now();
  const results: Record<string, unknown>[] = [];
  let allMatch = true;
  for (const tenant of tenants) {
    const file = join(work, `${tenant}.verification.json`);
    let verified = true;
    try { await node('checkpoint.ts', ['verify', '--tenant', tenant, '--anchor-dir', anchors, '--keyring', keyringFile, '--evidence', file], env); }
    catch { verified = false; }
    const v = JSON.parse(readFileSync(file, 'utf8')).results[0];
    const equal = v.treeSize === before[tenant]!.treeSize && v.rootHash === before[tenant]!.rootHash;
    allMatch &&= verified && v.ok && equal;
    results.push({ tenant, checkpoint: before[tenant], restored: { treeSize: v.treeSize, rootHash: v.rootHash, chain: v.chain, storedTree: v.storedTree },
      checkpoints: v.checkpoints, rootEqualsCheckpoint: equal, ok: verified && v.ok && equal });
  }
  const verifyMs = ms(t);
  // 5. The restored database serves again: migrations verified, audit tail sound, a decision allowed.
  const restored = new PostgresStore(url, { migrate: false, requireRls: false });
  let serving = false;
  try {
    serving = (await Promise.all(tenants.map(x => restored.ready(x)))).every(Boolean)
      && (await new Engine(restored).openContext(bindings.intern, ['handbook'], 'work')).ok;
  } finally { await restored.close(); }
  const rtoMs = ms(lost);
  // Negative control: the same verification must FAIL once one restored audit row is altered,
  // so a passing drill is not vacuous. (Runs after the timings; the database is dropped anyway.)
  let negativeControl = false;
  {
    const c = new pg.Client({ connectionString: url }); await c.connect();
    // The append-only trigger refuses this; an attacker with owner rights disables it first, as here.
    try {
      await c.query('ALTER TABLE akac_audit DISABLE TRIGGER USER');
      await c.query("UPDATE akac_audit SET reason = 'DENIED:NOT_AUTHORIZED' WHERE tenant = 'beta' AND sequence = 1");
    } finally { await c.end(); }
    try { await node('checkpoint.ts', ['verify', '--tenant', 'beta', '--anchor-dir', anchors, '--keyring', keyringFile], env); }
    catch { negativeControl = true; }
  }
  ok = allMatch && serving && negativeControl;
  Object.assign(evidence, { ok, tenants: results, serving, negativeControl: { alteredRow: 'beta#1', verificationFailed: negativeControl }, dump: { bytes: dumpBytes, sha256: dumpSha256, format: 'pg_dump custom' },
    timingsMs: { dump: dumpMs, restore: restoreMs, verify: verifyMs, lossToServing: rtoMs },
    postgres: (await (async () => { const c = new pg.Client({ connectionString: base }); await c.connect(); try { return (await c.query('SHOW server_version')).rows[0].server_version; } finally { await c.end(); } })()) });
  log(ok ? 'backup/restore drill passed' : 'backup/restore drill FAILED', { tenants: results.map(r => ({ tenant: r.tenant, ok: r.ok })), timingsMs: evidence.timingsMs });
} catch (error) {
  Object.assign(evidence, { ok: false, error: error instanceof Error ? error.message.slice(0, 2000) : 'unknown' });
  console.error(JSON.stringify({ level: 'error', msg: 'backup/restore drill FAILED', error: evidence.error }));
} finally {
  await admin(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
  rmSync(work, { recursive: true, force: true });
  writeFileSync(evidenceFile, JSON.stringify(evidence, null, 2) + '\n');
}
process.exit(ok ? 0 : 1);
