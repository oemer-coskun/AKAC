import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { ConfigError, configuredStore, loadCheckpointSigner } from '../reference/config.ts';
import { signCheckpointV2, signCheckpointV3 } from '../reference/checkpoint.ts';
import type { AuditCheckpoint } from '../reference/checkpoint.ts';
import { FileAnchor, parseKeyring, signCheckpointWith, verifyAuditStream } from '../reference/custody.ts';
import { ALGORITHMS, detectAlgorithm, generateKeyMaterial, isAlgorithm, runtimeSupports, zeroize } from '../reference/crypto/algorithms.ts';
import { DEFAULT_POLICY, parsePolicy } from '../reference/crypto/policy.ts';
import type { VerifierPolicy } from '../reference/crypto/policy.ts';
import type { CheckpointSigner, Keyring } from '../reference/custody.ts';
import { treeHead } from '../reference/evidence.ts';
import { validId } from '../reference/validation.ts';
import type { Audit } from '../reference/types.ts';

// Audit checkpoints of one tenant stream (format 2, or format 3 for post-quantum and hybrid algorithms). Forms:
//
//   node scripts/checkpoint.ts PRIVATE_KEY_FILE TENANT KEY_ID OUTPUT
//     0.4 form: offline key file. An Ed25519 key writes format 2 (unchanged); a key of another registered
//     algorithm (detected from the PKCS#8 PEM; the hybrid is an Ed25519 block then an ML-DSA-65 block) writes
//     format 3 and KEY_ID must then be <alg>:<label>.
//   node scripts/checkpoint.ts keygen --alg ALG --out-private FILE --out-public FILE
//     Generates a key pair (private file mode 0600, never overwritten). ALG is one of the registered algorithms.
//   node scripts/checkpoint.ts sign --tenant T --out FILE [--anchor-dir DIR]
//     Signs with the server's signer configuration (AKAC_CHECKPOINT_KEY_FILE/_ID, or
//     AKAC_CHECKPOINT_SIGNER=vault-transit with the AKAC_VAULT_* variables; AKAC_CHECKPOINT_ALG selects the
//     algorithm, default ed25519 = format 2), then
//     optionally appends the checkpoint to an anchor directory (reference/custody.ts FileAnchor).
//   node scripts/checkpoint.ts verify --tenant T [--tenant T2 ...] [--checkpoint FILE ...] [--anchor-dir DIR]
//       [--keyring FILE] [--evidence FILE] [--allow-alg ALG ...] [--policy FILE] [--allow-classical-after-pq]
//     Verifies the hash chain of the whole stream, recomputes the RFC 9162 root, cross-checks
//     the stored tree, and checks that every given or anchored checkpoint is a prefix of the
//     stream (and, with a keyring, its signature under the verifier policy: --allow-alg / --policy, default every
//     registered algorithm; a classical-only checkpoint newer or larger than the first verified post-quantum one is
//     refused as a downgrade unless --allow-classical-after-pq). Exit 0 when everything verifies, 1 otherwise.
//     Used by the Helm audit-verify CronJob and the backup/restore drill.
const first = process.argv[2];
const fail = (message: string, code = 2): never => { console.error(message); process.exit(code); };
const readJson = (file: string): unknown => { try { return JSON.parse(readFileSync(file, 'utf8')); } catch { return fail(`not readable JSON: ${file}`); } };

async function readStream(tenant: string): Promise<{ entries: Audit[]; close: () => Promise<void>; store: ReturnType<typeof configuredStore> }> {
  const store = configuredStore(), entries: Audit[] = [];
  for (let after = 0; ;) {
    const page = await store.auditLog(tenant, after, 10_000);
    entries.push(...page);
    if (page.length < 10_000) break;
    after = page.at(-1)!.sequence;
  }
  return { entries, store, close: () => store.close() };
}

if (first === 'verify') {
  const { values } = parseArgs({ args: process.argv.slice(3), options: {
    tenant: { type: 'string', multiple: true }, checkpoint: { type: 'string', multiple: true }, 'anchor-dir': { type: 'string' }, keyring: { type: 'string' }, evidence: { type: 'string' },
    'allow-alg': { type: 'string', multiple: true }, policy: { type: 'string' }, 'allow-classical-after-pq': { type: 'boolean' } } });
  const tenants = values.tenant ?? [];
  if (!tenants.length || !tenants.every(validId) || (values.checkpoint?.length && tenants.length > 1))
    fail('Usage: node scripts/checkpoint.ts verify --tenant T [--tenant T2 ...] [--checkpoint FILE ...] [--anchor-dir DIR] [--keyring FILE] [--evidence FILE] [--allow-alg ALG ...] [--policy FILE] [--allow-classical-after-pq] (--checkpoint files apply to a single --tenant; anchored checkpoints are read per tenant)');
  let keyring: Keyring | undefined;
  if (values.keyring) { try { keyring = parseKeyring(readJson(values.keyring)); } catch { fail('invalid keyring'); } }
  let policy: VerifierPolicy = DEFAULT_POLICY;
  try {
    if (values.policy && values['allow-alg']?.length) fail('Use either --policy or --allow-alg');
    if (values.policy) policy = parsePolicy(readJson(values.policy));
    else if (values['allow-alg']?.length) { if (!values['allow-alg'].every(isAlgorithm)) fail(`--allow-alg must be one of ${ALGORITHMS.join(', ')}`); policy = parsePolicy({ algorithms: values['allow-alg'] }); }
    if (values['allow-classical-after-pq']) policy = { ...policy, allowClassicalAfterPq: true };
  } catch { fail('invalid verifier policy'); }
  const store = configuredStore();
  const results = [];
  try {
    for (const tenant of tenants) {
      const checkpoints: AuditCheckpoint[] = [...(values.checkpoint ?? []).map(f => readJson(f) as AuditCheckpoint), ...(values['anchor-dir'] ? FileAnchor.read(values['anchor-dir'], tenant) : [])];
      const result = await verifyAuditStream(store, tenant, { checkpoints, policy, ...(keyring ? { keyring } : {}) });
      results.push(result);
      console.log(JSON.stringify({ level: result.ok ? 'info' : 'error', time: new Date().toISOString(), msg: result.ok ? 'audit verified' : 'audit verification FAILED', tenant, treeSize: result.treeSize,
        rootHash: result.rootHash, chain: result.chain, storedTree: result.storedTree, checkpoints: result.checkpoints.length, failed: result.checkpoints.filter(c => !c.ok).length, algorithms: [...new Set(result.checkpoints.map(c => c.alg))] }));
    }
  } finally { await store.close(); }
  const ok = results.every(r => r.ok);
  if (values.evidence) writeFileSync(values.evidence, JSON.stringify({ format: 'akac-audit-verification/1', time: new Date().toISOString(), ok, results }, null, 2) + '\n', { mode: 0o600 });
  process.exit(ok ? 0 : 1);
} else if (first === 'keygen') {
  const { values } = parseArgs({ args: process.argv.slice(3), options: { alg: { type: 'string' }, 'out-private': { type: 'string' }, 'out-public': { type: 'string' } } });
  if (!isAlgorithm(values.alg) || !values['out-private'] || !values['out-public']) fail(`Usage: node scripts/checkpoint.ts keygen --alg ${ALGORITHMS.join('|')} --out-private FILE --out-public FILE`);
  if (!runtimeSupports(values.alg as never)) fail(`This Node.js/OpenSSL build does not support ${values.alg} (needs Node 24 with OpenSSL 3.5)`, 1);
  const material = generateKeyMaterial(values.alg as never);
  writeFileSync(values['out-private']!, material.privatePem, { mode: 0o600, flag: 'wx' });
  writeFileSync(values['out-public']!, material.publicPem, { flag: 'wx' });
  console.log(JSON.stringify({ level: 'info', msg: 'key pair written', alg: values.alg, keyId: `${values.alg}:<label>` }));
} else if (first === 'sign') {
  const { values } = parseArgs({ args: process.argv.slice(3), options: { tenant: { type: 'string' }, out: { type: 'string' }, 'anchor-dir': { type: 'string' } } });
  if (!validId(values.tenant) || !values.out) fail('Usage: node scripts/checkpoint.ts sign --tenant T --out FILE [--anchor-dir DIR]');
  let signer: CheckpointSigner | undefined;
  try { signer = loadCheckpointSigner(); } catch (error) {
    if (error instanceof ConfigError) { for (const p of error.problems) console.error(`configuration error: ${p}`); process.exit(2); }
    throw error;
  }
  if (!signer) fail('No checkpoint signer configured (AKAC_CHECKPOINT_KEY_FILE/AKAC_CHECKPOINT_KEY_ID or AKAC_CHECKPOINT_SIGNER=vault-transit)');
  const tenant = values.tenant!, store = configuredStore();
  try {
    // The root is recomputed from verified entries; the stored tree must agree when the stream did not grow.
    const result = await verifyAuditStream(store, tenant);
    if (!result.chain || result.storedTree === false) fail('Audit stream does not verify; refusing to sign', 1);
    const checkpoint = await signCheckpointWith({ stream: tenant, treeSize: result.treeSize, rootHash: result.rootHash }, signer!);
    writeFileSync(values.out!, JSON.stringify(checkpoint, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    const receipt = values['anchor-dir'] ? await new FileAnchor(values['anchor-dir']).anchor(checkpoint) : undefined;
    console.log(JSON.stringify({ level: 'info', msg: 'checkpoint written', format: checkpoint.format, treeSize: checkpoint.treeSize, keyId: checkpoint.keyId, ...(receipt ? { anchored: receipt.anchor } : {}) }));
  } finally { await store.close(); }
} else {
  const [privateKeyFile, tenant, keyId, output] = process.argv.slice(2);
  if (!privateKeyFile || !tenant || !keyId || !output) fail('Usage: node scripts/checkpoint.ts PRIVATE_KEY_FILE TENANT KEY_ID OUTPUT | sign ... | verify ...');
  const { entries, store, close } = await readStream(tenant!);
  try {
    // Each tenant is its own audit stream; the checkpoint stream identifier is the tenant.
    // The whole stream is read in pages, its hash chain verified and the RFC 9162 root
    // recomputed from the entries themselves, so stored Merkle nodes are not trusted.
    // The key file is read as a Buffer and erased after parsing (strings cannot be erased); the algorithm comes from the key material.
    const keyBytes = readFileSync(privateKeyFile!), alg = detectAlgorithm(keyBytes);
    if (!alg) { zeroize(keyBytes); throw new Error('Unsupported or unreadable private key (need PKCS#8 PEM of a registered algorithm)'); }
    const pem = keyBytes.toString('latin1'); zeroize(keyBytes);
    const checkpoint = alg === 'ed25519' ? signCheckpointV2(entries, pem, tenant!, keyId!) : signCheckpointV3(entries, alg, pem, tenant!, keyId!);
    // Cross-check the store's incremental tree when the stream did not grow meanwhile.
    const head = await treeHead(store, tenant!);
    if (head.treeSize === checkpoint.treeSize && head.rootHash !== checkpoint.rootHash) throw new Error('Stored audit tree disagrees with the audit entries');
    writeFileSync(output!, JSON.stringify(checkpoint, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    console.log(`Checkpoint (${checkpoint.format}${checkpoint.format.endsWith('/3') ? `, ${alg}` : ''}, treeSize ${checkpoint.treeSize}) written. Anchor it in independently protected storage.`);
  } finally { await close(); }
}
