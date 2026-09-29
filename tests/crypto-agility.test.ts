import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { inspect } from 'node:util';
import { fileURLToPath } from 'node:url';
import { ALGORITHMS, algorithmOfKeyId, detectAlgorithm, generateKeyMaterial, isAlgorithm, keyIdMatches, parsePrivateKeys, parsePublicKeys, runtimeSupports, signBytes, signatureLength, verifyBytes, zeroize } from '../reference/crypto/algorithms.ts';
import type { AlgorithmId } from '../reference/crypto/algorithms.ts';
import { AlgorithmFloor, CLASSICAL_ONLY_POLICY, DEFAULT_POLICY, parsePolicy } from '../reference/crypto/policy.ts';
import { signCheckpointV2, signCheckpointV3, signTreeHead, signTreeHeadV3, verifyAuditCheckpoint, verifyCheckpointExtension, verifyCheckpointHistory, verifyCheckpointV2, verifyCheckpointV3 } from '../reference/checkpoint.ts';
import type { AuditCheckpoint, CheckpointV3 } from '../reference/checkpoint.ts';
import { FileAnchor, FileCheckpointSigner, parseKeyring, signCheckpointWith, signTreeHeadWith, verifyAuditStream, verifyWithKeyring } from '../reference/custody.ts';
import { consistencyProof } from '../reference/evidence.ts';
import { ControlPlane } from '../reference/control.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryStore } from '../reference/store.ts';
import { ConfigError, loadCheckpointSigner, loadConfig } from '../reference/config.ts';
import { bindings } from '../examples/fixture.ts';
import { world } from './support.ts';
import { evalPython, skipReason } from './differential-harness.ts';

const head = { stream: 'acme', treeSize: 5, rootHash: 'ab'.repeat(32) };
const keyIdOf = (alg: AlgorithmId) => `${alg}:test-1`;
const material = new Map<AlgorithmId, ReturnType<typeof generateKeyMaterial>>();
const keys = (alg: AlgorithmId) => { if (!material.has(alg)) material.set(alg, generateKeyMaterial(alg)); return material.get(alg)!; };
async function populated(n = 3) {
  const store = new MemoryStore(world());
  for (let i = 0; i < n; i++) await new Engine(store).openContext(bindings.intern, ['handbook'], 'work');
  return store;
}

test('crypto agility: the runtime provides every registered algorithm and each signs and verifies a format 3 checkpoint', () => {
  assert.deepEqual([...ALGORITHMS], ['ed25519', 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87', 'slh-dsa-sha2-128s', 'slh-dsa-sha2-256s', 'ed25519+ml-dsa-65']);
  for (const alg of ALGORITHMS) {
    assert.ok(runtimeSupports(alg), `${alg} needs Node 24 with OpenSSL 3.5`);
    const k = keys(alg);
    assert.equal(detectAlgorithm(k.privatePem), alg); assert.equal(detectAlgorithm(k.publicPem), alg);
    const cp = signTreeHeadV3(head, alg, k.privatePem, keyIdOf(alg), 1000);
    assert.equal(cp.format, 'akac-audit-checkpoint/3'); assert.equal(cp.alg, alg);
    assert.equal(Buffer.from(cp.signature, 'base64url').length, signatureLength(alg), alg);
    assert.ok(verifyCheckpointV3(cp, k.publicPem, 'acme', keyIdOf(alg)), alg);
    assert.ok(verifyAuditCheckpoint(cp, k.publicPem, 'acme', keyIdOf(alg)), alg);
    // Another key of the same algorithm does not verify it.
    assert.equal(verifyCheckpointV3(cp, generateKeyMaterial(alg).publicPem, 'acme', keyIdOf(alg)), false, alg);
  }
  // Ed25519 is deterministic (RFC 8032); ML-DSA and SLH-DSA signing is randomised (FIPS 204/205 hedged mode), so they need verification-only vectors.
  const ed = keys('ed25519');
  assert.equal(signTreeHeadV3(head, 'ed25519', ed.privatePem, keyIdOf('ed25519'), 1000).signature, signTreeHeadV3(head, 'ed25519', ed.privatePem, keyIdOf('ed25519'), 1000).signature);
  assert.notEqual(signTreeHeadV3(head, 'ml-dsa-65', keys('ml-dsa-65').privatePem, keyIdOf('ml-dsa-65'), 1000).signature, signTreeHeadV3(head, 'ml-dsa-65', keys('ml-dsa-65').privatePem, keyIdOf('ml-dsa-65'), 1000).signature);
});

test('crypto agility: key ids carry the algorithm; the algorithm is inside the signed content and cannot be swapped or stripped', () => {
  assert.equal(algorithmOfKeyId('ml-dsa-65:prod'), 'ml-dsa-65'); assert.equal(algorithmOfKeyId('ed25519+ml-dsa-65:prod'), 'ed25519+ml-dsa-65');
  assert.equal(algorithmOfKeyId('legacy-key'), undefined); assert.equal(algorithmOfKeyId('rsa:x'), undefined);
  assert.ok(keyIdMatches('ml-dsa-65:x', 'ml-dsa-65')); assert.ok(!keyIdMatches('ml-dsa-65:', 'ml-dsa-65')); assert.ok(!keyIdMatches('ml-dsa-87:x', 'ml-dsa-65')); assert.ok(!keyIdMatches('x', 'ml-dsa-65'));
  assert.throws(() => signTreeHeadV3(head, 'ml-dsa-65', keys('ml-dsa-65').privatePem, 'no-prefix', 1), /Invalid checkpoint input/);
  const k = keys('ml-dsa-65'), cp = signTreeHeadV3(head, 'ml-dsa-65', k.privatePem, keyIdOf('ml-dsa-65'), 1000);
  const v = (r: unknown, keyId = cp.keyId) => verifyCheckpointV3(r as CheckpointV3, k.publicPem, 'acme', keyId);
  assert.ok(v(cp));
  assert.equal(v({ ...cp, alg: 'ml-dsa-87' }), false); assert.equal(v({ ...cp, alg: 'ml-dsa-87', keyId: 'ml-dsa-87:test-1' }, 'ml-dsa-87:test-1'), false);
  assert.equal(v({ ...cp, alg: 'ml-dsa-99' }), false); assert.equal(v({ ...cp, alg: 'none', signature: '' }), false);
  assert.equal(v({ ...cp, format: 'akac-audit-checkpoint/2' }), false); assert.equal(v({ ...cp, extra: 1 }), false);
  const { alg: _alg, ...noAlg } = cp; assert.equal(v(noAlg), false);
  // A v3 Ed25519 signature is never valid as the v2 form, and a v2 signature is not a v3 one.
  const ed = keys('ed25519'), v3 = signTreeHeadV3(head, 'ed25519', ed.privatePem, keyIdOf('ed25519'), 1000);
  const { alg: _a, ...rest } = v3;
  assert.equal(verifyCheckpointV2({ ...rest, format: 'akac-audit-checkpoint/2' } as never, ed.publicPem, 'acme', keyIdOf('ed25519')), false);
  const v2 = signTreeHead(head, ed.privatePem, 'legacy-1', 1000);
  assert.equal(verifyCheckpointV3({ ...v2, format: 'akac-audit-checkpoint/3', alg: 'ed25519', keyId: 'ed25519:legacy-1' } as never, ed.publicPem, 'acme', 'ed25519:legacy-1'), false);
  // Signature encoding is canonical and exact-length.
  const raw = Buffer.from(cp.signature, 'base64url');
  assert.equal(v({ ...cp, signature: raw.subarray(1).toString('base64url') }), false); assert.equal(v({ ...cp, signature: raw.toString('base64') }), false);
  assert.equal(v({ ...cp, signature: cp.signature + '=' }), false);
  assert.equal(verifyCheckpointV3(cp, k.publicPem, 'acme', cp.keyId, { minimumSize: 6 }), false, 'rollback below a trusted size');
});

test('crypto agility: a hybrid signature is valid only if both the Ed25519 and the ML-DSA-65 signature verify', () => {
  const alg = 'ed25519+ml-dsa-65' as const, k = keys(alg), cp = signTreeHeadV3(head, alg, k.privatePem, keyIdOf(alg), 1000);
  assert.ok(verifyCheckpointV3(cp, k.publicPem, 'acme', cp.keyId));
  const sig = Buffer.from(cp.signature, 'base64url'), other = Buffer.from(signTreeHeadV3({ ...head, treeSize: 6 }, alg, k.privatePem, keyIdOf(alg), 1000).signature, 'base64url');
  const check = (b: Buffer, pem = k.publicPem) => verifyCheckpointV3({ ...cp, signature: b.toString('base64url') }, pem, 'acme', cp.keyId);
  const flipped = (b: Buffer, at: number) => { const c = Buffer.from(b); c[at]! ^= 1; return c; };
  assert.equal(check(flipped(sig, 5)), false, 'Ed25519 half broken'); assert.equal(check(flipped(sig, 200)), false, 'ML-DSA half broken');
  assert.equal(check(sig.subarray(0, 64)), false, 'Ed25519 half only'); assert.equal(check(sig.subarray(64)), false, 'ML-DSA half only');
  assert.equal(check(Buffer.concat([other.subarray(0, 64), sig.subarray(64)])), false); assert.equal(check(Buffer.concat([sig.subarray(0, 64), other.subarray(64)])), false);
  const blocks = k.publicPem.match(/-----BEGIN PUBLIC KEY-----[^-]+-----END PUBLIC KEY-----\n?/g)!;
  assert.equal(blocks.length, 2);
  assert.equal(check(sig, blocks[0]!), false, 'one public key block'); assert.equal(check(sig, blocks[1]!), false); assert.equal(check(sig, blocks[1]! + blocks[0]!), false, 'blocks in the wrong order');
  // Signing refuses key material that is not exactly the hybrid pair.
  assert.throws(() => signTreeHeadV3(head, alg, keys('ed25519').privatePem, keyIdOf(alg), 1));
  assert.throws(() => parsePrivateKeys(alg, keys('ml-dsa-65').privatePem));
  // Primitive level: verifyBytes never throws on garbage.
  assert.equal(verifyBytes(alg, Buffer.from('m'), parsePublicKeys(alg, k.publicPem), Buffer.alloc(3)), false);
  assert.equal(verifyBytes('ml-dsa-65', Buffer.from('m'), parsePublicKeys(alg, k.publicPem), sig), false);
  const ed = keys('ed25519'), edCp = signTreeHeadV3(head, 'ed25519', ed.privatePem, keyIdOf('ed25519'), 1000);
  assert.equal(verifyCheckpointV3({ ...edCp, alg, keyId: keyIdOf(alg) }, k.publicPem, 'acme', keyIdOf(alg)), false, 'an Ed25519 signature claimed as hybrid');
});

test('crypto agility: verifier policy is an allowlist decided by the verifier, not by the document', () => {
  const k = keys('ml-dsa-65'), cp = signTreeHeadV3(head, 'ml-dsa-65', k.privatePem, keyIdOf('ml-dsa-65'), 1000);
  assert.ok(verifyCheckpointV3(cp, k.publicPem, 'acme', cp.keyId, { policy: DEFAULT_POLICY }));
  assert.equal(verifyCheckpointV3(cp, k.publicPem, 'acme', cp.keyId, { policy: CLASSICAL_ONLY_POLICY }), false);
  assert.equal(verifyCheckpointV3(cp, k.publicPem, 'acme', cp.keyId, { policy: parsePolicy({ algorithms: ['ml-dsa-87', 'ed25519+ml-dsa-65'] }) }), false);
  assert.ok(verifyCheckpointV3(cp, k.publicPem, 'acme', cp.keyId, { policy: parsePolicy({ algorithms: ['ml-dsa-65'] }) }));
  // Format 2 (Ed25519) is refused by a policy that excludes ed25519, and accepted by the default.
  const ed = keys('ed25519'), v2 = signTreeHead(head, ed.privatePem, 'legacy-1', 1000);
  assert.ok(verifyAuditCheckpoint(v2, ed.publicPem, 'acme', 'legacy-1'));
  assert.equal(verifyAuditCheckpoint(v2, ed.publicPem, 'acme', 'legacy-1', { policy: parsePolicy({ algorithms: ['ml-dsa-65'] }) }), false);
  for (const bad of [null, {}, { algorithms: [] }, { algorithms: ['rsa'] }, { algorithms: 'ed25519' }, { algorithms: ['ed25519'], extra: 1 }, { algorithms: ['ed25519'], allowClassicalAfterPq: 'yes' }]) assert.throws(() => parsePolicy(bad), /Invalid verifier policy/);
  assert.deepEqual(parsePolicy({ algorithms: ['ed25519', 'ed25519'], allowClassicalAfterPq: true }), { algorithms: ['ed25519'], allowClassicalAfterPq: true });
  assert.ok(isAlgorithm('ml-dsa-44')); assert.ok(!isAlgorithm('rsa-pss')); assert.ok(!isAlgorithm(undefined));
});

test('crypto agility: no downgrade, a stream that used hybrid or post-quantum signatures does not verify against a later classical-only checkpoint', () => {
  const E = keys('ed25519'), H = keys('ed25519+ml-dsa-65'), M = keys('ml-dsa-65');
  const at = (t: number, size: number) => ({ stream: 'acme', treeSize: size, rootHash: 'ee'.repeat(32) });
  const classical = (t: number, size: number): AuditCheckpoint => signTreeHead(at(t, size), E.privatePem, 'legacy-1', t);
  const hybrid = (t: number, size: number): AuditCheckpoint => signTreeHeadV3(at(t, size), 'ed25519+ml-dsa-65', H.privatePem, keyIdOf('ed25519+ml-dsa-65'), t);
  const pq = (t: number, size: number): AuditCheckpoint => signTreeHeadV3(at(t, size), 'ml-dsa-65', M.privatePem, keyIdOf('ml-dsa-65'), t);
  const item = (checkpoint: AuditCheckpoint) => ({ checkpoint, publicPem: checkpoint.format === 'akac-audit-checkpoint/2' ? E.publicPem : checkpoint.alg === 'ml-dsa-65' ? M.publicPem : H.publicPem });
  const ok = (cps: AuditCheckpoint[], policy = DEFAULT_POLICY) => verifyCheckpointHistory(cps.map(item), 'acme', policy);
  assert.ok(ok([classical(1000, 3), classical(3000, 6)]), 'classical history');
  assert.ok(ok([classical(1000, 3), hybrid(2000, 5)]), 'migration to hybrid');
  assert.equal(ok([hybrid(2000, 5), classical(3000, 6)]), false, 'classical after hybrid');
  assert.equal(ok([classical(3000, 6), hybrid(2000, 5)]), false, 'order of the set does not matter');
  assert.equal(ok([pq(2500, 5), classical(3000, 6)]), false, 'classical after post-quantum');
  assert.ok(ok([pq(2500, 5), hybrid(2600, 6)]), 'pq then hybrid is not a downgrade');
  assert.ok(ok([classical(500, 2), classical(1000, 3), hybrid(2000, 5)]), 'older classical checkpoints stay valid');
  assert.equal(ok([hybrid(2000, 5), classical(1500, 9)]), false, 'older but larger than the migration point: not a prefix of it');
  assert.ok(ok([hybrid(2000, 5), classical(3000, 6)], parsePolicy({ algorithms: [...ALGORITHMS], allowClassicalAfterPq: true })), 'explicitly permitted');
  assert.equal(ok([classical(1000, 3), hybrid(2000, 5)], CLASSICAL_ONLY_POLICY), false, 'hybrid not in the allowlist');
  assert.equal(verifyCheckpointHistory([], 'acme'), false);
  // A tampered post-quantum checkpoint must not lower the floor by being dropped silently: the whole set fails.
  const broken = hybrid(2000, 5) as CheckpointV3;
  assert.equal(ok([classical(1000, 3), { ...broken, signature: Buffer.alloc(3373).toString('base64url') }]), false);
  // Persisted verifier state: a fresh process that remembers the floor refuses the classical checkpoint on its own.
  const floor = new AlgorithmFloor(); floor.observe({ stream: 'acme', alg: 'ed25519+ml-dsa-65', issuedAt: 2000, treeSize: 5 });
  const restored = new AlgorithmFloor(DEFAULT_POLICY, JSON.parse(JSON.stringify(floor.snapshot())));
  assert.equal(verifyCheckpointHistory([item(classical(3000, 6))], 'acme', DEFAULT_POLICY, restored), false);
  assert.ok(verifyCheckpointHistory([item(classical(1000, 3))], 'acme', DEFAULT_POLICY, restored));
  assert.equal(new AlgorithmFloor().check({ stream: 'other', alg: 'ed25519', issuedAt: 9, treeSize: 9 }), 'ok', 'floors are per stream');
});

test('crypto agility: keyring, custody and control plane carry format 3; a migration is verified end to end, downgrade included', async () => {
  const store = await populated(3), classic = keys('ed25519'), hy = keys('ed25519+ml-dsa-65');
  let now = 1_000;
  const c1 = await new ControlPlane(store, { checkpoint: new FileCheckpointSigner(classic.privatePem, 'cp-classic-1'), clock: () => now }).latestCheckpoint('acme', 'aud');
  const cp1 = c1.ok ? c1.value.checkpoint! : undefined!;
  assert.equal(cp1.format, 'akac-audit-checkpoint/2', 'an Ed25519 signer still writes the 0.4 form');
  now = 2_000; await new Engine(store).openContext(bindings.intern, ['handbook'], 'work');
  const hybridSigner = new FileCheckpointSigner(hy.privatePem, keyIdOf('ed25519+ml-dsa-65'));
  const c2 = await new ControlPlane(store, { checkpoint: hybridSigner, clock: () => now }).latestCheckpoint('acme', 'aud');
  const cp2 = c2.ok ? c2.value.checkpoint! : undefined!;
  assert.equal(cp2.format, 'akac-audit-checkpoint/3'); assert.equal(cp2.format === 'akac-audit-checkpoint/3' && cp2.alg, 'ed25519+ml-dsa-65');
  now = 3_000; await new Engine(store).openContext(bindings.intern, ['handbook'], 'work');
  const c3 = await new ControlPlane(store, { checkpoint: new FileCheckpointSigner(classic.privatePem, 'cp-classic-1'), clock: () => now }).latestCheckpoint('acme', 'aud');
  const cp3 = c3.ok ? c3.value.checkpoint! : undefined!;
  const keyring = parseKeyring({ keys: [
    { keyId: 'cp-classic-1', publicPem: classic.publicPem, status: 'active' },
    { keyId: keyIdOf('ed25519+ml-dsa-65'), publicPem: hy.publicPem, status: 'active', notBefore: 1_500 }] });
  assert.deepEqual(verifyWithKeyring(cp2, keyring, 'acme'), { ok: true, keyId: keyIdOf('ed25519+ml-dsa-65') });
  const proof = await consistencyProof(store, 'acme', cp1.treeSize, cp2.treeSize);
  assert.ok(verifyCheckpointExtension(cp1, cp2, proof.path), 'the hybrid checkpoint extends the classical one');
  const migrated = await verifyAuditStream(store, 'acme', { checkpoints: [cp1, cp2], keyring });
  assert.equal(migrated.ok, true); assert.deepEqual(migrated.checkpoints.map(c => [c.alg, c.signature]), [['ed25519', 'verified'], ['ed25519+ml-dsa-65', 'verified']]);
  const downgraded = await verifyAuditStream(store, 'acme', { checkpoints: [cp1, cp2, cp3], keyring });
  assert.equal(downgraded.ok, false); assert.equal(downgraded.checkpoints[2]!.signature, 'downgrade'); assert.equal(downgraded.checkpoints[2]!.prefix, true, 'the roots agree; only the algorithm is refused');
  const allowed = await verifyAuditStream(store, 'acme', { checkpoints: [cp1, cp2, cp3], keyring, policy: parsePolicy({ algorithms: [...ALGORITHMS], allowClassicalAfterPq: true }) });
  assert.equal(allowed.ok, true);
  const narrow = await verifyAuditStream(store, 'acme', { checkpoints: [cp1, cp2], keyring, policy: CLASSICAL_ONLY_POLICY });
  assert.deepEqual(narrow.checkpoints.map(c => c.signature), ['verified', 'algorithm_not_allowed']); assert.equal(narrow.ok, false);
  // Without a keyring nothing is proven about the algorithm, so no downgrade verdict is invented; signatures stay unchecked.
  assert.deepEqual((await verifyAuditStream(store, 'acme', { checkpoints: [cp1, cp2, cp3] })).checkpoints.map(c => c.signature), ['unchecked', 'unchecked', 'unchecked']);
  // Key ids carry the algorithm: a keyring entry whose key material is of another algorithm is refused.
  assert.throws(() => parseKeyring({ keys: [{ keyId: 'ml-dsa-65:k', publicPem: classic.publicPem, status: 'active' }] }), /Key material does not match/);
  assert.throws(() => parseKeyring({ keys: [{ keyId: 'legacy', publicPem: keys('ml-dsa-65').publicPem, status: 'active' }] }));
  // Anchors keep both formats.
  const dir = mkdtempSync(join(tmpdir(), 'akac-anchor-'));
  try {
    const anchor = new FileAnchor(dir); await anchor.anchor(cp1); await anchor.anchor(cp2);
    assert.deepEqual(FileAnchor.read(dir, 'acme').map(c => c.format), ['akac-audit-checkpoint/2', 'akac-audit-checkpoint/3']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('crypto agility: signers, format selection and fail-closed signing', async () => {
  const pqKeys = keys('ml-dsa-65'), signer = new FileCheckpointSigner(pqKeys.privatePem, keyIdOf('ml-dsa-65'));
  assert.equal(signer.alg, 'ml-dsa-65');
  const cp = await signCheckpointWith(head, signer, 1000);
  assert.equal(cp.format, 'akac-audit-checkpoint/3'); assert.ok(verifyAuditCheckpoint(cp, signer.publicPem, 'acme', signer.keyId));
  await assert.rejects(signTreeHeadWith(head, signer, 1000), /Format 2 needs an Ed25519 signer/);
  const legacy = new FileCheckpointSigner(keys('ed25519').privatePem, 'legacy-1');
  assert.deepEqual(await signCheckpointWith(head, legacy, 1000), await signTreeHeadWith(head, legacy, 1000), 'Ed25519 through the generic path is exactly format 2');
  // A signer that returns a wrong signature never yields a checkpoint.
  const liar = { keyId: signer.keyId, publicPem: signer.publicPem, alg: 'ml-dsa-65' as const, sign: async () => Buffer.alloc(3309) };
  await assert.rejects(signCheckpointWith(head, liar, 1000), /invalid signature/);
  assert.throws(() => new FileCheckpointSigner(pqKeys.privatePem, 'no-prefix'), /Key id must be ml-dsa-65/);
  assert.throws(() => new FileCheckpointSigner(pqKeys.privatePem, keyIdOf('ml-dsa-65'), 'ml-dsa-87'), /ml-dsa-87 checkpoint key required/);
  assert.throws(() => new FileCheckpointSigner(pqKeys.publicPem, keyIdOf('ml-dsa-65')), /checkpoint key required/);
});

test('key hygiene: Buffers are erased after parsing, and signers never serialise or inspect key material', () => {
  const k = keys('ml-dsa-65'), buffer = Buffer.from(k.privatePem);
  const signer = new FileCheckpointSigner(buffer, keyIdOf('ml-dsa-65'));
  assert.ok(buffer.every(b => b === 0), 'the input Buffer is zeroed after the key was parsed');
  const secretBody = k.privatePem.split('\n')[1]!;
  for (const text of [JSON.stringify(signer), inspect(signer, { depth: 10, showHidden: true }), String(signer), `${JSON.stringify({ signer })}`]) {
    assert.ok(!text.includes(secretBody) && !text.includes('PRIVATE KEY'), 'no key material in serialisations');
  }
  assert.deepEqual(JSON.parse(JSON.stringify(signer)), { keyId: keyIdOf('ml-dsa-65'), alg: 'ml-dsa-65' });
  const raw = Buffer.from('secret'); zeroize(raw); assert.ok(raw.every(b => b === 0));
  const b2 = Buffer.from(k.privatePem); parsePrivateKeys('ml-dsa-65', b2); assert.ok(b2.every(b => b === 0));
  const b3 = Buffer.from('not a key'); assert.throws(() => parsePrivateKeys('ml-dsa-65', b3)); assert.ok(b3.every(b => b === 0), 'erased on failure as well');
  const rejected = keys('ed25519'); const buf4 = Buffer.from(rejected.privatePem);
  assert.throws(() => new FileCheckpointSigner(buf4, keyIdOf('ml-dsa-65'), 'ml-dsa-65'));
  // An error from a failed signature never carries the message or key.
  assert.equal(signBytes('ml-dsa-65', Buffer.from('x'), parsePrivateKeys('ml-dsa-65', k.privatePem)).length, 3309);
});

test('configuration selects the checkpoint algorithm; Vault Transit stays Ed25519; misconfigurations fail closed', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'akac-alg-'));
  try {
    const file = (name: string, content: string) => { const p = join(dir, name); writeFileSync(p, content, { mode: 0o600 }); return p; };
    const problems = (env: Record<string, string>) => { try { loadCheckpointSigner(env); return ''; } catch (e) { return (e as ConfigError).problems.join('; '); } };
    const hy = keys('ed25519+ml-dsa-65'), pq = keys('ml-dsa-87');
    const signer = loadCheckpointSigner({ AKAC_CHECKPOINT_ALG: 'ed25519+ml-dsa-65', AKAC_CHECKPOINT_KEY_FILE: file('hy.pem', hy.privatePem), AKAC_CHECKPOINT_KEY_ID: keyIdOf('ed25519+ml-dsa-65') })!;
    assert.equal(signer.alg, 'ed25519+ml-dsa-65');
    const cp = await signCheckpointWith(head, signer, 5);
    assert.ok(verifyAuditCheckpoint(cp, hy.publicPem, 'acme', signer.keyId));
    assert.equal(loadCheckpointSigner({ AKAC_CHECKPOINT_ALG: 'ed25519', AKAC_CHECKPOINT_KEY_FILE: file('e.pem', keys('ed25519').privatePem), AKAC_CHECKPOINT_KEY_ID: 'k-1' })!.keyId, 'k-1');
    assert.match(problems({ AKAC_CHECKPOINT_ALG: 'rsa', AKAC_CHECKPOINT_KEY_FILE: 'x', AKAC_CHECKPOINT_KEY_ID: 'k' }), /AKAC_CHECKPOINT_ALG must be one of/);
    assert.match(problems({ AKAC_CHECKPOINT_ALG: 'ml-dsa-87', AKAC_CHECKPOINT_KEY_FILE: file('p.pem', pq.privatePem), AKAC_CHECKPOINT_KEY_ID: 'plain-id' }), /must be ml-dsa-87:<label>/);
    assert.match(problems({ AKAC_CHECKPOINT_ALG: 'ml-dsa-65', AKAC_CHECKPOINT_KEY_FILE: file('p2.pem', pq.privatePem), AKAC_CHECKPOINT_KEY_ID: 'ml-dsa-65:x' }), /not readable ml-dsa-65 private key/);
    assert.match(problems({ AKAC_CHECKPOINT_ALG: 'ml-dsa-65', AKAC_CHECKPOINT_KEY_FILE: file('junk.pem', 'junk'), AKAC_CHECKPOINT_KEY_ID: 'ml-dsa-65:x' }), /not readable/);
    assert.match(problems({ AKAC_CHECKPOINT_ALG: 'ml-dsa-65' }), /requires AKAC_CHECKPOINT_KEY_FILE/);
    assert.match(problems({ AKAC_CHECKPOINT_ALG: 'ml-dsa-65', AKAC_CHECKPOINT_SIGNER: 'vault-transit' }), /Ed25519 only/);
    // AKAC_CHECKPOINT_SIGNER=extension (ADR-023): configuration names the algorithm and key id only; without an extension signer nothing signs.
    const ext = { AKAC_CHECKPOINT_SIGNER: 'extension', AKAC_CHECKPOINT_ALG: 'ed25519+ml-dsa-65', AKAC_CHECKPOINT_KEY_ID: 'ed25519+ml-dsa-65:hsm-2026' };
    assert.match(problems(ext), /requires a checkpoint signer supplied by an extension/);
    assert.match(problems({ ...ext, AKAC_CHECKPOINT_KEY_ID: 'hsm-2026' }), /must be ed25519\+ml-dsa-65:<label>/);
    assert.match(problems({ ...ext, AKAC_CHECKPOINT_KEY_FILE: 'x' }), /cannot be combined with AKAC_CHECKPOINT_SIGNER=extension/);
    const extConfig = loadConfig({ AKAC_CREDENTIALS_FILE: file('agent-ext.json', JSON.stringify([{}])), ...ext });
    assert.deepEqual(extConfig.checkpointExtension, { alg: 'ed25519+ml-dsa-65', keyId: 'ed25519+ml-dsa-65:hsm-2026' });
    assert.equal(extConfig.checkpointSigner, undefined); assert.equal(extConfig.checkpoint, undefined); assert.equal(extConfig.checkpointVault, undefined);
    // The whole configuration loads the signer into ServerConfig without exposing a PEM string.
    const config = loadConfig({ AKAC_CREDENTIALS_FILE: file('agent.json', JSON.stringify([{}])), AKAC_CHECKPOINT_ALG: 'ml-dsa-87', AKAC_CHECKPOINT_KEY_FILE: file('p3.pem', pq.privatePem), AKAC_CHECKPOINT_KEY_ID: keyIdOf('ml-dsa-87') });
    assert.equal(config.checkpointSigner?.alg, 'ml-dsa-87'); assert.equal(config.checkpoint, undefined);
    assert.ok(!JSON.stringify(config.checkpointSigner).includes('PRIVATE'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('scripts/checkpoint.ts keygen writes a key pair with a private file mode and never overwrites', () => {
  const dir = mkdtempSync(join(tmpdir(), 'akac-keygen-'));
  try {
    const script = fileURLToPath(new URL('../scripts/checkpoint.ts', import.meta.url));
    const run = (args: string[]) => spawnSync(process.execPath, [script, 'keygen', ...args], { encoding: 'utf8', env: { ...process.env, AKAC_DB: join(dir, 'unused.sqlite') } });
    const priv = join(dir, 'k.pem'), pub = join(dir, 'k.pub.pem');
    const r = run(['--alg', 'ml-dsa-65', '--out-private', priv, '--out-public', pub]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(detectAlgorithm(readFileSync(priv)), 'ml-dsa-65'); assert.equal(detectAlgorithm(readFileSync(pub)), 'ml-dsa-65');
    if (process.platform !== 'win32') assert.equal(statSync(priv).mode & 0o077, 0);
    assert.ok(!r.stdout.includes('PRIVATE'));
    assert.notEqual(run(['--alg', 'ml-dsa-65', '--out-private', priv, '--out-public', join(dir, 'other.pub')]).status, 0, 'existing private key is never overwritten');
    assert.equal(run(['--alg', 'rsa', '--out-private', join(dir, 'a'), '--out-public', join(dir, 'b')]).status, 2);
    assert.ok(!existsSync(join(dir, 'a')));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the offline 0.4 signing form writes format 2 for Ed25519 and format 3 for other algorithms', async () => {
  const store = await populated(2), entries = await store.auditLog('acme');
  const ed = keys('ed25519'), hy = keys('ed25519+ml-dsa-65');
  const v2 = signCheckpointV2(entries, ed.privatePem, 'acme', 'off-1', 7);
  assert.equal(v2.format, 'akac-audit-checkpoint/2'); assert.ok(verifyCheckpointV2(v2, ed.publicPem, 'acme', 'off-1', { entries }));
  const v3 = signCheckpointV3(entries, 'ed25519+ml-dsa-65', hy.privatePem, 'acme', keyIdOf('ed25519+ml-dsa-65'), 7);
  assert.ok(verifyCheckpointV3(v3, hy.publicPem, 'acme', v3.keyId, { entries }));
  assert.equal(verifyCheckpointV3(v3, hy.publicPem, 'acme', v3.keyId, { entries: entries.slice(0, 1) }), false, 'root must match the entries');
  assert.equal(verifyCheckpointV3(v3, hy.publicPem, 'other', v3.keyId), false);
});

test('conformance vectors: public data only, and every applicable vector agrees between TypeScript and Python', { skip: skipReason }, () => {
  const text = readFileSync(new URL('../conformance/vectors-0.6-crypto.json', import.meta.url), 'utf8');
  assert.ok(!/PRIVATE KEY/.test(text), 'the vector file contains no private key');
  const data = JSON.parse(text) as { cases: { id: string; kind: string; expected: boolean; checkpoint?: { alg?: string }; items?: { checkpoint: { alg?: string } }[] }[] };
  const ops = { 'checkpoint-v3': 'checkpointV3', 'checkpoint-history': 'checkpointHistory' } as const;
  const results = evalPython(data.cases.map(v => ({ ...v, op: ops[v.kind as keyof typeof ops] }))) as unknown[];
  assert.equal(results.length, data.cases.length);
  let compared = 0, notApplicable = 0;
  data.cases.forEach((v, i) => {
    const r = results[i];
    if (r && typeof r === 'object' && 'unavailable' in r) {
      // Not applicable here, never a pass: only algorithms the Python package lacks may be skipped (SLH-DSA; ML-DSA on older releases).
      const algs = v.kind === 'checkpoint-v3' ? [v.checkpoint!.alg ?? ''] : v.items!.map(x => x.checkpoint.alg ?? 'ed25519');
      assert.ok(algs.some(a => a.startsWith('slh-dsa') || a.includes('ml-dsa')), `${v.id}: unexpected N/A`);
      notApplicable++;
      return;
    }
    compared++;
    assert.equal(r, v.expected, `${v.id}: Python disagrees with the expected verdict`);
  });
  assert.ok(compared > 0);
  assert.equal(compared + notApplicable, data.cases.length);
});
