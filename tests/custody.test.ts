import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileAnchor, FileCheckpointSigner, VaultTransitSigner, ed25519PemFromRaw, parseKeyring, signTreeHeadWith, verifyAuditStream, verifyWithKeyring } from '../reference/custody.ts';
import { checkpointSigningInput, signTreeHead, verifyCheckpointExtension, verifyCheckpointV2 } from '../reference/checkpoint.ts';
import { consistencyProof, treeHead } from '../reference/evidence.ts';
import { ControlPlane } from '../reference/control.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryStore } from '../reference/store.ts';
import { ConfigError, loadCheckpointSigner } from '../reference/config.ts';
import type { Audit, Store } from '../reference/types.ts';
import { bindings } from '../examples/fixture.ts';
import { world } from './support.ts';

const keypair = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), privateKey, publicKey };
};
async function populated(n = 5) {
  const store = new MemoryStore(world());
  const engine = new Engine(store);
  for (let i = 0; i < n; i++) await engine.openContext(bindings.intern, ['handbook'], 'work');
  return store;
}
/** A mock Vault Transit endpoint holding `versions` (version -> private key). Records every request. */
function mockVault(versions: Record<number, ReturnType<typeof keypair>>, options: { status?: number; lie?: number } = {}) {
  const requests: { url: string; headers: Record<string, string>; body: { input: string; key_version: number } }[] = [];
  const fetcher = (async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body)) as { input: string; key_version: number };
    requests.push({ url, headers: init.headers as Record<string, string>, body });
    if (options.status) return new Response('{"errors":["permission denied: secret request data echoed"]}', { status: options.status });
    const key = versions[body.key_version];
    if (!key) return new Response('{"errors":["unknown version"]}', { status: 400 });
    const sig = sign(null, Buffer.from(body.input, 'base64'), key.privateKey).toString('base64');
    return Response.json({ data: { signature: `vault:v${options.lie ?? body.key_version}:${sig}`, key_version: body.key_version } });
  }) as unknown as typeof fetch;
  return { fetcher, requests };
}

test('custody: a file signer produces exactly the 0.4 format 2 checkpoint', async () => {
  const k = keypair();
  const head = { stream: 'acme', treeSize: 3, rootHash: 'a'.repeat(64) };
  const viaSigner = await signTreeHeadWith(head, new FileCheckpointSigner(k.privatePem, 'k-1'), 1000);
  assert.deepEqual(viaSigner, signTreeHead(head, k.privatePem, 'k-1', 1000), 'Ed25519 is deterministic: same bytes, same signature');
  assert.ok(verifyCheckpointV2(viaSigner, k.publicPem, 'acme', 'k-1'));
  assert.throws(() => new FileCheckpointSigner(generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), 'k'), /Ed25519/);
});

test('custody: the Vault Transit signer sends only the signing input, pins the key version and verifies every signature', async () => {
  const v1 = keypair(), v2 = keypair();
  const vault = mockVault({ 1: v1, 2: v2 });
  let token = 'test-token-rotating-1';
  const signer = new VaultTransitSigner({ address: 'https://vault.example.invalid:8200', keyName: 'akac-checkpoint', keyVersion: 1, publicPem: v1.publicPem,
    token: () => token, namespace: 'ops', fetch: vault.fetcher });
  assert.equal(signer.keyId, 'vault-transit:akac-checkpoint:v1');
  const head = { stream: 'acme', treeSize: 7, rootHash: 'b'.repeat(64) };
  const cp = await signTreeHeadWith(head, signer, 5000);
  assert.ok(verifyCheckpointV2(cp, v1.publicPem, 'acme', signer.keyId));
  const [request] = vault.requests;
  assert.equal(request!.url, 'https://vault.example.invalid:8200/v1/transit/sign/akac-checkpoint');
  assert.equal(request!.headers['x-vault-token'], 'test-token-rotating-1'); assert.equal(request!.headers['x-vault-namespace'], 'ops');
  assert.equal(request!.body.key_version, 1);
  assert.deepEqual(Buffer.from(request!.body.input, 'base64'), checkpointSigningInput({ format: 'akac-audit-checkpoint/2', stream: 'acme', treeSize: 7, rootHash: 'b'.repeat(64), issuedAt: 5000, keyId: signer.keyId }),
    'Vault sees the JCS signing input only: no audit content');
  token = 'test-token-rotating-2';
  await signTreeHeadWith(head, signer); assert.equal(vault.requests[1]!.headers['x-vault-token'], 'test-token-rotating-2', 'the token provider is asked on every signature');

  // Fail closed: wrong reported version, a key that does not match the pinned public key, HTTP errors, bad addresses.
  await assert.rejects(signTreeHeadWith(head, new VaultTransitSigner({ address: 'https://v.invalid', keyName: 'k', keyVersion: 1, publicPem: v1.publicPem, token: () => 't', fetch: mockVault({ 1: v1 }, { lie: 2 }).fetcher })), /unexpected key version/);
  await assert.rejects(signTreeHeadWith(head, new VaultTransitSigner({ address: 'https://v.invalid', keyName: 'k', keyVersion: 2, publicPem: v1.publicPem, token: () => 't', fetch: vault.fetcher })), /does not verify/);
  const denied = signTreeHeadWith(head, new VaultTransitSigner({ address: 'https://v.invalid', keyName: 'k', keyVersion: 1, publicPem: v1.publicPem, token: () => 't', fetch: mockVault({ 1: v1 }, { status: 403 }).fetcher }));
  await assert.rejects(denied, (e: Error) => /returned 403/.test(e.message) && !/secret request data/.test(e.message));
  await assert.rejects(signTreeHeadWith(head, new VaultTransitSigner({ address: 'https://v.invalid', keyName: 'k', keyVersion: 1, publicPem: v1.publicPem, token: () => '', fetch: vault.fetcher })), /token unavailable/);
  for (const address of ['http://vault.example.invalid', 'https://user' + ':pw@vault.invalid', 'not a url'])
    assert.throws(() => new VaultTransitSigner({ address, keyName: 'k', keyVersion: 1, publicPem: v1.publicPem, token: () => 't' }));
  assert.throws(() => new VaultTransitSigner({ address: 'https://v.invalid', keyName: '../sys', keyVersion: 1, publicPem: v1.publicPem, token: () => 't' }));
  assert.throws(() => new VaultTransitSigner({ address: 'https://v.invalid', keyName: 'k', keyVersion: 0, publicPem: v1.publicPem, token: () => 't' }));
  // Vault reports Ed25519 public keys as raw 32 bytes; the helper yields the SPKI PEM to pin.
  const raw = v2.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  assert.equal(ed25519PemFromRaw(raw), v2.publicPem);
});

test('custody: key rotation keeps every checkpoint verifiable through the keyring, and history stays append-only across keys', async () => {
  const old = keypair(), next = keypair();
  let now = 1_000;
  const store = await populated(3);
  const control1 = new ControlPlane(store, { checkpoint: new FileCheckpointSigner(old.privatePem, 'cp-2026-1'), clock: () => now });
  const first = await control1.latestCheckpoint('acme', 'aud');
  assert.ok(first.ok && first.value.checkpoint);
  const cp1 = first.ok ? first.value.checkpoint! : undefined!;
  // Rotation at t=2000: the old key is retired (verifies up to its notAfter), the new key signs from now on.
  now = 3_000;
  const control2 = new ControlPlane(store, { checkpoint: new FileCheckpointSigner(next.privatePem, 'cp-2026-2'), clock: () => now });
  await new Engine(store).openContext(bindings.intern, ['handbook'], 'work');
  const second = await control2.latestCheckpoint('acme', 'aud');
  const cp2 = second.ok ? second.value.checkpoint! : undefined!;
  const keyring = parseKeyring({ keys: [
    { keyId: 'cp-2026-1', publicPem: old.publicPem, status: 'retired', notAfter: 2_000 },
    { keyId: 'cp-2026-2', publicPem: next.publicPem, status: 'active', notBefore: 2_000 }] });
  assert.deepEqual(verifyWithKeyring(cp1, keyring, 'acme'), { ok: true, keyId: 'cp-2026-1' });
  assert.deepEqual(verifyWithKeyring(cp2, keyring, 'acme'), { ok: true, keyId: 'cp-2026-2' });
  const proof = await consistencyProof(store, 'acme', cp1.treeSize, cp2.treeSize);
  assert.ok(verifyCheckpointExtension(cp1, cp2, proof.path), 'the checkpoint under the new key extends the one under the old key');
  // A retired key cannot sign new history; a revoked key verifies nothing; unknown keys are refused.
  const late = signTreeHead(await treeHead(store, 'acme'), old.privatePem, 'cp-2026-1', 9_000);
  assert.deepEqual(verifyWithKeyring(late, keyring, 'acme'), { ok: false, reason: 'outside_key_window' });
  const revoked = parseKeyring({ keys: [{ keyId: 'cp-2026-1', publicPem: old.publicPem, status: 'revoked' }] });
  assert.deepEqual(verifyWithKeyring(cp1, revoked, 'acme'), { ok: false, reason: 'revoked_key' });
  assert.deepEqual(verifyWithKeyring({ ...cp1, keyId: 'other' }, keyring, 'acme'), { ok: false, reason: 'unknown_key' });
  assert.deepEqual(verifyWithKeyring({ ...cp1, rootHash: 'c'.repeat(64) }, keyring, 'acme'), { ok: false, reason: 'invalid' });
  for (const bad of [{}, { keys: [] }, { keys: [{ keyId: 'a', publicPem: old.publicPem, status: 'retired' }] }, { keys: [{ keyId: 'a', publicPem: 'x', status: 'active' }] },
    { keys: [{ keyId: 'a', publicPem: old.publicPem, status: 'active' }, { keyId: 'a', publicPem: next.publicPem, status: 'active' }] }]) assert.throws(() => parseKeyring(bad));
});

test('custody: the audit-verify job checks chain, stored tree and anchored checkpoints, and detects a rewritten stream', async () => {
  const k = keypair();
  const store = await populated(4);
  const dir = mkdtempSync(join(tmpdir(), 'akac-anchor-'));
  try {
    const signer = new FileCheckpointSigner(k.privatePem, 'cp-1');
    const cp = await signTreeHeadWith(await treeHead(store, 'acme'), signer);
    const receipt = await new FileAnchor(dir).anchor(cp);
    assert.equal(receipt.treeSize, cp.treeSize);
    await new Engine(store).openContext(bindings.intern, ['handbook'], 'work');
    const keyring = parseKeyring({ keys: [{ keyId: 'cp-1', publicPem: signer.publicPem, status: 'active' }] });
    const anchored = FileAnchor.read(dir, 'acme');
    assert.equal(anchored.length, 1);
    const good = await verifyAuditStream(store, 'acme', { checkpoints: anchored, keyring });
    assert.equal(good.ok, true); assert.equal(good.chain, true); assert.equal(good.storedTree, true);
    assert.deepEqual(good.checkpoints.map(c => [c.signature, c.prefix]), [['verified', true]]);
    assert.equal(good.treeSize, cp.treeSize + 1, 'the stream grew after the checkpoint; the checkpoint is still its prefix');
    // A host that rewrites an early entry breaks the chain; had it recomputed the chain, the anchored root would still differ.
    const entries = await store.auditLog('acme');
    const rewritten: Store = { ...store, transaction: store.transaction.bind(store), ready: store.ready.bind(store), close: store.close.bind(store),
      auditLog: async (tenant: string, after = 0, limit = 100_000) => (await store.auditLog(tenant, after, limit)).map((e: Audit) => e.sequence === 1 ? { ...e, reason: 'DENIED:NOT_AUTHORIZED' } : e) };
    const bad = await verifyAuditStream(rewritten, 'acme', { checkpoints: anchored, keyring });
    assert.equal(bad.ok, false); assert.equal(bad.chain, false);
    assert.equal((await verifyAuditStream(store, 'acme', { checkpoints: [{ ...cp, rootHash: 'd'.repeat(64) }] })).ok, false, 'a checkpoint that is not a prefix fails');
    assert.equal((await verifyAuditStream(store, 'acme', { checkpoints: [{ ...cp, treeSize: entries.length + 5 }] })).ok, false, 'a checkpoint beyond the stream (rollback) fails');
    assert.equal((await verifyAuditStream(store, 'acme', { checkpoints: anchored, keyring: parseKeyring({ keys: [{ keyId: 'cp-1', publicPem: keypair().publicPem, status: 'active' }] }) })).ok, false, 'a wrong key fails');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('custody: checkpoint signer configuration (file or Vault Transit) is validated up front', () => {
  const k = keypair();
  const dir = mkdtempSync(join(tmpdir(), 'akac-signer-'));
  try {
    const file = (name: string, content: string) => { const p = join(dir, name); writeFileSync(p, content); return p; };
    assert.equal(loadCheckpointSigner({}), undefined);
    assert.equal(loadCheckpointSigner({ AKAC_CHECKPOINT_KEY_FILE: file('k.pem', k.privatePem), AKAC_CHECKPOINT_KEY_ID: 'k-1' })!.keyId, 'k-1');
    const vault = { AKAC_CHECKPOINT_SIGNER: 'vault-transit', AKAC_VAULT_ADDR: 'https://vault.example.invalid', AKAC_VAULT_TRANSIT_KEY: 'akac-checkpoint', AKAC_VAULT_KEY_VERSION: '3',
      AKAC_VAULT_TOKEN_FILE: file('token', 'test-token\n'), AKAC_CHECKPOINT_PUBLIC_KEY_FILE: file('pub.pem', k.publicPem) };
    const signer = loadCheckpointSigner(vault)!;
    assert.equal(signer.keyId, 'vault-transit:akac-checkpoint:v3'); assert.equal(signer.publicPem, k.publicPem);
    const problems = (env: Record<string, string>) => { try { loadCheckpointSigner(env); return []; } catch (e) { return (e as ConfigError).problems; } };
    assert.match(problems({ ...vault, AKAC_VAULT_KEY_VERSION: 'latest' }).join(), /positive integer/);
    assert.match(problems({ ...vault, AKAC_VAULT_TOKEN: 'inline' }).join(), /AKAC_VAULT_TOKEN_FILE/);
    assert.match(problems({ ...vault, AKAC_VAULT_ADDR: 'http://vault.example.invalid' }).join(), /https/);
    assert.match(problems({ ...vault, AKAC_CHECKPOINT_KEY_FILE: 'x' }).join(), /cannot be combined/);
    assert.match(problems({ AKAC_VAULT_ADDR: 'https://v.invalid' }).join(), /requires AKAC_CHECKPOINT_SIGNER=vault-transit/);
    assert.match(problems({ AKAC_CHECKPOINT_SIGNER: 'hsm' }).join(), /file or vault-transit/);
    assert.ok(verify(null, Buffer.from('x'), k.publicKey, sign(null, Buffer.from('x'), k.privateKey)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
