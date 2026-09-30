import { createPublicKey, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checkpointAlgorithm, checkpointBodyV3, checkpointSigningInput, checkpointSigningInputV3, verifyAuditCheckpoint } from './checkpoint.ts';
import type { AuditCheckpoint, CheckpointV2 } from './checkpoint.ts';
import { algorithmOfKeyId, detectAlgorithm, isAlgorithm, keyIdMatches, parsePrivateKeys, parsePublicKeys, signBytes, verifyBytes } from './crypto/algorithms.ts';
import type { AlgorithmId } from './crypto/algorithms.ts';
import { AlgorithmFloor, DEFAULT_POLICY, allows } from './crypto/policy.ts';
import type { VerifierPolicy } from './crypto/policy.ts';
import { inspect } from 'node:util';
import type { Audit, Store } from './types.ts';
import { treeHead } from './evidence.ts';
import type { TreeHead } from './evidence.ts';
import { auditLeaf, verifyAudit } from './audit.ts';
import { isHash, rootOf } from './merkle.ts';
import { exactKeys, safeNumber, safeText } from './validation.ts';

/**
 * Checkpoint key custody (0.6, ADR-016). A CheckpointSigner produces the Ed25519
 * signature of a format 2 checkpoint without the caller ever holding the private
 * key: a file key (FileCheckpointSigner, the 0.4 behaviour) or a key held by a KMS
 * or HSM behind an HTTP API (VaultTransitSigner). Every signature is verified
 * against the signer's pinned public key before it is returned, so a misrouted or
 * rotated remote key fails closed instead of producing an unverifiable checkpoint.
 */
export interface CheckpointSigner {
  /** The key id written into the checkpoint; verifiers look it up in their keyring. */
  readonly keyId: string;
  /** SPKI PEM of the public key (for keyrings and local verification); the hybrid: an Ed25519 block then an ML-DSA-65 block. */
  readonly publicPem: string;
  /**
   * Signature algorithm (0.6, ADR-021). Absent or `ed25519`: format 2 checkpoints (the 0.4 form). Anything else:
   * format 3 checkpoints, and `keyId` must be `<alg>:<label>`.
   */
  readonly alg?: AlgorithmId;
  sign(message: Buffer): Promise<Buffer>;
}
const KEY_ID = /^[A-Za-z0-9._:-]{1,128}$/;
function ed25519Public(pem: string): KeyObject {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Ed25519 public key required');
  return key;
}
/** SPKI PEM of a raw 32-byte Ed25519 public key (RFC 8410). */
export function ed25519PemFromRaw(raw: Buffer): string {
  if (raw.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }).toString();
}
/**
 * Private key in process memory (PKCS#8 PEM, or a JWK for Ed25519). The 0.4 behaviour, as a signer, generalised to
 * every registered algorithm (0.6): `alg` defaults to the algorithm of the key material. A Buffer input is overwritten
 * after parsing; the key then lives in KeyObjects, which node:crypto offers no way to erase (docs/CRYPTO-AGILITY.md).
 * The object never serialises or inspects its keys.
 */
export class FileCheckpointSigner implements CheckpointSigner {
  readonly keyId: string; readonly publicPem: string; readonly alg: AlgorithmId;
  private keys: KeyObject[];
  constructor(privatePem: string | Buffer, keyId: string, alg?: AlgorithmId) {
    if (alg !== undefined && !isAlgorithm(alg)) throw new Error('Unknown checkpoint algorithm');
    const detected = detectAlgorithm(privatePem);
    if (!detected || (alg !== undefined && alg !== detected)) throw new Error(`${alg ?? 'Ed25519'} checkpoint key required`);
    const chosen = alg ?? detected;
    if (chosen === 'ed25519' ? !KEY_ID.test(keyId) : !keyIdMatches(keyId, chosen)) throw new Error(chosen === 'ed25519' ? 'Invalid key id' : `Key id must be ${chosen}:<label>`);
    try { this.keys = parsePrivateKeys(chosen, privatePem); } catch { throw new Error(`${chosen} checkpoint key required (private PKCS#8 PEM)`); }
    this.alg = chosen; this.keyId = keyId;
    this.publicPem = this.keys.map(k => createPublicKey(k).export({ type: 'spki', format: 'pem' }).toString()).join('');
  }
  async sign(message: Buffer): Promise<Buffer> { return signBytes(this.alg, message, this.keys); }
  toJSON() { return { keyId: this.keyId, alg: this.alg }; }
  [inspect.custom]() { return `FileCheckpointSigner { keyId: '${this.keyId}', alg: '${this.alg}' }`; }
}

export type VaultTransitOptions = {
  /** Vault address; https unless loopback. */
  address: string;
  /** Transit key name (type ed25519). */
  keyName: string;
  /** Pinned key version: rotation is an explicit configuration change, never implicit. */
  keyVersion: number;
  /** Pinned SPKI PEM of that version (from `GET /v1/transit/keys/:name`, see ed25519PemFromRaw). */
  publicPem: string;
  /** Returns a current Vault token (for example re-read from a Vault Agent sink file). */
  token: () => string | Promise<string>;
  /** Default `vault-transit:<keyName>:v<keyVersion>`. */
  keyId?: string;
  mount?: string; namespace?: string; timeoutMs?: number;
  fetch?: typeof fetch;
};
const loopback = (host: string) => host === 'localhost' || host === '[::1]' || /^127(\.\d{1,3}){3}$/.test(host);
/**
 * Example KMS adapter: HashiCorp Vault Transit (`POST /v1/<mount>/sign/<key>` with
 * `key_version`, response `data.signature` = `vault:v<N>:<base64>`). The private key
 * never leaves Vault; AKAC sends only the checkpoint signing input (tree size, root
 * hash, stream, time), no audit content. Tests use a mock `fetch`; nothing here runs
 * against a real Vault in CI. The same interface fits any KMS or HSM that offers
 * Ed25519 signatures; a product without Ed25519 cannot sign format 2 checkpoints.
 */
export class VaultTransitSigner implements CheckpointSigner {
  readonly keyId: string; readonly publicPem: string;
  private endpoint: string; private version: number; private token: VaultTransitOptions['token'];
  private namespace?: string; private timeout: number; private fetcher: typeof fetch; private verifyKey: KeyObject;
  constructor(o: VaultTransitOptions) {
    let url: URL;
    try { url = new URL(o.address); } catch { throw new Error('Invalid Vault address'); }
    if (url.username || url.password || url.search || url.hash) throw new Error('Invalid Vault address');
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback(url.hostname))) throw new Error('Vault address must use https unless loopback');
    const name = /^[A-Za-z0-9_-]{1,128}$/, mount = o.mount ?? 'transit';
    if (!name.test(o.keyName) || !/^[A-Za-z0-9_/-]{1,128}$/.test(mount) || mount.includes('..')) throw new Error('Invalid Vault key name or mount');
    if (!Number.isSafeInteger(o.keyVersion) || o.keyVersion < 1) throw new Error('Invalid Vault key version');
    if (o.namespace !== undefined && !/^[A-Za-z0-9_/-]{1,256}$/.test(o.namespace)) throw new Error('Invalid Vault namespace');
    if (typeof o.token !== 'function') throw new Error('Vault token provider required');
    this.keyId = o.keyId ?? `vault-transit:${o.keyName}:v${o.keyVersion}`;
    if (!KEY_ID.test(this.keyId)) throw new Error('Invalid key id');
    this.verifyKey = ed25519Public(o.publicPem);
    this.publicPem = this.verifyKey.export({ type: 'spki', format: 'pem' }).toString();
    this.endpoint = `${url.origin}${url.pathname.replace(/\/+$/, '')}/v1/${mount}/sign/${o.keyName}`;
    this.version = o.keyVersion; this.token = o.token; this.namespace = o.namespace;
    this.timeout = o.timeoutMs ?? 5000; this.fetcher = o.fetch ?? fetch;
  }
  async sign(message: Buffer): Promise<Buffer> {
    const token = await this.token();
    if (typeof token !== 'string' || !token || /[\r\n]/.test(token)) throw new Error('Vault token unavailable');
    const response = await this.fetcher(this.endpoint, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(this.timeout),
      headers: { 'content-type': 'application/json', 'x-vault-token': token, ...(this.namespace ? { 'x-vault-namespace': this.namespace } : {}) },
      body: JSON.stringify({ input: message.toString('base64'), key_version: this.version }) });
    // Errors never include the response body (it may echo request data) or the token.
    if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new Error(`Vault sign returned ${response.status}`); }
    const text = await response.text();
    if (text.length > 65536) throw new Error('Vault response too large');
    let signature: unknown;
    try { signature = (JSON.parse(text) as { data?: { signature?: unknown } })?.data?.signature; } catch { throw new Error('Vault response is not JSON'); }
    const m = typeof signature === 'string' ? /^vault:v(\d+):([A-Za-z0-9+/]+={0,2})$/.exec(signature) : null;
    if (!m || Number(m[1]) !== this.version) throw new Error('Vault signature from an unexpected key version');
    const raw = Buffer.from(m[2]!, 'base64');
    if (raw.length !== 64 || !verify(null, message, this.verifyKey, raw)) throw new Error('Vault signature does not verify under the pinned public key');
    return raw;
  }
}
/** Signs a tree head as a format 2 checkpoint with any signer (same bytes as signTreeHead). */
export async function signTreeHeadWith(head: TreeHead, signer: CheckpointSigner, issuedAt = Date.now()): Promise<CheckpointV2> {
  if (signer?.alg !== undefined && signer.alg !== 'ed25519') throw new Error('Format 2 needs an Ed25519 signer; use signCheckpointWith');
  if (!safeText(head?.stream, 128) || !KEY_ID.test(signer?.keyId) || !safeNumber(issuedAt) || !safeNumber(head.treeSize) || !isHash(head.rootHash)) throw new Error('Invalid checkpoint input');
  const body: Omit<CheckpointV2, 'signature'> = { format: 'akac-audit-checkpoint/2', stream: head.stream, treeSize: head.treeSize, rootHash: head.rootHash, issuedAt, keyId: signer.keyId };
  const signature = await signer.sign(checkpointSigningInput(body));
  if (!Buffer.isBuffer(signature) || signature.length !== 64) throw new Error('Signer returned an invalid signature');
  return { ...body, signature: signature.toString('base64url') };
}

/**
 * Signs a tree head with any signer: format 2 for an Ed25519 signer (identical to signTreeHeadWith, the default and the
 * form every 0.4-0.5 verifier reads), format 3 for any other registered algorithm. The signature is verified against the
 * signer's own public key before it is returned, so a misconfigured or rotated key fails closed here rather than at a
 * verifier.
 */
export async function signCheckpointWith(head: TreeHead, signer: CheckpointSigner, issuedAt = Date.now()): Promise<AuditCheckpoint> {
  const alg = signer?.alg ?? 'ed25519';
  if (alg === 'ed25519') return signTreeHeadWith(head, signer, issuedAt);
  const body = checkpointBodyV3(head, alg, signer.keyId, issuedAt);
  const signature = await signer.sign(checkpointSigningInputV3(body));
  if (!Buffer.isBuffer(signature) || !verifyBytes(alg, checkpointSigningInputV3(body), parsePublicKeys(alg, signer.publicPem), signature)) throw new Error('Signer returned an invalid signature');
  return { ...body, signature: signature.toString('base64url') };
}

/**
 * Verification keyring for key rotation. Every key that ever signed a checkpoint
 * stays listed: `active` keys sign now; a `retired` key verifies only checkpoints
 * issued inside its [notBefore, notAfter] window; a `revoked` key (suspected
 * compromise) verifies nothing, so its checkpoints must be re-established from
 * anchored copies and consistency proofs.
 */
export type KeyringEntry = { keyId: string; publicPem: string; status: 'active' | 'retired' | 'revoked'; notBefore?: number; notAfter?: number };
export type Keyring = { keys: KeyringEntry[] };
export function parseKeyring(value: unknown): Keyring {
  if (!exactKeys(value, ['keys']) || !Array.isArray(value.keys) || !value.keys.length || value.keys.length > 256) throw new Error('Invalid keyring');
  const seen = new Set<string>();
  const keys = value.keys.map((k: unknown) => {
    if (!exactKeys(k, ['keyId', 'publicPem', 'status'], ['notBefore', 'notAfter']) || typeof k.keyId !== 'string' || !(KEY_ID.test(k.keyId) || (algorithmOfKeyId(k.keyId) && keyIdMatches(k.keyId, algorithmOfKeyId(k.keyId)!))) || seen.has(k.keyId)
      || typeof k.publicPem !== 'string' || !['active', 'retired', 'revoked'].includes(k.status as string)
      || (k.notBefore !== undefined && !safeNumber(k.notBefore)) || (k.notAfter !== undefined && !safeNumber(k.notAfter))
      || (k.notBefore !== undefined && k.notAfter !== undefined && (k.notBefore as number) > (k.notAfter as number))
      || (k.status === 'retired' && k.notAfter === undefined)) throw new Error('Invalid keyring entry');
    // The key id names the algorithm (an id without a registered prefix is the legacy Ed25519 form); the key material must be of it.
    parsePublicKeys(algorithmOfKeyId(k.keyId) ?? 'ed25519', k.publicPem);
    seen.add(k.keyId);
    return { keyId: k.keyId, publicPem: k.publicPem, status: k.status as KeyringEntry['status'],
      ...(k.notBefore !== undefined ? { notBefore: k.notBefore as number } : {}), ...(k.notAfter !== undefined ? { notAfter: k.notAfter as number } : {}) };
  });
  return { keys };
}
export type KeyringVerdict = { ok: true; keyId: string } | { ok: false; reason: 'unknown_key' | 'revoked_key' | 'outside_key_window' | 'invalid' | 'algorithm_not_allowed' | 'downgrade' };
/**
 * Verifies a format 2 or 3 checkpoint under whichever keyring key signed it (verifyCheckpointV2/V3 semantics otherwise).
 * `policy` is the verifier's algorithm allowlist (default: every registered algorithm). Downgrade across checkpoints is
 * decided by verifyAuditStream (it sees the set), or by a caller-held AlgorithmFloor.
 */
export function verifyWithKeyring(record: AuditCheckpoint, keyring: Keyring, expectedStream: string, options: { entries?: Audit[]; minimumSize?: number; policy?: VerifierPolicy } = {}): KeyringVerdict {
  const entry = keyring.keys.find(k => k.keyId === record?.keyId);
  if (!entry) return { ok: false, reason: 'unknown_key' };
  if (entry.status === 'revoked') return { ok: false, reason: 'revoked_key' };
  if (!safeNumber(record.issuedAt) || (entry.notBefore !== undefined && record.issuedAt < entry.notBefore)
    || (entry.notAfter !== undefined && record.issuedAt > entry.notAfter)) return { ok: false, reason: 'outside_key_window' };
  const policy = options.policy ?? DEFAULT_POLICY;
  if (record.format === 'akac-audit-checkpoint/3' && isAlgorithm(record.alg) && !allows(policy, record.alg)) return { ok: false, reason: 'algorithm_not_allowed' };
  return verifyAuditCheckpoint(record, entry.publicPem, expectedStream, entry.keyId, options) ? { ok: true, keyId: entry.keyId } : { ok: false, reason: 'invalid' };
}

/**
 * External anchoring hook: after a checkpoint is signed it is handed to one or
 * more anchors that store it outside the reach of the gateway host (WORM bucket,
 * a separate account, a transparency service). A compromised host can then not
 * rewrite history unseen: a later stream must extend every anchored checkpoint
 * (consistency proof). AKAC ships no network anchor.
 */
export type AnchorReceipt = { anchor: string; stream: string; treeSize: number; rootHash: string; reference: string };
export interface CheckpointAnchor {
  readonly name: string;
  anchor(checkpoint: AuditCheckpoint): Promise<AnchorReceipt>;
}
/**
 * Appends each checkpoint as one JSON line to `<directory>/<stream>.jsonl`. Meant
 * for a mount that the gateway host cannot rewrite (object-lock bucket mount,
 * append-only volume); on an ordinary disk it is only a local copy.
 */
export class FileAnchor implements CheckpointAnchor {
  readonly name = 'file';
  private directory: string;
  constructor(directory: string) { this.directory = directory; }
  async anchor(cp: AuditCheckpoint): Promise<AnchorReceipt> {
    if ((cp?.format !== 'akac-audit-checkpoint/2' && cp?.format !== 'akac-audit-checkpoint/3') || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(cp.stream) || !isHash(cp.rootHash)) throw new Error('Invalid checkpoint');
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    const file = join(this.directory, `${cp.stream.replace(/:/g, '_')}.jsonl`);
    appendFileSync(file, JSON.stringify(cp) + '\n', { mode: 0o600 });
    return { anchor: this.name, stream: cp.stream, treeSize: cp.treeSize, rootHash: cp.rootHash, reference: `${file}#${cp.treeSize}` };
  }
  /** Every anchored checkpoint of a stream, oldest first (for verification against the live stream). */
  static read(directory: string, stream: string): AuditCheckpoint[] {
    let text: string;
    try { text = readFileSync(join(directory, `${stream.replace(/:/g, '_')}.jsonl`), 'utf8'); } catch { return []; }
    return text.split('\n').filter(Boolean).map(line => JSON.parse(line) as AuditCheckpoint);
  }
}

export type CheckpointCheck = { alg: AlgorithmId; treeSize: number; rootHash: string; keyId: string; signature: 'verified' | 'unchecked' | Extract<KeyringVerdict, { ok: false }>['reason']; prefix: boolean; ok: boolean };
export type AuditVerification = {
  tenant: string; treeSize: number; rootHash: string;
  /** Hash chain of the whole stream from sequence 1. */
  chain: boolean;
  /** Stored RFC 9162 tree head equals the root recomputed from the entries (`grew`: the stream grew while it was read). */
  storedTree: boolean | 'grew';
  checkpoints: CheckpointCheck[];
  ok: boolean;
};
/**
 * The audit-verify job (0.6, ADR-016): reads the whole tenant stream in pages,
 * verifies the hash chain, recomputes the RFC 9162 root, cross-checks the store's
 * incremental tree head, and checks that every given checkpoint (for example the
 * anchored ones, or the one taken before a backup) is a prefix of the stream:
 * the root of its first treeSize entries equals its rootHash. With a keyring the
 * checkpoint signatures are verified too; without one they are reported unchecked.
 */
export async function verifyAuditStream(store: Store, tenant: string, options: { checkpoints?: AuditCheckpoint[]; keyring?: Keyring; page?: number; policy?: VerifierPolicy; floor?: AlgorithmFloor } = {}): Promise<AuditVerification> {
  const page = options.page ?? 10_000, entries: Audit[] = [];
  for (let after = 0; ;) {
    const batch = await store.auditLog(tenant, after, page);
    entries.push(...batch);
    if (batch.length < page) break;
    after = batch.at(-1)!.sequence;
  }
  const chain = verifyAudit(entries) && entries.every((e, i) => e.tenant === tenant && e.sequence === i + 1);
  const leaves = entries.map(auditLeaf), rootHash = rootOf(leaves);
  const head = await treeHead(store, tenant);
  const storedTree = head.treeSize > entries.length ? 'grew' as const : head.treeSize === entries.length && head.rootHash === rootHash;
  // No-downgrade (0.6, ADR-021): the earliest signature-verified checkpoint with a post-quantum component sets the floor of the
  // stream; a verified classical-only checkpoint that is newer or larger is a downgrade. Needs a keyring (claims alone prove nothing).
  const policy = options.policy ?? DEFAULT_POLICY, floor = options.floor ?? new AlgorithmFloor(policy);
  const verdicts = (options.checkpoints ?? []).map(cp => options.keyring ? verifyWithKeyring(cp, options.keyring, tenant, { policy }) : undefined);
  const algOf = (cp: AuditCheckpoint) => (isAlgorithm(checkpointAlgorithm(cp)) ? checkpointAlgorithm(cp) : 'ed25519' as AlgorithmId);
  const headOf = (cp: AuditCheckpoint) => ({ stream: cp.stream, alg: algOf(cp), issuedAt: cp.issuedAt, treeSize: cp.treeSize });
  (options.checkpoints ?? []).forEach((cp, i) => { if (verdicts[i]?.ok) floor.observe(headOf(cp)); });
  const checkpoints = (options.checkpoints ?? []).map((cp, i): CheckpointCheck => {
    const prefix = chain && safeNumber(cp?.treeSize) && cp.treeSize <= entries.length && cp.stream === tenant && rootOf(leaves, 0, cp.treeSize) === cp.rootHash;
    const v = verdicts[i];
    let signature: CheckpointCheck['signature'] = 'unchecked';
    if (v) signature = v.ok ? (floor.check(headOf(cp)) === 'downgrade' ? 'downgrade' : 'verified') : v.reason;
    return { alg: algOf(cp), treeSize: cp?.treeSize, rootHash: cp?.rootHash, keyId: cp?.keyId, signature, prefix, ok: prefix && (signature === 'verified' || signature === 'unchecked') };
  });
  return { tenant, treeSize: entries.length, rootHash, chain, storedTree, checkpoints, ok: chain && storedTree !== false && checkpoints.every(c => c.ok) };
}
