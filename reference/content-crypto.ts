import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import type { Knowledge, Need, Store, Tx } from './types.ts';
import { tombstone } from './lifecycle.ts';
import { validId } from './validation.ts';

/**
 * Content encryption at rest and crypto-shredding (0.6, R195, ADR-022).
 *
 * Every stored record content is sealed with AES-256-GCM under a fresh 256-bit content
 * encryption key (CEK) per record version; the CEK is wrapped by a KeyProvider under key
 * material that belongs to that record alone. Erasing the record tombstones it (R-LIFE-9)
 * and then destroys that key material, so the content becomes unreadable everywhere it
 * was copied, backups included, provided the key material itself is not in the same
 * backup. The associated data binds each ciphertext to its tenant, record id and version,
 * so a ciphertext moved to another record or version does not decrypt.
 *
 * Scope: record content only. Labels, ACLs, provenance and audit metadata stay in the
 * clear (every gate needs them). Chunk text is never stored (the vector index holds
 * embeddings and label metadata only), but embeddings of restricted content are protected
 * data too: encrypt the database volume and its backups (operator obligation). The community edition ships only a local development provider;
 * KMS and HSM providers implement the same interface and are not part of this repository.
 */
export interface KeyProvider {
  /** Provider id recorded in every envelope: 1-64 of a-z 0-9 - (no colon). */
  readonly id: string;
  /** Wraps the CEK of one record; the result is opaque, 1-4096 characters of A-Z a-z 0-9 . _ - */
  wrap(tenant: string, record: string, cek: Uint8Array): Promise<string>;
  /**
   * Unwraps; MUST reject for a record whose key material was destroyed, and for a wrapped key of another record.
   * A provider SHOULD reject with KeyDestroyed only when it positively knows the key material of this record was
   * destroyed; any other rejection (timeout, key service down, permission) reads as unreadable, never as erased.
   */
  unwrap(tenant: string, record: string, wrapped: string): Promise<Uint8Array>;
  /** Destroys the key material of one record (every version). Idempotent. */
  destroy(tenant: string, record: string): Promise<void>;
}
/**
 * Rejection of KeyProvider.unwrap() that means "this record's key material was destroyed" (crypto-shredded).
 * Only this rejection makes a record read as erased; every other failure makes it unreadable (0.6b, R195).
 */
export class KeyDestroyed extends Error {
  constructor() { super('Content key destroyed'); this.name = 'KeyDestroyed'; }
}
/** A transaction tried to write a record whose content could not be opened (0.6b); the store refuses it (DEFERRED:STORE_ERROR). */
export class UnreadableRecord extends Error {
  constructor() { super('Record content unreadable; refusing to write it'); this.name = 'UnreadableRecord'; }
}
export const PROVIDER_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const WRAPPED = /^[A-Za-z0-9._-]{1,4096}$/;
const B64 = /^[A-Za-z0-9_-]+$/;
const PREFIX = 'akac-enc:1:';
export const isEnvelope = (content: unknown): content is string => typeof content === 'string' && content.startsWith(PREFIX);
const aad = (tenant: string, id: string, version: number) => Buffer.from(`akac-content/1\n${tenant}\n${id}\n${version}`, 'utf8');

/** Seals one record's content: `akac-enc:1:<provider>:<wrapped CEK>:<iv>:<ciphertext||tag>` (base64url). */
export async function seal(provider: KeyProvider, tenant: string, record: Pick<Knowledge, 'id' | 'version'>, text: string): Promise<string> {
  const cek = randomBytes(32), iv = randomBytes(12);
  try {
    const wrapped = await provider.wrap(tenant, record.id, cek);
    if (!PROVIDER_ID.test(provider.id) || typeof wrapped !== 'string' || !WRAPPED.test(wrapped)) throw new Error('Invalid key provider result');
    const cipher = createCipheriv('aes-256-gcm', cek, iv);
    cipher.setAAD(aad(tenant, record.id, record.version));
    const body = Buffer.concat([cipher.update(text, 'utf8'), cipher.final(), cipher.getAuthTag()]);
    return `${PREFIX}${provider.id}:${wrapped}:${iv.toString('base64url')}:${body.toString('base64url')}`;
  } finally { cek.fill(0); }
}
/** Opens an envelope of this record; throws when it is malformed, of another record or version, or its key was destroyed. */
export async function open(provider: KeyProvider, tenant: string, record: Pick<Knowledge, 'id' | 'version'>, envelope: string): Promise<string> {
  const parts = envelope.slice(PREFIX.length).split(':');
  if (!isEnvelope(envelope) || parts.length !== 4) throw new Error('Malformed envelope');
  const [id, wrapped, iv, body] = parts as [string, string, string, string];
  if (id !== provider.id || !WRAPPED.test(wrapped) || !B64.test(iv) || !B64.test(body)) throw new Error('Malformed envelope');
  const nonce = Buffer.from(iv, 'base64url'), data = Buffer.from(body, 'base64url');
  if (nonce.length !== 12 || data.length < 16) throw new Error('Malformed envelope');
  const cek = Buffer.from(await provider.unwrap(tenant, record.id, wrapped));
  try {
    if (cek.length !== 32) throw new Error('Invalid content key');
    const decipher = createDecipheriv('aes-256-gcm', cek, nonce);
    decipher.setAAD(aad(tenant, record.id, record.version));
    decipher.setAuthTag(data.subarray(data.length - 16));
    return Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]).toString('utf8');
  } finally { cek.fill(0); }
}

/**
 * Local development key provider: one random 256-bit key-encryption key per record in a
 * JSON file (created with mode 0600, written atomically). NOT FOR PRODUCTION: the keys
 * sit next to the service, a single process owns the file, and a copy of the file in a
 * backup defeats crypto-shredding. Production deployments use a KMS or HSM provider.
 */
export class LocalDevKeyProvider implements KeyProvider {
  readonly id = 'local-dev';
  private path: string;
  private keys: Record<string, string>;
  constructor(path: string) {
    this.path = path;
    if (existsSync(path)) {
      if (process.platform !== 'win32' && (statSync(path).mode & 0o077) !== 0) throw new Error('Content key file must not be readable by group or others (chmod 600)');
      const data = JSON.parse(readFileSync(path, 'utf8')) as { format?: unknown; keys?: unknown };
      if (data.format !== 'akac-local-content-keys/1' || !data.keys || typeof data.keys !== 'object' || Array.isArray(data.keys)) throw new Error('Invalid content key file');
      this.keys = Object.assign(Object.create(null) as Record<string, string>, data.keys as Record<string, string>);
    } else this.keys = Object.create(null) as Record<string, string>;
  }
  private name(tenant: string, record: string) {
    if (!validId(tenant) || !validId(record)) throw new Error('Invalid key name');
    return `${tenant}/${record}`;
  }
  private persist() {
    const next = `${this.path}.tmp-${process.pid}`;
    writeFileSync(next, JSON.stringify({ format: 'akac-local-content-keys/1', keys: this.keys }), { mode: 0o600 });
    if (process.platform !== 'win32') chmodSync(next, 0o600);
    renameSync(next, this.path);
  }
  private kek(name: string): Buffer | undefined {
    const k = this.keys[name];
    return typeof k === 'string' && B64.test(k) ? Buffer.from(k, 'base64url') : undefined;
  }
  async wrap(tenant: string, record: string, cek: Uint8Array): Promise<string> {
    const name = this.name(tenant, record);
    let kek = this.kek(name);
    if (!kek) { kek = randomBytes(32); this.keys[name] = kek.toString('base64url'); this.persist(); }
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', kek, iv);
    cipher.setAAD(Buffer.from(`akac-cek/1\n${name}`, 'utf8'));
    const out = Buffer.concat([cipher.update(cek), cipher.final(), cipher.getAuthTag()]);
    kek.fill(0);
    return `${iv.toString('base64url')}.${out.toString('base64url')}`;
  }
  async unwrap(tenant: string, record: string, wrapped: string): Promise<Uint8Array> {
    const name = this.name(tenant, record), kek = this.kek(name);
    if (!kek) throw new KeyDestroyed();
    const [iv, body] = wrapped.split('.');
    if (!iv || !body || !B64.test(iv) || !B64.test(body)) throw new Error('Malformed wrapped key');
    const data = Buffer.from(body, 'base64url');
    try {
      const decipher = createDecipheriv('aes-256-gcm', kek, Buffer.from(iv, 'base64url'));
      decipher.setAAD(Buffer.from(`akac-cek/1\n${name}`, 'utf8'));
      decipher.setAuthTag(data.subarray(data.length - 16));
      return Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]);
    } finally { kek.fill(0); }
  }
  async destroy(tenant: string, record: string): Promise<void> {
    const name = this.name(tenant, record);
    if (!(name in this.keys)) return;
    delete this.keys[name];
    this.persist();
  }
}

/** Crypto-shredding outcome of one committed transaction (metrics; no content, no ids). */
export type ShredEvent = { type: 'shredded'; tenant: string; records: number } | { type: 'shred_failed'; tenant: string; records: number } | { type: 'unreadable'; tenant: string; records: number };
/**
 * A Store that keeps every record content sealed at rest (see seal()). Inside a
 * transaction the snapshot holds plaintext; before the underlying store commits, new or
 * changed content is sealed and unchanged records are put back exactly as stored (so a
 * read never rewrites a row). After the commit, the key material of every record the
 * transaction erased is destroyed. A record whose key the provider reports as destroyed
 * (KeyDestroyed, for example in a restored backup) is shown as its tombstone. A record whose
 * content cannot be opened for any other reason (key service down or slow, tampered
 * envelope) is shown with the internal `unreadable` flag and no content: every gate hides it
 * and everything derived from it, and any transaction that would change it fails
 * (UnreadableRecord, audited DEFERRED:STORE_ERROR) so it is never tombstoned, shredded or
 * overwritten on the strength of an outage (0.6b).
 * Pre-existing plaintext content stays readable and is sealed when its record next changes.
 */
export class EncryptingStore implements Store {
  readonly inner: Store;
  readonly auditTree?: Store['auditTree'];
  private provider: KeyProvider;
  private emit: (event: ShredEvent) => void;
  /** Records whose key destruction failed after their erasure committed; retried by shredPending(). */
  private pendingShreds = new Map<string, Set<string>>();
  constructor(inner: Store, provider: KeyProvider, options: { onEvent?: (event: ShredEvent) => void } = {}) {
    if (!PROVIDER_ID.test(provider?.id ?? '')) throw new Error('Invalid key provider');
    this.inner = inner; this.provider = provider;
    if (inner.auditTree) this.auditTree = inner.auditTree.bind(inner);
    const listener = options.onEvent; this.emit = e => { try { listener?.(e); } catch { /* metrics never affect storage */ } };
  }
  async transaction<T>(tenant: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    const shred: string[] = [];
    const result = await this.inner.transaction(tenant, async tx => {
      /** Stored form and the form handed to the operation, per processed record. */
      const seen = new Map<string, { stored: Knowledge; shown: string; text?: string; sealed?: string }>();
      let unreadable = 0;
      /** Records whose content could not be opened (not a destroyed key): any change to them aborts the transaction. */
      const locked = new Set<string>();
      const openAll = async () => {
        for (const [id, k] of Object.entries(tx.state.knowledge)) {
          if (seen.has(id) || k?.tenant !== tenant) continue;
          const stored = structuredClone(k);
          if (isEnvelope(k.content)) {
            try { const text = await open(this.provider, tenant, k, k.content); k.content = text; seen.set(id, { stored, shown: JSON.stringify(k), text, sealed: stored.content }); continue; }
            catch (error) {
              // Only a key the provider reports as destroyed reads as erased (a tombstone view). Anything else (key
              // service down, tampered envelope) is unreadable: hidden by every gate, and never written back (0.6b).
              if (error instanceof KeyDestroyed) tombstone(k, k.lifecycleAt ?? 0);
              else { k.content = ''; k.unreadable = true; locked.add(id); }
              unreadable++;
            }
          }
          seen.set(id, { stored, shown: JSON.stringify(k) });
        }
      };
      await openAll();
      const view: Tx = {
        get state() { return tx.state; },
        complete: tx.complete,
        load: async (need: Need) => { await tx.load(need); await openAll(); },
        ...(tx.catalog ? { catalog: tx.catalog.bind(tx) } : {}),
        ...(tx.countSodHolders ? { countSodHolders: tx.countSodHolders.bind(tx) } : {}),
        ...(tx.descendants ? { descendants: tx.descendants.bind(tx) } : {}),
        ...(tx.retentionDue ? { retentionDue: tx.retentionDue.bind(tx) } : {}),
        ...(tx.modelRecords ? { modelRecords: tx.modelRecords.bind(tx) } : {}),
        ...(tx.pendingErasures ? { pendingErasures: tx.pendingErasures.bind(tx) } : {})
      };
      if (unreadable) this.emit({ type: 'unreadable', tenant, records: unreadable });
      const value = await fn(view);
      await openAll(); // records a load added late are sealed like the rest
      for (const [id, k] of Object.entries(tx.state.knowledge)) {
        if (k?.tenant !== tenant) continue;
        const before = seen.get(id);
        if (before && JSON.stringify(k) === before.shown) { tx.state.knowledge[id] = before.stored; continue; }
        // Never persist, tombstone, shred or overwrite a record that could not be opened: the key service may only be
        // down, and its real content (and legal hold) must survive. The whole transaction fails; callers defer.
        if (locked.has(id) || k.unreadable !== undefined) throw new UnreadableRecord();
        if (k.lifecycle === 'erased' && (before?.sealed !== undefined || isEnvelope(before?.stored.content))) shred.push(id);
        if (typeof k.content !== 'string' || k.content === '' || isEnvelope(k.content)) continue;
        // Unchanged text of the same version keeps its ciphertext; anything else is sealed afresh.
        k.content = before && before.text === k.content && before.stored.version === k.version && before.sealed !== undefined
          ? before.sealed : await seal(this.provider, tenant, k, k.content);
      }
      return value;
    });
    if (shred.length) await this.destroy(tenant, shred);
    return result;
  }
  private async destroy(tenant: string, ids: readonly string[]) {
    let failed = 0;
    for (const id of ids) {
      try { await this.provider.destroy(tenant, id); this.pendingShreds.get(tenant)?.delete(id); }
      catch { failed++; let set = this.pendingShreds.get(tenant); if (!set) { set = new Set(); this.pendingShreds.set(tenant, set); } set.add(id); }
    }
    if (ids.length - failed) this.emit({ type: 'shredded', tenant, records: ids.length - failed });
    if (failed) this.emit({ type: 'shred_failed', tenant, records: failed });
  }
  /** Retries key destruction that failed after an erasure committed (the erasure itself stands). Returns how many are still pending. */
  async shredPending(tenant: string): Promise<number> {
    const ids = [...this.pendingShreds.get(tenant) ?? []];
    if (ids.length) await this.destroy(tenant, ids);
    return this.pendingShreds.get(tenant)?.size ?? 0;
  }
  /** Destroys the key material of records erased earlier (for example before encryption was configured). */
  async shred(tenant: string, ids: readonly string[]): Promise<void> {
    if (!validId(tenant) || !ids.every(validId)) throw new Error('Invalid shred request');
    await this.destroy(tenant, ids);
  }
  ready(tenant?: string) { return this.inner.ready(tenant); }
  auditLog(tenant: string, after?: number, limit?: number) { return this.inner.auditLog(tenant, after, limit); }
  close() { return this.inner.close(); }
}
