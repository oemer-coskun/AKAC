import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import fc from 'fast-check';
import { canonicalize } from '../reference/jcs.ts';
import { EMPTY_ROOT, Frontier, consistencyRanges, inclusionRanges, leafHash, leafLookup, nodeHash, perfectKeys, rangeHash, rootKeys, rootOf,
  verifyConsistency, verifyInclusion } from '../reference/merkle.ts';
import { appendAudit, auditHash, auditLeaf, GENESIS, verifyAudit } from '../reference/audit.ts';
import { signCheckpoint, signCheckpointV2, signTreeHead, verifyCheckpoint, verifyCheckpointExtension, verifyCheckpointV2, verifyAuditCheckpoint } from '../reference/checkpoint.ts';
import { consistencyProof, inclusionProof, treeHead } from '../reference/evidence.ts';
import { Engine } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { MemoryStore, SqliteStore } from '../reference/store.ts';
import { emptyState } from '../reference/types.ts';
import type { Audit, Store } from '../reference/types.ts';
import { fixture, bindings } from '../examples/fixture.ts';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const now = 1800000000000;
const hex = (b: Buffer | string) => typeof b === 'string' ? b : b.toString('hex');
const keys = () => {
  const pair = generateKeyPairSync('ed25519');
  return { privatePem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), publicPem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString() };
};

// --- RFC 8785 -------------------------------------------------------------
test('JCS: RFC 8785 member ordering by UTF-16 code units, literals and string escaping', () => {
  // The property-sorting example of RFC 8785 §3.2.3 (keys only; values are plain strings here).
  const input = { '€': 'Euro Sign', '\r': 'Carriage Return', 'דּ': 'Hebrew Letter Dalet With Dagesh', '1': 'One',
    '😀': 'Emoji: Grinning Face', '\u0080': 'Control', 'ö': 'Latin Small Letter O With Diaeresis' };
  const text = canonicalize(input), at = Object.keys(input).map(k => [k, text.indexOf(JSON.stringify(k) + ':')] as const);
  assert.deepEqual(at.sort((x, y) => x[1] - y[1]).map(x => x[0].codePointAt(0)), [0x0d, 0x31, 0x80, 0xf6, 0x20ac, 0x1f600, 0xfb33]);
  assert.equal(canonicalize({ b: [true, false, null, -0, 42, 'x"\\\n\u001f'], a: {} }), '{"a":{},"b":[true,false,null,0,42,"x\\"\\\\\\n\\u001f"]}');
  assert.equal(canonicalize(' /'), '" /"', 'no extra escaping beyond ECMAScript JSON.stringify');
  for (const bad of [1.5, NaN, Infinity, 2 ** 53, undefined, '\ud800', { k: undefined }, new Date(0), [() => 1], 10n]) assert.throws(() => canonicalize(bad), String(bad));
});

// --- RFC 9162 Merkle tree -------------------------------------------------
// The eight-leaf test tree used for RFC 6962 implementations: leaf inputs and roots.
const INPUTS = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'];
const ROOTS = ['6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d', 'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77', 'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4', '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c', '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328'];
const LEAVES = INPUTS.map(h => leafHash(Buffer.from(h, 'hex')));

/** Independent naive RFC 9162 §2.1 implementation over raw leaf hashes (slices, no ranges, no lookups). */
const naive = {
  split: (n: number) => 2 ** Math.ceil(Math.log2(n)) / 2,
  mth(d: string[]): string {
    if (d.length === 0) return createHash('sha256').digest('hex');
    if (d.length === 1) return d[0]!;
    const k = naive.split(d.length);
    return hex(createHash('sha256').update(Buffer.concat([Buffer.of(1), Buffer.from(naive.mth(d.slice(0, k)), 'hex'), Buffer.from(naive.mth(d.slice(k)), 'hex')])).digest());
  },
  path(m: number, d: string[]): string[] {
    if (d.length <= 1) return [];
    const k = naive.split(d.length);
    return m < k ? [...naive.path(m, d.slice(0, k)), naive.mth(d.slice(k))] : [...naive.path(m - k, d.slice(k)), naive.mth(d.slice(0, k))];
  },
  sub(m: number, d: string[], b: boolean): string[] {
    if (m === d.length) return b ? [] : [naive.mth(d)];
    const k = naive.split(d.length);
    return m <= k ? [...naive.sub(m, d.slice(0, k), b), naive.mth(d.slice(k))] : [...naive.sub(m - k, d.slice(k), false), naive.mth(d.slice(0, k))];
  }
};
const random = (n: number) => Array.from({ length: n }, (_, i) => leafHash(Buffer.from(`synthetic-leaf-${i}`)));

test('Merkle: RFC 6962/9162 eight-leaf test tree (roots, inclusion and consistency proofs)', () => {
  assert.equal(EMPTY_ROOT, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  for (let n = 1; n <= 8; n++) assert.equal(rootOf(LEAVES.slice(0, n)), ROOTS[n - 1], `root ${n}`);
  const look = leafLookup(LEAVES);
  const proof = (ranges: [number, number][]) => ranges.map(r => rangeHash(look, r));
  assert.deepEqual(proof(inclusionRanges(0, 8)), ['96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
    '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e', '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4']);
  assert.deepEqual(proof(consistencyRanges(1, 8)), proof(inclusionRanges(0, 8)));
  assert.deepEqual(proof(consistencyRanges(6, 8)), ['0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a',
    'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0', 'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7']);
  assert.deepEqual(proof(consistencyRanges(2, 5)), ['5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
    'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b']);
  assert.deepEqual(consistencyRanges(4, 4), []);
});

test('Merkle: range-based proofs equal an independent naive implementation for every m <= n <= 40', () => {
  const leaves = random(40);
  for (let n = 1; n <= 40; n++) {
    const d = leaves.slice(0, n), look = leafLookup(d);
    assert.equal(rootOf(d), naive.mth(d));
    for (let m = 0; m < n; m++) assert.deepEqual(inclusionRanges(m, n).map(r => rangeHash(look, r)), naive.path(m, d), `path ${m}/${n}`);
    for (let m = 1; m <= n; m++) assert.deepEqual(consistencyRanges(m, n).map(r => rangeHash(look, r)), naive.sub(m, d, true), `proof ${m}/${n}`);
  }
});

test('Merkle: the incremental frontier stores exactly the perfect subtrees and yields the RFC root', () => {
  const leaves = random(70), frontier = new Frontier(), nodes = new Map<string, string>();
  for (const [i, leaf] of leaves.entries()) {
    for (const n of frontier.append(leaf)) { assert.ok(!nodes.has(`${n.level}:${n.index}`), 'a node is written once'); nodes.set(`${n.level}:${n.index}`, n.hash); }
    assert.equal(frontier.root(), rootOf(leaves.slice(0, i + 1)));
    // A frontier resumed from stored nodes continues identically (what a store does per transaction).
    const resumed = new Frontier(i + 1, new Map(rootKeys(i + 1).map(k => [k.level, nodes.get(`${k.level}:${k.index}`)!])));
    assert.equal(resumed.root(), frontier.root());
  }
  const look = leafLookup(leaves);
  for (const [key, hash] of nodes) { const [level, index] = key.split(':').map(Number); assert.equal(look({ level: level!, index: index! }), hash); }
  assert.equal(nodes.size, 2 * 70 - [...(70).toString(2)].filter(b => b === '1').length, 'n leaves complete 2n - popcount(n) perfect subtrees');
  assert.throws(() => new Frontier(5, new Map([[2, leaves[0]!]])), /Inconsistent/);
  assert.throws(() => perfectKeys([1, 3]), /unaligned/);
});

test('Merkle (property): inclusion and consistency proofs verify, and any tampering fails', () => {
  const leaves = random(301);
  fc.assert(fc.property(fc.integer({ min: 1, max: 300 }), fc.integer({ min: 0, max: 299 }), fc.integer({ min: 0, max: 63 }), (n, raw, flip) => {
    const m = raw % n, d = leaves.slice(0, n), look = leafLookup(d), root = rootOf(d);
    const path = inclusionRanges(m, n).map(r => rangeHash(look, r));
    assert.ok(verifyInclusion(d[m]!, m, n, path, root));
    assert.equal(verifyInclusion(d[(m + 1) % n]!, m, n, path, root), n === 1, 'another leaf');
    if (n > 1) assert.equal(verifyInclusion(d[m]!, (m + 1) % n, n, path, root), false, 'another index');
    if (path.length) {
      const tampered = [...path]; const i = flip % path.length;
      tampered[i] = nodeHash(tampered[i]!, tampered[i]!);
      assert.equal(verifyInclusion(d[m]!, m, n, tampered, root), false, 'tampered path');
      assert.equal(verifyInclusion(d[m]!, m, n, path.slice(0, -1), root), false, 'truncated path');
    }
    const first = 1 + raw % n, cpath = consistencyRanges(first, n).map(r => rangeHash(look, r)), old = rootOf(d.slice(0, first));
    assert.ok(verifyConsistency(first, n, old, root, cpath));
    if (first < n) {
      assert.equal(verifyConsistency(first, n, rootOf(leaves.slice(1, first + 1)), root, cpath), false, 'different history');
      assert.equal(verifyConsistency(first, n, old, rootOf(leaves.slice(0, n + 1)), cpath), false, 'different new tree');
      assert.equal(verifyConsistency(n, first, root, old, cpath), false, 'shrinking tree');
      assert.equal(verifyConsistency(first, n, old, root, []), false, 'empty proof');
    }
    return true;
  }), { numRuns: 300 });
});

// --- Audit format 2 ---------------------------------------------------------
function legacyEntries(tenant: string, count: number): Audit[] {
  const out: Audit[] = []; let previous = GENESIS;
  for (let i = 1; i <= count; i++) {
    const body = { sequence: i, time: now + i, tenant, actor: `actor-${i}`, operation: 'read', decision: 'deny' as const,
      reason: 'DENIED:KNOWLEDGE_BOUNDARY', policyVersion: 'akac-reference/0.3.0|v|core-only', epoch: 0, previous };
    const hash = auditHash(body); out.push({ ...body, hash }); previous = hash;
  }
  return out;
}
const v2 = (s = emptyState(), tenant = 'acme', reason = 'AUTHORIZED') => appendAudit(s, { time: now, tenant, actor: 'someone', operation: 'read',
  decision: reason === 'AUTHORIZED' ? 'allow' : 'deny', reason, policyVersion: 'p', epoch: 0, decisionId: '0f8fad5b-d9cb-469f-a165-70867728950e',
  reasonCode: reason === 'AUTHORIZED' ? 'AUTHORIZED' : 'KNOWLEDGE_BOUNDARY', policyDigest: 'a'.repeat(64), obligations: [], runId: 'run-1' });

test('audit: format 2 entries are JCS-hashed, closed and chained after format 1 entries; downgrades fail', () => {
  const s = emptyState(); s.audits = legacyEntries('acme', 3);
  const entry = v2(s);
  assert.equal(entry.formatVersion, 2); assert.equal(entry.previous, s.audits[2]!.hash, 'the chain continues across the format change');
  const { hash, ...body } = entry;
  assert.equal(hash, createHash('sha256').update(canonicalize(body)).digest('hex'));
  assert.ok(verifyAudit(s.audits));
  v2(s, 'acme', 'DENIED:KNOWLEDGE_BOUNDARY'); assert.ok(verifyAudit(s.audits));
  const mutate = (fn: (a: Audit[]) => void) => { const copy = structuredClone(s.audits); fn(copy); return verifyAudit(copy); };
  assert.equal(mutate(a => { a[3]!.reasonCode = 'AUTHORIZED_RECIPIENT'; }), false, 'reason code must match the reason');
  assert.equal(mutate(a => { (a[3] as Record<string, unknown>).extra = 1; }), false, 'closed shape');
  assert.equal(mutate(a => { a[3]!.decisionId = 'not-a-uuid'; }), false);
  assert.equal(mutate(a => { a[4]!.obligations = [{ type: 'no_persist' }]; }), false, 'a deny carries no obligations');
  assert.equal(mutate(a => { a[3]!.obligations = [{ type: 'retain_forever' } as never]; }), false, 'unknown obligation');
  assert.equal(mutate(a => { a[3]!.formatVersion = 3 as never; }), false, 'unknown format');
  // Downgrade: a format 1 entry after format 2 in the same stream, even with a valid format 1 hash.
  const downgrade = structuredClone(s.audits);
  const body1 = { sequence: 6, time: now, tenant: 'acme', actor: 'x', operation: 'read', decision: 'allow' as const, reason: 'AUTHORIZED', policyVersion: 'p', epoch: 0, previous: downgrade[4]!.hash };
  downgrade.push({ ...body1, hash: auditHash(body1) });
  assert.equal(verifyAudit(downgrade), false);
  assert.throws(() => appendAudit(emptyState(), { ...structuredClone(entry), reasonCode: 'NOT_A_CODE' as never } as never), /Malformed/);
});

test('audit leaves: H(0x00 || JCS(entry)) for both formats', () => {
  const [old] = legacyEntries('acme', 1), next = v2();
  for (const e of [old!, next]) assert.equal(auditLeaf(e), leafHash(Buffer.from(canonicalize(e), 'utf8')));
});

// --- Checkpoints ------------------------------------------------------------
async function stream(store: Store, count: number) {
  const engine = new Engine(store, { clock: () => now });
  for (let i = 0; i < count; i++) await engine.openContext(bindings.intern, [i % 2 ? 'handbook' : 'strategy'], 'work');
  return store.auditLog('acme');
}

test('checkpoint v2: signs the RFC 9162 root; entry rewrite, reordering, truncation and key substitution are detected', async () => {
  const { privatePem, publicPem } = keys();
  const entries = await stream(new MemoryStore(fixture(now)), 9);
  const record = signCheckpointV2(entries, privatePem, 'acme', 'key-a', now);
  assert.equal(record.treeSize, 9); assert.equal(record.rootHash, rootOf(entries.map(auditLeaf)));
  const check = (logs: Audit[] | undefined, c = record, key = publicPem, minimumSize = 0) => verifyCheckpointV2(c, key, 'acme', 'key-a', { ...(logs ? { entries: logs } : {}), minimumSize });
  assert.ok(check(undefined)); assert.ok(check(entries));
  const rewritten = structuredClone(entries); rewritten[4]!.reason = 'DENIED:IDENTITY_BOUNDARY';
  assert.equal(check(rewritten), false, 'modified entry');
  const reordered = structuredClone(entries); [reordered[2], reordered[3]] = [reordered[3]!, reordered[2]!];
  assert.equal(check(reordered), false, 'reordered entries');
  assert.equal(check(entries.slice(0, 8)), false, 'truncated stream');
  assert.equal(check(undefined, { ...record, rootHash: '0'.repeat(64) }), false, 'forged root');
  assert.equal(check(undefined, { ...record, treeSize: 8 }), false, 'signed size');
  assert.equal(check(undefined, record, keys().publicPem), false, 'substituted key');
  assert.equal(check(undefined, record, publicPem, 10), false, 'rollback below a trusted size');
  assert.equal(verifyCheckpointV2(record, publicPem, 'other', 'key-a'), false, 'stream binding');
  assert.throws(() => signCheckpointV2(entries, privatePem, 'other', 'key-a'), /Invalid/);
  // Format 1 checkpoints still verify over format 2 entries.
  const v1 = signCheckpoint(entries, privatePem, 'acme', 'key-a', now);
  assert.ok(verifyCheckpoint(entries, v1, publicPem, 'acme', 'key-a', 9));
});

test('checkpoint v2: consistency proofs accept an extension and reject a forked, rolled-back or truncated history', async () => {
  const { privatePem } = keys();
  const store = new MemoryStore(fixture(now));
  const early = await stream(store, 6);
  const older = signCheckpointV2(early, privatePem, 'acme', 'k', now);
  const later = await stream(store, 5);
  const newer = signCheckpointV2(later, privatePem, 'acme', 'k', now + 1);
  const honest = await consistencyProof(store, 'acme', older.treeSize, newer.treeSize);
  assert.ok(verifyCheckpointExtension(older, newer, honest.path));
  // A forked history: entry 3 rewritten and the chain re-hashed from there. It still verifies as a chain.
  const forked = structuredClone(later);
  forked[2]!.actor = 'someone-else';
  for (let i = 2; i < forked.length; i++) {
    if (i > 2) forked[i]!.previous = forked[i - 1]!.hash;
    const { hash: _h, ...body } = forked[i]!; forked[i]!.hash = createHash('sha256').update(canonicalize(body)).digest('hex');
  }
  assert.ok(verifyAudit(forked), 'the rewritten chain is internally consistent');
  const forkedHead = signCheckpointV2(forked, privatePem, 'acme', 'k', now + 2);
  const look = leafLookup(forked.map(auditLeaf));
  const forkProof = consistencyRanges(older.treeSize, forked.length).map(r => rangeHash(look, r));
  assert.equal(verifyCheckpointExtension(older, forkedHead, forkProof), false, 'fork detected against the older checkpoint');
  assert.equal(verifyCheckpointExtension(older, forkedHead, honest.path), false);
  // Rolled back / truncated: a newer checkpoint smaller than the trusted one.
  const truncated = signCheckpointV2(later.slice(0, 4), privatePem, 'acme', 'k', now + 3);
  assert.equal(verifyCheckpointExtension(older, truncated, []), false);
  assert.equal(verifyCheckpointExtension(older, { ...newer, stream: 'other' }, honest.path), false);
});

test('evidence: proofs and tree heads match for memory, SQLite and the auditLog fallback', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'akac-evidence-'));
  const sqlite = new SqliteStore(join(dir, 'state.db'));
  try {
    const { importState } = await import('../reference/store.ts');
    await importState(sqlite, fixture(now));
    const memory = new MemoryStore(fixture(now));
    for (const store of [memory, sqlite]) await stream(store, 13);
    const plain: Store = { transaction: memory.transaction.bind(memory), ready: memory.ready.bind(memory), auditLog: memory.auditLog.bind(memory), close: async () => {} };
    for (const store of [memory, sqlite, plain]) {
      const entries = await store.auditLog('acme'), leaves = entries.map(auditLeaf);
      const head = await treeHead(store, 'acme');
      assert.deepEqual(head, { stream: 'acme', treeSize: 13, rootHash: rootOf(leaves) });
      for (const [m, n] of [[0, 1], [5, 13], [12, 13], [7, 8]] as const) {
        const p = await inclusionProof(store, 'acme', m, n);
        assert.ok(verifyInclusion(leaves[m]!, m, n, p.path, rootOf(leaves.slice(0, n))));
      }
      const c = await consistencyProof(store, 'acme', 5, 13);
      assert.ok(verifyConsistency(5, 13, rootOf(leaves.slice(0, 5)), head.rootHash, c.path));
      await assert.rejects(inclusionProof(store, 'acme', 3, 14));
    }
  } finally { await sqlite.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('control plane: auditor proofs are audited, range-checked and verify against a signed tree head', async () => {
  const { privatePem, publicPem } = keys();
  const s = fixture(now); s.actors.aud = { id: 'aud', tenant: 'acme', kind: 'user', roles: ['auditor'], projects: [], clearance: 'public', active: true };
  const store = new MemoryStore(s);
  await stream(store, 4);
  const control = new ControlPlane(store, { clock: () => now, checkpoint: { privatePem, keyId: 'server-key' } });
  const latest = await control.latestCheckpoint('acme', 'aud'); assert.ok(latest.ok);
  const { head, checkpoint } = latest.value;
  assert.equal(head.treeSize, 5, 'four decisions plus the checkpoint read itself');
  assert.ok(checkpoint && verifyAuditCheckpoint(checkpoint, publicPem, 'acme', 'server-key', { entries: await store.auditLog('acme') }));
  const proof = await control.auditProof('acme', 'aud', 1, head.treeSize); assert.ok(proof.ok);
  const entries = await store.auditLog('acme');
  assert.ok(verifyInclusion(auditLeaf(entries[1]!), 1, head.treeSize, proof.value.path, head.rootHash));
  assert.equal(proof.value.leafHash, auditLeaf(entries[1]!));
  const later = await control.latestCheckpoint('acme', 'aud'); assert.ok(later.ok);
  const consistency = await control.auditConsistency('acme', 'aud', head.treeSize, later.value.head.treeSize); assert.ok(consistency.ok);
  assert.ok(verifyCheckpointExtension(checkpoint!, later.value.checkpoint!, consistency.value.path));
  // Refusals: out of range, wrong role. Every attempt is audited with its decision id.
  const outOfRange = await control.auditProof('acme', 'aud', 0, 10_000);
  assert.equal(outOfRange.ok, false); assert.equal(!outOfRange.ok && outOfRange.code, 'INVALID_REQUEST');
  assert.equal((await control.auditConsistency('acme', 'aud', 0, 3)).ok, false, 'first >= 1');
  const denied = await control.auditProof('acme', 'admin', 0, 1);
  assert.equal(!denied.ok && denied.code, 'NOT_AUTHORIZED');
  const log = await store.auditLog('acme');
  const byId = (id: string) => log.find(e => e.decisionId === id);
  assert.deepEqual([byId(outOfRange.decisionId)?.operation, byId(outOfRange.decisionId)?.reasonCode], ['audit_proof', 'INVALID_REQUEST']);
  assert.deepEqual([byId(denied.decisionId)?.reason, byId(denied.decisionId)?.reasonCode], ['DENIED:NOT_ADMIN', 'NOT_ADMIN']);
  assert.equal(byId(proof.decisionId)?.decision, 'allow');
  const unsigned = await new ControlPlane(store).latestCheckpoint('acme', 'aud');
  assert.ok(unsigned.ok && !unsigned.value.checkpoint, 'no key, no signature');
  assert.equal(signTreeHead(head, privatePem, 'k', now).format, 'akac-audit-checkpoint/2');
});
