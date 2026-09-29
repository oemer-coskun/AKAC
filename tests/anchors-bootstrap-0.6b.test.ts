// 0.6 review follow-up: embedding-anchor baselines never reset on restart (ADR-020), and AuthZEN applies the
// risk provider and pads every post-authentication response to the timing floor.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AnchorMonitor, FileAnchorBaseline, RetrievalDisabled } from '../reference/anchors.ts';
import { HashEmbedder } from '../reference/embedding.ts';
import type { Embedder } from '../reference/embedding.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryVectorIndex } from '../reference/vector.ts';
import { VectorCandidateSource } from '../reference/retrieval.ts';
import { createAuthzenGateway } from '../reference/authzen.ts';
import { MemoryStore } from '../reference/store.ts';
import type { Store } from '../reference/types.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';
import { close, listen } from './support.ts';

class Model implements Embedder {
  readonly dimensions = 16; model = 'model-a'; rotated = false;
  private base = new HashEmbedder(16);
  async embed(texts: string[]): Promise<Float32Array[]> {
    const v = await this.base.embed(texts);
    return this.rotated ? v.map(x => Float32Array.from([...x].map((_, i, a) => a[(i + 5) % a.length]!))) : v;
  }
}
const TEXTS = ['anchor one about invoices', 'anchor two about forecasts'];
const tmp = () => mkdtempSync(join(tmpdir(), 'akac-anchor-boot-'));

test('anchors: a restart without a stored baseline stays pending (retrieval disabled); a check never creates one', async () => {
  const dir = tmp();
  try {
    const store = new FileAnchorBaseline(join(dir, 'baseline.json')), embedder = new Model();
    // First life: bootstrapped explicitly, then the file is lost (for example an emptyDir volume) and the model swapped.
    assert.equal(await new AnchorMonitor({ embedder, anchors: TEXTS, store, bootstrap: true }).start(), 'ok');
    rmSync(join(dir, 'baseline.json'));
    embedder.rotated = true;
    const restarted = new AnchorMonitor({ embedder, anchors: TEXTS, store });
    assert.equal(await restarted.start(), 'pending', 'the swapped model is not silently adopted as the reference');
    assert.throws(() => restarted.assertEnabled(), RetrievalDisabled);
    assert.equal(await restarted.check(), 'pending', 'a periodic check never baselines either');
    // Retrieval through the vector source is a deferred denial and never queries the index.
    const index = new MemoryVectorIndex(); let queried = 0; const q = index.query.bind(index); index.query = async x => { queried++; return q(x); };
    const kb = new MemoryStore(kbFixture());
    const engine = new Engine(kb, { candidates: new VectorCandidateSource({ index, embedder, monitor: restarted }) });
    assert.equal((await engine.retrieve(bindings.chief, 'product', 'work')).ok, false);
    assert.equal(queried, 0); assert.equal((await kb.auditLog('acme')).at(-1)!.reason, 'DEFERRED:RETRIEVAL_DISABLED');
    // Explicit administrator re-baseline (POST /admin/v1/index/anchors/rebaseline) enables it and persists.
    await restarted.rebaseline(); restarted.assertEnabled();
    assert.equal(await new AnchorMonitor({ embedder, anchors: TEXTS, store }).start(), 'ok', 'the re-baseline survives the next restart');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('anchors: an unreadable baseline stays pending and is never replaced, not even by the bootstrap flag', async () => {
  const dir = tmp();
  try {
    const file = join(dir, 'baseline.json'), store = new FileAnchorBaseline(file), embedder = new Model();
    writeFileSync(file, '{not json');
    const m = new AnchorMonitor({ embedder, anchors: TEXTS, store, bootstrap: true });
    assert.equal(await m.start(), 'pending'); assert.throws(() => m.assertEnabled(), RetrievalDisabled);
    assert.equal(readFileSync(file, 'utf8'), '{not json', 'the unreadable file is left for the operator');
    // A path that exists but cannot be read as a file (a directory) is unreadable, not "missing".
    const dirPath = join(dir, 'as-dir'); mkdirSync(dirPath);
    assert.equal(await new AnchorMonitor({ embedder, anchors: TEXTS, store: new FileAnchorBaseline(dirPath), bootstrap: true }).start(), 'pending');
    if (process.platform !== 'win32' && process.getuid?.() !== 0) {
      const locked = join(dir, 'locked.json'); writeFileSync(locked, '{}'); chmodSync(locked, 0o000);
      assert.equal(await new AnchorMonitor({ embedder, anchors: TEXTS, store: new FileAnchorBaseline(locked), bootstrap: true }).start(), 'pending');
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('anchors: the bootstrap flag creates the baseline once and never overwrites an existing one', async () => {
  const dir = tmp();
  try {
    const file = join(dir, 'baseline.json'), store = new FileAnchorBaseline(file), embedder = new Model();
    const m = new AnchorMonitor({ embedder, anchors: TEXTS, store, bootstrap: true });
    assert.equal(await m.start(), 'ok');
    const first = readFileSync(file, 'utf8');
    embedder.rotated = true;
    assert.equal(await new AnchorMonitor({ embedder, anchors: TEXTS, store, bootstrap: true }).start(), 'drifted', 'an existing baseline is compared, not replaced');
    assert.equal(readFileSync(file, 'utf8'), first);
    // One-time per monitor: a second start() of the same monitor does not bootstrap again after the file is gone.
    rmSync(file); assert.equal(await m.start(), 'pending');
    assert.throws(() => new AnchorMonitor({ embedder, anchors: TEXTS, bootstrap: 'yes' as unknown as boolean }), /Invalid embedding anchor/);
    // Without a store (library use) nothing survives a restart, so the monitor also needs the explicit flag or a re-baseline.
    const bare = new AnchorMonitor({ embedder, anchors: TEXTS });
    assert.equal(await bare.start(), 'pending'); await bare.rebaseline(); assert.equal(bare.state, 'ok');
    // A failed save during re-baseline changes nothing.
    const failing = new AnchorMonitor({ embedder, anchors: TEXTS, store: { load: async () => undefined, save: async () => { throw new Error('disk full'); } } });
    await assert.rejects(failing.rebaseline()); assert.equal(failing.state, 'pending');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---- AuthZEN --------------------------------------------------------------------------------------------------------
const secret = () => randomBytes(24).toString('hex');
const ask = (user: string, agent: string, grant: string, resource: string) => ({ subject: { type: 'user', id: user, properties: { agent, grant } }, resource: { type: 'knowledge', id: resource }, action: { name: 'read' }, context: { purpose: 'work' } });

test('AuthZEN: the configured risk provider applies to PDP decisions exactly as to the engine', async () => {
  const token = secret(); let level: 'none' | 'critical' | 'broken' = 'none';
  const risk = { level: async () => { if (level === 'broken') throw new Error('down'); return level; } };
  const server = createAuthzenGateway(new MemoryStore(kbFixture()), { credentials: [{ token, binding: { tenant: 'acme', pep: 'gw' } }], risk, reasons: 'admin' });
  const base = await listen(server);
  try {
    const call = async () => (await (await fetch(`${base}/access/v1/evaluation`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify(ask('chief', 'chief-agent', 'chief-run', 'handbook')) })).json()) as any;
    assert.equal((await call()).decision, true);
    level = 'critical'; const denied = await call();
    assert.equal(denied.decision, false, 'a critical risk level denies at the PDP too');
    level = 'broken'; const failed = await call();
    assert.equal(failed.decision, false); assert.equal(failed.context.reason_admin.code, 'POLICY_UNAVAILABLE');
  } finally { await close(server); }
});

test('AuthZEN: every post-authentication response (400, 404, 500) is padded to the timing floor', async () => {
  const token = secret(), floor = 150;
  let broken = false;
  const inner = new MemoryStore(kbFixture());
  const store: Store = Object.assign(Object.create(inner) as Store, { transaction: (tenant: string, fn: Parameters<Store['transaction']>[1]) => broken ? Promise.reject(new Error('store down')) : inner.transaction(tenant, fn) });
  const server = createAuthzenGateway(store, { credentials: [{ token, binding: { tenant: 'acme', pep: 'gw' } }], timing: { minMs: floor, jitterMs: 10 } });
  const base = await listen(server);
  try {
    const time = async (path: string, body: string, auth = token, type = 'application/json') => {
      const t = performance.now();
      const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': type, authorization: `Bearer ${auth}` }, body });
      await r.arrayBuffer(); return { status: r.status, ms: performance.now() - t };
    };
    const cases = [
      await time('/access/v1/evaluation', '{not json'),
      await time('/access/v1/evaluation', JSON.stringify({ subject: 1 })),
      await time('/access/v1/evaluation', '{}', token, 'text/plain'),
      await time('/access/v1/nothing', '{}'),
      await time('/access/v1/evaluations', JSON.stringify({ evaluations: [] }))
    ];
    broken = true; cases.push(await time('/access/v1/evaluation', JSON.stringify(ask('chief', 'chief-agent', 'chief-run', 'handbook')))); broken = false;
    assert.deepEqual(cases.map(c => c.status), [400, 400, 400, 404, 400, 500]);
    for (const c of cases) assert.ok(c.ms >= floor - 8, `${c.status} answered after ${Math.round(c.ms)} ms`);
    const unauthenticated = await time('/access/v1/evaluation', '{}', secret());
    assert.equal(unauthenticated.status, 401, 'before authentication nothing is padded (no work to hide, no cost for floods)');
  } finally { await close(server); }
});
