import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Engine } from '../reference/engine.ts';
import { createGateway } from '../reference/http.ts';
import type { ProtectionOptions, RuntimeObligationMode } from '../reference/http.ts';
import { createAuthzenGateway } from '../reference/authzen.ts';
import { MemoryStore } from '../reference/store.ts';
import { MemoryRateLimits } from '../reference/limits.ts';
import { Backoff, Equaliser, VolumeBudget } from '../reference/protection.ts';
import { AnchorMonitor, FileAnchorBaseline, RetrievalDisabled, cosine } from '../reference/anchors.ts';
import type { AnchorBaseline } from '../reference/anchors.ts';
import { HashEmbedder } from '../reference/embedding.ts';
import type { Embedder } from '../reference/embedding.ts';
import { MemoryVectorIndex } from '../reference/vector.ts';
import type { IndexedChunk } from '../reference/vector.ts';
import { VectorCandidateSource } from '../reference/retrieval.ts';
import { Metrics } from '../reference/metrics.ts';
import { DENIAL_HINTS } from '../reference/decision.ts';
import { ConfigError, loadConfig } from '../reference/config.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';
import type { RuntimeProfilePolicy, State } from '../reference/types.ts';
import { close, listen } from './support.ts';

const secret = () => `test-only-${randomBytes(24).toString('hex')}`;
type Opts = ConstructorParameters<typeof Engine>[1];
const RUNTIME_POLICY: RuntimeProfilePolicy = { id: 'rt', tenant: 'acme', classification: 'confidential', profiles: { network: 'internal-only' }, active: true };
async function gateway(options: Parameters<typeof createGateway>[2] = {}, engineOptions: Opts = {}, change?: (s: State) => void) {
  const state = kbFixture(); change?.(state);
  const store = new MemoryStore(state), engine = new Engine(store, engineOptions);
  const chief = secret(), intern = secret();
  const server = createGateway(engine, [{ token: chief, binding: bindings.chief }, { token: intern, binding: bindings.intern }], options);
  const base = await listen(server);
  const post = async (path: string, body: unknown, token = chief) => {
    const started = performance.now();
    const r = await fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
    return { status: r.status, body: await r.json() as any, headers: r.headers, ms: performance.now() - started };
  };
  return { store, engine, post, tokens: { chief, intern }, stop: () => close(server) };
}
const contexts = (resource: string, purpose = 'work') => ({ resources: [resource], purpose });
const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;

// ---- timing equalisation ------------------------------------------------------------------------------------------
test('timing: a denial, a no-match and a match all answer at or after the floor, with the same shape', async () => {
  const floor = 150;
  const g = await gateway({ timing: { minMs: floor, jitterMs: 30 } });
  try {
    const paths = {
      deniedMissing: () => g.post('/v1/contexts', contexts('no-such-resource')),
      deniedForbidden: () => g.post('/v1/contexts', contexts('strategy'), g.tokens.intern),
      noMatch: () => g.post('/v1/retrieve', { query: 'zzqxunmatchedterm', purpose: 'work' }),
      match: () => g.post('/v1/retrieve', { query: 'product', purpose: 'work' }),
    };
    const samples: Record<string, number[]> = {}, shapes: Record<string, string> = {};
    for (const [name, run] of Object.entries(paths)) {
      samples[name] = [];
      for (let i = 0; i < 4; i++) { const r = await run(); samples[name]!.push(r.ms); shapes[name] = `${r.status}:${Object.keys(r.body).sort().join()}`; }
    }
    for (const [name, xs] of Object.entries(samples)) assert.ok(Math.min(...xs) >= floor - 8, `${name} padded to the floor: ${xs.map(x => Math.round(x))}`);
    assert.equal(shapes.deniedMissing, shapes.deniedForbidden); assert.equal(shapes.deniedMissing, shapes.noMatch);
    assert.equal(shapes.deniedMissing, '403:code,decisionId,ok');
    // Statistical and tolerant: the means of the three indistinguishable outcomes sit within one jitter range plus scheduling noise.
    const denied = mean(samples.deniedMissing!), none = mean(samples.noMatch!), forbidden = mean(samples.deniedForbidden!);
    assert.ok(Math.abs(denied - none) < 90 && Math.abs(denied - forbidden) < 90, `means ${Math.round(denied)} ${Math.round(none)} ${Math.round(forbidden)}`);
  } finally { await g.stop(); }
});
test('timing: without a floor nothing is padded; jitter stays within its range; other routes are not padded', async () => {
  const floors: number[] = [];
  const eq = new Equaliser({ minMs: 100, jitterMs: 50, now: () => 0, sleep: async ms => { floors.push(ms); } });
  for (let i = 0; i < 200; i++) await eq.pad(0);
  assert.ok(floors.every(ms => ms >= 100 && ms <= 150)); assert.ok(new Set(floors).size > 10, 'jitter varies');
  floors.length = 0;
  const late = new Equaliser({ minMs: 100, now: () => 500, sleep: async ms => { floors.push(ms); } });
  await late.pad(0); assert.deepEqual(floors, [], 'work that already took longer than the floor is not delayed');
  assert.throws(() => new Equaliser({ minMs: -1 }), /Invalid timing/); assert.throws(() => new Equaliser({ minMs: 6000 }), /Invalid timing/); assert.throws(() => new Equaliser({ minMs: 10, jitterMs: 2000 }), /Invalid timing/);
  const g = await gateway({ timing: { minMs: 300 } });
  try {
    const r = await g.post('/v1/derive', { context: 'nope', content: 'x', kind: 'memory' });
    assert.ok(r.ms < 250, `derive is not equalised (${Math.round(r.ms)} ms)`);
  } finally { await g.stop(); }
});
test('timing: AuthZEN evaluation pads allow and deny to the floor', async () => {
  const token = secret(), floor = 120;
  const store = new MemoryStore(kbFixture());
  const server = createAuthzenGateway(store, { credentials: [{ token, binding: { tenant: 'acme', pep: 'gw' } }], timing: { minMs: floor, jitterMs: 20 } });
  const base = await listen(server);
  try {
    const ask = (user: string, agent: string, grant: string, resource: string) => ({ subject: { type: 'user', id: user, properties: { agent, grant } }, resource: { type: 'knowledge', id: resource }, action: { name: 'read' }, context: { purpose: 'work' } });
    const time = async (body: unknown) => { const t = performance.now(); const r = await fetch(`${base}/access/v1/evaluation`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify(body) }); return { ms: performance.now() - t, body: await r.json() as any }; };
    const allow = await time(ask('chief', 'chief-agent', 'chief-run', 'handbook'));
    const deny = await time(ask('intern', 'intern-agent', 'intern-run', 'strategy'));
    const missing = await time(ask('intern', 'intern-agent', 'intern-run', 'no-such'));
    assert.equal(allow.body.decision, true); assert.equal(deny.body.decision, false); assert.equal(missing.body.decision, false);
    for (const r of [allow, deny, missing]) assert.ok(r.ms >= floor - 8, `${Math.round(r.ms)}`);
    assert.deepEqual(Object.keys(deny.body), Object.keys(missing.body));
  } finally { await close(server); }
});

// ---- denial hints -------------------------------------------------------------------------------------------------
const RESOURCES = ['handbook', 'strategy', 'project-alpha', 'vault-memo', 'no-such-resource', 'other.tenant:doc'];
async function hintsFor(g: Awaited<ReturnType<typeof gateway>>, token: string, body: (resource: string) => unknown, path = '/v1/contexts') {
  const out: (string | undefined)[] = [];
  for (const resource of RESOURCES) { const r = await g.post(path, body(resource), token); out.push(r.body.hint); if (r.status === 403) assert.equal(r.body.code, 'NOT_AUTHORIZED'); }
  return out;
}
test('hints: off by default, so a denial carries nothing beyond NOT_AUTHORIZED', async () => {
  const g = await gateway({}, { clock: () => Date.now() + 2 * 3_600_000 });
  try { const r = await g.post('/v1/contexts', contexts('handbook')); assert.equal(r.status, 403); assert.deepEqual(Object.keys(r.body).sort(), ['code', 'decisionId', 'ok']); } finally { await g.stop(); }
});
test('hints: GRANT_EXPIRED, PURPOSE_NOT_GRANTED and ACTION_NOT_GRANTED depend on the grant of the caller only, never on the resource', async () => {
  // expired grant: the same hint for every resource, existing or not
  const expired = await gateway({ denialHints: true }, { clock: () => Date.now() + 2 * 3_600_000 });
  try {
    const list = await hintsFor(expired, expired.tokens.chief, r => contexts(r));
    assert.deepEqual(new Set(list), new Set(['GRANT_EXPIRED']), `${list}`);
    assert.deepEqual(new Set(await hintsFor(expired, expired.tokens.chief, r => ({ query: r, purpose: 'work' }), '/v1/retrieve')), new Set(['GRANT_EXPIRED']));
  } finally { await expired.stop(); }
  const g = await gateway({ denialHints: true }, {}, s => { s.grants['chief-run']!.actions = ['read']; });
  try {
    assert.deepEqual(new Set(await hintsFor(g, g.tokens.chief, r => contexts(r, 'marketing'))), new Set(['PURPOSE_NOT_GRANTED']));
    // a valid purpose and a granted action: resources the caller may not read, and ones that do not exist, look alike (no hint)
    assert.deepEqual(new Set(await hintsFor(g, g.tokens.intern, r => contexts(r))), new Set([undefined]));
    // derive is not in the grant: the hint is the same for an existing context and a missing one
    const ok = await g.post('/v1/contexts', contexts('handbook')); assert.equal(ok.status, 200);
    const real = await g.post('/v1/derive', { context: ok.body.value.context, content: 'x', kind: 'memory' }), missing = await g.post('/v1/derive', { context: 'no-such-context', content: 'x', kind: 'memory' });
    assert.equal(real.body.hint, 'ACTION_NOT_GRANTED'); assert.equal(missing.body.hint, 'ACTION_NOT_GRANTED');
    const release = await g.post('/v1/release', { context: ok.body.value.context, recipient: 'chief', content: 'x', action: 'share' });
    assert.equal(release.body.hint, 'ACTION_NOT_GRANTED');
    assert.ok(DENIAL_HINTS.includes(release.body.hint));
  } finally { await g.stop(); }
  // a purpose the grant lists is not hinted even though every other check would deny
  const plain = await gateway({ denialHints: true });
  try { assert.deepEqual(new Set(await hintsFor(plain, plain.tokens.intern, r => contexts(r))), new Set([undefined])); } finally { await plain.stop(); }
});
test('hints: the hint of a request is a function of the caller state and request parameters, not of the resource (exhaustive over resource kinds)', async () => {
  const cases: { name: string; options: Opts; change?: (s: State) => void; purpose: string; expect: string | undefined }[] = [
    { name: 'valid', options: {}, purpose: 'work', expect: undefined },
    { name: 'purpose', options: {}, purpose: 'other', expect: 'PURPOSE_NOT_GRANTED' },
    { name: 'expired', options: { clock: () => Date.now() + 9e9 }, purpose: 'work', expect: 'GRANT_EXPIRED' },
    { name: 'expired wins over purpose', options: { clock: () => Date.now() + 9e9 }, purpose: 'other', expect: 'GRANT_EXPIRED' },
    { name: 'parent expired', options: { clock: () => Date.now() + 7_000_000 }, change: s => { s.grants['chief-child'] = { ...s.grants['chief-run']!, id: 'chief-child', parent: 'chief-run', expiresAt: Date.now() + 8_000_000 }; s.grants['chief-run']!.expiresAt = Date.now() + 6_000_000; }, purpose: 'work', expect: 'GRANT_EXPIRED' },
  ];
  for (const c of cases) {
    const g = await gateway({ denialHints: true }, c.options, c.change);
    try {
      for (const token of [g.tokens.chief, g.tokens.intern]) {
        const seen = new Set<string | undefined>();
        // only denials count: a valid case allows readable resources, which carry no hint at all
        for (const resource of RESOURCES) { const r = await g.post('/v1/contexts', contexts(resource, c.purpose), token); if (r.status === 403) seen.add(r.body.hint); }
        assert.ok([...seen].every(h => h === c.expect), `${c.name}: ${[...seen]}`);
      }
    } finally { await g.stop(); }
  }
});
test('hints: RATE_LIMITED accompanies a 429 only when hints are on', async () => {
  for (const denialHints of [true, false]) {
    const g = await gateway({ denialHints, rateLimits: { contexts: 1 } });
    try {
      await g.post('/v1/contexts', contexts('handbook'));
      const limited = await g.post('/v1/contexts', contexts('handbook'));
      assert.equal(limited.status, 429); assert.ok(limited.headers.get('retry-after'));
      assert.equal(limited.body.error, 'RATE_LIMITED'); assert.equal(limited.body.hint, denialHints ? 'RATE_LIMITED' : undefined);
    } finally { await g.stop(); }
  }
});
test('hints: RUNTIME_ENFORCER_REQUIRED is listener and tenant state, the same for a protected, a forbidden and a missing resource', async () => {
  const contained = (s: State) => { s.runtimeProfiles = { rt: structuredClone(RUNTIME_POLICY) }; };
  for (const [mode, expected] of [['deny', 'RUNTIME_ENFORCER_REQUIRED'], ['trusted-enforcer', undefined]] as [RuntimeObligationMode, string | undefined][]) {
    const g = await gateway({ denialHints: true, runtimeObligations: mode }, {}, contained);
    try {
      const seen: (string | undefined)[] = [];
      // project-alpha (confidential) carries a runtime_profile: refused in deny mode; strategy is forbidden to the intern; the others are missing
      for (const [token, resource] of [[g.tokens.chief, 'project-alpha'], [g.tokens.chief, 'strategy'], [g.tokens.intern, 'strategy'], [g.tokens.chief, 'no-such-resource'], [g.tokens.intern, 'no-such-resource']] as const) {
        const r = await g.post('/v1/contexts', contexts(resource), token);
        if (r.status === 403) seen.push(r.body.hint);
        else assert.equal(mode, 'trusted-enforcer');
      }
      assert.ok(seen.length >= 3); assert.ok(seen.every(h => h === expected), `${mode}: ${seen}`);
    } finally { await g.stop(); }
  }
  const none = await gateway({ denialHints: true });
  try { assert.equal((await none.post('/v1/contexts', contexts('no-such-resource'))).body.hint, undefined, 'a tenant without runtime policies has nothing to hint'); } finally { await none.stop(); }
});
test('hints: APPROVAL_REQUIRED and RATE_LIMITED come from the own volume state of the principal; another principal sees none', async () => {
  for (const [onExceed, hint] of [['approval', 'APPROVAL_REQUIRED'], ['deny', 'RATE_LIMITED']] as const) {
    const volume = new VolumeBudget({ limiter: new MemoryRateLimits(), windowMs: 3_600_000, limits: { confidential: { documents: 1 } }, onExceed });
    const g = await gateway({ denialHints: true }, { volume });
    try {
      assert.equal((await g.post('/v1/contexts', contexts('project-alpha'))).status, 200);
      const over = await g.post('/v1/contexts', contexts('project-alpha'));
      assert.equal(over.status, 403); assert.equal(over.body.hint, undefined, 'the crossing call itself carries no volume hint: it would show that the resource existed');
      const later = await Promise.all(['no-such-resource', 'strategy', 'handbook'].map(r => g.post('/v1/contexts', contexts(r), g.tokens.chief)));
      for (const r of later) if (r.status === 403) assert.equal(r.body.hint, hint);
      assert.equal(later[0]!.body.hint, hint);
      assert.equal((await g.post('/v1/contexts', contexts('no-such-resource'), g.tokens.intern)).body.hint, undefined);
    } finally { await g.stop(); }
  }
});

// ---- progressive backoff ------------------------------------------------------------------------------------------
test('backoff: free denials, then exponential Retry-After up to the cap; success resets; streaks expire', () => {
  let t = 0; const b = new Backoff({ freeDenials: 2, baseSeconds: 1, maxSeconds: 8, resetSeconds: 60, clock: () => t });
  const p = bindings.chief, q = bindings.intern;
  assert.deepEqual([b.denied(p), b.denied(p), b.denied(p), b.denied(p), b.denied(p), b.denied(p), b.denied(p)], [0, 0, 1, 2, 4, 8, 8]);
  assert.equal(b.blocked(p), 8); t += 3000; assert.equal(b.blocked(p), 5); t += 5000; assert.equal(b.blocked(p), 0);
  assert.equal(b.blocked(q), 0, 'another principal is unaffected');
  b.allowed(p); assert.equal(b.denied(p), 0, 'a success resets the streak');
  assert.equal(b.denied(p), 0); assert.equal(b.denied(p), 1);
  t += 61_000; assert.equal(b.denied(p), 0, 'an old streak expires');
  const tight = new Backoff({ maxPrincipals: 2, freeDenials: 1, clock: () => t });
  tight.denied(p); tight.denied(q); tight.denied(bindings.lead); assert.ok(true, 'bounded state drops the oldest entry');
  for (const bad of [{ freeDenials: 0 }, { baseSeconds: 10, maxSeconds: 5 }, { maxSeconds: 100_000 }, { resetSeconds: 0 }]) assert.throws(() => new Backoff(bad), /Invalid backoff/);
});
test('backoff: repeated denials over HTTP earn 429 with growing Retry-After; other principals and successes are unaffected', async () => {
  let t = 1_000_000;
  const g = await gateway({ backoff: { freeDenials: 1, baseSeconds: 1, maxSeconds: 4, clock: () => t }, denialHints: true });
  try {
    const miss = () => g.post('/v1/contexts', contexts('no-such-resource'));
    const first = await miss(); assert.equal(first.status, 403); assert.equal(first.headers.get('retry-after'), null);
    const second = await miss(); assert.equal(second.status, 403); assert.equal(second.headers.get('retry-after'), '1');
    const blocked = await miss(); assert.equal(blocked.status, 429); assert.equal(blocked.headers.get('retry-after'), '1'); assert.equal(blocked.body.hint, 'RATE_LIMITED');
    assert.equal((await g.post('/v1/contexts', contexts('handbook'))).status, 429, 'even a valid request waits: the streak is per principal');
    assert.equal((await g.post('/v1/contexts', contexts('handbook'), g.tokens.intern)).status, 200, 'another principal is unaffected');
    t += 1500;
    const third = await miss(); assert.equal(third.status, 403); assert.equal(third.headers.get('retry-after'), '2');
    t += 2500; const fourth = await miss(); assert.equal(fourth.headers.get('retry-after'), '4');
    t += 4500; const fifth = await miss(); assert.equal(fifth.headers.get('retry-after'), '4', 'bounded');
    t += 4500; assert.equal((await g.post('/v1/contexts', contexts('handbook'))).status, 200);
    assert.equal((await miss()).headers.get('retry-after'), null, 'a success reset the streak');
  } finally { await g.stop(); }
});
test('backoff: a no-match and a denial count alike, so the streak reveals nothing about resources', async () => {
  let t = 5_000_000;
  const g = await gateway({ backoff: { freeDenials: 1, baseSeconds: 1, maxSeconds: 4, clock: () => t } });
  try {
    await g.post('/v1/retrieve', { query: 'zzqxunmatchedterm', purpose: 'work' });
    const second = await g.post('/v1/contexts', contexts('no-such-resource'));
    assert.equal(second.status, 403); assert.equal(second.headers.get('retry-after'), '1');
  } finally { await g.stop(); }
});

// ---- embedding anchors --------------------------------------------------------------------------------------------
class Switchable implements Embedder {
  readonly dimensions = 16; model = 'model-a'; mode: 'same' | 'rotated' | 'down' = 'same';
  private base = new HashEmbedder(16);
  async embed(texts: string[]): Promise<Float32Array[]> {
    if (this.mode === 'down') throw new Error('unreachable');
    const vectors = await this.base.embed(texts);
    return this.mode === 'same' ? vectors : vectors.map(v => Float32Array.from([...v].map((_, i, a) => a[(i + 3) % a.length]!)));
  }
}
const ANCHORS = ['the quick brown fox jumps over the lazy dog', 'invoice number and payment terms', 'quarterly revenue forecast'];
test('anchors: drift beyond the threshold disables retrieval until an administrator re-baselines; a down embedder does not', async () => {
  const embedder = new Switchable(); const states: string[] = [];
  const m = new AnchorMonitor({ embedder, anchors: ANCHORS, threshold: 0.98, bootstrap: true, onCheck: r => states.push(`${r.state}${r.failed ? '!' : ''}`) });
  assert.throws(() => m.assertEnabled(), RetrievalDisabled, 'no baseline yet: fail closed');
  assert.equal(await m.start(), 'ok'); m.assertEnabled();
  assert.equal(await m.check(), 'ok');
  embedder.mode = 'down'; assert.equal(await m.check(), 'ok', 'an unreachable embedder is reported, not mistaken for drift'); assert.equal(states.at(-1), 'ok!');
  embedder.mode = 'rotated'; assert.equal(await m.check(), 'drifted'); assert.throws(() => m.assertEnabled(), RetrievalDisabled);
  embedder.mode = 'same'; assert.equal(await m.check(), 'drifted', 'sticky: the vectors are back, but only an administrator re-enables');
  await m.rebaseline(); assert.equal(m.state, 'ok'); m.assertEnabled();
  embedder.mode = 'rotated'; await m.check(); assert.equal(m.state, 'drifted');
  await m.rebaseline(); assert.equal(await m.check(), 'ok', 'the new baseline is the rotated function');
  assert.equal(cosine([1, 0], [1, 0]), 1); assert.equal(cosine([1, 0], [0, 1]), 0); assert.equal(cosine([1, 0], [1]), -1);
  for (const bad of [[], ['']]) assert.throws(() => new AnchorMonitor({ embedder, anchors: bad }), /Invalid embedding anchor/);
  assert.throws(() => new AnchorMonitor({ embedder, anchors: ['a', 'a'] }), /Invalid embedding anchor/); assert.throws(() => new AnchorMonitor({ embedder, anchors: ['a'], threshold: 1.5 }), /Invalid/);
});
test('anchors: the baseline file survives restarts; a model or anchor change is drift; a replaced baseline is adopted', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'akac-anchors-'));
  try {
    const file = join(dir, 'baseline.json'), store = new FileAnchorBaseline(file);
    const embedder = new Switchable();
    assert.equal(await new AnchorMonitor({ embedder, anchors: ANCHORS, store }).start(), 'pending', 'never an implicit baseline');
    assert.equal(await new AnchorMonitor({ embedder, anchors: ANCHORS, store, bootstrap: true }).start(), 'ok', 'explicit one-time bootstrap');
    assert.equal(await new AnchorMonitor({ embedder, anchors: ANCHORS, store }).start(), 'ok', 'same model, same anchors');
    embedder.mode = 'rotated';
    const restarted = new AnchorMonitor({ embedder, anchors: ANCHORS, store, clock: () => Date.now() + 10 });
    assert.equal(await restarted.start(), 'drifted', 'the model changed while the gateway was down');
    assert.throws(() => restarted.assertEnabled(), RetrievalDisabled);
    // an administrator re-baselines out of band (a newer baseline file): adopted on the next check
    const admin = new AnchorMonitor({ embedder, anchors: ANCHORS, store, clock: () => Date.now() + 1000 }); await admin.rebaseline();
    assert.equal(await restarted.check(), 'ok'); restarted.assertEnabled();
    const renamed = new Switchable(); renamed.model = 'model-b';
    assert.equal(await new AnchorMonitor({ embedder: renamed, anchors: ANCHORS, store }).start(), 'drifted', 'a different model name is drift');
    assert.equal(await new AnchorMonitor({ embedder, anchors: [...ANCHORS, 'extra anchor'], store }).start(), 'drifted', 'a changed anchor set needs a deliberate re-baseline');
    writeFileSync(file, '{"model":1}'); await assert.rejects(store.load(), /Invalid anchor baseline/);
    assert.equal(await new AnchorMonitor({ embedder, anchors: ANCHORS, store, bootstrap: true }).start(), 'pending', 'an unreadable baseline is never replaced');
    const stored = JSON.parse((await (async () => { await admin.rebaseline(); return (await import('node:fs')).readFileSync(file, 'utf8'); })())) as AnchorBaseline;
    assert.equal(stored.anchors.length, ANCHORS.length); assert.ok(!JSON.stringify(stored).includes('invoice'), 'the anchor texts are stored as digests only');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('anchors: a drifted monitor defers vector retrieval with RETRIEVAL_DISABLED (audited, metric) and never queries the index', async () => {
  const embedder = new Switchable(), metrics = new Metrics();
  const monitor = new AnchorMonitor({ embedder, anchors: ANCHORS, bootstrap: true, onCheck: metrics.onAnchorCheck });
  const index = new MemoryVectorIndex(); let queried = 0; const q = index.query.bind(index); index.query = async x => { queried++; return q(x); };
  const store = new MemoryStore(kbFixture());
  const engine = new Engine(store, { onEvent: metrics.onEvent, candidates: new VectorCandidateSource({ index, embedder, monitor }) });
  const ask = () => engine.retrieve(bindings.chief, 'product', 'work');
  assert.equal((await ask()).ok, false); assert.equal(queried, 0, 'no baseline: disabled');
  assert.equal((await store.auditLog('acme')).at(-1)!.reason, 'DEFERRED:RETRIEVAL_DISABLED');
  await monitor.start(); await ask(); assert.equal(queried, 1); assert.equal((await store.auditLog('acme')).at(-1)!.reason, 'DENIED:NOT_AUTHORIZED'.replace('DENIED:NOT_AUTHORIZED', 'DEFERRED:INVALID_REQUEST'));
  embedder.mode = 'rotated'; await monitor.check();
  const denied = await ask(); assert.equal(denied.ok, false); assert.equal(queried, 1);
  assert.equal((await store.auditLog('acme')).at(-1)!.reason, 'DEFERRED:RETRIEVAL_DISABLED'); assert.equal((await store.auditLog('acme')).at(-1)!.reasonCode, 'RETRIEVAL_DISABLED');
  const text = metrics.expose();
  assert.match(text, /akac_embedding_drift 1/); assert.match(text, /akac_embedding_anchor_checks_total\{result="drifted"\}/); assert.match(text, /akac_retrieval_disabled_total 2/);
  await monitor.rebaseline(); assert.match(metrics.expose(), /akac_embedding_drift 0/);
  await ask(); assert.equal(queried, 2);
});

// ---- retrieval recall ---------------------------------------------------------------------------------------------
test('recall: the vector pre-filter uses the user AND the agent audience, so invisible candidates neither fetch nor crowd out visible ones', async () => {
  const embedder = new HashEmbedder(64);
  const state = kbFixture();
  // chief (user) additionally holds "board"; the chief-agent does not: board documents are visible to the user only.
  state.actors.chief!.roles = [...state.actors.chief!.roles, 'board'];
  const [query] = await embedder.embed(['quarterly product plan']);
  const chunks: IndexedChunk[] = [];
  const add = async (id: string, text: string, role: string) => {
    state.knowledge[id] = { id, tenant: 'acme', version: 1, kind: 'document', origin: 'system', content: text, classification: 'public', readerRoles: [role], projects: [], readers: [], sources: [], active: true };
    const [vector] = await embedder.embed([text]);
    chunks.push({ tenant: 'acme', docId: id, docVersion: 1, chunkId: `${id}#0`, ordinal: 0, compartment: 'public', readTokens: [`role:${role}`], requiredProjects: [], containerTokens: [], model: embedder.model, vector: vector! });
  };
  for (let i = 0; i < 30; i++) await add(`board-${i}`, 'quarterly product plan', 'board');
  await add('visible-plan', 'quarterly product plan and roadmap for staff', 'staff');
  const index = new MemoryVectorIndex(); await index.upsert(chunks);
  const source = new VectorCandidateSource({ index, embedder });
  // Control: with the user's tokens alone, the top-k are all board documents and the visible one is missed.
  const userOnly = await source.candidates({ tenant: 'acme', maxClassification: 'restricted', tokens: ['user:chief', 'role:staff', 'role:board', 'role:executive', 'project:alpha'], query: 'quarterly product plan', limit: 5 });
  assert.ok(!userOnly.includes('visible-plan') && userOnly.every(id => id.startsWith('board-')), `${userOnly}`);
  const events: string[] = [];
  const engine = new Engine(new MemoryStore(state), { candidates: source, onEvent: e => events.push(e.type) });
  const r = await engine.retrieve(bindings.chief, 'quarterly product plan', 'work', 5);
  assert.ok(r.ok, 'the engine passes both audiences');
  assert.deepEqual(r.value.documents.map(d => d.id), ['visible-plan']);
  assert.equal(engine.stats().filterMismatches, 0, 'candidates the agent cannot see were never fetched');
  assert.ok(!events.includes('filter_mismatch'));
  // Pre-filter only: an index that ignores the agent stays safe (authoritative re-check), it just loses recall.
  const ignoring: IndexedChunk[] = chunks; const blind = new MemoryVectorIndex(); await blind.upsert(ignoring);
  const original = blind.query.bind(blind); blind.query = async q => original({ ...q, agent: undefined });
  const safe = new Engine(new MemoryStore(state), { candidates: new VectorCandidateSource({ index: blind, embedder }) });
  const s = await safe.retrieve(bindings.chief, 'quarterly product plan', 'work', 5);
  assert.equal(s.ok, false); assert.ok(safe.stats().filterMismatches > 0, 'no board document was disclosed');
});
test('recall: agent audience also applies to container audiences and required projects', async () => {
  const embedder = new HashEmbedder(32), [vector] = await embedder.embed(['x y z']);
  const chunk = (docId: string, over: Partial<IndexedChunk>): IndexedChunk => ({ tenant: 'acme', docId, docVersion: 1, chunkId: `${docId}#0`, ordinal: 0, compartment: 'public', readTokens: ['role:staff'], requiredProjects: [], containerTokens: [], model: embedder.model, vector: vector!, ...over });
  const index = new MemoryVectorIndex();
  await index.upsert([chunk('plain', {}), chunk('project', { requiredProjects: ['alpha'] }), chunk('folder', { containerTokens: [['role:board']] }), chunk('either', { readTokens: ['user:u', 'user:a'] })]);
  const ids = async (agent?: { tokens: string[]; projects: string[] }) => (await index.query({ tenant: 'acme', compartments: ['public'], tokens: ['role:staff', 'role:board', 'user:u'], projects: ['alpha'], vector: vector!, k: 10, ...(agent ? { agent } : {}) })).map(h => h.docId).sort();
  assert.deepEqual(await ids(), ['either', 'folder', 'plain', 'project']);
  assert.deepEqual(await ids({ tokens: ['role:staff'], projects: [] }), ['plain'], 'the agent lacks the project and the folder role, and is not a reader of "either"');
  assert.deepEqual(await ids({ tokens: ['role:staff', 'user:a'], projects: ['alpha'] }), ['either', 'plain', 'project']);
  await assert.rejects(index.query({ tenant: 'acme', compartments: ['public'], tokens: [], projects: [], vector: vector!, k: 1, agent: {} as never }), /Invalid vector query/);
});

// ---- configuration ------------------------------------------------------------------------------------------------
const dir = mkdtempSync(join(tmpdir(), 'akac-release-'));
test.after(() => rmSync(dir, { recursive: true, force: true }));
const anchorsFile = join(dir, 'anchors.json'); writeFileSync(anchorsFile, JSON.stringify(['one anchor', 'another anchor']));
const base = { AKAC_CREDENTIALS_FILE: (() => { const p = join(dir, 'agent.json'); writeFileSync(p, JSON.stringify([{}])); return p; })() };
const cfg = (env: Record<string, string>) => loadConfig({ ...base, ...env });
const problems = (env: Record<string, string>) => { try { cfg(env); return []; } catch (error) { assert.ok(error instanceof ConfigError); return error.problems; } };
test('config: protections are off or fail-closed by default and validated strictly', () => {
  const c = cfg({}).protection;
  assert.deepEqual(c, { denialHints: false, hooks: { timeoutMs: 2000, failure: 'deny', requiredFilters: {} } });
  const on = cfg({ AKAC_MIN_RESPONSE_MS: '200', AKAC_RESPONSE_JITTER_MS: '25', AKAC_DENIAL_HINTS: 'true', AKAC_BACKOFF_FREE_DENIALS: '3', AKAC_BACKOFF_MAX_SECONDS: '60',
    AKAC_VOLUME_LIMITS: 'confidential:bytes=1000,documents=10;restricted:documents=2', AKAC_VOLUME_WINDOW_SECONDS: '600', AKAC_VOLUME_ON_EXCEED: 'approval',
    AKAC_DECISION_CACHE_TTL_MS: '5000', AKAC_RELEASE_REQUIRED_FILTERS: 'confidential=pii,dlp;restricted=pii', AKAC_HOOK_TIMEOUT_MS: '500', AKAC_HOOK_FAILURE: 'skip', AKAC_HOOKS_MODULE: './hooks.mjs' }).protection;
  assert.deepEqual(on.timing, { minMs: 200, jitterMs: 25 }); assert.equal(on.denialHints, true); assert.deepEqual(on.backoff, { freeDenials: 3, baseSeconds: 1, maxSeconds: 60 });
  assert.deepEqual(on.volume, { windowSeconds: 600, onExceed: 'approval', limits: { confidential: { bytes: 1000, documents: 10 }, restricted: { documents: 2 } } });
  assert.deepEqual(on.decisionCache, { ttlMs: 5000, maxEntries: 10000 });
  assert.deepEqual(on.hooks, { timeoutMs: 500, failure: 'skip', requiredFilters: { confidential: ['pii', 'dlp'], restricted: ['pii'] }, module: './hooks.mjs' });
  const bad: [Record<string, string>, string][] = [
    [{ AKAC_MIN_RESPONSE_MS: '9999' }, 'AKAC_MIN_RESPONSE_MS'], [{ AKAC_MIN_RESPONSE_MS: 'fast' }, 'AKAC_MIN_RESPONSE_MS'], [{ AKAC_RESPONSE_JITTER_MS: '5' }, 'requires AKAC_MIN_RESPONSE_MS'],
    [{ AKAC_DENIAL_HINTS: 'maybe' }, 'AKAC_DENIAL_HINTS'], [{ AKAC_BACKOFF_MAX_SECONDS: '5' }, 'require AKAC_BACKOFF_FREE_DENIALS'],
    [{ AKAC_BACKOFF_FREE_DENIALS: '2', AKAC_BACKOFF_BASE_SECONDS: '10', AKAC_BACKOFF_MAX_SECONDS: '5' }, 'at least'],
    [{ AKAC_VOLUME_LIMITS: 'secret:bytes=1' }, 'AKAC_VOLUME_LIMITS'], [{ AKAC_VOLUME_LIMITS: 'public:bytes=0' }, 'AKAC_VOLUME_LIMITS'], [{ AKAC_VOLUME_LIMITS: 'public:lines=4' }, 'AKAC_VOLUME_LIMITS'],
    [{ AKAC_VOLUME_LIMITS: 'public:bytes=1;public:bytes=2' }, 'AKAC_VOLUME_LIMITS'], [{ AKAC_VOLUME_LIMITS: 'public:bytes=1', AKAC_VOLUME_ON_EXCEED: 'allow' }, 'AKAC_VOLUME_ON_EXCEED'],
    [{ AKAC_VOLUME_ON_EXCEED: 'deny' }, 'requires AKAC_VOLUME_LIMITS'], [{ AKAC_DECISION_CACHE_TTL_MS: '300001' }, 'AKAC_DECISION_CACHE_TTL_MS'], [{ AKAC_DECISION_CACHE_MAX: '5' }, 'requires AKAC_DECISION_CACHE_TTL_MS'],
    [{ AKAC_RELEASE_REQUIRED_FILTERS: 'secret=pii' }, 'AKAC_RELEASE_REQUIRED_FILTERS'], [{ AKAC_RELEASE_REQUIRED_FILTERS: 'public=a b' }, 'AKAC_RELEASE_REQUIRED_FILTERS'],
    [{ AKAC_HOOK_FAILURE: 'allow' }, 'AKAC_HOOK_FAILURE'], [{ AKAC_HOOK_TIMEOUT_MS: '0' }, 'AKAC_HOOK_TIMEOUT_MS'],
    [{ AKAC_ANCHOR_THRESHOLD: '0.9' }, 'requires AKAC_ANCHOR_TEXTS_FILE'], [{ AKAC_ANCHOR_TEXTS_FILE: anchorsFile }, 'requires AKAC_RETRIEVAL=vector'],
    [{ AKAC_ANCHOR_TEXTS_FILE: join(dir, 'missing.json'), AKAC_RETRIEVAL: 'vector' }, 'AKAC_ANCHOR_TEXTS_FILE'],
  ];
  for (const [env, part] of bad) assert.ok(problems(env).some(p => p.includes(part)), `${part} in ${JSON.stringify(problems(env))}`);
});
test('config: embedding anchors', () => {
  const vector = { AKAC_RETRIEVAL: 'vector', AKAC_VECTOR_BACKEND: 'memory', AKAC_EMBEDDINGS: 'hash' };
  const a = cfg({ ...vector, AKAC_ANCHOR_TEXTS_FILE: anchorsFile, AKAC_ANCHOR_THRESHOLD: '0.95', AKAC_ANCHOR_INTERVAL_SECONDS: '60', AKAC_ANCHOR_BASELINE_FILE: join(dir, 'b.json') }).protection.anchors;
  assert.deepEqual(a, { texts: ['one anchor', 'another anchor'], threshold: 0.95, intervalSeconds: 60, baselineFile: join(dir, 'b.json') });
  assert.equal(cfg({ ...vector, AKAC_ANCHOR_TEXTS_FILE: anchorsFile, AKAC_ANCHOR_BASELINE_FILE: join(dir, 'b.json') }).protection.anchors!.threshold, 0.98);
  assert.ok(problems({ ...vector, AKAC_ANCHOR_TEXTS_FILE: anchorsFile }).some(p => p.includes('requires AKAC_ANCHOR_BASELINE_FILE')), 'a persistent baseline is required');
  assert.equal(cfg({ ...vector, AKAC_ANCHOR_TEXTS_FILE: anchorsFile, AKAC_ANCHOR_BASELINE_FILE: join(dir, 'b.json'), AKAC_ANCHOR_BOOTSTRAP: 'true' }).protection.anchors!.bootstrap, true);
  assert.ok(problems({ ...vector, AKAC_ANCHOR_TEXTS_FILE: anchorsFile, AKAC_ANCHOR_BASELINE_FILE: join(dir, 'b.json'), AKAC_ANCHOR_BOOTSTRAP: 'maybe' }).some(p => p.includes('AKAC_ANCHOR_BOOTSTRAP')));
  assert.ok(problems({ AKAC_ANCHOR_BOOTSTRAP: 'true' }).some(p => p.includes('requires AKAC_ANCHOR_TEXTS_FILE')));
  const dup = join(dir, 'dup.json'); writeFileSync(dup, JSON.stringify(['a', 'a']));
  assert.ok(problems({ ...vector, AKAC_ANCHOR_TEXTS_FILE: dup }).some(p => p.includes('distinct')));
  assert.ok(problems({ ...vector, AKAC_ANCHOR_TEXTS_FILE: anchorsFile, AKAC_ANCHOR_THRESHOLD: '1.5' }).some(p => p.includes('AKAC_ANCHOR_THRESHOLD')));
});
test('protection options are validated by the gateway', async () => {
  const engine = new Engine(new MemoryStore(kbFixture()));
  const options = (o: ProtectionOptions) => () => createGateway(engine, [{ token: secret(), binding: bindings.chief }], o);
  assert.throws(options({ denialHints: 'yes' as never }), /Invalid denial hints/);
  assert.throws(options({ timing: { minMs: -5 } }), /Invalid timing/);
  assert.throws(options({ backoff: { freeDenials: 0 } }), /Invalid backoff/);
});
