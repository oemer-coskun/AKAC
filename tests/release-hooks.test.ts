import test from 'node:test';
import assert from 'node:assert/strict';
import { Engine, verifyAudit } from '../reference/engine.ts';
import type { EngineEvent } from '../reference/engine.ts';
import { ProtectedRuntime } from '../reference/runtime.ts';
import { MemoryStore } from '../reference/store.ts';
import { MemoryRateLimits } from '../reference/limits.ts';
import { DecisionCache } from '../reference/decision-cache.ts';
import { VolumeBudget } from '../reference/protection.ts';
import { validFindings, parseObligations, merge } from '../reference/decision.ts';
import type { DeriveSanitizer, ReleaseFilter } from '../reference/hooks.ts';
import { HOOK_LIMITS } from '../reference/hooks.ts';
import type { PolicyHook, State } from '../reference/types.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';

const now = 1800000000000;
const chief = bindings.chief;
function world(change?: (s: State) => void): State {
  const s = kbFixture(now);
  s.actors.admin!.roles = ['security-admin', 'kb-admin', 'auditor'];
  s.actors.provider = { id: 'provider', tenant: 'acme', kind: 'service', roles: ['staff', 'executive', 'project'], projects: ['alpha'], clearance: 'restricted', active: true };
  change?.(s); return s;
}
type Opts = ConstructorParameters<typeof Engine>[1];
function setup(options: Opts = {}, change?: (s: State) => void) {
  const store = new MemoryStore(world(change)), events: EngineEvent[] = [];
  return { store, events, engine: new Engine(store, { clock: () => now, onEvent: e => events.push(e), ...options }) };
}
const filter = (id: string, run: ReleaseFilter['filter']): ReleaseFilter => ({ id, filter: run });
const sanitizer = (id: string, run: DeriveSanitizer['sanitize']): DeriveSanitizer => ({ id, sanitize: run });
const last = async (store: MemoryStore) => (await store.auditLog('acme')).at(-1)!;
async function context(engine: Engine, ids = ['project-alpha']) {
  const c = await engine.openContext(chief, ids, 'work'); assert.ok(c.ok); return c.value.context;
}
const stored = (store: MemoryStore, id: string) => new Promise<string>((resolve, reject) => { store.transaction('acme', async tx => { await tx.load({ knowledge: [id] }); resolve(tx.state.knowledge[id]!.content); }).catch(reject); });
const SECRET = 'Contact jane.doe@example.invalid about the launch.';

test('release filter: redaction replaces the released content; the audit entry holds closed findings only', async () => {
  const seen: string[] = [];
  const pii = filter('pii', async input => { seen.push(`${input.classification}|${input.recipient}|${input.purpose}|${input.tenant}`); return { action: 'redact', content: input.content.replace(/\S+@\S+/, '[email]') }; });
  const { engine, store, events } = setup({ releaseFilters: [pii] });
  const r = await engine.release(chief, await context(engine), 'chief', SECRET);
  assert.ok(r.ok); assert.equal(r.value.content, 'Contact [email]. about the launch.'.replace('[email].', '[email]'));
  assert.deepEqual(seen, ['confidential|chief|work|acme']);
  const entry = await last(store);
  assert.deepEqual(entry.findings, ['pii:redact']);
  assert.ok(!JSON.stringify(entry).includes('jane.doe'));
  assert.ok(events.some(e => e.type === 'hook' && e.hook === 'release_filter' && e.outcome === 'redact'));
  assert.equal(verifyAudit(await store.auditLog('acme')), true);
});
test('release filter: a deny, an error, a timeout and a malformed result all deny (fail closed); nothing is released', async () => {
  const cases: [string, ReleaseFilter['filter'], string[]][] = [
    ['deny', async () => ({ action: 'deny', reason: 'contains-pii' }), ['f:deny', 'reason:contains-pii']],
    ['throw', async () => { throw new Error('boom'); }, ['f:error']],
    ['hang', () => new Promise(() => {}), ['f:timeout']],
    ['unknown action', async () => ({ action: 'allow' }) as never, ['f:invalid']],
    ['extra member', async () => ({ action: 'pass', content: 'x' }) as never, ['f:invalid']],
    ['bad reason', async () => ({ action: 'deny', reason: 'has space' }) as never, ['f:invalid']],
    ['empty redaction', async () => ({ action: 'redact', content: '' }), ['f:invalid']],
    ['content growth', async () => ({ action: 'redact', content: 'x'.repeat(SECRET.length * HOOK_LIMITS.growth + HOOK_LIMITS.slack + 1) }), ['f:invalid']],
    ['non-string redaction', async () => ({ action: 'redact', content: 7 }) as never, ['f:invalid']],
  ];
  for (const [name, run, findings] of cases) {
    const { engine, store } = setup({ releaseFilters: [filter('f', run)], hooks: { timeoutMs: 40 } });
    const r = await engine.release(chief, await context(engine), 'chief', SECRET);
    assert.equal(r.ok, false, name);
    const entry = await last(store);
    assert.equal(entry.reason, 'DENIED:RELEASE_FILTER', name); assert.equal(entry.reasonCode, 'RELEASE_FILTER');
    assert.deepEqual(entry.findings, findings, name);
  }
});
test('release filter: failure "skip" ignores a broken filter, but never one that a policy requires', async () => {
  const broken = filter('broken', async () => { throw new Error('boom'); });
  const skipping = setup({ releaseFilters: [broken], hooks: { failure: 'skip' } });
  const r = await skipping.engine.release(chief, await context(skipping.engine), 'chief', SECRET);
  assert.ok(r.ok && r.value.content === SECRET);
  assert.deepEqual((await last(skipping.store)).findings, ['broken:error']);
  const required = setup({ releaseFilters: [broken], hooks: { failure: 'skip' }, requiredFilters: () => ['broken'] });
  assert.equal((await required.engine.release(chief, await context(required.engine), 'chief', SECRET)).ok, false);
});
test('release filter: filters only narrow; an unauthorized release is denied before any filter runs, and pass changes nothing', async () => {
  let calls = 0;
  const counting = filter('count', async () => { calls++; return { action: 'pass' }; });
  const { engine } = setup({ releaseFilters: [counting] });
  const ctx = await context(engine);
  assert.equal((await engine.release(chief, ctx, 'intern', SECRET)).ok, false); // the intern cannot see project-alpha
  assert.equal((await engine.release(chief, 'no-such-context', 'chief', SECRET)).ok, false);
  assert.equal(calls, 0);
  const ok = await engine.release(chief, ctx, 'chief', SECRET);
  assert.ok(ok.ok && ok.value.content === SECRET); assert.equal(calls, 1);
});
test('release filter: filters run in order and see the previous redaction', async () => {
  const order: string[] = [];
  const a = filter('a', async i => { order.push(`a:${i.content}`); return { action: 'redact', content: i.content.replace('launch', 'L') }; });
  const b = filter('b', async i => { order.push(`b:${i.content}`); return { action: 'redact', content: i.content.toUpperCase() }; });
  const { engine, store } = setup({ releaseFilters: [a, b] });
  const r = await engine.release(chief, await context(engine), 'chief', 'the launch');
  assert.ok(r.ok); assert.equal(r.value.content, 'THE L'); assert.deepEqual(order, ['a:the launch', 'b:the L']);
  assert.deepEqual((await last(store)).findings, ['a:redact', 'b:redact']);
});
test('release_filter obligation: a required filter that is not configured denies; a configured one is enforced and not passed on', async () => {
  const policy = (ids: string[], actions = ['share', 'export']): PolicyHook => ({ revision: 'p1', check: async () => true,
    verdict: async i => ({ allow: true, obligations: actions.includes(i.action) ? [{ type: 'release_filter', value: ids }] : [] }) });
  const missing = setup({ policy: policy(['pii']) });
  assert.equal((await missing.engine.release(chief, await context(missing.engine), 'chief', SECRET)).ok, false);
  const denied = await last(missing.store);
  assert.equal(denied.reason, 'DENIED:RELEASE_FILTER'); assert.deepEqual(denied.findings, ['required:pii:missing']);
  const seen: string[] = [];
  const pii = filter('pii', async i => { seen.push(i.content); return { action: 'pass' }; });
  const ok = setup({ policy: policy(['pii']), releaseFilters: [pii] });
  const r = await ok.engine.release(chief, await context(ok.engine), 'chief', SECRET);
  assert.ok(r.ok); assert.deepEqual(seen, [SECRET]);
  assert.ok(!r.obligations.some(o => o.type === 'release_filter'), 'enforced in the engine, so not handed to the caller');
  const entry = await last(ok.store);
  assert.ok(entry.obligations!.some(o => o.type === 'release_filter' && o.value.join() === 'pii'), 'but recorded in audit');
  // Two policy records name different filters: the union applies.
  const both = setup({ policy: { ...policy(['pii']), verdict: async i => ({ allow: true, obligations: i.action === 'share' ? [{ type: 'release_filter', value: [i.classification === 'confidential' ? 'dlp' : 'x'] }, { type: 'release_filter', value: ['pii'] }] : [] }) }, releaseFilters: [pii] });
  assert.equal((await both.engine.release(chief, await context(both.engine), 'chief', SECRET)).ok, false);
});
test('required filters per tenant and classification (option): unmet requirement denies, and the caller can add requirements only', async () => {
  const pii = filter('pii', async () => ({ action: 'pass' }));
  const perClass = (_t: string, level: string) => level === 'confidential' || level === 'restricted' ? ['pii'] : [];
  const none = setup({ requiredFilters: perClass });
  assert.equal((await none.engine.release(chief, await context(none.engine), 'chief', SECRET)).ok, false);
  const fresh = setup({ requiredFilters: perClass });
  assert.ok((await fresh.engine.release(chief, await context(fresh.engine, ['handbook']), 'chief', 'public text')).ok, 'a public release needs no filter');
  const ok = setup({ requiredFilters: perClass, releaseFilters: [pii] });
  assert.ok((await ok.engine.release(chief, await context(ok.engine), 'chief', SECRET)).ok);
  const asked = await ok.engine.release(chief, await context(ok.engine), 'chief', SECRET, 'share', { requireFilters: ['pii', 'ghost'] });
  assert.equal(asked.ok, false, 'a caller-required filter that is not configured denies');
  const broken = setup({ requiredFilters: () => { throw new Error('config'); }, releaseFilters: [pii] });
  assert.equal((await broken.engine.release(chief, await context(broken.engine), 'chief', SECRET)).ok, false, 'an error in the requirement lookup denies');
});
test('derive sanitizer: clean stores the cleaned content; deny and error store nothing; findings are closed', async () => {
  const strip = sanitizer('inv', async i => ({ action: 'clean', content: i.content.replace(/​/g, ''), findings: ['zero-width'] }));
  const { engine, store } = setup({ deriveSanitizers: [strip] });
  const ctx = await context(engine, ['handbook']);
  const d = await engine.derive(chief, ctx, 'note​ text', 'memory');
  assert.ok(d.ok);
  assert.equal(await stored(store, d.value.id), 'note text');
  assert.deepEqual((await last(store)).findings, ['inv:clean', 'finding:zero-width']);
  for (const [name, run] of [['deny', async () => ({ action: 'deny', findings: ['injection'] })], ['throw', async () => { throw new Error('x'); }], ['bad finding', async () => ({ action: 'clean', content: 'x', findings: ['has space'] })]] as const) {
    const t = setup({ deriveSanitizers: [sanitizer('s', run as never)] });
    const before = (await t.store.auditLog('acme')).length;
    const r = await t.engine.derive(chief, await context(t.engine, ['handbook']), 'text', 'artifact');
    assert.equal(r.ok, false, name);
    const entry = await last(t.store);
    assert.equal(entry.reason, 'DENIED:SANITIZER', name);
    assert.ok((await t.store.auditLog('acme')).length > before);
    const ids = await new Promise<string[]>((resolve, reject) => { t.store.transaction('acme', async tx => { await tx.load({ corpus: 1000 }); resolve(Object.values(tx.state.knowledge).filter(k => k.origin === 'model').map(k => k.id)); }).catch(reject); });
    assert.deepEqual(ids, [], `${name}: nothing derived`);
  }
});
test('closed findings: validation, and audit verification rejects a tampered finding', async () => {
  assert.ok(validFindings(['pii:redact', 'volume:confidential']));
  assert.equal(validFindings(['has space']), false); assert.equal(validFindings(['x'.repeat(129)]), false);
  assert.equal(validFindings(new Array(33).fill('a')), false); assert.equal(validFindings('a'), false);
  const { engine, store } = setup({ releaseFilters: [filter('pii', async () => ({ action: 'redact', content: 'x' }))] });
  await engine.release(chief, await context(engine), 'chief', SECRET);
  const log = structuredClone(await store.auditLog('acme'));
  assert.equal(verifyAudit(log), true);
  log.at(-1)!.findings = ['secret content here'];
  assert.equal(verifyAudit(log), false);
});
test('obligations: release_filter and approval_required are validated, merged as a union and ordered', () => {
  assert.deepEqual(parseObligations([{ type: 'release_filter', value: ['b', 'a'] }, { type: 'release_filter', value: ['c', 'a'] }]), [{ type: 'release_filter', value: ['a', 'b', 'c'] }]);
  assert.equal(parseObligations([{ type: 'release_filter', value: [] }]), null);
  assert.equal(parseObligations([{ type: 'release_filter', value: ['a', 'a'] }]), null);
  assert.equal(parseObligations([{ type: 'release_filter', value: ['a b'] }]), null);
  assert.equal(parseObligations([{ type: 'release_filter', value: 'a' }]), null);
  assert.equal(parseObligations([{ type: 'release_filter', value: Array.from({ length: 17 }, (_, i) => `f${i}`) }]), null);
  const wide = [{ type: 'release_filter' as const, value: Array.from({ length: 10 }, (_, i) => `f${i}`) }, { type: 'release_filter' as const, value: Array.from({ length: 10 }, (_, i) => `g${i}`) }];
  assert.equal(parseObligations(wide), null, 'a union beyond 16 filters cannot be satisfied');
  assert.deepEqual(parseObligations([{ type: 'approval_required', value: 'volume_budget' }]), [{ type: 'approval_required', value: 'volume_budget' }]);
  assert.equal(parseObligations([{ type: 'approval_required' }]), null);
  assert.equal(parseObligations([{ type: 'approval_required', value: 'x', extra: 1 }]), null);
  assert.deepEqual(merge([{ type: 'no_persist' }], [{ type: 'release_filter', value: ['p'] }, { type: 'approval_required', value: 'a' }]).map(o => o.type), ['no_persist', 'release_filter', 'approval_required']);
});
test('approval_required from a policy is refused by the engine callers that cannot obtain an approval (fail closed)', async () => {
  const policy: PolicyHook = { revision: 'p', check: async () => true, verdict: async () => ({ allow: true, obligations: [{ type: 'approval_required', value: 'manager' }] }) };
  const { engine, store } = setup({ policy });
  const r = await engine.openContext(chief, ['handbook'], 'work', { unenforceable: ['approval_required'] });
  assert.equal(r.ok, false); assert.equal((await last(store)).reason, 'DENIED:UNSUPPORTED_OBLIGATION');
  const open = await engine.openContext(chief, ['handbook'], 'work');
  assert.ok(open.ok && open.obligations.some(o => o.type === 'approval_required'), 'an enforcement point that can hold for approval receives the obligation');
});

// ---- ProtectedRuntime -------------------------------------------------------------------------------------------
test('ProtectedRuntime: release_filter of the context applies to the provider hop; a missing filter stops before the provider', async () => {
  const policy: PolicyHook = { revision: 'p', check: async () => true, verdict: async i => ({ allow: true, obligations: i.action === 'read' ? [{ type: 'release_filter', value: ['pii'] }] : [] }) };
  const prompts: string[] = [];
  const provider = { principal: 'provider', generate: async (r: { instruction: string; documents: { content: string }[] }) => { prompts.push(r.documents[0]!.content); return 'Synthetic answer'; } };
  const redact = filter('pii', async i => ({ action: 'redact', content: i.content.replace('project alpha', 'project [x]') }));
  const withFilter = setup({ policy, releaseFilters: [redact] });
  const answer = await new ProtectedRuntime(withFilter.engine, provider).answer(chief, ['project-alpha'], 'work', 'Summarize');
  assert.ok(answer.ok, 'release_filter is enforced by the runtime, not a reason to deny');
  assert.deepEqual(prompts, ['Product project [x] schedule: launch in November.']);
  const without = setup({ policy });
  prompts.length = 0;
  assert.equal((await new ProtectedRuntime(without.engine, provider).answer(chief, ['project-alpha'], 'work', 'Summarize')).ok, false);
  assert.deepEqual(prompts, [], 'the provider never received the content');
  const bad = setup({ policy, releaseFilters: [filter('pii', async () => ({ action: 'redact', content: 'not json' }))] });
  assert.equal((await new ProtectedRuntime(bad.engine, provider).answer(chief, ['project-alpha'], 'work', 'Summarize')).ok, false, 'a redaction that breaks the payload denies');
  assert.deepEqual(prompts, []);
});

// ---- volume budgets ---------------------------------------------------------------------------------------------
function budget(limits: ConstructorParameters<typeof VolumeBudget>[0]['limits'], extra: Partial<ConstructorParameters<typeof VolumeBudget>[0]> = {}) {
  let t = now; const limiter = new MemoryRateLimits({ clock: () => t });
  return { volume: new VolumeBudget({ limiter, windowMs: 60_000, limits, ...extra }), advance: (ms: number) => { t += ms; }, limiter };
}
test('volume budget: bytes and documents per classification; the crossing disclosure is denied, audited with a closed finding and creates no context', async () => {
  const size = Buffer.byteLength(kbFixture(now).knowledge['project-alpha']!.content);
  const b = budget({ confidential: { bytes: size * 2 } });
  const { engine, store, events } = setup({ volume: b.volume });
  assert.ok((await engine.openContext(chief, ['project-alpha'], 'work')).ok);
  assert.ok((await engine.openContext(chief, ['project-alpha'], 'work')).ok);
  const third = await engine.openContext(chief, ['project-alpha'], 'work');
  assert.equal(third.ok, false);
  const entry = await last(store);
  assert.equal(entry.reason, 'DENIED:VOLUME_EXCEEDED'); assert.deepEqual(entry.findings, ['volume:confidential']);
  assert.ok(events.some(e => e.type === 'volume_exceeded' && e.classification === 'confidential'));
  assert.ok((await engine.openContext(chief, ['handbook'], 'work')).ok, 'public content has no limit');
  b.advance(60_000);
  assert.ok((await engine.openContext(chief, ['project-alpha'], 'work')).ok, 'the window has moved on');
  const docs = budget({ public: { documents: 1 } });
  const t2 = setup({ volume: docs.volume });
  assert.ok((await t2.engine.openContext(chief, ['handbook'], 'work')).ok);
  assert.equal((await t2.engine.openContext(chief, ['handbook'], 'work')).ok, false, 'the second disclosure of one document goes over a one-document budget');
});
test('volume budget: per (tenant, user, agent); released output counts too; approval mode defers with a distinct code; a store error fails closed', async () => {
  const b = budget({ confidential: { bytes: 60 } });
  const { engine, store } = setup({ volume: b.volume });
  const lead = bindings.lead;
  const chiefCtx = await engine.openContext(chief, ['project-alpha'], 'work'); assert.ok(chiefCtx.ok);
  assert.ok((await engine.openContext(lead, ['project-alpha'], 'work')).ok, 'another principal has its own window');
  // the chief spent 52 bytes of 60 reading; a 40-byte release goes over the confidential budget
  const rel = await engine.release(chief, chiefCtx.value.context, 'chief', 'x'.repeat(40));
  assert.equal(rel.ok, false); assert.equal((await last(store)).reason, 'DENIED:VOLUME_EXCEEDED');
  assert.equal((await engine.release(chief, chiefCtx.value.context, 'chief', 'x'.repeat(4))).ok, false, 'a refused charge still counts: the budget stays exhausted for the window');
  const approval = budget({ confidential: { documents: 1 } }, { onExceed: 'approval' });
  const t = setup({ volume: approval.volume });
  assert.ok((await t.engine.openContext(chief, ['project-alpha'], 'work')).ok);
  assert.equal((await t.engine.openContext(chief, ['project-alpha'], 'work')).ok, false);
  assert.equal((await last(t.store)).reason, 'DEFERRED:APPROVAL_REQUIRED');
  const broken = new VolumeBudget({ limiter: { shared: false, take: async () => { throw new Error('store down'); } }, windowMs: 60_000, limits: { confidential: { bytes: 1000 } } });
  const f = setup({ volume: broken });
  assert.equal((await f.engine.openContext(chief, ['project-alpha'], 'work')).ok, false);
  assert.equal((await last(f.store)).reason, 'DEFERRED:STORE_ERROR');
  assert.ok((await f.engine.openContext(chief, ['handbook'], 'work')).ok, 'classifications without a limit do not touch the store');
  assert.throws(() => new VolumeBudget({ limiter: new MemoryRateLimits(), windowMs: 10, limits: {} }), /Invalid volume/);
  assert.throws(() => new VolumeBudget({ limiter: new MemoryRateLimits(), windowMs: 60_000, limits: { secret: { bytes: 1 } } as never }), /Invalid volume/);
  assert.throws(() => new VolumeBudget({ limiter: new MemoryRateLimits(), windowMs: 60_000, limits: { public: { bytes: 0 } } }), /Invalid volume/);
});

// ---- decision cache ---------------------------------------------------------------------------------------------
test('decision cache: an allow is served from the cache and audited; a revocation advances the epoch, so no stale allow follows', async () => {
  const cache = new DecisionCache({ ttlMs: 60_000, clock: () => now });
  const { engine, store } = setup({ decisionCache: cache });
  const ask = () => engine.evaluate(chief, 'strategy', 'read', 'work');
  const first = await ask(), second = await ask();
  assert.ok(first.decision && second.decision); assert.notEqual(first.decisionId, second.decisionId);
  assert.deepEqual(cache.stats(), { hits: 1, misses: 1, size: 1 });
  assert.deepEqual(second.obligations, first.obligations);
  const log = await store.auditLog('acme');
  assert.equal(log.length, 2, 'the cached decision is audited too'); assert.equal(log[1]!.policyDigest, log[0]!.policyDigest);
  assert.equal(verifyAudit(log), true);
  await engine.revoke('acme', 'admin', 'grant', 'chief-run');
  const stale = await ask();
  assert.equal(stale.decision, false, 'no stale allow after revocation');
  assert.equal(cache.stats().hits, 1);
  // a knowledge revocation also advances the epoch
  const other = setup({ decisionCache: new DecisionCache({ ttlMs: 60_000, clock: () => now }) });
  assert.ok((await other.engine.evaluate(chief, 'handbook', 'read', 'work')).decision);
  await other.engine.revoke('acme', 'admin', 'knowledge', 'handbook');
  assert.equal((await other.engine.evaluate(chief, 'handbook', 'read', 'work')).decision, false);
});
test('decision cache: TTL, grant expiry, policy revision, destination and principal are part of the key; denials are never cached', async () => {
  let t = now;
  const cache = new DecisionCache({ ttlMs: 10_000, clock: () => t });
  const store = new MemoryStore(world(s => { s.grants['chief-run']!.expiresAt = now + 4000; }));
  const engine = new Engine(store, { clock: () => t, decisionCache: cache });
  assert.ok((await engine.evaluate(chief, 'strategy', 'read', 'work')).decision);
  t = now + 3000; assert.ok((await engine.evaluate(chief, 'strategy', 'read', 'work')).decision); assert.equal(cache.stats().hits, 1);
  t = now + 4001; assert.equal((await engine.evaluate(chief, 'strategy', 'read', 'work')).decision, false, 'the entry ends with the grant');
  assert.equal(cache.size, 0, 'the expired entry was dropped and the denial not cached');
  // TTL
  const s2 = setup({ decisionCache: new DecisionCache({ ttlMs: 1000, clock: () => t }) }); t = now;
  await s2.engine.evaluate(chief, 'handbook', 'read', 'work'); t = now + 1001; await s2.engine.evaluate(chief, 'handbook', 'read', 'work');
  // a different purpose, resource, action and principal are different keys
  const shared = new DecisionCache({ ttlMs: 10_000, clock: () => now });
  const e = setup({ decisionCache: shared }).engine;
  await e.evaluate(chief, 'handbook', 'read', 'work'); await e.evaluate(chief, 'handbook', 'derive', 'work'); await e.evaluate(chief, 'staff-faq', 'read', 'work'); await e.evaluate(bindings.lead, 'handbook', 'read', 'work');
  assert.equal(shared.stats().hits, 0); assert.equal(shared.size, 4);
  const deny = await e.evaluate(bindings.intern, 'strategy', 'read', 'work'); assert.equal(deny.decision, false);
  await e.evaluate(bindings.intern, 'strategy', 'read', 'work'); assert.equal(shared.size, 4, 'denials are not cached');
  // a new policy revision changes the digest, so an entry of the old revision is not used
  const a = new DecisionCache({ ttlMs: 10_000, clock: () => now });
  const st = new MemoryStore(world());
  const v1 = new Engine(st, { clock: () => now, decisionCache: a, policy: { revision: 'r1', check: async () => true } });
  const v2 = new Engine(st, { clock: () => now, decisionCache: a, policy: { revision: 'r2', check: async () => false } });
  assert.ok((await v1.evaluate(chief, 'handbook', 'read', 'work')).decision);
  assert.equal((await v2.evaluate(chief, 'handbook', 'read', 'work')).decision, false);
  assert.throws(() => new DecisionCache({ ttlMs: 300_001 }), /Invalid decision cache/); assert.throws(() => new DecisionCache({ ttlMs: 0 }), /Invalid/);
  assert.throws(() => new Engine(new MemoryStore(world()), { decisionCache: {} as never }), /Invalid decision cache/);
});
test('decision cache: a returned obligation list is a copy, so a caller cannot change what later hits return', async () => {
  const { engine } = setup({ decisionCache: new DecisionCache({ ttlMs: 60_000, clock: () => now }) });
  const first = await engine.evaluate(chief, 'strategy', 'read', 'work');
  first.obligations.length = 0;
  const second = await engine.evaluate(chief, 'strategy', 'read', 'work');
  const third = await engine.evaluate(chief, 'strategy', 'read', 'work');
  assert.ok(second.obligations.length === 2 && third.obligations.length === 2);
  second.obligations.pop(); assert.equal((await engine.evaluate(chief, 'strategy', 'read', 'work')).obligations.length, 2);
});
