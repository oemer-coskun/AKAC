// Destination profiles and run result limits (AKAC 0.4, ADR-008, spec/drafts/0.4-destinations.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { Engine } from '../reference/engine.ts';
import type { EngineOptions } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { ProtectedRuntime } from '../reference/runtime.ts';
import { AuthzenPdp, mapEvaluation } from '../reference/authzen.ts';
import { MemoryStore } from '../reference/store.ts';
import { decide, transitiveClassification } from '../reference/policy.ts';
import { runDestinationVectors } from '../conformance/run-destinations.ts';
import { DESTINATION_CLASSES, LEVELS } from '../reference/types.ts';
import type { Binding, Grant, Knowledge, Level, PolicyHook, State } from '../reference/types.ts';
import { bindings } from '../examples/fixture.ts';
import { destination, destinationWorld, now } from './destinations-fixture.ts';

const chief = bindings.chief;
function setup(state: State = destinationWorld(), options: EngineOptions = {}) {
  const store = new MemoryStore(state);
  return { store, engine: new Engine(store, { clock: () => now, ...options }), control: new ControlPlane(store, { clock: () => now }) };
}
const last = async (store: MemoryStore) => (await store.auditLog('acme')).at(-1)!;
let runs = 0;
/** A fresh run (grant copy) of the subject: every release below covers exactly the documents it names. */
async function fresh(store: MemoryStore, from = 'chief-run'): Promise<Binding> {
  const grant = `run-${++runs}`;
  await store.transaction('acme', async tx => { tx.state.grants[grant] = { ...structuredClone(tx.state.grants[from]!), id: grant }; });
  return { ...chief, grant };
}
async function share(engine: Engine, ids: string[], recipient: string, options: { purpose?: string; action?: 'share' | 'export'; b?: Binding; store?: MemoryStore } = {}) {
  const b = options.b ?? (options.store ? await fresh(options.store) : chief);
  const context = await engine.openContext(b, ids, options.purpose ?? 'work');
  assert.ok(context.ok, 'the context itself is authorized');
  return engine.release(b, context.value.context, recipient, 'Synthetic answer', options.action ?? 'share');
}
const restrictedTo = (s: State, ...destinations: string[]) => { s.grants['chief-run']!.destinations = destinations; };
const hook = (verdict: unknown): PolicyHook => ({ revision: 'test/destinations', check: async () => true, verdict: async () => verdict as never });

test('a model-provider profile up to confidential: restricted content is denied, confidential content allowed with destination_restricted', async () => {
  const { engine, store } = setup();
  const denied = await share(engine, ['strategy'], 'llm', { store });
  assert.equal(denied.ok, false);
  assert.equal((await last(store)).reasonCode, 'RECIPIENT');
  for (const action of ['share', 'export'] as const) {
    const allowed = await share(engine, ['project-alpha'], 'llm', { action, store });
    assert.ok(allowed.ok);
    assert.deepEqual(allowed.value.destination, { id: 'eu-llm', class: 'model-provider' });
    assert.deepEqual(allowed.obligations.find(o => o.type === 'destination_restricted'), { type: 'destination_restricted', value: ['model-provider', 'eu-llm'] });
    assert.deepEqual((await last(store)).obligations, allowed.obligations, 'the obligation is audited');
  }
  // A tool profile up to internal: confidential denied, public allowed.
  assert.equal((await share(engine, ['project-alpha'], 'crm', { store })).ok, false);
  assert.ok((await share(engine, ['handbook'], 'crm', { store })).ok);
  // 0.3 behaviour: a user without a profile under an unrestricted run carries no destination obligation.
  const legacy = await share(engine, ['strategy'], 'chief', { store });
  assert.ok(legacy.ok); assert.equal(legacy.value.destination, undefined);
  assert.ok(!legacy.obligations.some(o => o.type === 'destination_restricted'));
});

test('a run restricted to internal-user cannot release to a provider, a tool or a service without a profile', async () => {
  const { engine } = setup(destinationWorld(s => restrictedTo(s, 'internal-user')));
  assert.equal((await share(engine, ['handbook'], 'llm')).ok, false);
  assert.equal((await share(engine, ['handbook'], 'crm')).ok, false);
  assert.equal((await share(engine, ['handbook'], 'legacy-svc')).ok, false, 'no profile under a restricted run denies');
  const user = await share(engine, ['handbook'], 'lead');
  assert.ok(user.ok);
  assert.deepEqual(user.obligations.find(o => o.type === 'destination_restricted'), { type: 'destination_restricted', value: ['internal-user'] });
  assert.deepEqual(user.value.destination, { class: 'internal-user' });
  // A run restricted to one profile id admits exactly that profile.
  const byId = setup(destinationWorld(s => restrictedTo(s, 'eu-llm')));
  assert.ok((await share(byId.engine, ['handbook'], 'llm')).ok);
  assert.equal((await share(byId.engine, ['handbook'], 'crm')).ok, false);
  assert.equal((await share(byId.engine, ['handbook'], 'lead')).ok, false, 'the implicit internal-user destination is not listed');
});

test('inactive, unknown, foreign, malformed and class-named profiles deny', async () => {
  const cases: [string, (s: State) => void, string][] = [
    ['inactive', s => { s.destinations!['eu-llm']!.active = false; }, 'llm'],
    ['unknown', s => { s.actors.llm!.destination = 'no-such-profile'; }, 'llm'],
    ['another tenant', () => {}, 'xt'],
    ['malformed class', s => { (s.destinations!['eu-llm'] as { class: string }).class = 'partner'; }, 'llm'],
    ['malformed level', s => { (s.destinations!['eu-llm'] as { maxClassification: string }).maxClassification = 'secret'; }, 'llm'],
    ['malformed purposes', s => { (s.destinations!['eu-llm'] as { purposes: unknown }).purposes = 'work'; }, 'llm'],
    ['id is a class name', s => { s.destinations!.tool = destination('tool', 'tool', 'restricted'); s.actors.llm!.destination = 'tool'; }, 'llm'],
    ['malformed run destinations', s => { (s.grants['chief-run'] as { destinations: unknown }).destinations = []; }, 'chief']
  ];
  for (const [name, edit, recipient] of cases) {
    const { engine } = setup(destinationWorld(edit));
    const context = await engine.openContext(chief, ['handbook'], 'work');
    // A malformed run restriction already invalidates the grant (decide denies INVALID_DELEGATION).
    if (!context.ok) { assert.equal(name, 'malformed run destinations'); continue; }
    assert.equal((await engine.release(chief, context.value.context, recipient, 'Synthetic answer')).ok, false, name);
  }
});

test('purpose mismatch between the context and the profile denies', async () => {
  const state = destinationWorld(s => { s.destinations!['eu-llm']!.purposes = ['support']; s.grants['chief-run']!.purposes = ['work', 'support']; });
  const { engine } = setup(state);
  assert.equal((await share(engine, ['handbook'], 'llm', { purpose: 'work' })).ok, false);
  const fresh = setup(structuredClone(state));
  assert.ok((await share(fresh.engine, ['handbook'], 'llm', { purpose: 'support' })).ok);
});

test('the transitive classification of released sources counts, including through a derived artifact', async () => {
  // A mislabelled artifact (own label internal) derived from restricted strategy.
  const digest: Knowledge = { id: 'digest', tenant: 'acme', version: 1, kind: 'artifact', origin: 'model', content: 'Synthetic digest.',
    classification: 'internal', projects: [], readerRoles: ['executive'], readers: [], sources: [{ id: 'strategy', version: 1 }], active: true };
  const state = destinationWorld(s => { s.knowledge.digest = digest; });
  assert.equal(transitiveClassification(state, digest), 'restricted');
  const { engine } = setup(state);
  assert.equal((await share(engine, ['digest'], 'llm')).ok, false, 'restricted via its source, above the profile');
  assert.equal((await share(engine, ['digest'], 'crm')).ok, false);
  // Derivation through the engine: the artifact of a restricted source is never released to the provider.
  const derived = setup();
  const context = await derived.engine.openContext(chief, ['strategy'], 'work'); assert.ok(context.ok);
  const artifact = await derived.engine.derive(chief, context.value.context, 'Synthetic summary', 'artifact'); assert.ok(artifact.ok);
  // derive() does not end the run; a second run of the same subject reads the artifact.
  const next: Binding = { ...chief, grant: 'chief-run-2' };
  await derived.store.transaction('acme', async tx => { tx.state.grants['chief-run-2'] = { ...structuredClone(tx.state.grants['chief-run']!), id: 'chief-run-2' }; });
  assert.equal((await share(derived.engine, [artifact.value.id], 'llm', { b: next })).ok, false);
  // Positive control: a profile cleared for restricted content receives it.
  const cleared = setup(destinationWorld(s => { s.knowledge.digest = digest; s.destinations!['eu-llm']!.maxClassification = 'restricted'; }));
  assert.ok((await share(cleared.engine, ['digest'], 'llm')).ok);
});

test('child grants can only narrow destinations and the result limit', async () => {
  const parent = (s: State) => { s.grants['chief-run']!.destinations = ['internal-user', 'model-provider']; s.grants['chief-run']!.maxResults = 10; };
  const child = (extra: Partial<Grant>, drop: (keyof Grant)[] = []): Grant => {
    const g: Grant = { ...structuredClone(destinationWorld(parent).grants['chief-run']!), id: `child-${Math.random().toString(16).slice(2, 10)}`, parent: 'chief-run', ...extra };
    for (const k of drop) delete g[k];
    return g;
  };
  const widening: [string, Grant][] = [
    ['adds a destination class', child({ destinations: ['internal-user', 'tool'] })],
    ['drops the destination restriction', child({}, ['destinations'])],
    ['raises the result limit', child({ maxResults: 20 })],
    ['drops the result limit', child({}, ['maxResults'])],
    ['result limit above the core cap', child({ maxResults: 65 })]
  ];
  for (const [name, g] of widening) {
    const { engine, control } = setup(destinationWorld(parent));
    assert.equal((await engine.delegate(chief, g)).ok, false, `delegate: ${name}`);
    const issued = await control.issueGrant('acme', 'sec', g);
    assert.equal(issued.ok, false, `issueGrant: ${name}`);
    const s = destinationWorld(parent); s.grants[g.id] = g;
    assert.equal(decide(s, { binding: { ...chief, grant: g.id }, resource: 'handbook', action: 'read', purpose: 'work', now }).effect, 'deny', `decide: ${name}`);
  }
  const { engine, control } = setup(destinationWorld(parent));
  assert.ok((await engine.delegate(chief, child({ destinations: ['internal-user'], maxResults: 5 }))).ok);
  assert.ok((await control.issueGrant('acme', 'sec', child({ destinations: ['model-provider'], maxResults: 10 }))).ok);
  // An unrestricted parent admits a restricted child.
  const open = setup();
  assert.ok((await open.engine.delegate(chief, { ...structuredClone(destinationWorld().grants['chief-run']!), id: 'narrow', parent: 'chief-run', destinations: ['tool'], maxResults: 1 })).ok);
});

test('grant.maxResults bounds openContext and retrieval', async () => {
  const { engine, store } = setup(destinationWorld(s => { s.grants['chief-run']!.maxResults = 2; }));
  assert.equal((await engine.openContext(chief, ['handbook', 'strategy', 'project-alpha'], 'work')).ok, false);
  assert.equal((await last(store)).reasonCode, 'OUT_OF_SCOPE');
  const retrieved = await engine.retrieve(chief, 'Product', 'work', 5);
  assert.ok(retrieved.ok); assert.equal(retrieved.value.documents.length, 2, 'the limit is capped by the run');
  const unbounded = setup();
  const all = await unbounded.engine.retrieve(chief, 'Product', 'work', 5);
  assert.ok(all.ok); assert.equal(all.value.documents.length, 3);
  const candidates = { candidates: async () => ['handbook', 'strategy', 'project-alpha'] };
  const indexed = setup(destinationWorld(s => { s.grants['chief-run']!.maxResults = 1; }), { candidates });
  const one = await indexed.engine.retrieve(chief, 'Product', 'work', 5);
  assert.ok(one.ok); assert.equal(one.value.documents.length, 1);
});

test('runtime provider gate: the provider profile is enforced before inference and destination obligations are honoured', async () => {
  let invoked = 0;
  const provider = { principal: 'llm', generate: async () => { invoked++; return 'Synthetic answer'; } };
  const plain = setup();
  assert.equal((await new ProtectedRuntime(plain.engine, provider).answer(await fresh(plain.store), ['strategy'], 'work', 'Summarize')).ok, false);
  assert.equal(invoked, 0, 'restricted input never reaches a confidential-only provider');
  const answer = await new ProtectedRuntime(plain.engine, provider).answer(await fresh(plain.store), ['project-alpha'], 'work', 'Summarize');
  assert.ok(answer.ok); assert.equal(invoked, 1);
  // Restricted run: the provider class is listed, the answer goes to the (internal-user) subject.
  const restricted = setup(destinationWorld(s => restrictedTo(s, 'model-provider', 'internal-user')));
  const bound = await new ProtectedRuntime(restricted.engine, provider).answer(chief, ['project-alpha'], 'work', 'Summarize');
  assert.ok(bound.ok); assert.equal(invoked, 2);
  assert.deepEqual(bound.obligations.find(o => o.type === 'destination_restricted'), { type: 'destination_restricted', value: ['internal-user'] });
  // A run that does not list the provider class: denied before inference.
  const userOnly = setup(destinationWorld(s => restrictedTo(s, 'internal-user')));
  assert.equal((await new ProtectedRuntime(userOnly.engine, provider).answer(chief, ['handbook'], 'work', 'Summarize')).ok, false);
  assert.equal(invoked, 2);
  // A supplemental-policy destination the provider is not: denied before inference.
  const elsewhere = setup(destinationWorld(), { policy: hook({ allow: true, obligations: [{ type: 'destination_restricted', value: ['other-dest'] }] }) });
  assert.equal((await new ProtectedRuntime(elsewhere.engine, provider).answer(chief, ['handbook'], 'work', 'Summarize')).ok, false);
  assert.equal(invoked, 2);
  // A provider without a profile cannot satisfy any destination obligation (0.3 providers keep working without one).
  const legacy = setup(destinationWorld(), { policy: hook({ allow: true, obligations: [{ type: 'destination_restricted', value: ['model-provider'] }] }) });
  assert.equal((await new ProtectedRuntime(legacy.engine, { ...provider, principal: 'legacy-svc' }).answer(chief, ['handbook'], 'work', 'Summarize')).ok, false);
  assert.equal(invoked, 2);
  assert.ok((await new ProtectedRuntime(setup().engine, { ...provider, principal: 'legacy-svc' }).answer(chief, ['handbook'], 'work', 'Summarize')).ok);
});

test('Engine.evaluate and AuthZEN context.destination apply the destination gate without creating contexts', async () => {
  const { engine, store } = setup();
  const allow = await engine.evaluate(chief, 'project-alpha', 'share', 'work', { destination: 'eu-llm' });
  assert.equal(allow.decision, true);
  assert.deepEqual(allow.obligations.find(o => o.type === 'destination_restricted')?.value, ['model-provider', 'eu-llm']);
  assert.equal((await last(store)).decisionId, allow.decisionId);
  assert.equal((await last(store)).operation, 'evaluate');
  for (const [resource, dest] of [['strategy', 'eu-llm'], ['handbook', 'no-such-profile'], ['handbook', 'other-dest'], ['handbook', 'tool']] as const) {
    const v = await engine.evaluate(chief, resource, 'share', 'work', { destination: dest });
    assert.equal(v.decision, false, `${resource} -> ${dest}`); assert.equal(v.code, 'RECIPIENT');
  }
  const read = await engine.evaluate(chief, 'handbook', 'read', 'work');
  assert.ok(read.decision && !read.obligations.some(o => o.type === 'destination_restricted'));
  await store.transaction('acme', async tx => { assert.equal(Object.keys(tx.state.contexts).length, 0, 'no context was created'); });
  const restricted = setup(destinationWorld(s => restrictedTo(s, 'internal-user', 'tool')));
  // R121: a share/export evaluation that names no Destination is denied, restricted run or not.
  const unnamed = await restricted.engine.evaluate(chief, 'handbook', 'export', 'work');
  assert.equal(unnamed.decision, false); assert.equal(unnamed.code, 'RECIPIENT');
  assert.equal((await engine.evaluate(chief, 'handbook', 'share', 'work')).code, 'RECIPIENT');
  const named = await restricted.engine.evaluate(chief, 'handbook', 'export', 'work', { destination: 'crm-tool' });
  assert.equal(named.decision, true);
  assert.deepEqual(named.obligations.find(o => o.type === 'destination_restricted')?.value, ['tool', 'crm-tool'], 'the PEP must keep to the named destination');
  assert.equal((await restricted.engine.evaluate(chief, 'handbook', 'share', 'work', { destination: 'eu-llm' })).decision, false);
  // AuthZEN profile mapping.
  const ask = (dest?: unknown) => ({ subject: { type: 'user', id: 'chief', properties: { agent: 'chief-agent', grant: 'chief-run' } },
    resource: { type: 'knowledge', id: 'project-alpha' }, action: { name: 'share' }, context: { purpose: 'work', ...(dest !== undefined ? { destination: dest } : {}) } });
  const mapped = mapEvaluation('acme', ask('eu-llm'));
  assert.ok(mapped.ok); assert.equal(mapped.destination, 'eu-llm');
  assert.deepEqual(mapEvaluation('acme', ask('../x')), { ok: false, kind: 'unsupported', actor: 'chief', grant: 'chief-run' });
  assert.equal((mapEvaluation('acme', ask()) as { destination?: string }).destination, undefined);
  const pdp = new AuthzenPdp(store, { clock: () => now });
  const out = await pdp.evaluate('acme', mapped);
  assert.equal(out.decision, true); assert.equal((await last(store)).operation, 'authzen_evaluate');
  const crm = mapEvaluation('acme', ask('crm-tool')); assert.ok(crm.ok);
  assert.equal((await pdp.evaluate('acme', crm)).decision, false);
});

test('control plane: upsertDestination is security-admin only, validated, audited and tenant-scoped', async () => {
  const { control, store, engine } = setup();
  const d = destination('eu-llm-2', 'model-provider', 'internal');
  const denied = await control.upsertDestination('acme', 'chief', d);
  assert.equal(denied.ok, false); assert.equal((await last(store)).reasonCode, 'NOT_ADMIN');
  const created = await control.upsertDestination('acme', 'sec', d);
  assert.ok(created.ok); assert.equal((await last(store)).operation, 'upsert_destination');
  const epoch = async () => store.transaction('acme', async tx => tx.state.epochs.acme ?? 0);
  const before = await epoch();
  assert.ok((await control.upsertDestination('acme', 'sec', { ...d, active: false })).ok);
  assert.equal(await epoch(), before + 1, 'an update advances the tenant epoch');
  for (const bad of [{ ...d, id: 'tool' }, { ...d, class: 'partner' }, { ...d, maxClassification: 'secret' }, { ...d, tenant: 'other' },
    { ...d, purposes: ['work', 'work'] }, { ...d, extra: true }, { ...d, purposes: [''] }]) {
    const r = await control.upsertDestination('acme', 'sec', bad as never);
    assert.ok(!r.ok && r.code === 'INVALID_REQUEST', JSON.stringify(bad));
  }
  // Tenant scoping: the same id in another tenant is another record.
  assert.ok((await control.upsertDestination('other', 'other-sec', destination('eu-llm', 'external', 'restricted', ['work'], 'other'))).ok);
  const mine = await control.readDestination('acme', 'sec', 'eu-llm');
  assert.ok(mine.ok); assert.equal(mine.value?.class, 'model-provider');
  assert.equal((await control.readDestination('acme', 'other-sec', 'eu-llm')).ok, false);
  const theirs = await control.readDestination('other', 'other-sec', 'crm-tool');
  assert.ok(theirs.ok); assert.equal(theirs.value, null, 'another tenant\'s record reads as absent');
  // Actors reference profiles; grants carry run restrictions.
  const llm = structuredClone(destinationWorld().actors.llm!);
  assert.ok((await control.upsertActor('acme', 'sec', { ...llm, destination: 'crm-tool' })).ok);
  assert.equal((await share(engine, ['project-alpha'], 'llm')).ok, false, 'now a tool profile up to internal');
  assert.equal((await control.upsertActor('acme', 'sec', { ...llm, destination: 'tool' })).ok, false, 'a class name is not a profile id');
  const grant = { ...structuredClone(destinationWorld().grants['chief-run']!), id: 'fresh-run' };
  assert.ok((await control.issueGrant('acme', 'sec', { ...grant, destinations: ['model-provider'], maxResults: 3 })).ok);
  for (const bad of [{ destinations: [] }, { destinations: ['../x'] }, { maxResults: 0 }, { maxResults: 65 }, { maxResults: 1.5 }]) {
    assert.equal((await control.issueGrant('acme', 'sec', { ...grant, id: `bad-${Math.random().toString(16).slice(2, 8)}`, ...bad } as never)).ok, false, JSON.stringify(bad));
  }
});

test('property: a destination restriction or profile never turns a deny into an allow', async () => {
  const names = [...DESTINATION_CLASSES, 'eu-llm', 'crm-tool', 'other-dest'];
  const arb = fc.record({
    restrict: fc.subarray(names, { minLength: 1 }),
    recipient: fc.constantFrom('llm', 'crm', 'legacy-svc', 'xt', 'chief', 'lead', 'intern'),
    doc: fc.constantFrom('handbook', 'project-alpha', 'strategy'),
    max: fc.constantFrom(...LEVELS), active: fc.boolean(), purposes: fc.constantFrom(['work'], ['support'], [] as string[]),
    profile: fc.constantFrom('eu-llm', 'crm-tool', 'no-such-profile')
  });
  await fc.assert(fc.asyncProperty(arb, async x => {
    const base = (edit: (s: State) => void = () => {}) => destinationWorld(s => {
      Object.assign(s.destinations!['eu-llm']!, { maxClassification: x.max as Level, active: x.active, purposes: x.purposes }); edit(s);
    });
    const outcome = async (s: State) => {
      const { engine } = setup(s);
      const context = await engine.openContext(chief, [x.doc], 'work');
      return context.ok && (await engine.release(chief, context.value.context, x.recipient, 'Synthetic answer')).ok;
    };
    const open = await outcome(base());
    // Run restriction.
    if (await outcome(base(s => restrictedTo(s, ...x.restrict)))) assert.ok(open, `restriction widened: ${JSON.stringify(x)}`);
    // Recipient profile (for principals that have none in the base world).
    if (['legacy-svc', 'chief', 'lead', 'intern'].includes(x.recipient) && await outcome(base(s => { s.actors[x.recipient]!.destination = x.profile; }))) {
      assert.ok(open, `profile widened: ${JSON.stringify(x)}`);
    }
  }), { numRuns: 60, seed: 8008 });
});

test('destination conformance vectors pass (conformance/vectors-destinations.json)', () => {
  const rows = runDestinationVectors();
  assert.ok(rows.length >= 29);
  for (const r of rows) assert.ok(r.pass && (r.outcome === 'SUCCESS' || r.outcome === 'SAFE_BLOCK'), `${r.id}: ${r.outcome}`);
});

test('destination records and extended grants and principals validate against the closed JSON schemas', async () => {
  const { Ajv2020 } = await import('ajv/dist/2020.js');
  const { readFileSync } = await import('node:fs');
  const schema = (name: string) => new Ajv2020().compile(JSON.parse(readFileSync(new URL(`../schemas/${name}.json`, import.meta.url), 'utf8')));
  const [dest, grant, principal] = [schema('destination'), schema('grant'), schema('principal')];
  const w = destinationWorld(s => { s.grants['chief-run']!.destinations = ['internal-user', 'eu-llm']; s.grants['chief-run']!.maxResults = 5; });
  for (const d of Object.values(w.destinations!)) assert.ok(dest(d), JSON.stringify(dest.errors));
  assert.ok(grant(w.grants['chief-run']), JSON.stringify(grant.errors)); assert.ok(principal(w.actors.llm), JSON.stringify(principal.errors));
  assert.equal(dest({ ...w.destinations!['eu-llm'], id: 'tool' }), false);
  assert.equal(grant({ ...w.grants['chief-run'], maxResults: 65 }), false);
  assert.equal(principal({ ...w.actors.llm, destination: 'model-provider' }), false);
});
