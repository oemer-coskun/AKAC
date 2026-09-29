import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { generateKeyPairSync } from 'node:crypto';
import { runEvidenceVectors, runVectors, vectorCases } from '../conformance/run.ts';
import { Engine } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { MemoryStore } from '../reference/store.ts';
import { kbFixture, bindings } from '../examples/fixture.ts';
import { decide } from '../reference/policy.ts';
const schema = (name: string) => JSON.parse(readFileSync(new URL(`../schemas/${name}.json`, import.meta.url), 'utf8'));
test('all portable conformance vectors pass', () => {
  const results = runVectors();
  assert.ok(results.length >= 48);
  for (const result of results) assert.equal(result.pass, true, result.id);
});
test('reference records validate against closed JSON schemas', () => {
  const ajv = new Ajv2020(); const state = kbFixture();
  for (const [name, records] of [['principal', Object.values(state.actors)], ['grant', Object.values(state.grants)], ['knowledge', Object.values(state.knowledge)],
    ['binding', Object.values(bindings)], ['role', Object.values(state.roles)], ['group', Object.values(state.groups)],
    ['constraint', Object.values(state.constraints)], ['container', Object.values(state.containers)]] as const) {
    const validate = ajv.compile(schema(name));
    for (const record of records) assert.ok(validate(record), `${name}: ${JSON.stringify(validate.errors)}`);
    assert.equal(validate({ ...records[0], allowed: true }), false);
  }
  const knowledge = new Ajv2020().compile(schema('knowledge')), container = new Ajv2020().compile(schema('container'));
  const { origin: _origin, ...withoutOrigin } = state.knowledge.handbook!;
  assert.equal(knowledge(withoutOrigin), false, 'origin is required');
  assert.equal(knowledge({ ...state.knowledge.handbook!, kind: 'memory', origin: 'human' }), false, 'memory is always model-originated');
  assert.equal(container({ ...state.containers['kb-corporate']!, parent: 'f-vault' }), false, 'a knowledge base is a root');
  const { parent: _parent, ...orphan } = state.containers['f-vault']!;
  assert.equal(container(orphan), false, 'a folder has a parent');
});
test('every vector decision matches the decision schema', () => {
  const validate = new Ajv2020().addSchema(schema('obligation')).compile(schema('decision'));
  for (const c of vectorCases()) { const d = decide(c.state, c.request); assert.ok(validate(d), `${c.id}: ${JSON.stringify(validate.errors)}`); }
  assert.equal(validate({ effect: 'deny', code: 'X' }), false, 'deny requires a category');
});
test('0.4 evidence vectors pass: RFC 9162 trees, RFC 8785 canonical form, audit formats, obligations, reason codes', () => {
  const results = runEvidenceVectors();
  assert.ok(results.length >= 30);
  for (const result of results) assert.equal(result.pass, true, result.id);
});
test('0.4 evidence records validate against closed JSON schemas', async () => {
  const ajv = new Ajv2020().addSchema(schema('obligation'));
  const [audit, checkpoint, proof, decision] = [ajv.compile(schema('audit')), ajv.compile(schema('checkpoint')), ajv.compile(schema('audit-proof')), ajv.compile(schema('decision'))];
  const now = 1800000000000;
  const state = kbFixture(now); state.actors.aud = { id: 'aud', tenant: 'acme', kind: 'user', roles: ['auditor'], projects: [], clearance: 'public', active: true };
  const store = new MemoryStore(state), engine = new Engine(store, { clock: () => now });
  const allowed = await engine.openContext(bindings.chief, ['strategy'], 'work', { trace: { traceId: '4bf92f3577b34da6a3ce929d0e0e4736' } });
  await engine.openContext(bindings.intern, ['strategy'], 'work');
  assert.ok(allowed.ok);
  const pair = generateKeyPairSync('ed25519');
  const control = new ControlPlane(store, { clock: () => now, checkpoint: { privatePem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), keyId: 'k' } });
  const head = await control.latestCheckpoint('acme', 'aud'); assert.ok(head.ok && head.value.checkpoint);
  assert.ok(checkpoint(head.value.checkpoint), JSON.stringify(checkpoint.errors));
  for (const entry of await store.auditLog('acme')) assert.ok(audit(entry), JSON.stringify(audit.errors));
  const inclusion = await control.auditProof('acme', 'aud', 0, 2), consistency = await control.auditConsistency('acme', 'aud', 1, 2);
  assert.ok(inclusion.ok && consistency.ok);
  for (const p of [inclusion.value, consistency.value]) assert.ok(proof(p), JSON.stringify(proof.errors));
  const entry = (await store.auditLog('acme'))[0]!;
  assert.ok(decision({ decisionId: allowed.decisionId, effect: 'allow', code: entry.reasonCode, policyRevision: entry.policyVersion, policyDigest: entry.policyDigest, obligations: allowed.obligations }), JSON.stringify(decision.errors));
  assert.equal(decision({ effect: 'deny', code: 'KNOWLEDGE_BOUNDARY', category: 'deny', obligations: [{ type: 'no_persist' }] }), false, 'a deny carries no obligations');
  assert.equal(decision({ effect: 'allow', code: 'KNOWLEDGE_BOUNDARY' }), false);
  assert.equal(audit({ ...entry, reasonCode: 'MADE_UP' }), false);
});
