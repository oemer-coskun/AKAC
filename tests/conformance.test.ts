import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { runVectors, vectorCases } from '../conformance/run.ts';
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
  const validate = new Ajv2020().compile(schema('decision'));
  for (const c of vectorCases()) { const d = decide(c.state, c.request); assert.ok(validate(d), `${c.id}: ${JSON.stringify(validate.errors)}`); }
  assert.equal(validate({ effect: 'deny', code: 'X' }), false, 'deny requires a category');
});
