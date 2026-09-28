import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { runVectors } from '../conformance/run.ts';
import { fixture, bindings } from '../examples/fixture.ts';
test('all portable conformance vectors pass', () => {
  for (const result of runVectors()) assert.equal(result.pass, true, result.id);
});
test('reference records validate against closed JSON schemas', () => {
  const ajv = new Ajv2020(); const state = fixture();
  for (const [name, records] of [['principal', Object.values(state.actors)], ['grant', Object.values(state.grants)], ['knowledge', Object.values(state.knowledge)], ['binding', Object.values(bindings)]] as const) {
    const validate = ajv.compile(JSON.parse(readFileSync(new URL(`../schemas/${name}.json`, import.meta.url), 'utf8')));
    for (const record of records) assert.ok(validate(record), JSON.stringify(validate.errors));
    assert.equal(validate({ ...records[0], allowed: true }), false);
  }
});
