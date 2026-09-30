// Evidence for requirements that the rule coverage matrix (conformance/coverage/matrix.json) found without a test:
// documentation obligations (R12, R17, R103, R131) and the AuthZEN per-PEP budget (R90).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { AUTHZEN_LIMITS, createAuthzenGateway } from '../reference/authzen.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryRateLimits } from '../reference/limits.ts';
import type { RateLimitStore, RateVerdict } from '../reference/limits.ts';
import { LIMITS } from '../reference/policy.ts';
import { MemoryStore } from '../reference/store.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';
import { close, listen } from './support.ts';

const doc = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const NOW = 1800000000000;

test('R12: the revocation linearization point and the stale-access bound are published and match the reference', async () => {
  const text = doc('docs/ARCHITECTURE.md');
  assert.match(text, /linearization point is transaction commit/i);
  assert.match(text, /context lifetime to five minutes or the grant expiry, whichever is sooner/);
  const engine = new Engine(new MemoryStore(kbFixture(NOW)), { clock: () => NOW });
  const opened = await engine.openContext(bindings.chief, ['strategy'], 'work');
  assert.ok(opened.ok);
  assert.equal(opened.value.expiresAt, Math.min(NOW + 300_000, kbFixture(NOW).grants['chief-run']!.expiresAt), 'five minutes, or the grant expiry when sooner');
});

test('R17: the published resource budgets equal the limits the decision core enforces', () => {
  const text = doc('docs/CONFORMANCE-COVERAGE.md');
  const section = text.slice(text.indexOf('## Published resource budgets'));
  assert.ok(section.startsWith('## Published resource budgets'), 'section exists');
  const rows = new Map([...section.matchAll(/^\|\s*`(\w+)`\s*\|\s*(\d+)\s*\|/gm)].map(m => [m[1]!, Number(m[2])]));
  assert.deepEqual(Object.fromEntries(rows), { ...LIMITS }, 'every LIMITS member is listed with its value');
});

test('R90: the per-PEP evaluation budget counts every batch item, refuses with 429 before any engine work and fails closed with 503', async () => {
  const token = `test-only-${randomBytes(24).toString('hex')}`;
  const calls: { scope: string; limit: number; windowMs: number; cost: number }[] = [];
  let verdict: RateVerdict | 'throw' = { ok: true };
  const memory = new MemoryRateLimits({ clock: () => NOW });
  const limiter: RateLimitStore = {
    shared: false,
    take: async (tenant, scope, key, limit, windowMs, cost = 1) => {
      calls.push({ scope, limit, windowMs, cost });
      if (verdict === 'throw') throw new Error('store unavailable');
      return verdict.ok ? memory.take(tenant, scope, key, limit, windowMs, cost) : verdict;
    }
  };
  const store = new MemoryStore(kbFixture(NOW));
  const server = createAuthzenGateway(store, { credentials: [{ token, binding: { tenant: 'acme', pep: 'gateway-1' } }], limiter });
  const base = await listen(server);
  const item = { subject: { type: 'user', id: 'chief', properties: { agent: 'chief-agent', grant: 'chief-run' } }, resource: { type: 'knowledge', id: 'handbook' }, action: { name: 'read' }, context: { purpose: 'work' } };
  const post = (path: string, body: unknown) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
  try {
    assert.equal(AUTHZEN_LIMITS.perMinute, 1200);
    assert.equal(AUTHZEN_LIMITS.evaluations, 64);
    assert.equal((await post('/access/v1/evaluation', item)).status, 200);
    assert.equal((await post('/access/v1/evaluations', { evaluations: [item, item, item, item, item] })).status, 200);
    assert.equal(calls.reduce((n, c) => n + c.cost, 0), 6, 'one unit for the single evaluation and one for each of the five batch items');
    assert.ok(calls.every(c => c.scope === 'authzen' && c.limit === 1200 && c.windowMs === 60_000));
    const audited = (await store.auditLog('acme')).length;
    assert.equal(audited, 6);

    verdict = { ok: false, status: 429, retryAfter: 7, reason: 'limited' };
    const limited = await post('/access/v1/evaluation', item);
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('retry-after'), '7');
    assert.deepEqual(await limited.json(), { error: 'RATE_LIMITED' });
    assert.equal((await store.auditLog('acme')).length, audited, 'a refused request reaches no decision and no audit entry');

    verdict = 'throw';
    for (const path of ['/access/v1/evaluation', '/access/v1/evaluations']) {
      const failed = await post(path, path.endsWith('s') ? { evaluations: [item] } : item);
      assert.equal(failed.status, 503, `${path}: an unavailable limiter store fails closed`);
      assert.deepEqual(await failed.json(), { error: 'UNAVAILABLE' });
    }
    assert.equal((await store.auditLog('acme')).length, audited);
  } finally { await close(server); }
});

test('R131: the implementations table states who wrote each implementation and claims no independence', () => {
  const text = doc('docs/IMPLEMENTATIONS.md');
  const table = text.slice(text.indexOf('## Implementations'), text.indexOf('## Results per vector file')).split('\n').filter(l => l.startsWith('|'));
  const header = table[0]!.split('|').map(c => c.trim());
  const column = header.indexOf('Written by');
  assert.ok(column > 0, 'a "Written by" column exists');
  const rows = table.slice(2);
  assert.ok(rows.length >= 2);
  for (const row of rows) assert.ok(row.split('|')[column]!.trim().length > 0, `writer stated: ${row.slice(0, 40)}`);
  assert.match(text, /same-project differential\s+evidence/);
  assert.match(text, /No implementation by an independent party exists yet/);
  assert.match(text, /nothing here is a certification/);
});
