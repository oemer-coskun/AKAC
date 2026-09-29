import test from 'node:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { ConfigError, loadConfig } from '../reference/config.ts';
import { createLogger, traceIdOf } from '../reference/log.ts';
import { createMetricsServer, Metrics, Registry } from '../reference/metrics.ts';
import { close, listen, start, tokens } from './support.ts';

type Sample = { name: string; labels: Record<string, string>; value: number };
/** Strict parser for the Prometheus text format 0.0.4 subset this registry emits. */
function parse(text: string) {
  const samples: Sample[] = [], types = new Map<string, string>(), helps = new Set<string>();
  assert.ok(text.endsWith('\n'));
  for (const line of text.trimEnd().split('\n')) {
    let m = /^# HELP ([a-zA-Z_:][a-zA-Z0-9_:]*) .+$/.exec(line);
    if (m) { helps.add(m[1]!); continue; }
    m = /^# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*) (counter|gauge|histogram)$/.exec(line);
    if (m) { types.set(m[1]!, m[2]!); continue; }
    m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{((?:[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\.)*",?)*)\})? (-?\d+(?:\.\d+)?(?:e[+-]?\d+)?|\+Inf|NaN)$/.exec(line);
    assert.ok(m, `unparseable line: ${line}`);
    const labels: Record<string, string> = {};
    for (const l of (m[2] ?? '').matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\\n]|\\.)*)"/g)) labels[l[1]!] = l[2]!;
    samples.push({ name: m[1]!, labels, value: Number(m[3]) });
  }
  for (const s of samples) {
    const base = s.name.replace(/_(bucket|sum|count)$/, '');
    assert.ok(types.has(s.name) || types.get(base) === 'histogram', `no TYPE for ${s.name}`);
    assert.ok(helps.has(base) || helps.has(s.name), `no HELP for ${s.name}`);
  }
  return { samples, types };
}
const find = (samples: Sample[], name: string, labels: Record<string, string> = {}) =>
  samples.filter(s => s.name === name && Object.entries(labels).every(([k, v]) => s.labels[k] === v));

test('registry: exposition format, escaping, histogram invariants and series bound', () => {
  const r = new Registry();
  const c = r.counter('demo_total', 'A counter.', ['kind']);
  const g = r.gauge('demo_gauge', 'A gauge.');
  const h = r.histogram('demo_seconds', 'A histogram.', ['route'], [0.1, 1]);
  c.inc(['a']); c.inc(['a']); c.inc(['b"\\\n']); g.set([], 2.5);
  for (const v of [0.05, 0.5, 5]) h.observe(['/x'], v);
  h.observe(['/x'], -1); h.observe(['/x'], Number.NaN);
  const { samples, types } = parse(r.expose());
  assert.deepEqual([types.get('demo_total'), types.get('demo_gauge'), types.get('demo_seconds')], ['counter', 'gauge', 'histogram']);
  assert.equal(find(samples, 'demo_total', { kind: 'a' })[0]!.value, 2);
  assert.equal(find(samples, 'demo_total', { kind: 'other' })[0]!.value, 1, 'unsafe label values are folded, not emitted');
  assert.equal(find(samples, 'demo_gauge')[0]!.value, 2.5);
  const buckets = find(samples, 'demo_seconds_bucket').map(s => [s.labels.le, s.value]);
  assert.deepEqual(buckets, [['0.1', 1], ['1', 2], ['+Inf', 3]]);
  assert.equal(find(samples, 'demo_seconds_count')[0]!.value, 3);
  assert.equal(find(samples, 'demo_seconds_sum')[0]!.value, 5.55);
  assert.throws(() => r.counter('demo_total', 'dup'));
  assert.throws(() => r.counter('bad name', 'x'));
  assert.throws(() => r.histogram('h2', 'x', [], [1, 1]));
  assert.throws(() => r.counter('c2', 'x', ['le']));
  const bounded = new Registry().counter('bounded_total', 'x', ['id']);
  for (let i = 0; i < 2000; i++) bounded.inc([`v${i}`]);
  assert.equal(bounded.series.size, 512);
  assert.equal(new Registry().counter('empty_total', 'x').lines().at(-1), 'empty_total 0');
});

test('gateways: decision counters, request metrics and bounded labels', async () => {
  const metrics = new Metrics();
  const s = await start({ engine: { onEvent: metrics.onEvent }, agent: { metrics }, admin: { metrics } });
  const opsServer = createMetricsServer(metrics), ops = await listen(opsServer);
  try {
    const post = (resources: string[]) => s.call(tokens.intern, 'POST', '/v1/contexts', { resources, purpose: 'work' }, {}, s.agentUrl);
    assert.equal((await post(['handbook'])).status, 200);
    assert.equal((await post(['strategy'])).status, 403);
    assert.equal((await s.call('bad-token', 'POST', '/v1/contexts', {}, {}, s.agentUrl)).status, 401);
    // Hostile, high-cardinality paths and ids must not create series.
    for (let i = 0; i < 60; i++) await fetch(`${s.agentUrl}/probe-${i}/${'x'.repeat(i)}`);
    for (let i = 0; i < 60; i++) await s.call(tokens.sec, 'PUT', `/admin/v1/actors/user-${i}`, { kind: 'user', roles: [], projects: [], clearance: 'public', active: true });
    await s.call(tokens.kb, 'PUT', '/admin/v1/actors/nope', {});
    await s.call(tokens.aud, 'GET', '/admin/v1/audit');

    const res = await fetch(ops + '/metrics');
    assert.equal(res.headers.get('content-type'), 'text/plain; version=0.0.4; charset=utf-8');
    const text = await res.text();
    const { samples } = parse(text);
    assert.equal(find(samples, 'akac_decisions_total', { operation: 'read', allowed: 'true', reason_class: 'authorized' })[0]!.value, 1);
    assert.equal(find(samples, 'akac_decisions_total', { operation: 'read', allowed: 'false', reason_class: 'denied' })[0]!.value, 1);
    assert.equal(find(samples, 'akac_http_requests_total', { listener: 'agent', route: '/v1/contexts', status: '200' })[0]!.value, 1);
    assert.equal(find(samples, 'akac_http_requests_total', { listener: 'agent', route: '/v1/contexts', status: '401' })[0]!.value, 1);
    assert.equal(find(samples, 'akac_http_requests_total', { listener: 'agent', route: 'unmatched' }).reduce((n, x) => n + x.value, 0), 60);
    assert.equal(find(samples, 'akac_http_requests_total', { listener: 'admin', route: '/admin/v1/actors/{id}', status: '200' })[0]!.value, 60);
    assert.equal(find(samples, 'akac_admin_operations_total', { operation: 'put_actor', result: 'ok' })[0]!.value, 60);
    assert.equal(find(samples, 'akac_admin_operations_total', { operation: 'put_actor', result: 'denied' })[0]!.value, 1);
    assert.equal(find(samples, 'akac_filter_mismatch_total')[0]!.value, 0);
    assert.equal(find(samples, 'akac_candidates_unavailable_total')[0]!.value, 0);
    assert.ok(find(samples, 'akac_process_uptime_seconds')[0]!.value >= 0);
    assert.ok(find(samples, 'akac_process_heap_used_bytes')[0]!.value > 0);
    // Histogram: cumulative buckets end at +Inf == count.
    const buckets = find(samples, 'akac_http_request_duration_seconds_bucket', { listener: 'agent', route: '/v1/contexts' });
    assert.ok(buckets.every((b, i) => i === 0 || b.value >= buckets[i - 1]!.value));
    assert.equal(buckets.at(-1)!.value, find(samples, 'akac_http_request_duration_seconds_count', { listener: 'agent', route: '/v1/contexts' })[0]!.value);
    // Cardinality: labels are closed sets; nothing derived from ids, tenants, tokens or paths.
    const allowedKeys = new Set(['listener', 'route', 'status', 'operation', 'allowed', 'reason_class', 'result', 'le']);
    for (const sample of samples) for (const k of Object.keys(sample.labels)) assert.ok(allowedKeys.has(k), `unexpected label ${k}`);
    assert.ok(samples.length < 120, `series count ${samples.length}`);
    for (const secret of ['acme', 'intern', 'handbook', 'strategy', 'user-7', 'probe-', tokens.intern, tokens.sec]) assert.ok(!text.includes(secret), secret);
    assert.equal((await fetch(ops + '/metrics', { method: 'POST' })).status, 404);
    assert.equal((await fetch(ops + '/other')).status, 404);
  } finally { await s.stop(); await close(opsServer); }
});

test('metrics: filter mismatches and candidate failures are counted without identifiers', () => {
  const m = new Metrics();
  m.onEvent({ type: 'filter_mismatch', tenant: 'acme' }); m.onEvent({ type: 'candidates_unavailable', tenant: 'acme' });
  m.onEvent({ type: 'decision', tenant: 'acme', operation: 'attacker-controlled-' + 'x'.repeat(500), allowed: false, reason: 'DEFERRED:BUDGET_EXCEEDED' });
  m.onEvent({ type: 'decision', tenant: 'acme', operation: 'derive', allowed: true, reason: 'PROTECTED_DERIVATION' });
  const { samples } = parse(m.expose());
  assert.equal(find(samples, 'akac_filter_mismatch_total')[0]!.value, 1);
  assert.equal(find(samples, 'akac_candidates_unavailable_total')[0]!.value, 1);
  assert.equal(find(samples, 'akac_decisions_total', { operation: 'other', reason_class: 'deferred' })[0]!.value, 1);
  assert.equal(find(samples, 'akac_decisions_total', { operation: 'derive', reason_class: 'other' })[0]!.value, 1);
});

test('logging: structured, request and trace ids, and no content or credentials', async () => {
  const lines: string[] = [];
  const logger = createLogger({ write: l => lines.push(l) });
  const s = await start({ agent: { logger }, admin: { logger } });
  try {
    const trace = '4bf92f3577b34da6a3ce929d0e0e4736';
    const res = await s.call(tokens.intern, 'POST', '/v1/retrieve', { query: 'SECRET-QUERY-TEXT confidential budget', purpose: 'work' },
      { traceparent: `00-${trace}-00f067aa0ba902b7-01`, 'x-request-id': 'attacker-chosen' }, s.agentUrl);
    const requestId = res.headers.get('x-request-id')!;
    assert.match(requestId, /^[0-9a-f-]{36}$/); assert.notEqual(requestId, 'attacker-chosen');
    await s.call(tokens.sec, 'PUT', '/admin/v1/actors/x', { kind: 'user', roles: [], projects: [], clearance: 'public', active: true, note: 'SECRET-BODY-TEXT' });
    await s.call('wrong-token-value', 'GET', '/admin/v1/audit');
    await new Promise(resolve => setTimeout(resolve, 20));
    const entries = lines.map(l => JSON.parse(l) as Record<string, unknown>);
    const agent = entries.find(e => e.requestId === requestId)!;
    assert.deepEqual([agent.level, agent.msg, agent.listener, agent.route, agent.status, agent.traceId], ['info', 'request', 'agent', '/v1/retrieve', 403, trace]);
    assert.match(String(agent.time), /^\d{4}-\d\d-\d\dT/);
    assert.ok(entries.every(e => typeof e.traceId === 'string' && /^[0-9a-f]{32}$/.test(e.traceId as string)));
    assert.ok(entries.some(e => e.listener === 'admin' && e.status === 401));
    const all = lines.join('\n');
    for (const secret of ['SECRET-QUERY-TEXT', 'SECRET-BODY-TEXT', 'wrong-token-value', tokens.intern, tokens.sec, 'Bearer']) assert.ok(!all.includes(secret), secret);
  } finally { await s.stop(); }
  const out: string[] = [];
  const log = createLogger({ level: 'warn', write: l => out.push(l) });
  log.info('dropped'); log.warn('kept', { ok: 1, token: 'x', authorization: 'y', content: 'z', 'bad key': 1, nested: { a: 1 } as never });
  assert.equal(out.length, 1);
  assert.deepEqual(Object.keys(JSON.parse(out[0]!)), ['level', 'time', 'msg', 'ok']);
  assert.equal(traceIdOf('garbage').length, 32);
  assert.equal(traceIdOf(`00-${'0'.repeat(32)}-00f067aa0ba902b7-01`).includes('00000000000000000000000000000000'), false);
});

test('configuration: every problem is reported up front', () => {
  const dir = mkdtempSync(join(tmpdir(), 'akac-config-'));
  const file = (name: string, body: unknown) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(body)); return p; };
  try {
    const ok = { AKAC_CREDENTIALS_FILE: file('agent.json', [{}]) };
    const config = loadConfig({ ...ok, AKAC_METRICS_PORT: '9999', PORT: '18787', AKAC_LOG_LEVEL: 'warn' });
    assert.deepEqual([config.agent.port, config.metrics.port, config.metrics.host, config.admin, config.logLevel], [18787, 9999, '127.0.0.1', undefined, 'warn']);
    assert.equal(loadConfig({ ...ok, METRICS_PORT: '9100', ADMIN_PORT: '9101', AKAC_ADMIN_CREDENTIALS_FILE: file('admin.json', [{}]) }).admin?.port, 9101);
    assert.deepEqual(loadConfig(ok).agent.host, '127.0.0.1');
    assert.throws(() => loadConfig({}), /exactly one of AKAC_CREDENTIALS_FILE or AKAC_JWT_CONFIG_FILE/);
    try {
      loadConfig({ AKAC_CREDENTIALS_FILE: join(dir, 'missing.json'), AKAC_ADMIN_CREDENTIALS_FILE: file('a.json', [{}]), AKAC_ADMIN_JWT_CONFIG_FILE: file('j.json', {}),
        PORT: 'abc', AKAC_METRICS_PORT: '70000', AKAC_AUTO_MIGRATE: 'maybe', OPA_URL: 'ftp://x', AKAC_LOG_LEVEL: 'loud' });
      assert.fail('expected failure');
    } catch (error) {
      assert.ok(error instanceof ConfigError);
      for (const part of ['file not found', 'Set only one of AKAC_ADMIN_CREDENTIALS_FILE', 'PORT must be a port', 'AKAC_METRICS_PORT must be a port', 'AKAC_AUTO_MIGRATE', 'OPA_URL', 'AKAC_LOG_LEVEL'])
        assert.ok(error.problems.some(p => p.includes(part)), part);
    }
    assert.throws(() => loadConfig({ ...ok, PORT: '8000', AKAC_METRICS_PORT: '8000' }), /already used/);
    assert.throws(() => loadConfig({ AKAC_CREDENTIALS_FILE: ok.AKAC_CREDENTIALS_FILE, AKAC_JWT_CONFIG_FILE: file('jwt.json', {}) }), /exactly one/);
    assert.throws(() => loadConfig({ AKAC_JWT_CONFIG_FILE: file('jwt2.json', { audience: 'same' }), AKAC_ADMIN_JWT_CONFIG_FILE: file('ajwt.json', { audience: 'same' }) }), /audience must differ/);
    assert.throws(() => loadConfig({ AKAC_CREDENTIALS_FILE: file('empty.json', []) }), /non-empty array/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('metrics: authzen and lifecycle operations are in closed label sets; unknown names fold to other', () => {
  const m = new Metrics();
  m.onEvent({ type: 'decision', tenant: 'acme', operation: 'authzen_evaluate', allowed: true, reason: 'AUTHORIZED' });
  m.onEvent({ type: 'decision', tenant: 'acme', operation: 'write_memory', allowed: false, reason: 'DENIED:X' });
  m.admin('erase', 'conflict'); m.admin('quarantine', 'ok'); m.admin('scim_get_user', 'ok'); m.admin('attacker-' + 'x'.repeat(200), 'ok'); m.admin('made_up_operation', 'ok');
  const { samples } = parse(m.expose());
  assert.equal(find(samples, 'akac_decisions_total', { operation: 'authzen_evaluate', allowed: 'true', reason_class: 'authorized' })[0]!.value, 1);
  assert.equal(find(samples, 'akac_decisions_total', { operation: 'write_memory' })[0]!.value, 1);
  assert.equal(find(samples, 'akac_lifecycle_operations_total', { operation: 'erase', result: 'conflict' })[0]!.value, 1);
  assert.equal(find(samples, 'akac_lifecycle_operations_total').length, 2, 'only lifecycle operations reach the lifecycle counter');
  assert.equal(find(samples, 'akac_admin_operations_total', { operation: 'other' })[0]!.value, 2);
  assert.equal(find(samples, 'akac_admin_operations_total', { operation: 'scim_get_user' })[0]!.value, 1);
});
