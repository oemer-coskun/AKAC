import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { ConfigError, loadConfig } from '../reference/config.ts';

const dir = mkdtempSync(join(tmpdir(), 'akac-config-'));
test.after(() => rmSync(dir, { recursive: true, force: true }));
const file = (name: string, body: string, mode = 0o600) => { const p = join(dir, name); writeFileSync(p, body, { mode }); return p; };
const token = () => `test-only-${randomBytes(24).toString('hex')}`;
const agentToken = token(), adminToken = token(), pepToken = token();
const agent = file('agent.json', JSON.stringify([{ token: agentToken, binding: { tenant: 'acme', subject: 'u', agent: 'a', grant: 'g' } }]));
const admin = file('admin.json', JSON.stringify([{ token: adminToken, binding: { tenant: 'acme', admin: 'x' } }]));
const pep = file('pep.json', JSON.stringify([{ token: pepToken, binding: { tenant: 'acme', pep: 'gateway-1' } }]));
const base = { AKAC_CREDENTIALS_FILE: agent };
const problems = (env: Record<string, string>) => { try { loadConfig({ ...base, ...env }); return []; } catch (e) { assert.ok(e instanceof ConfigError); return e.problems; } };
const rejects = (env: Record<string, string>, part: string) => assert.ok(problems(env).some(p => p.includes(part)), `${part} in ${JSON.stringify(problems(env))}`);

test('config: the AuthZEN listener is off by default and needs its own credentials', () => {
  assert.equal(loadConfig(base).authzen, undefined);
  rejects({ AKAC_AUTHZEN_REASONS: 'admin' }, 'requires AKAC_AUTHZEN_PORT');
  rejects({ AKAC_AUTHZEN_PORT: '8789' }, 'requires AKAC_AUTHZEN_CREDENTIALS_FILE or AKAC_AUTHZEN_JWT_CONFIG_FILE');
  rejects({ AKAC_AUTHZEN_PORT: 'x', AKAC_AUTHZEN_CREDENTIALS_FILE: pep }, 'AKAC_AUTHZEN_PORT must be a port number');
  const c = loadConfig({ ...base, AKAC_AUTHZEN_PORT: '8789', AKAC_AUTHZEN_CREDENTIALS_FILE: pep }).authzen!;
  assert.deepEqual([c.host, c.port, c.reasons, c.publicUrl], ['127.0.0.1', 8789, 'none', undefined]);
  assert.equal(loadConfig({ ...base, AKAC_AUTHZEN_PORT: '8789', AKAC_AUTHZEN_CREDENTIALS_FILE: pep, AKAC_AUTHZEN_REASONS: 'admin', AKAC_AUTHZEN_PUBLIC_URL: 'https://pdp.example.test' }).authzen!.reasons, 'admin');
  const authzen = { AKAC_AUTHZEN_PORT: '8789', AKAC_AUTHZEN_CREDENTIALS_FILE: pep };
  rejects({ ...authzen, AKAC_AUTHZEN_REASONS: 'all' }, 'AKAC_AUTHZEN_REASONS must be none or admin');
  rejects({ ...authzen, AKAC_AUTHZEN_PUBLIC_URL: 'https://pdp.example.test/base' }, 'origin without a path');
  rejects({ ...authzen, AKAC_AUTHZEN_PUBLIC_URL: 'http://pdp.example.test', NODE_ENV: 'production' }, 'must be https');
  rejects({ ...authzen, AKAC_AUTHZEN_JWT_CONFIG_FILE: file('pj.json', '{}') }, 'Set only one of');
  rejects({ ...authzen, AKAC_PORT: '8789' }, 'already used by another listener');
  rejects({ ...authzen, AKAC_AUTHZEN_DPOP: 'required', AKAC_AUTHZEN_PUBLIC_URL: 'https://pdp.example.test' }, 'requires JWT authentication on the AuthZEN listener');
});

test('config: a credential is valid on one listener only; JWT audiences are distinct', () => {
  rejects({ AKAC_AUTHZEN_PORT: '8789', AKAC_AUTHZEN_CREDENTIALS_FILE: file('reuse.json', JSON.stringify([{ token: agentToken, binding: { tenant: 'acme', pep: 'g' } }])) }, 'must not reuse');
  rejects({ AKAC_ADMIN_CREDENTIALS_FILE: admin, AKAC_AUTHZEN_PORT: '8789', AKAC_AUTHZEN_CREDENTIALS_FILE: file('reuse2.json', JSON.stringify([{ token: adminToken, binding: { tenant: 'acme', pep: 'g' } }])) }, 'must not reuse');
  const jwt = (aud: string, key: string) => file(`${aud}.json`, JSON.stringify({ issuer: 'https://id.example.test', audience: aud, jwksUrl: 'https://id.example.test/jwks', algorithms: ['ES256'], [key]: {} }));
  const env = { AKAC_JWT_CONFIG_FILE: jwt('akac', 'subjects'), AKAC_AUTHZEN_PORT: '8789' };
  const only = (extra: Record<string, string>) => { try { loadConfig({ ...env, ...extra }); return []; } catch (e) { return (e as ConfigError).problems; } };
  assert.ok(only({ AKAC_AUTHZEN_JWT_CONFIG_FILE: jwt('akac', 'peps') }).some(p => p.includes('audience must differ')));
  assert.deepEqual(only({ AKAC_AUTHZEN_JWT_CONFIG_FILE: jwt('akac-authzen', 'peps') }), []);
});

test('config: checkpoint key file (PEM or JWK), key id, Ed25519 only, permissions in production', () => {
  const key = generateKeyPairSync('ed25519').privateKey, other = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
  const pem = file('cp.pem', key.export({ type: 'pkcs8', format: 'pem' }).toString());
  const jwk = file('cp.jwk', JSON.stringify(key.export({ format: 'jwk' })));
  assert.equal(loadConfig(base).checkpoint, undefined);
  for (const f of [pem, jwk]) {
    const c = loadConfig({ ...base, AKAC_CHECKPOINT_KEY_FILE: f, AKAC_CHECKPOINT_KEY_ID: 'audit-2026' }).checkpoint!;
    assert.equal(c.keyId, 'audit-2026'); assert.match(c.privatePem, /^-----BEGIN PRIVATE KEY-----/);
  }
  rejects({ AKAC_CHECKPOINT_KEY_FILE: pem }, 'must be set together');
  rejects({ AKAC_CHECKPOINT_KEY_ID: 'k' }, 'must be set together');
  rejects({ AKAC_CHECKPOINT_KEY_FILE: pem, AKAC_CHECKPOINT_KEY_ID: 'bad id' }, 'AKAC_CHECKPOINT_KEY_ID must be');
  rejects({ AKAC_CHECKPOINT_KEY_FILE: join(dir, 'missing'), AKAC_CHECKPOINT_KEY_ID: 'k' }, 'file not readable');
  rejects({ AKAC_CHECKPOINT_KEY_FILE: file('bad.pem', 'not a key'), AKAC_CHECKPOINT_KEY_ID: 'k' }, 'not a readable Ed25519 private key');
  rejects({ AKAC_CHECKPOINT_KEY_FILE: file('ec.pem', other.export({ type: 'pkcs8', format: 'pem' }).toString()), AKAC_CHECKPOINT_KEY_ID: 'k' }, 'Ed25519');
  const x = (key.export({ format: 'jwk' }) as { x: string }).x;
  rejects({ AKAC_CHECKPOINT_KEY_FILE: file('pub.jwk', JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x })), AKAC_CHECKPOINT_KEY_ID: 'k' }, 'not a readable Ed25519 private key');
  if (process.platform !== 'win32') {
    const open = file('open.pem', key.export({ type: 'pkcs8', format: 'pem' }).toString()); chmodSync(open, 0o644);
    rejects({ AKAC_CHECKPOINT_KEY_FILE: open, AKAC_CHECKPOINT_KEY_ID: 'k', NODE_ENV: 'production' }, 'must not be accessible by others');
    const group = file('group.pem', key.export({ type: 'pkcs8', format: 'pem' }).toString()); chmodSync(group, 0o640);
    assert.ok(loadConfig({ ...base, AKAC_CHECKPOINT_KEY_FILE: group, AKAC_CHECKPOINT_KEY_ID: 'k', NODE_ENV: 'production' }).checkpoint, 'group read is allowed (mounted secrets)');
    chmodSync(group, 0o660);
    rejects({ AKAC_CHECKPOINT_KEY_FILE: group, AKAC_CHECKPOINT_KEY_ID: 'k', NODE_ENV: 'production' }, 'writable by group');
    assert.ok(loadConfig({ ...base, AKAC_CHECKPOINT_KEY_FILE: pem, AKAC_CHECKPOINT_KEY_ID: 'k', NODE_ENV: 'production' }).checkpoint);
  }
});
