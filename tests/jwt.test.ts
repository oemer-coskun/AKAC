import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { JwtAuthenticator } from '../adapters/jwt.ts';
import type { JwtConfiguration } from '../adapters/jwt.ts';
import { fixture, bindings } from '../examples/fixture.ts';
import { Engine } from '../reference/engine.ts';
import { MemoryStore } from '../reference/store.ts';
import { createGateway } from '../reference/http.ts';

const keys = await generateKeyPair('RS256');
const jwk = { ...await exportJWK(keys.publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
const config: JwtConfiguration = { issuer: 'https://identity.example.test', audience: 'akac-gateway', jwksUrl: 'https://identity.example.test/jwks',
  algorithms: ['RS256'], subjects: { 'verified-agent-service': bindings.intern } };
const auth = new JwtAuthenticator(config, createLocalJWKSet({ keys: [jwk] }));
async function token(overrides: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub: 'verified-agent-service', iss: config.issuer, aud: config.audience, iat: now, exp: now + 120, jti: 'test-token', ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'at+jwt', ...header }).sign(keys.privateKey);
}
test('verified JWT maps to server identity, ignoring forged roles and bindings', async () => {
  assert.deepEqual(await auth.authenticate(await token({ roles: ['security-admin'], subject: 'chief', agent: 'chief-agent' })), bindings.intern);
});
const attacks: Record<string, Record<string, unknown>> = {
  issuer: { iss: 'https://attacker.example.test' }, audience: { aud: 'different-service' },
  subject: { sub: 'unprovisioned' }, expiry: { exp: 1 }, future: { nbf: 9000000000 },
  lifetime: { exp: Math.floor(Date.now() / 1000) + 3600 }, missingExpiry: { exp: undefined },
  missingJti: { jti: undefined }, missingIssuedAt: { iat: undefined }
};
for (const [name, override] of Object.entries(attacks)) test(`JWT rejects invalid ${name}`, async () => {
  assert.equal(await auth.authenticate(await token(override)), null);
});
test('JWT rejects wrong token type, token-supplied key URL, bad signature and oversized token', async () => {
  assert.equal(await auth.authenticate(await token({}, { typ: 'JWT' })), null);
  assert.equal(await auth.authenticate(await token({}, { jku: 'https://attacker.example.test/jwks' })), null);
  const value = await token(); const parts = value.split('.'); parts[2] = 'A'.repeat(parts[2]!.length);
  assert.equal(await auth.authenticate(parts.join('.')), null);
  assert.equal(await auth.authenticate('x'.repeat(16385)), null);
});
test('JWT key rotation requires a trusted configured key', async () => {
  const next = await generateKeyPair('RS256');
  const now = Math.floor(Date.now() / 1000);
  const value = await new SignJWT({ sub: 'verified-agent-service', iss: config.issuer, aud: config.audience, iat: now, exp: now + 120, jti: 'rotated' })
    .setProtectedHeader({ alg: 'RS256', kid: 'rotated', typ: 'at+jwt' }).sign(next.privateKey);
  assert.equal(await auth.authenticate(value), null);
  const rotated = new JwtAuthenticator(config, createLocalJWKSet({ keys: [{ ...await exportJWK(next.publicKey), kid: 'rotated', alg: 'RS256' }] }));
  assert.deepEqual(await rotated.authenticate(value), bindings.intern);
});
test('HTTP signed authentication enforces the same resource boundary and readiness', async () => {
  const server = createGateway(new Engine(new MemoryStore(fixture())), [], { authenticator: auth });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}`, valid = await token();
  try {
    assert.equal((await fetch(base + '/ready')).status, 401);
    assert.equal((await fetch(base + '/ready', { headers: { authorization: `Bearer ${valid}` } })).status, 200);
    for (const [resource, status] of [['handbook', 200], ['strategy', 403]] as const) {
      assert.equal((await fetch(base + '/v1/contexts', { method: 'POST', headers: { authorization: `Bearer ${valid}`, 'content-type': 'application/json' },
        body: JSON.stringify({ resources: [resource], purpose: 'work' }) })).status, status);
    }
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
