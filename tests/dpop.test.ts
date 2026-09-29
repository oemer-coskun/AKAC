import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { calculateJwkThumbprint, createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { CryptoKey, JWK } from 'jose';
import { AdminJwtAuthenticator, JwtAuthenticator } from '../adapters/jwt.ts';
import { DpopGuard, MemoryReplayCache, verifyDpopProof } from '../adapters/dpop.ts';
import type { DpopMode } from '../adapters/dpop.ts';
import { bindings, fixture } from '../examples/fixture.ts';
import { Engine } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import { MemoryStore } from '../reference/store.ts';
import { createGateway } from '../reference/http.ts';
import { createAdminGateway } from '../reference/admin.ts';
import { AdminClient, AkacClient } from '../sdk/typescript/index.ts';
import { close, listen, world } from './support.ts';

const issuer = 'https://identity.example.test', now = () => Math.floor(Date.now() / 1000);
const signing = await generateKeyPair('RS256');
const jwks = createLocalJWKSet({ keys: [{ ...await exportJWK(signing.publicKey), kid: 'k', alg: 'RS256' }] });
const agentAuth = () => new JwtAuthenticator({ issuer, audience: 'akac-gateway', jwksUrl: issuer + '/jwks', algorithms: ['RS256'], subjects: { svc: bindings.intern } }, jwks);
const adminAuth = () => new AdminJwtAuthenticator({ issuer, audience: 'akac-admin', jwksUrl: issuer + '/jwks', algorithms: ['RS256'], admins: { op: { tenant: 'acme', admin: 'aud' } } }, jwks);
const access = (aud: string, sub: string, cnf?: unknown) => new SignJWT({ sub, iss: issuer, aud, iat: now(), exp: now() + 120, jti: randomUUID(), ...(cnf !== undefined ? { cnf } : {}) })
  .setProtectedHeader({ alg: 'RS256', kid: 'k', typ: 'at+jwt' }).sign(signing.privateKey);

type Alg = 'ES256' | 'EdDSA' | 'PS256';
async function holder(alg: Alg = 'ES256') {
  const pair = await generateKeyPair(alg, alg === 'PS256' ? { modulusLength: 2048 } : { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  return { alg, pair, jwk, jkt: await calculateJwkThumbprint(jwk, 'sha256') };
}
type Holder = Awaited<ReturnType<typeof holder>>;
const ath = (token: string) => createHash('sha256').update(token).digest('base64url');
async function proof(h: Holder, token: string, method: string, htu: string, over: { payload?: Record<string, unknown>; header?: Record<string, unknown>; key?: CryptoKey } = {}) {
  return new SignJWT({ jti: randomUUID(), htm: method, htu, iat: now(), ath: ath(token), ...over.payload })
    .setProtectedHeader({ alg: h.alg, typ: 'dpop+jwt', jwk: h.jwk, ...over.header }).sign(over.key ?? h.pair.privateKey);
}
async function servers(agent: DpopMode | undefined, admin?: DpopMode) {
  let agentBase = '', adminBase = '';
  const store = new MemoryStore(world());
  const gateway = createGateway(new Engine(store), [], { authenticator: agentAuth(), ...(agent ? { dpop: { mode: agent, publicUrl: () => agentBase } } : {}) });
  const adminGateway = createAdminGateway(new ControlPlane(store), { authenticator: adminAuth(), ...(admin ? { dpop: { mode: admin, publicUrl: () => adminBase } } : {}) });
  agentBase = await listen(gateway); adminBase = await listen(adminGateway);
  return { agentBase, adminBase, stop: () => close(gateway, adminGateway) };
}
const dpopHeaders = (token: string, p: string, extra: Record<string, string> = {}) => ({ authorization: `DPoP ${token}`, dpop: p, ...extra });
const get = (url: string, headers: Record<string, string>) => fetch(url, { headers });

test('DPoP required: a bound token with a valid proof is accepted, every mismatch is refused', async () => {
  const s = await servers('required');
  try {
    for (const alg of ['ES256', 'EdDSA', 'PS256'] as const) {
      const h = await holder(alg), token = await access('akac-gateway', 'svc', { jkt: h.jkt }), url = s.agentBase + '/ready';
      assert.equal((await get(url, dpopHeaders(token, await proof(h, token, 'GET', url)))).status, 200, alg);
    }
    const h = await holder(), token = await access('akac-gateway', 'svc', { jkt: h.jkt }), url = s.agentBase + '/ready';
    const status = async (p: string, t = token) => (await get(url, dpopHeaders(t, p))).status;
    assert.equal(await status(await proof(h, token, 'POST', url)), 401, 'wrong htm');
    assert.equal(await status(await proof(h, token, 'GET', s.agentBase + '/v1/retrieve')), 401, 'wrong htu path');
    assert.equal(await status(await proof(h, token, 'GET', 'https://attacker.example.test/ready')), 401, 'wrong htu origin');
    assert.equal(await status(await proof(h, token, 'GET', url + '?x=1')), 401, 'htu with query');
    assert.equal(await status(await proof(h, token, 'GET', url, { payload: { iat: now() - 120 } })), 401, 'stale iat');
    assert.equal(await status(await proof(h, token, 'GET', url, { payload: { iat: now() + 120 } })), 401, 'future iat');
    assert.equal(await status(await proof(h, token, 'GET', url, { payload: { ath: ath('another-token') } })), 401, 'wrong ath');
    assert.equal(await status(await proof(h, token, 'GET', url, { payload: { ath: undefined } })), 401, 'missing ath');
    assert.equal(await status(await proof(h, token, 'GET', url, { payload: { jti: undefined } })), 401, 'missing jti');
    assert.equal(await status(await proof(h, token, 'GET', url, { header: { typ: 'JWT' } })), 401, 'wrong typ');
    const other = await holder();
    assert.equal(await status(await proof(other, token, 'GET', url)), 401, 'proof key differs from cnf.jkt');
    const unbound = await access('akac-gateway', 'svc');
    assert.equal(await status(await proof(h, unbound, 'GET', url), unbound), 401, 'DPoP with an unbound token');
    assert.equal(await status(await proof(h, token, 'GET', url), 'x'.repeat(40)), 401, 'garbage token');
    assert.equal((await get(url, { authorization: `DPoP ${token}` })).status, 401, 'missing proof');
    assert.equal((await get(url, dpopHeaders(token, 'a.b'))).status, 401, 'malformed proof');
    assert.equal((await get(url, dpopHeaders(token, 'x'.repeat(8193)))).status, 401, 'oversized proof');
    const bad = await get(url, dpopHeaders(token, await proof(h, token, 'GET', url, { payload: { htm: 'POST' } })));
    assert.match(bad.headers.get('www-authenticate') ?? '', /^DPoP error="invalid_dpop_proof", algs="ES256 EdDSA PS256"$/);
    assert.deepEqual(await bad.json(), { error: 'UNAUTHENTICATED' });
  } finally { await s.stop(); }
});

test('DPoP: a replayed proof identifier is refused, including from a copy of the request', async () => {
  const s = await servers('required');
  try {
    const h = await holder(), token = await access('akac-gateway', 'svc', { jkt: h.jkt }), url = s.agentBase + '/ready';
    const p = await proof(h, token, 'GET', url);
    assert.equal((await get(url, dpopHeaders(token, p))).status, 200);
    assert.equal((await get(url, dpopHeaders(token, p))).status, 401);
    const fresh = await proof(h, token, 'GET', url, { payload: { jti: 'same' } }), same = await proof(h, token, 'GET', url, { payload: { jti: 'same' } });
    assert.equal((await get(url, dpopHeaders(token, fresh))).status, 200);
    assert.equal((await get(url, dpopHeaders(token, same))).status, 401, 'same jti, same key');
  } finally { await s.stop(); }
});

test('DPoP: Bearer downgrade is refused; optional mode accepts unbound Bearer tokens only', async () => {
  const req = await servers('required'), opt = await servers('optional'), off = await servers(undefined);
  try {
    const h = await holder(), bound = await access('akac-gateway', 'svc', { jkt: h.jkt }), plain = await access('akac-gateway', 'svc');
    const bearer = (base: string, t: string) => get(base + '/ready', { authorization: `Bearer ${t}` });
    assert.equal((await bearer(req.agentBase, plain)).status, 401, 'required refuses Bearer');
    assert.equal((await bearer(req.agentBase, bound)).status, 401);
    assert.equal((await bearer(opt.agentBase, bound)).status, 401, 'bound token as Bearer');
    assert.equal((await bearer(off.agentBase, bound)).status, 401, 'bound token as Bearer with DPoP off');
    assert.equal((await bearer(opt.agentBase, plain)).status, 200, 'unbound Bearer in optional mode');
    assert.equal((await bearer(off.agentBase, plain)).status, 200);
    const challenge = (await bearer(opt.agentBase, bound)).headers.get('www-authenticate') ?? '';
    assert.match(challenge, /Bearer/); assert.match(challenge, /DPoP algs=/);
    const url = opt.agentBase + '/ready';
    assert.equal((await get(url, dpopHeaders(bound, await proof(h, bound, 'GET', url)))).status, 200, 'DPoP in optional mode');
    // DPoP off: the DPoP scheme is not an accepted credential.
    const offUrl = off.agentBase + '/ready';
    assert.equal((await get(offUrl, dpopHeaders(bound, await proof(h, bound, 'GET', offUrl)))).status, 401);
    // Case-insensitive scheme, per RFC 9110.
    assert.equal((await get(url, { authorization: `dpop ${bound}`, dpop: await proof(h, bound, 'GET', url) })).status, 200);
  } finally { await req.stop(); await opt.stop(); await off.stop(); }
});

test('DPoP: cnf other than a valid jkt is refused', async () => {
  const s = await servers('optional');
  try {
    const h = await holder(), url = s.agentBase + '/ready';
    for (const cnf of [{ 'x5t#S256': 'abc' }, { jkt: 'short' }, { jkt: h.jkt, extra: 1 }, {}, 'text', null, [h.jkt]]) {
      const token = await access('akac-gateway', 'svc', cnf);
      assert.equal((await get(url, dpopHeaders(token, await proof(h, token, 'GET', url)))).status, 401, JSON.stringify(cnf));
      assert.equal((await get(url, { authorization: `Bearer ${token}` })).status, 401, JSON.stringify(cnf));
    }
  } finally { await s.stop(); }
});

test('DPoP proof rejects alg none/HS256, private key material, key references and foreign key types', async () => {
  const h = await holder(), token = 'access-token-value-0000000000000000000', htu = 'https://gw.example.test/ready';
  const check = { method: 'GET', htu, accessToken: token, algorithms: ['ES256', 'EdDSA', 'PS256'] as Alg[], skewSeconds: 60, now: now() };
  assert.ok(await verifyDpopProof(await proof(h, token, 'GET', htu), check), 'baseline');
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const body = { jti: randomUUID(), htm: 'GET', htu, iat: now(), ath: ath(token) };
  assert.equal(await verifyDpopProof(`${b64({ alg: 'none', typ: 'dpop+jwt', jwk: h.jwk })}.${b64(body)}.`, check), null, 'alg none');
  const hmac = await new SignJWT(body).setProtectedHeader({ alg: 'HS256', typ: 'dpop+jwt', jwk: { kty: 'oct', k: 'AAAA' } as never }).sign(new Uint8Array(32));
  assert.equal(await verifyDpopProof(hmac, check), null, 'HS256 with a symmetric jwk');
  assert.equal(await verifyDpopProof(await proof(h, token, 'GET', htu), { ...check, algorithms: ['EdDSA'] }), null, 'alg not allowed by configuration');
  const priv = await exportJWK(h.pair.privateKey);
  assert.equal(await verifyDpopProof(`${b64({ alg: 'ES256', typ: 'dpop+jwt', jwk: h.jwk, crit: ['exp'], exp: 1 })}.${b64(body)}.AAAA`, check), null, 'crit');
  assert.equal(await verifyDpopProof(await proof(h, token, 'GET', htu, { header: { jwk: priv } }), check), null, 'private key in jwk');
  assert.equal(await verifyDpopProof(await proof(h, token, 'GET', htu, { header: { jwk: { ...h.jwk, d: priv.d } } }), check), null, 'd member');
  assert.equal(await verifyDpopProof(await proof(h, token, 'GET', htu, { header: { jwk: { ...h.jwk, x5u: 'https://attacker.example.test/k' } } }), check), null, 'x5u member');
  for (const header of [{ jku: 'https://attacker.example.test/jwks' }, { x5u: 'https://attacker.example.test/c' }, { x5c: ['AAAA'] }])
    assert.equal(await verifyDpopProof(await proof(h, token, 'GET', htu, { header }), check), null, JSON.stringify(header));
  const kidOnly = await new SignJWT(body).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', kid: 'server-side-key' }).sign(h.pair.privateKey);
  assert.equal(await verifyDpopProof(kidOnly, check), null, 'kid without jwk');
  // Deliberately below the 2048-bit floor: the verifier must reject it before it trusts the signature. Test-only key, never used to protect anything.
  const weakModulusBits = [512, 512].reduce((a, b) => a + b);
  const rsa = await holder('PS256'), weak = generateKeyPairSync('rsa', { modulusLength: weakModulusBits });
  assert.equal(await verifyDpopProof(await proof(h, token, 'GET', htu, { header: { jwk: rsa.jwk } }), check), null, 'alg/key type mismatch');
  const weakJwk = weak.publicKey.export({ format: 'jwk' }) as JWK;
  const signingInput = `${b64({ alg: 'PS256', typ: 'dpop+jwt', jwk: weakJwk })}.${b64(body)}`;
  const signature = sign('sha256', Buffer.from(signingInput), { key: weak.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64url');
  assert.equal(await verifyDpopProof(`${signingInput}.${signature}`, check), null, 'RSA modulus below 2048 bits');
  const p384 = await generateKeyPair('ES384');
  assert.equal(await verifyDpopProof(await new SignJWT(body).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: await exportJWK(p384.publicKey) }).sign(h.pair.privateKey), check), null, 'P-384 key for ES256');
  const other = await holder();
  assert.equal(await verifyDpopProof(await proof(h, token, 'GET', htu, { key: other.pair.privateKey }), check), null, 'signature by a different key');
  assert.equal((await verifyDpopProof(await proof(h, token, 'GET', htu), check))?.jkt, h.jkt);
});

test('DPoP: listeners are configured independently', async () => {
  const s = await servers('required', undefined);
  try {
    const plain = await access('akac-admin', 'op');
    assert.equal((await get(s.adminBase + '/admin/v1/audit', { authorization: `Bearer ${plain}` })).status, 200, 'admin without DPoP accepts Bearer');
    const agentPlain = await access('akac-gateway', 'svc');
    assert.equal((await get(s.agentBase + '/ready', { authorization: `Bearer ${agentPlain}` })).status, 401, 'agent requires DPoP');
  } finally { await s.stop(); }
  const r = await servers(undefined, 'required');
  try {
    const h = await holder(), url = r.adminBase + '/admin/v1/audit', bound = await access('akac-admin', 'op', { jkt: h.jkt });
    assert.equal((await get(url, { authorization: `Bearer ${await access('akac-admin', 'op')}` })).status, 401);
    const denied = await get(url, { authorization: `Bearer ${bound}` });
    assert.equal(denied.status, 401); assert.match(denied.headers.get('www-authenticate') ?? '', /^DPoP algs=/);
    const used = await proof(h, bound, 'GET', url);
    assert.equal((await get(url, dpopHeaders(bound, used))).status, 200);
    assert.equal((await get(url + '?limit=1', dpopHeaders(bound, used))).status, 401, 'jti already used');
    const q = await proof(h, bound, 'GET', url);
    assert.equal((await get(url + '?limit=1', dpopHeaders(bound, q))).status, 200, 'htu ignores the query');
    const wrongService = await access('akac-gateway', 'svc', { jkt: h.jkt });
    assert.equal((await get(url, dpopHeaders(wrongService, await proof(h, wrongService, 'GET', url)))).status, 401, 'agent token on the admin listener');
    assert.equal((await get(r.agentBase + '/ready', { authorization: `Bearer ${await access('akac-gateway', 'svc')}` })).status, 200, 'agent listener unaffected');
  } finally { await r.stop(); }
});

test('DPoP: public URL with a path prefix, and the Host header is never trusted', async () => {
  let base = '';
  const gateway = createGateway(new Engine(new MemoryStore(fixture())), [], { authenticator: agentAuth(), dpop: { mode: 'required', publicUrl: () => base + '/akac/' } });
  base = await listen(gateway);
  try {
    const h = await holder(), token = await access('akac-gateway', 'svc', { jkt: h.jkt });
    const prefixed = base + '/akac/ready', local = base + '/ready';
    // The listener sees /ready (a proxy stripped the prefix); the proof names the public URL.
    assert.equal((await get(local, dpopHeaders(token, await proof(h, token, 'GET', prefixed)))).status, 200);
    assert.equal((await get(local, dpopHeaders(token, await proof(h, token, 'GET', local)))).status, 401, 'the unprefixed URL is not the public URL');
    const spoofed = await fetch(local, { headers: { ...dpopHeaders(token, await proof(h, token, 'GET', 'https://spoof.example.test/akac/ready')), 'x-forwarded-host': 'spoof.example.test' } });
    assert.equal(spoofed.status, 401);
  } finally { await close(gateway); }
});

test('DPoP guard: option validation, clock skew configuration and replay cache bounds', async () => {
  assert.throws(() => new DpopGuard({ mode: 'off' as never, publicUrl: 'https://gw.example.test' }));
  assert.throws(() => new DpopGuard({ mode: 'required', publicUrl: 'https://user@gw.example.test' }));
  assert.throws(() => new DpopGuard({ mode: 'required', publicUrl: 'https://gw.example.test/?q=1' }));
  assert.throws(() => new DpopGuard({ mode: 'required', publicUrl: 'ftp://gw.example.test' }));
  assert.throws(() => new DpopGuard({ mode: 'required', publicUrl: 'https://gw.example.test', algorithms: ['HS256' as never] }));
  assert.throws(() => new DpopGuard({ mode: 'required', publicUrl: 'https://gw.example.test', skewSeconds: 0 }));
  assert.throws(() => createGateway(new Engine(new MemoryStore(fixture())), [{ token: 'x'.repeat(40), binding: bindings.intern }], { dpop: { mode: 'required', publicUrl: 'https://gw.example.test' } }), /signed-token/);
  assert.throws(() => createAdminGateway(new ControlPlane(new MemoryStore(world())), { credentials: [{ token: 'x'.repeat(40), binding: { tenant: 'acme', admin: 'sec' } }], dpop: { mode: 'required', publicUrl: 'https://gw.example.test' } }), /signed-token/);
  let clock = 1_000_000_000_000;
  const cache = new MemoryReplayCache(2, () => clock);
  const jkt = 'k'.repeat(43);
  assert.equal(await cache.consume('a', jkt, 1_000_000_060), true);
  assert.equal(await cache.consume('a', jkt, 1_000_000_060), false);
  assert.equal(await cache.consume('a', 'j'.repeat(43), 1_000_000_060), true, 'keyed by (jti, jkt)');
  await assert.rejects(cache.consume('b', jkt, 1_000_000_060), /full/, 'bounded and fail closed');
  clock += 61_000;
  assert.equal(await cache.consume('a', jkt, 1_000_000_130), true, 'expired entries are reusable and swept');
  // Skew is configurable: a proof 90 seconds old passes with 120 seconds of skew only.
  const h = await holder(), token = await access('akac-gateway', 'svc', { jkt: h.jkt });
  let base = '';
  for (const [skewSeconds, status] of [[60, 401], [120, 200]] as const) {
    const gateway = createGateway(new Engine(new MemoryStore(fixture())), [], { authenticator: agentAuth(), dpop: { mode: 'required', publicUrl: () => base, skewSeconds } });
    base = await listen(gateway);
    try { const url = base + '/ready'; assert.equal((await get(url, dpopHeaders(token, await proof(h, token, 'GET', url, { payload: { iat: now() - 90 } })))).status, status); }
    finally { await close(gateway); }
  }
});

test('SDK clients sign requests with a DPoP signer', async () => {
  const s = await servers('required', 'required');
  try {
    const h = await holder();
    const signer = (token: string) => async (method: string, url: string) => proof(h, token, method, url.split('?')[0]!);
    const token = await access('akac-gateway', 'svc', { jkt: h.jkt });
    const agent = new AkacClient(s.agentBase, token, { dpop: signer(token) });
    const context = await agent.context(['handbook'], 'work');
    assert.ok('ok' in context);
    const adminToken = await access('akac-admin', 'op', { jkt: h.jkt });
    const admin = new AdminClient(s.adminBase, adminToken, { dpop: signer(adminToken) });
    assert.equal((await admin.audit(0, 1)).ok, true);
    const unsigned = new AkacClient(s.agentBase, token);
    await assert.rejects(unsigned.context(['handbook'], 'work'), /transport failed \(401\)/);
  } finally { await s.stop(); }
});
