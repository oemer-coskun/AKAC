import { createServer } from 'node:http';
import type { ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { Engine, validId } from './engine.ts';
import type { Binding } from './types.ts';
import type { Authenticator } from '../adapters/jwt.ts';
import { observe } from './observe.ts';
import type { Observability } from './observe.ts';

export type Credential = { token: string; binding: Binding };
const digest = (token: string) => createHash('sha256').update(token).digest('hex');
const text = (v: unknown, max: number) => typeof v === 'string' && v.length > 0 && v.length <= max;
function keys(value: unknown, required: string[], optional: string[] = []): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
    && required.every(k => Object.hasOwn(value, k))
    && Object.keys(value).every(k => [...required, ...optional].includes(k));
}
function send(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'" });
  res.end(JSON.stringify(body));
}
export function createGateway(engine: Engine, credentials: Credential[], options: { authenticator?: Authenticator } & Observability = {}) {
  if (!credentials.length && !options.authenticator) throw new Error('Authentication is required');
  if (credentials.length && options.authenticator) throw new Error('Authentication modes cannot be mixed');
  const auth = new Map<string, Binding>();
  for (const credential of credentials) {
    if (!text(credential.token, 512) || credential.token.length < 32
      || !keys(credential.binding, ['tenant', 'subject', 'agent', 'grant'])
      || !Object.values(credential.binding).every(validId) || auth.has(digest(credential.token))) throw new Error('Invalid credential configuration');
    auth.set(digest(credential.token), structuredClone(credential.binding));
  }
  const buckets = new Map<string, { minute: number; count: number }>();
  let active = 0;
  const routes = new Set(['/health', '/ready', '/v1/retrieve', '/v1/contexts', '/v1/derive', '/v1/release']);
  const server = createServer(async (req, res) => {
    const obs = observe('agent', req, res, options);
    obs.setRoute(routes.has(req.url ?? '') ? req.url! : 'unmatched');
    if (active >= 32) { req.resume(); send(res, 503, { error: 'BUSY' }); return; }
    active++;
    try {
    if (req.url === '/health' && req.method === 'GET') { send(res, 200, { status: 'ok', specification: '0.3-draft' }); return; }
    const header = req.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
    const binding = options.authenticator ? await options.authenticator.authenticate(token)
      : auth.get(token.length <= 512 ? digest(token) : '');
    if (!binding) { req.resume(); send(res, 401, { error: 'UNAUTHENTICATED' }); return; }
    const hash = digest(JSON.stringify(binding));
    const minute = Math.floor(Date.now() / 60000);
    for (const [key, value] of buckets) if (value.minute !== minute) buckets.delete(key);
    if (!buckets.has(hash) && buckets.size >= 10000) { req.resume(); send(res, 503, { error: 'BUSY' }); return; }
    const bucket = buckets.get(hash)?.minute === minute ? buckets.get(hash)! : { minute, count: 0 };
    buckets.set(hash, bucket);
    if (++bucket.count > 120) { req.resume(); send(res, 429, { error: 'RATE_LIMITED' }); return; }
    if (req.url === '/ready' && req.method === 'GET') {
      const ready = await engine.ready(binding.tenant); send(res, ready ? 200 : 503, { status: ready ? 'ready' : 'unavailable' }); return;
    }
    if (req.method !== 'POST' || req.headers['content-type']?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
      req.resume(); send(res, 400, { error: 'INVALID_REQUEST' }); return;
    }
    try {
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 131072) { send(res, 413, { error: 'REQUEST_TOO_LARGE' }); return; }
        chunks.push(Buffer.from(chunk));
      }
      let body: unknown;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { send(res, 400, { error: 'INVALID_JSON' }); return; }
      let result;
      if (req.url === '/v1/retrieve' && keys(body, ['query', 'purpose'], ['limit'])
        && text(body.query, 4096) && text(body.purpose, 128)
        && (body.limit === undefined || (Number.isInteger(body.limit) && Number(body.limit) >= 1 && Number(body.limit) <= 20))) {
        result = await engine.retrieve(binding, body.query as string, body.purpose as string, body.limit as number | undefined);
      } else if (req.url === '/v1/contexts' && keys(body, ['resources', 'purpose'])
        && Array.isArray(body.resources) && body.resources.length > 0 && body.resources.length <= 64
        && body.resources.every(validId) && text(body.purpose, 128)) {
        result = await engine.openContext(binding, body.resources, body.purpose as string);
      } else if (req.url === '/v1/derive' && keys(body, ['context', 'content', 'kind'])
        && validId(body.context) && text(body.content, 100000) && ['memory', 'artifact'].includes(body.kind as string)) {
        result = await engine.derive(binding, body.context, body.content as string, body.kind as 'memory' | 'artifact');
      } else if (req.url === '/v1/release' && keys(body, ['context', 'recipient', 'content', 'action'])
        && validId(body.context) && validId(body.recipient) && text(body.content, 100000)
        && ['share', 'export'].includes(body.action as string)) {
        result = await engine.release(binding, body.context, body.recipient, body.content as string, body.action as 'share' | 'export');
      } else { send(res, 400, { error: 'INVALID_REQUEST' }); return; }
      send(res, result.ok ? 200 : 403, result);
    } catch { if (!res.headersSent) send(res, 503, { error: 'UNAVAILABLE' }); }
    } catch { if (!res.headersSent) send(res, 503, { error: 'UNAVAILABLE' }); }
    finally { active--; }
  });
  server.requestTimeout = 10000; server.headersTimeout = 5000; server.timeout = 15000;
  server.maxHeadersCount = 32;
  return server;
}
