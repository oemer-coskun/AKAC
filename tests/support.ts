import { once } from 'node:events';
import type { Server } from 'node:http';
import { ControlPlane } from '../reference/control.ts';
import { Engine } from '../reference/engine.ts';
import type { EngineOptions } from '../reference/engine.ts';
import { createAdminGateway } from '../reference/admin.ts';
import type { AdminOptions } from '../reference/admin.ts';
import { createGateway } from '../reference/http.ts';
import type { RuntimeObligationMode } from '../reference/http.ts';
import type { Observability } from '../reference/observe.ts';
import { MemoryStore } from '../reference/store.ts';
import { kbFixture, bindings } from '../examples/fixture.ts';
import type { State } from '../reference/types.ts';

export const tokens = {
  sec: 'test-only-security-admin-token-0000000000000', kb: 'test-only-kb-admin-token-000000000000000',
  aud: 'test-only-auditor-token-000000000000000000', other: 'test-only-other-tenant-admin-token-00000000',
  intern: 'test-only-credential-never-deploy-0000000000000'
};
export function world(): State {
  const s = kbFixture();
  const admin = (id: string, roles: string[], tenant = 'acme') => { s.actors[id] = { id, tenant, kind: 'user', roles, projects: [], clearance: 'restricted', active: true }; };
  admin('sec', ['security-admin']); admin('kbadm', ['kb-admin']); admin('aud', ['auditor']); admin('other-sec', ['security-admin', 'auditor'], 'other');
  return s;
}
export async function listen(server: Server) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('no address');
  return `http://127.0.0.1:${address.port}`;
}
export const close = async (...servers: Server[]) => {
  for (const s of servers) { s.closeAllConnections(); await new Promise<void>(resolve => s.close(() => resolve())); }
};
export async function start(options: { admin?: Partial<AdminOptions>; engine?: EngineOptions; agent?: Observability & { runtimeObligations?: RuntimeObligationMode }; state?: State } = {}) {
  const store = new MemoryStore(options.state ?? world());
  const engine = new Engine(store, options.engine);
  const control = new ControlPlane(store);
  const agent = createGateway(engine, [{ token: tokens.intern, binding: bindings.intern }], options.agent);
  const admin = createAdminGateway(control, { credentials: [
    { token: tokens.sec, binding: { tenant: 'acme', admin: 'sec' } }, { token: tokens.kb, binding: { tenant: 'acme', admin: 'kbadm' } },
    { token: tokens.aud, binding: { tenant: 'acme', admin: 'aud' } }, { token: tokens.other, binding: { tenant: 'other', admin: 'other-sec' } }], ...options.admin });
  const agentUrl = await listen(agent), adminUrl = await listen(admin);
  const call = (token: string, method: string, path: string, body?: unknown, headers: Record<string, string> = {}, base = adminUrl) =>
    fetch(base + path, { method, headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers },
      ...(body !== undefined ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {}) });
  return { store, engine, control, agent, admin, agentUrl, adminUrl, call, stop: () => close(agent, admin) };
}
