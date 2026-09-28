import type { ControlPlane, ControlResult } from './control.ts';
import { LEVELS } from './types.ts';
import type { Actor, Group, Level } from './types.ts';
import { validId } from './validation.ts';

/**
 * SCIM 2.0 subset (RFC 7643/7644) mapped onto the control plane. The IdP is a
 * provisioning source, not an authority: it can create/deactivate users, set
 * clearance and projects, and manage group membership and group roles, all through the
 * audited control plane with the caller's security-admin role. Roles, groups and
 * entitlements sent on a User are refused, never applied.
 *
 * Identifiers: userName and displayName must be AKAC ids and are the resource ids
 * (immutable), so no shadow store is needed. Other profile attributes are accepted and
 * discarded.
 */
export const SCIM = {
  user: 'urn:ietf:params:scim:schemas:core:2.0:User', group: 'urn:ietf:params:scim:schemas:core:2.0:Group',
  extension: 'urn:ietf:params:scim:schemas:extension:akac:2.0:User',
  list: 'urn:ietf:params:scim:api:messages:2.0:ListResponse', patch: 'urn:ietf:params:scim:api:messages:2.0:PatchOp',
  error: 'urn:ietf:params:scim:api:messages:2.0:Error', config: 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig',
  resourceType: 'urn:ietf:params:scim:schemas:core:2.0:ResourceType', schema: 'urn:ietf:params:scim:schemas:core:2.0:Schema'
} as const;
export const scimError = (status: number, detail: string, scimType?: string) =>
  ({ schemas: [SCIM.error], status: String(status), ...(scimType ? { scimType } : {}), detail });

type Out = { status: number; body?: unknown; extra?: Record<string, string> };
type Ctx = { tenant: string; admin: string; params: string[]; body: unknown; query: URLSearchParams };
type Match = { label: string; operation: string; body: boolean; run(ctx: Ctx): Promise<Out> };
class Refusal extends Error {
  status: number; scimType: string | undefined;
  constructor(status: number, detail: string, scimType?: string) { super(detail); this.status = status; this.scimType = scimType; }
}
const plain = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const bad = (detail: string, type = 'invalidValue') => new Refusal(400, detail, type);
const idList = (x: unknown, max: number, what: string): string[] => {
  if (!Array.isArray(x) || x.length > max || !x.every(validId) || new Set(x).size !== x.length) throw bad(`${what} must be a list of at most ${max} unique identifiers`);
  return x as string[];
};
const flag = (x: unknown): boolean => {
  if (typeof x === 'boolean') return x;
  if (typeof x === 'string' && /^(true|false)$/i.test(x)) return x.toLowerCase() === 'true';
  throw bad('active must be a boolean');
};
const members = (x: unknown): string[] => {
  if (!Array.isArray(x) || x.length > 1024) throw bad('members must be a list of at most 1024 entries');
  const out = x.map(m => { if (!plain(m) || !validId(m.value)) throw bad('member value must be an identifier'); return m.value as string; });
  return [...new Set(out)];
};
/** Extension attributes are ours: strict. */
function extension(body: Record<string, unknown>): { clearance?: Level; projects?: string[]; roles?: string[] } {
  const e = body[SCIM.extension];
  if (e === undefined) return {};
  if (!plain(e) || Object.keys(e).some(k => !['clearance', 'projects', 'roles'].includes(k))) throw bad('Invalid extension object');
  if (e.clearance !== undefined && !LEVELS.includes(e.clearance as Level)) throw bad('clearance must be public, internal, confidential or restricted');
  return { ...(e.clearance !== undefined ? { clearance: e.clearance as Level } : {}),
    ...(e.projects !== undefined ? { projects: idList(e.projects, 256, 'projects') } : {}),
    ...(e.roles !== undefined ? { roles: idList(e.roles, 64, 'roles') } : {}) };
}
const FORBIDDEN_USER = ['roles', 'groups', 'entitlements', 'x509Certificates'];
const PROFILE = /^(displayName|name(\..+)?|nickName|profileUrl|title|userType|preferredLanguage|locale|timezone|externalId|emails.*|phoneNumbers.*|ims.*|photos.*|addresses.*|password)$/;

const userResource = (a: Actor) => ({
  schemas: [SCIM.user, SCIM.extension], id: a.id, userName: a.id, active: a.active,
  [SCIM.extension]: { clearance: a.clearance, projects: [...a.projects] },
  meta: { resourceType: 'User', location: `/scim/v2/Users/${a.id}` }
});
const groupResource = (g: Group) => ({
  schemas: [SCIM.group, SCIM.extension], id: g.id, displayName: g.id, members: g.members.map(value => ({ value })),
  [SCIM.extension]: { roles: [...g.roles] },
  meta: { resourceType: 'Group', location: `/scim/v2/Groups/${g.id}` }
});
const listOf = (resources: unknown[]) => ({ schemas: [SCIM.list], totalResults: resources.length, startIndex: 1, itemsPerPage: resources.length, Resources: resources });

function filter(query: URLSearchParams, attribute: 'userName' | 'displayName'): string | null {
  const raw = query.get('filter');
  const m = raw === null ? null : /^\s*([A-Za-z]+)\s+eq\s+"([^"\\]{1,128})"\s*$/i.exec(raw);
  if (!m || m[1]!.toLowerCase() !== attribute.toLowerCase()) throw new Refusal(400, `Only the filter ${attribute} eq "value" is supported`, 'invalidFilter');
  return m[2]!;
}
type Op = { op: 'add' | 'remove' | 'replace'; path?: string; value?: unknown };
function operations(body: unknown): Op[] {
  if (!plain(body) || !Array.isArray(body.schemas) || !body.schemas.includes(SCIM.patch) || !Array.isArray(body.Operations)
    || body.Operations.length < 1 || body.Operations.length > 32) throw bad('Invalid PatchOp request', 'invalidSyntax');
  return body.Operations.map(o => {
    const op = plain(o) && typeof o.op === 'string' ? o.op.toLowerCase() : '';
    if (!plain(o) || !['add', 'remove', 'replace'].includes(op) || (o.path !== undefined && (typeof o.path !== 'string' || o.path.length > 256))
      || (o.path === undefined && op === 'remove')) throw bad('Invalid operation', 'invalidSyntax');
    return { op: op as Op['op'], ...(o.path !== undefined ? { path: o.path as string } : {}), ...(o.value !== undefined ? { value: o.value } : {}) };
  });
}
/** No-path operations carry an object whose keys are attribute paths. */
const expand = (ops: Op[]): Op[] => ops.flatMap(o => o.path === undefined
  ? plain(o.value) ? Object.entries(o.value).map(([path, value]) => ({ op: o.op, path, value })) : (() => { throw bad('A value object is required without a path', 'invalidSyntax'); })()
  : [o]);
const scalarList = (v: unknown, what: string) => Array.isArray(v) ? idList(v, 1024, what) : idList([v], 1, what);
function listOp(current: string[], op: Op, value: unknown, max: number, what: string): string[] {
  if (op.op === 'replace') return idList(value, max, what);
  if (op.op === 'add') return idList([...new Set([...current, ...(Array.isArray(value) ? value : [value])])], max, what);
  return current.filter(x => !scalarList(value, what).includes(x));
}

export function createScim(control: ControlPlane) {
  const fromControl = (r: Exclude<ControlResult<unknown>, { ok: true }>): never => {
    if (r.code === 'NOT_AUTHORIZED') throw new Refusal(403, 'Not authorized');
    if (r.code === 'CONFLICT') throw new Refusal(409, 'Conflicting resource', 'uniqueness');
    if (r.code === 'SOD_VIOLATION') throw new Refusal(409, 'Separation-of-duty constraint violated');
    throw bad('Invalid resource');
  };
  const need = <T>(r: ControlResult<T>): T => r.ok ? r.value : fromControl(r);
  const user = async (c: Ctx, id: string) => { const a = need(await control.readActor(c.tenant, c.admin, id)); return a && a.kind === 'user' ? a : null; };
  const group = async (c: Ctx, id: string) => { const g = need(await control.readGroup(c.tenant, c.admin, id)); return g && g.active ? g : null; };
  const missing = (what: string, id: string) => new Refusal(404, `${what} ${id} not found`);
  const saveUser = async (c: Ctx, a: Actor) => { need(await control.upsertActor(c.tenant, c.admin, a)); };
  const saveGroup = async (c: Ctx, g: Group) => { need(await control.upsertGroup(c.tenant, c.admin, g)); };
  const userName = (b: Record<string, unknown>) => { if (!validId(b.userName)) throw bad('userName must be an identifier', 'invalidValue'); return b.userName; };
  const rejectUnsafe = (b: Record<string, unknown>) => { for (const k of FORBIDDEN_USER) if (Object.hasOwn(b, k)) throw new Refusal(400, `${k} are managed through groups`, 'mutability'); };

  const handlers: { method: string; pattern: RegExp; label: string; operation: string; body: boolean; run(c: Ctx): Promise<Out> }[] = [
    { method: 'POST', pattern: /^\/scim\/v2\/Users$/, label: '/scim/v2/Users', operation: 'scim_create_user', body: true, run: async c => {
      if (!plain(c.body)) throw bad('Body must be an object', 'invalidSyntax');
      rejectUnsafe(c.body);
      const id = userName(c.body), ext = extension(c.body);
      if (need(await control.readActor(c.tenant, c.admin, id))) throw new Refusal(409, 'userName already exists', 'uniqueness');
      const a: Actor = { id, tenant: c.tenant, kind: 'user', roles: [], projects: ext.projects ?? [], clearance: ext.clearance ?? 'public', active: c.body.active === undefined ? true : flag(c.body.active) };
      await saveUser(c, a);
      return { status: 201, body: userResource(a), extra: { location: `/scim/v2/Users/${id}` } };
    } },
    { method: 'GET', pattern: /^\/scim\/v2\/Users$/, label: '/scim/v2/Users', operation: 'scim_find_user', body: false, run: async c => {
      const name = filter(c.query, 'userName')!;
      const a = validId(name) ? await user(c, name) : null;
      return { status: 200, body: listOf(a ? [userResource(a)] : []) };
    } },
    { method: 'GET', pattern: /^\/scim\/v2\/Users\/([^/]+)$/, label: '/scim/v2/Users/{id}', operation: 'scim_get_user', body: false, run: async c => {
      const a = await user(c, c.params[0]!); if (!a) throw missing('User', c.params[0]!);
      return { status: 200, body: userResource(a) };
    } },
    { method: 'PUT', pattern: /^\/scim\/v2\/Users\/([^/]+)$/, label: '/scim/v2/Users/{id}', operation: 'scim_replace_user', body: true, run: async c => {
      if (!plain(c.body)) throw bad('Body must be an object', 'invalidSyntax');
      rejectUnsafe(c.body);
      const id = c.params[0]!, current = await user(c, id); if (!current) throw missing('User', id);
      if (userName(c.body) !== id) throw new Refusal(400, 'userName is immutable', 'mutability');
      const ext = extension(c.body);
      // Omitted authority-bearing attributes fall back to the least privilege; omitted `active` never reactivates.
      const a: Actor = { ...current, projects: ext.projects ?? [], clearance: ext.clearance ?? 'public', active: c.body.active === undefined ? current.active : flag(c.body.active) };
      await saveUser(c, a);
      return { status: 200, body: userResource(a) };
    } },
    { method: 'PATCH', pattern: /^\/scim\/v2\/Users\/([^/]+)$/, label: '/scim/v2/Users/{id}', operation: 'scim_patch_user', body: true, run: async c => {
      const ops = expand(operations(c.body)), id = c.params[0]!, current = await user(c, id); if (!current) throw missing('User', id);
      const a: Actor = structuredClone(current);
      for (const o of ops) {
        const path = o.path!.startsWith(`${SCIM.extension}:`) ? o.path!.slice(SCIM.extension.length + 1) : o.path!;
        const ext = o.path!.startsWith(`${SCIM.extension}:`);
        if (o.path === SCIM.extension && plain(o.value)) { // whole extension object
          const e = extension({ [SCIM.extension]: o.value });
          if (e.roles) throw new Refusal(400, 'roles are managed through groups', 'mutability');
          if (e.clearance) a.clearance = e.clearance; if (e.projects) a.projects = e.projects; continue;
        }
        if (!ext && path === 'active' && o.op !== 'remove') a.active = flag(o.value);
        else if (ext && path === 'clearance') {
          if (o.op === 'remove') a.clearance = 'public';
          else if (LEVELS.includes(o.value as Level)) a.clearance = o.value as Level;
          else throw bad('clearance must be public, internal, confidential or restricted');
        }
        else if (ext && path === 'projects') a.projects = listOp(a.projects, o, o.value, 256, 'projects');
        else if (!ext && path === 'userName') { if (o.value !== id) throw new Refusal(400, 'userName is immutable', 'mutability'); }
        else if (!ext && FORBIDDEN_USER.includes(path.split(/[.[]/)[0]!)) throw new Refusal(400, `${path} is managed through groups`, 'mutability');
        else if (!ext && PROFILE.test(path)) continue;
        else throw new Refusal(400, `Unsupported path ${path.slice(0, 64)}`, 'invalidPath');
      }
      await saveUser(c, a);
      return { status: 200, body: userResource(a) };
    } },
    { method: 'DELETE', pattern: /^\/scim\/v2\/Users\/([^/]+)$/, label: '/scim/v2/Users/{id}', operation: 'scim_deactivate_user', body: false, run: async c => {
      const id = c.params[0]!, a = await user(c, id); if (!a) throw missing('User', id);
      // Deprovisioning is a revocation: it only removes authority, so it succeeds even for a
      // user who violates a constraint, and it always advances the tenant epoch (running
      // contexts end immediately).
      need(await control.revoke(c.tenant, c.admin, 'actor', id));
      return { status: 204 };
    } },

    { method: 'POST', pattern: /^\/scim\/v2\/Groups$/, label: '/scim/v2/Groups', operation: 'scim_create_group', body: true, run: async c => {
      if (!plain(c.body) || !validId(c.body.displayName)) throw bad('displayName must be an identifier');
      const id = c.body.displayName, ext = extension(c.body);
      if (need(await control.readGroup(c.tenant, c.admin, id))?.active) throw new Refusal(409, 'displayName already exists', 'uniqueness');
      const g: Group = { id, tenant: c.tenant, members: c.body.members === undefined ? [] : members(c.body.members), roles: ext.roles ?? [], active: true };
      await saveGroup(c, g);
      return { status: 201, body: groupResource(g), extra: { location: `/scim/v2/Groups/${id}` } };
    } },
    { method: 'GET', pattern: /^\/scim\/v2\/Groups$/, label: '/scim/v2/Groups', operation: 'scim_find_group', body: false, run: async c => {
      const name = filter(c.query, 'displayName')!;
      const g = validId(name) ? await group(c, name) : null;
      return { status: 200, body: listOf(g ? [groupResource(g)] : []) };
    } },
    { method: 'GET', pattern: /^\/scim\/v2\/Groups\/([^/]+)$/, label: '/scim/v2/Groups/{id}', operation: 'scim_get_group', body: false, run: async c => {
      const g = await group(c, c.params[0]!); if (!g) throw missing('Group', c.params[0]!);
      return { status: 200, body: groupResource(g) };
    } },
    { method: 'PUT', pattern: /^\/scim\/v2\/Groups\/([^/]+)$/, label: '/scim/v2/Groups/{id}', operation: 'scim_replace_group', body: true, run: async c => {
      if (!plain(c.body)) throw bad('Body must be an object', 'invalidSyntax');
      const id = c.params[0]!, current = await group(c, id); if (!current) throw missing('Group', id);
      if (c.body.displayName !== id) throw new Refusal(400, 'displayName is immutable', 'mutability');
      const g: Group = { ...current, members: c.body.members === undefined ? [] : members(c.body.members), roles: extension(c.body).roles ?? [] };
      await saveGroup(c, g);
      return { status: 200, body: groupResource(g) };
    } },
    { method: 'PATCH', pattern: /^\/scim\/v2\/Groups\/([^/]+)$/, label: '/scim/v2/Groups/{id}', operation: 'scim_patch_group', body: true, run: async c => {
      const ops = operations(c.body), id = c.params[0]!, current = await group(c, id); if (!current) throw missing('Group', id);
      const g: Group = structuredClone(current);
      for (const o of ops.flatMap(x => x.path === undefined ? expand([x]) : [x])) {
        const path = o.path!;
        const one = /^members\[value eq "([^"\\]{1,128})"\]$/i.exec(path);
        if (path.toLowerCase() === 'members') {
          if (o.op === 'remove') g.members = o.value === undefined ? [] : g.members.filter(m => !members(o.value).includes(m));
          else if (o.op === 'add') g.members = [...new Set([...g.members, ...members(o.value)])];
          else g.members = members(o.value);
        } else if (one) {
          if (o.op !== 'remove') throw new Refusal(400, 'A member filter path supports remove only', 'invalidPath');
          g.members = g.members.filter(m => m !== one[1]);
        } else if (path === 'displayName') { if (o.value !== id) throw new Refusal(400, 'displayName is immutable', 'mutability'); }
        else if (path === SCIM.extension && plain(o.value)) { const e = extension({ [SCIM.extension]: o.value }); if (e.roles) g.roles = e.roles; }
        else if (path === `${SCIM.extension}:roles`) g.roles = listOp(g.roles, o, o.value, 64, 'roles');
        else throw new Refusal(400, `Unsupported path ${path.slice(0, 64)}`, 'invalidPath');
        if (g.members.length > 1024) throw bad('members must be a list of at most 1024 entries');
      }
      await saveGroup(c, g);
      return { status: 200, body: groupResource(g) };
    } },
    { method: 'DELETE', pattern: /^\/scim\/v2\/Groups\/([^/]+)$/, label: '/scim/v2/Groups/{id}', operation: 'scim_delete_group', body: false, run: async c => {
      const id = c.params[0]!, g = await group(c, id); if (!g) throw missing('Group', id);
      await saveGroup(c, { ...g, active: false });
      return { status: 204 };
    } }
  ];

  const attribute = (name: string, type: string, extra: Record<string, unknown> = {}) =>
    ({ name, type, multiValued: false, required: false, caseExact: true, mutability: 'readWrite', returned: 'default', uniqueness: 'none', ...extra });
  const schemas = [
    { id: SCIM.user, name: 'User', description: 'Provisioned human identity. Profile attributes other than those listed are accepted and discarded.',
      attributes: [attribute('userName', 'string', { required: true, mutability: 'immutable', uniqueness: 'server', description: 'AKAC actor id: [A-Za-z0-9][A-Za-z0-9._:-]{0,127}' }), attribute('active', 'boolean')], meta: { resourceType: 'Schema', location: `/scim/v2/Schemas/${SCIM.user}` } },
    { id: SCIM.group, name: 'Group', description: 'AKAC group: members receive the group roles while active.',
      attributes: [attribute('displayName', 'string', { required: true, mutability: 'immutable', uniqueness: 'server' }),
        attribute('members', 'complex', { multiValued: true, subAttributes: [attribute('value', 'string', { mutability: 'immutable' })] })], meta: { resourceType: 'Schema', location: `/scim/v2/Schemas/${SCIM.group}` } },
    { id: SCIM.extension, name: 'AkacExtension', description: 'AKAC authority attributes. clearance and projects apply to Users, roles to Groups.',
      attributes: [attribute('clearance', 'string', { canonicalValues: [...LEVELS], caseExact: false }), attribute('projects', 'string', { multiValued: true }), attribute('roles', 'string', { multiValued: true })],
      meta: { resourceType: 'Schema', location: `/scim/v2/Schemas/${SCIM.extension}` } }
  ];
  const resourceTypes = [
    { schemas: [SCIM.resourceType], id: 'User', name: 'User', endpoint: '/Users', schema: SCIM.user, schemaExtensions: [{ schema: SCIM.extension, required: false }], meta: { resourceType: 'ResourceType', location: '/scim/v2/ResourceTypes/User' } },
    { schemas: [SCIM.resourceType], id: 'Group', name: 'Group', endpoint: '/Groups', schema: SCIM.group, schemaExtensions: [{ schema: SCIM.extension, required: false }], meta: { resourceType: 'ResourceType', location: '/scim/v2/ResourceTypes/Group' } }
  ];
  const provider = {
    schemas: [SCIM.config], patch: { supported: true }, bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 1 }, changePassword: { supported: false }, sort: { supported: false }, etag: { supported: false },
    authenticationSchemes: [{ type: 'oauthbearertoken', name: 'Bearer token', description: 'Administrator credential bound to a tenant and a security-admin actor', primary: true }],
    meta: { resourceType: 'ServiceProviderConfig', location: '/scim/v2/ServiceProviderConfig' }
  };
  const discovery: [RegExp, string, unknown][] = [
    [/^\/scim\/v2\/ServiceProviderConfig$/, '/scim/v2/ServiceProviderConfig', provider],
    [/^\/scim\/v2\/ResourceTypes$/, '/scim/v2/ResourceTypes', listOf(resourceTypes)],
    [/^\/scim\/v2\/Schemas$/, '/scim/v2/Schemas', listOf(schemas)]
  ];

  return {
    match(method: string, path: string, _query: URLSearchParams): Match | undefined {
      for (const [pattern, label, body] of discovery) if (method === 'GET' && pattern.test(path)) return { label, operation: 'scim_discovery', body: false, run: async () => ({ status: 200, body }) };
      const h = handlers.find(x => x.method === method && x.pattern.test(path));
      if (!h) return undefined;
      const params = h.pattern.exec(path)!.slice(1).map(p => { try { return decodeURIComponent(p); } catch { return ''; } });
      return { label: h.label, operation: h.operation, body: h.body, run: async ctx => {
        try {
          if (!params.every(validId)) throw new Refusal(404, 'Resource not found');
          return await h.run({ ...ctx, params });
        } catch (error) {
          if (error instanceof Refusal) return { status: error.status, body: scimError(error.status, error.message, error.scimType) };
          throw error;
        }
      } };
    }
  };
}
