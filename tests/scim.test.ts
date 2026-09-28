import test from 'node:test';
import assert from 'node:assert/strict';
import { bindings } from '../examples/fixture.ts';
import { SCIM } from '../reference/scim.ts';
import { decide } from '../reference/policy.ts';
import type { Binding } from '../reference/types.ts';
import type { MemoryStore } from '../reference/store.ts';
import { start, tokens } from './support.ts';

/** Pure policy probe over current state. (A context opened before an epoch change stays stale by design, so re-reading through the engine would conflate the two.) */
const allowed = (store: MemoryStore, b: Binding, resource: string) =>
  store.transaction(b.tenant, async tx => decide(tx.state, { binding: b, action: 'read', resource, purpose: 'work', now: Date.now() }).effect === 'allow');

const EXT = SCIM.extension;
const patch = (...Operations: unknown[]) => ({ schemas: [SCIM.patch], Operations });

test('SCIM: provisioning creates a user; PATCH active=false takes effect for agents immediately', async () => {
  const { call, agentUrl, stop, store } = await start();
  const read = async () => (await call(tokens.intern, 'POST', '/v1/contexts', { resources: ['handbook'], purpose: 'work' }, {}, agentUrl)).status;
  try {
    const created = await call(tokens.sec, 'POST', '/scim/v2/Users', { schemas: [SCIM.user], userName: 'newhire', displayName: 'New Hire', emails: [{ value: 'x@example.invalid' }], [EXT]: { clearance: 'internal', projects: ['alpha'] } });
    assert.equal(created.status, 201); assert.match(created.headers.get('content-type') ?? '', /^application\/scim\+json/);
    assert.equal(created.headers.get('location'), '/scim/v2/Users/newhire');
    const user = await created.json() as Record<string, any>;
    assert.equal(user.id, 'newhire'); assert.equal(user.active, true); assert.deepEqual(user[EXT], { clearance: 'internal', projects: ['alpha'] });
    assert.equal((await call(tokens.sec, 'POST', '/scim/v2/Users', { userName: 'newhire' })).status, 409);
    const dflt = await (await call(tokens.sec, 'POST', '/scim/v2/Users', { userName: 'plain' })).json() as Record<string, any>;
    assert.equal(dflt[EXT].clearance, 'public');

    const found = await (await call(tokens.sec, 'GET', '/scim/v2/Users?filter=' + encodeURIComponent('userName eq "newhire"'))).json() as Record<string, any>;
    assert.equal(found.totalResults, 1); assert.equal(found.Resources[0].id, 'newhire');
    assert.equal(((await (await call(tokens.sec, 'GET', '/scim/v2/Users?filter=' + encodeURIComponent('userName eq "nobody"'))).json()) as Record<string, any>).totalResults, 0);
    assert.equal((await call(tokens.sec, 'GET', '/scim/v2/Users/newhire')).status, 200);
    assert.equal((await call(tokens.sec, 'GET', '/scim/v2/Users/missing')).status, 404);

    // A seeded user in the agent fixture: authorized before, denied right after deprovisioning.
    assert.equal(await read(), 200);
    assert.equal(await allowed(store, bindings.intern, 'handbook'), true);
    const off = await call(tokens.sec, 'PATCH', '/scim/v2/Users/intern', patch({ op: 'Replace', path: 'active', value: 'False' }));
    assert.equal(off.status, 200); assert.equal(((await off.json()) as Record<string, any>).active, false);
    assert.equal(await read(), 403);
    assert.equal(await allowed(store, bindings.intern, 'handbook'), false);
    assert.equal(((await (await call(tokens.sec, 'GET', '/scim/v2/Users/intern')).json()) as Record<string, any>).active, false);
    // Okta style no-path PATCH reactivates; PUT without `active` never reactivates.
    assert.equal((await call(tokens.sec, 'PATCH', '/scim/v2/Users/intern', patch({ op: 'replace', value: { active: true } }))).status, 200);
    assert.equal(await allowed(store, bindings.intern, 'handbook'), true, 'reactivation restores authority; the earlier run stays revoked');
    assert.equal(await read(), 403, 'contexts opened before the epoch change are stale');
    const put = await call(tokens.sec, 'PUT', '/scim/v2/Users/intern', { userName: 'intern', [EXT]: { clearance: 'internal' } });
    assert.equal(put.status, 200);
    assert.equal((await call(tokens.sec, 'DELETE', '/scim/v2/Users/intern')).status, 204);
    assert.equal(await allowed(store, bindings.intern, 'handbook'), false);
    assert.equal((await call(tokens.sec, 'PUT', '/scim/v2/Users/intern', { userName: 'intern' })).status, 200);
    assert.equal(((await (await call(tokens.sec, 'GET', '/scim/v2/Users/intern')).json()) as Record<string, any>).active, false, 'omitted active keeps the account deactivated');
    assert.equal(await allowed(store, bindings.intern, 'handbook'), false);
    assert.equal((await call(tokens.sec, 'PUT', '/scim/v2/Users/intern', { userName: 'other-name' })).status, 400);
  } finally { await stop(); }
});

test('SCIM: group membership grants a role; removing the member takes it away', async () => {
  const { call, stop, store } = await start();
  const read = () => allowed(store, bindings.lead, 'board-notes');
  try {
    assert.equal(await read(), false);
    const group = await call(tokens.sec, 'POST', '/scim/v2/Groups', { schemas: [SCIM.group], displayName: 'exec-readers', members: [{ value: 'lead' }, { value: 'lead-agent' }], [EXT]: { roles: ['executive'] } });
    assert.equal(group.status, 201);
    const body = await group.json() as Record<string, any>;
    assert.deepEqual(body.members, [{ value: 'lead' }, { value: 'lead-agent' }]); assert.deepEqual(body[EXT], { roles: ['executive'] });
    assert.equal(await read(), true);
    assert.equal((await call(tokens.sec, 'POST', '/scim/v2/Groups', { displayName: 'exec-readers' })).status, 409);

    assert.equal((await call(tokens.sec, 'PATCH', '/scim/v2/Groups/exec-readers', patch({ op: 'remove', path: 'members[value eq "lead"]' }))).status, 200);
    assert.equal(await read(), false);
    assert.equal((await call(tokens.sec, 'PATCH', '/scim/v2/Groups/exec-readers', patch({ op: 'Add', path: 'members', value: [{ value: 'lead' }] }))).status, 200);
    assert.equal(await read(), true);
    assert.equal((await call(tokens.sec, 'PATCH', '/scim/v2/Groups/exec-readers', patch({ op: 'remove', path: 'members', value: [{ value: 'lead' }] }))).status, 200);
    assert.equal(await read(), false);
    // Separation of duty applies to SCIM-driven roles.
    await call(tokens.sec, 'PATCH', '/scim/v2/Groups/exec-readers', patch({ op: 'add', path: 'members', value: [{ value: 'lead' }] }));
    const sod = await call(tokens.sec, 'PATCH', '/scim/v2/Groups/exec-readers', patch({ op: 'replace', path: `${EXT}:roles`, value: ['requester', 'approver'] }));
    assert.equal(sod.status, 409);
    assert.equal(await read(), true, 'a rejected change leaves the previous roles in force');
    const replaced = await call(tokens.sec, 'PUT', '/scim/v2/Groups/exec-readers', { displayName: 'exec-readers', members: [] });
    assert.equal(replaced.status, 200); assert.equal(await read(), false);
    assert.equal((await call(tokens.sec, 'PUT', '/scim/v2/Groups/exec-readers', { displayName: 'renamed' })).status, 400);
    const found = await (await call(tokens.sec, 'GET', '/scim/v2/Groups?filter=' + encodeURIComponent('displayName eq "exec-readers"'))).json() as Record<string, any>;
    assert.equal(found.totalResults, 1);
    assert.equal((await call(tokens.sec, 'DELETE', '/scim/v2/Groups/exec-readers')).status, 204);
    assert.equal((await call(tokens.sec, 'GET', '/scim/v2/Groups/exec-readers')).status, 404);
  } finally { await stop(); }
});

test('SCIM: filters other than the supported equality filters are rejected', async () => {
  const { call, stop } = await start();
  try {
    for (const filter of ['userName co "a"', 'userName eq a', 'emails.value eq "a@example.invalid"', 'displayName eq "a"', 'userName eq "a" and active eq true', 'active eq true', '']) {
      const r = await call(tokens.sec, 'GET', '/scim/v2/Users?filter=' + encodeURIComponent(filter));
      assert.equal(r.status, 400, filter);
      const e = await r.json() as Record<string, any>;
      assert.deepEqual([e.schemas, e.status, e.scimType], [[SCIM.error], '400', 'invalidFilter']);
    }
    assert.equal((await call(tokens.sec, 'GET', '/scim/v2/Users')).status, 400, 'unfiltered listing is not supported');
    assert.equal((await call(tokens.sec, 'GET', '/scim/v2/Groups?filter=' + encodeURIComponent('userName eq "a"'))).status, 400);
  } finally { await stop(); }
});

test('SCIM: identity providers cannot smuggle authority, and only security-admin may provision', async () => {
  const { call, stop, adminUrl } = await start();
  try {
    for (const extra of [{ roles: [{ value: 'security-admin' }] }, { groups: [{ value: 'x' }] }, { entitlements: [] }]) {
      const r = await call(tokens.sec, 'POST', '/scim/v2/Users', { userName: 'sneaky', ...extra });
      assert.equal(r.status, 400); assert.equal(((await r.json()) as Record<string, any>).scimType, 'mutability');
    }
    await call(tokens.sec, 'POST', '/scim/v2/Users', { userName: 'plain2' });
    for (const op of [{ op: 'add', path: 'roles', value: [{ value: 'security-admin' }] }, { op: 'replace', path: `${EXT}:roles`, value: ['x'] }, { op: 'replace', path: 'bogus', value: 1 }]) {
      assert.equal((await call(tokens.sec, 'PATCH', '/scim/v2/Users/plain2', patch(op))).status, 400, JSON.stringify(op));
    }
    assert.equal((await call(tokens.sec, 'POST', '/scim/v2/Users', { userName: 'bad', [EXT]: { clearance: 'root' } })).status, 400);
    assert.equal((await call(tokens.sec, 'POST', '/scim/v2/Users', { userName: 'a@example.invalid' })).status, 400);
    assert.equal((await call(tokens.sec, 'POST', '/scim/v2/Users', { userName: 'bad2', [EXT]: { clearance: 'public', admin: true } })).status, 400);
    assert.equal((await call(tokens.sec, 'PATCH', '/scim/v2/Users/plain2', { Operations: [] })).status, 400);
    assert.equal((await call(tokens.kb, 'POST', '/scim/v2/Users', { userName: 'kb-made' })).status, 403);
    assert.equal((await call(tokens.aud, 'GET', '/scim/v2/Users/plain2')).status, 403);
    assert.equal((await call(tokens.intern, 'GET', '/scim/v2/Users/plain2')).status, 401);
    assert.equal((await fetch(adminUrl + '/scim/v2/Users/plain2')).status, 401);
    // Another tenant's provisioning credential cannot see or change acme users.
    assert.equal((await call(tokens.other, 'GET', '/scim/v2/Users/plain2')).status, 404);
    assert.equal((await call(tokens.other, 'DELETE', '/scim/v2/Users/plain2')).status, 404);
    assert.equal(((await (await call(tokens.sec, 'GET', '/scim/v2/Users/plain2')).json()) as Record<string, any>).active, true);
    // Agent actors are not SCIM users.
    assert.equal((await call(tokens.sec, 'GET', '/scim/v2/Users/intern-agent')).status, 404);
  } finally { await stop(); }
});

test('SCIM: discovery endpoints describe the supported subset', async () => {
  const { call, stop } = await start();
  try {
    const config = await (await call(tokens.sec, 'GET', '/scim/v2/ServiceProviderConfig')).json() as Record<string, any>;
    assert.deepEqual([config.patch.supported, config.bulk.supported, config.filter.supported, config.sort.supported], [true, false, true, false]);
    const types = await (await call(tokens.sec, 'GET', '/scim/v2/ResourceTypes')).json() as Record<string, any>;
    assert.deepEqual(types.Resources.map((r: { id: string }) => r.id), ['User', 'Group']);
    const schemas = await (await call(tokens.sec, 'GET', '/scim/v2/Schemas')).json() as Record<string, any>;
    assert.ok(schemas.Resources.some((s: { id: string }) => s.id === EXT));
    const missing = await call(tokens.sec, 'GET', '/scim/v2/Nothing');
    assert.equal(missing.status, 404); assert.equal(((await missing.json()) as Record<string, any>).schemas[0], SCIM.error);
    assert.equal((await call(tokens.sec, 'POST', '/scim/v2/Users', 'nope')).status, 400);
    assert.equal((await call(tokens.sec, 'POST', '/scim/v2/Users', { userName: 'ct' }, { 'content-type': 'application/scim+json' })).status, 201);
  } finally { await stop(); }
});
