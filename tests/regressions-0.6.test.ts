import test from 'node:test';
import assert from 'node:assert/strict';
import { ControlPlane } from '../reference/control.ts';
import { MemoryStore } from '../reference/store.ts';
import { verifyAudit } from '../reference/audit.ts';
import type { Knowledge, State } from '../reference/types.ts';
import { world } from './support.ts';

/** R15 / R126 (0.6): a label-widening document version is a declassification and needs a security-admin. */
function setup(extra?: (s: State) => void) {
  const s = world();
  // An administrator holding both roles (no SoD constraint covers them in the fixture).
  s.actors.both = { id: 'both', tenant: 'acme', kind: 'user', roles: ['kb-admin', 'security-admin'], projects: [], clearance: 'restricted', active: true };
  extra?.(s);
  const store = new MemoryStore(s);
  return { store, control: new ControlPlane(store) };
}
const next = (s: State, id: string, change: Partial<Knowledge>): Knowledge => ({ ...structuredClone(s.knowledge[id]!), version: s.knowledge[id]!.version + 1, ...change });
const stored = async (store: MemoryStore, id: string) => store.transaction('acme', async tx => structuredClone(tx.state.knowledge[id]!));
const last = async (store: MemoryStore) => (await store.auditLog('acme')).at(-1)!;

test('regression: a kb-admin cannot widen a document label through a new version (R15, R126)', async () => {
  const base = world();
  base.knowledge['project-alpha']!.accessExpiresAt = 4102444800000;
  const widenings: [string, Partial<Knowledge>][] = [
    ['lower classification', { classification: 'internal' }],
    ['added reader', { readers: ['intern'] }],
    ['added reader role', { readerRoles: ['project', 'executive', 'staff'] }],
    ['removed project', { projects: [] }],
    ['moved to a container', { container: 'kb-corporate' }],
    ['access expiry removed', { accessExpiresAt: undefined }],
    ['access expiry extended', { accessExpiresAt: 4102444800001 }]
  ];
  for (const [name, change] of widenings) {
    const { store, control } = setup(s => { s.knowledge['project-alpha']!.accessExpiresAt = 4102444800000; });
    const doc = next(base, 'project-alpha', change);
    if (change.accessExpiresAt === undefined && 'accessExpiresAt' in change) delete doc.accessExpiresAt;
    const r = await control.upsertKnowledge('acme', 'kbadm', doc);
    assert.deepEqual([r.ok, !r.ok && r.code], [false, 'CONFLICT'], name);
    assert.equal((await last(store)).reason, 'DENIED:CONFLICT', name);
    assert.equal((await stored(store, 'project-alpha')).version, 1, `${name}: nothing stored`);
    // The same version by an administrator who also holds security-admin is the separately authorized path.
    assert.ok((await control.upsertKnowledge('acme', 'both', doc)).ok, `${name} by security-admin`);
    assert.ok(verifyAudit(await store.auditLog('acme')));
  }
});

test('regression: narrowing versions stay kb-admin work; a security-admin alone may only relabel with unchanged content (R126)', async () => {
  const { store, control } = setup();
  const s = world();
  // Narrowing: higher classification, a reader role removed, a project added.
  const narrowed = next(s, 'project-alpha', { classification: 'restricted', readerRoles: ['executive'], projects: ['alpha', 'beta'], content: 'Revised synthetic plan.' });
  assert.ok((await control.upsertKnowledge('acme', 'kbadm', narrowed)).ok);
  // A security-admin without kb-admin: relabelling that widens, content unchanged, is accepted.
  const relabel = { ...narrowed, version: 3, classification: 'confidential' as const };
  assert.ok((await control.upsertKnowledge('acme', 'sec', relabel)).ok);
  assert.equal((await stored(store, 'project-alpha')).classification, 'confidential');
  // ...but it cannot author content, create documents or make non-widening changes.
  for (const [name, doc] of [
    ['content change', { ...relabel, version: 4, classification: 'internal' as const, content: 'Other text.' }],
    ['new document', { ...structuredClone(s.knowledge.handbook!), id: 'new-doc' }],
    ['narrowing only', { ...relabel, version: 4, classification: 'restricted' as const }]
  ] as [string, Knowledge][]) {
    const r = await control.upsertKnowledge('acme', 'sec', doc);
    assert.deepEqual([r.ok, !r.ok && r.code, Object.keys(r).sort()], [false, 'NOT_AUTHORIZED', ['code', 'decisionId', 'ok']], name);
    assert.equal((await last(store)).reason, 'DENIED:NOT_ADMIN', name);
  }
  assert.equal((await stored(store, 'project-alpha')).version, 3);
  // An auditor holds neither role.
  assert.equal((await control.upsertKnowledge('acme', 'aud', { ...relabel, version: 4 })).ok, false);
  assert.ok(verifyAudit(await store.auditLog('acme')));
});
