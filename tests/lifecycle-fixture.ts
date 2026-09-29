// Shared synthetic fixture of the knowledge lifecycle tests.
import { kbFixture } from '../examples/fixture.ts';
import type { Knowledge, State } from '../reference/types.ts';

export const now = 1800000000000;
/** A model-derived artifact with the given direct sources (version 1). */
export const derived = (id: string, sources: string[], tenant = 'acme'): Knowledge => ({ id, tenant, version: 1, kind: 'artifact', origin: 'model',
  content: `Derived ${id}: synthetic text.`, classification: 'public', projects: [], readerRoles: ['staff'], readers: [],
  sources: sources.map(s => ({ id: s, version: 1 })), active: true });
/**
 * handbook -> d1 -> d2 (chain), handbook -> a, b -> c (diamond), plus admins and a
 * second tenant with one document.
 */
export function lifecycleWorld(change?: (s: State) => void): State {
  const s = kbFixture(now);
  const admin = (id: string, roles: string[], tenant = 'acme') => { s.actors[id] = { id, tenant, kind: 'user', roles, projects: [], clearance: 'restricted', active: true }; };
  admin('sec', ['security-admin']); admin('kbadm', ['kb-admin']); admin('aud', ['auditor']); admin('other-sec', ['security-admin', 'auditor'], 'other');
  for (const k of [derived('d1', ['handbook']), derived('d2', ['d1']), derived('a', ['handbook']), derived('b', ['handbook']), derived('c', ['a', 'b'])]) s.knowledge[k.id] = k;
  s.knowledge['o-doc'] = { ...structuredClone(s.knowledge.handbook!), id: 'o-doc', tenant: 'other', content: 'Other tenant synthetic notes.' };
  change?.(s); return s;
}
export const LINEAGE = ['a', 'b', 'c', 'd1', 'd2'];
