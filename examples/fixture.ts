import { emptyState } from '../reference/types.ts';
import type { Actor, Binding, Grant, Knowledge, State } from '../reference/types.ts';

export const bindings: Record<'intern' | 'chief' | 'lead', Binding> = {
  intern: { tenant: 'acme', subject: 'intern', agent: 'intern-agent', grant: 'intern-run' },
  chief: { tenant: 'acme', subject: 'chief', agent: 'chief-agent', grant: 'chief-run' },
  lead: { tenant: 'acme', subject: 'lead', agent: 'lead-agent', grant: 'lead-run' }
};
export function fixture(now = Date.now()): State {
  const s = emptyState();
  const addActor = (id: string, roles: string[], clearance: Actor['clearance'], projects: string[] = [], tenant = 'acme') => {
    s.actors[id] = { id, tenant, kind: id.endsWith('-agent') ? 'agent' : 'user', roles, clearance, projects, active: true };
  };
  addActor('intern', ['staff'], 'internal'); addActor('intern-agent', ['staff'], 'internal');
  addActor('chief', ['staff', 'executive'], 'restricted', ['alpha']); addActor('chief-agent', ['staff', 'executive'], 'restricted', ['alpha']);
  addActor('lead', ['staff', 'project'], 'confidential', ['alpha']); addActor('lead-agent', ['staff', 'project'], 'confidential', ['alpha']);
  addActor('admin', ['security-admin'], 'restricted'); addActor('outsider', ['staff', 'executive'], 'restricted', ['alpha'], 'other');
  for (const b of Object.values(bindings)) {
    const g: Grant = { id: b.grant, tenant: b.tenant, subject: b.subject, agent: b.agent,
      actions: ['read', 'derive', 'write_memory', 'share', 'export'], resources: ['*'], purposes: ['work'],
      notBefore: now - 1000, expiresAt: now + 3_600_000, active: true };
    s.grants[g.id] = g;
  }
  const add = (id: string, content: string, classification: Knowledge['classification'], readerRoles: string[], projects: string[] = []) => {
    s.knowledge[id] = { id, tenant: 'acme', version: 1, kind: 'document', content, classification, readerRoles, projects, readers: [], sources: [], active: true };
  };
  add('handbook', 'Product handbook: our public product is a notebook.', 'public', ['staff']);
  add('strategy', 'Product acquisition strategy: confidential purchase budget is 900000.', 'restricted', ['executive']);
  add('project-alpha', 'Product project alpha schedule: launch in November.', 'confidential', ['project', 'executive'], ['alpha']);
  return s;
}
