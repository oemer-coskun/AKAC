// Synthetic world for the destination profile tests (0.4, ADR-008).
import { fixture } from '../examples/fixture.ts';
import type { Destination, State } from '../reference/types.ts';

export const now = 1_800_000_000_000;
export const destination = (id: string, cls: Destination['class'], maxClassification: Destination['maxClassification'], purposes = ['work'], tenant = 'acme'): Destination =>
  ({ id, tenant, class: cls, maxClassification, purposes, active: true });
/**
 * fixture() plus: a model-provider profile `eu-llm` (up to confidential, purpose
 * work), a tool profile `crm-tool` (up to internal), provider principal `llm` and
 * tool principal `crm` (fully cleared, so only the profile can deny), a service
 * `legacy-svc` without a profile, a security-admin `sec`, and a permissive profile
 * `other-dest` of tenant `other` that the acme service `xt` references.
 */
export function destinationWorld(edit?: (s: State) => void): State {
  const s = fixture(now);
  s.destinations = {
    'eu-llm': destination('eu-llm', 'model-provider', 'confidential'),
    'crm-tool': destination('crm-tool', 'tool', 'internal'),
    'other-dest': destination('other-dest', 'internal-service', 'restricted', ['work'], 'other')
  };
  const service = (id: string, dest?: string, tenant = 'acme') => {
    s.actors[id] = { id, tenant, kind: 'service', roles: ['staff', 'executive', 'project'], projects: ['alpha'], clearance: 'restricted', active: true, ...(dest ? { destination: dest } : {}) };
  };
  service('llm', 'eu-llm'); service('crm', 'crm-tool'); service('legacy-svc'); service('xt', 'other-dest');
  s.actors.sec = { id: 'sec', tenant: 'acme', kind: 'user', roles: ['security-admin'], projects: [], clearance: 'restricted', active: true };
  s.actors['other-sec'] = { id: 'other-sec', tenant: 'other', kind: 'user', roles: ['security-admin'], projects: [], clearance: 'restricted', active: true };
  edit?.(s);
  return s;
}
