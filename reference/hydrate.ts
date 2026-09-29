import { DESTINATION_CLASSES } from './types.ts';
import type { Binding, Need, Tx } from './types.ts';
import { validId } from './validation.ts';

export type Seed = {
  bindings?: Binding[]; actors?: string[]; grants?: string[]; knowledge?: string[];
  containers?: string[]; roles?: string[]; contexts?: string[]; groups?: string[];
  /** Destination profiles by id (0.4); the profiles of loaded actors are added automatically. */
  destinations?: string[];
  /** Every active principal of the tenant with its memberships and roles (bounded; administrative holder checks). */
  principals?: boolean;
  /** Every runtime profile policy of the tenant (0.5; bounded). */
  runtimeProfiles?: boolean;
  /** The Destination profiles named by id in the bindings' run restriction (0.5: share/export of unknown destination). */
  grantDestinations?: boolean;
};
/** Hydration budgets. Anything not loaded within them stays missing, and missing denies. */
export const HYDRATION = { rounds: 16, records: 8192 } as const;
/**
 * A load could not be completed within its published bound. Stores MUST throw it
 * instead of returning a truncated closure; callers turn it into a deferred
 * denial (`DEFERRED:BUDGET_EXCEEDED`), never into a decision over partial data.
 */
export class BudgetExceeded extends Error {
  constructor(what: string) { super(`AKAC ${what} budget exceeded`); this.name = 'BudgetExceeded'; }
}
const list = (x: unknown): unknown[] => Array.isArray(x) ? x : [];

/**
 * Loads the authorization closure a decision can reach: grant ancestry and its
 * principals, group memberships, role hierarchy, knowledge sources, container
 * ancestry, run contexts, SoD constraints, destination profiles of loaded
 * principals, the tenant epoch and audit head, and (on request) the tenant's
 * runtime profile policies.
 * decide() stays pure and synchronous over the resulting snapshot. Roles of
 * inactive groups and juniors of inactive roles are not requested: they never
 * contribute to a closure (R22, R23), and requesting them would only let
 * deprovisioned records exhaust the budget.
 *
 * An id is marked as asked only after `tx.load` returned, and stores never
 * truncate (they throw BudgetExceeded), so every asked id was really fetched.
 */
export async function hydrate(tx: Tx, seed: Seed): Promise<void> {
  if (tx.complete) return;
  const kinds = ['actors', 'grants', 'knowledge', 'containers', 'roles', 'memberships', 'contexts', 'groups', 'destinations'] as const;
  const asked = Object.fromEntries(kinds.map(k => [k, new Set<string>()])) as Record<typeof kinds[number], Set<string>>;
  let total = 0;
  for (let round = 0; round < HYDRATION.rounds; round++) {
    const s = tx.state;
    const want = Object.fromEntries(kinds.map(k => [k, new Set<string>()])) as Record<typeof kinds[number], Set<string>>;
    const add = (kind: typeof kinds[number], id: unknown) => { if (validId(id) && !asked[kind].has(id)) want[kind].add(id); };
    for (const kind of ['actors', 'grants', 'knowledge', 'containers', 'roles', 'contexts', 'groups', 'destinations'] as const) for (const id of seed[kind] ?? []) add(kind, id);
    for (const b of seed.bindings ?? []) {
      add('actors', b.subject); add('actors', b.agent); add('grants', b.grant);
      if (seed.grantDestinations && Object.hasOwn(s.grants, b.grant)) for (const d of list(s.grants[b.grant]?.destinations)) if (!(DESTINATION_CLASSES as readonly unknown[]).includes(d)) add('destinations', d);
    }
    for (const c of Object.values(s.contexts)) for (const ref of list(c.sources)) add('knowledge', (ref as { id?: unknown })?.id);
    for (const g of Object.values(s.grants)) { add('actors', g.subject); add('actors', g.agent); add('grants', g.parent); }
    for (const k of Object.values(s.knowledge)) {
      for (const ref of list(k.sources)) add('knowledge', (ref as { id?: unknown })?.id);
      add('containers', k.container);
    }
    for (const c of Object.values(s.containers)) add('containers', c.parent);
    for (const a of Object.values(s.actors)) { add('memberships', a.id); add('destinations', a.destination); for (const r of list(a.roles)) add('roles', r); }
    for (const g of Object.values(s.groups)) if (g.active !== false) for (const r of list(g.roles)) add('roles', r);
    for (const r of Object.values(s.roles)) if (r.active !== false) for (const j of list(r.inherits)) add('roles', j);
    const need: Need = {};
    for (const kind of kinds) if (want[kind].size) { need[kind] = [...want[kind]]; total += want[kind].size; }
    if (round === 0) Object.assign(need, { constraints: true, epoch: true, audit: true, bindings: seed.bindings ?? [], ...(seed.principals ? { principals: true } : {}),
      ...(seed.runtimeProfiles ? { runtimeProfiles: true } : {}) });
    if (!Object.keys(need).length) return;
    // An unloaded role or membership could be mistaken for a flat role or a missing
    // restriction, so an incomplete closure aborts the transaction instead.
    if (total > HYDRATION.records) throw new BudgetExceeded('hydration');
    await tx.load(need);
    for (const kind of kinds) for (const id of want[kind]) asked[kind].add(id);
  }
  throw new BudgetExceeded('hydration round');
}
