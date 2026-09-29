import type { State } from '../reference/types.ts';
/**
 * Patch entries: [collection, id, field, value] sets a field (existing, or one
 * of the optional fields below); [collection, id, record] inserts or replaces a
 * whole record; ['epochs', tenant, n] sets a tenant epoch.
 */
export type Patch = [string, string, string, unknown] | [string, string, unknown];
const OPTIONAL = ['container', 'activeRoles', 'parent', 'accessExpiresAt', 'lifecycle', 'lifecycleAt', 'quarantineReason', 'retainUntil', 'legalHolds', 'revokedAt',
  // Destination profiles (0.4, ADR-008).
  'destination', 'destinations', 'maxResults'];
export function apply(state: State, patch: Patch[]) {
  for (const entry of patch) {
    const collections = state as unknown as Record<string, Record<string, unknown>>;
    if (entry.length === 3) {
      const [collection, id, value] = entry;
      if (!collections[collection] || typeof collections[collection] !== 'object' || Array.isArray(collections[collection])) throw new Error('Invalid trusted test vector');
      collections[collection]![id] = structuredClone(value); continue;
    }
    const [collection, id, field, value] = entry;
    const target = collections[collection]?.[id] as Record<string, unknown> | undefined;
    if (!target || (!Object.hasOwn(target, field) && !OPTIONAL.includes(field))) throw new Error('Invalid trusted test vector');
    target[field] = structuredClone(value);
  }
}
