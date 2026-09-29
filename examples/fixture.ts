import { readFileSync } from 'node:fs';
import { emptyState } from '../reference/types.ts';
import type { Binding, State } from '../reference/types.ts';

/**
 * The synthetic company of the conformance vectors, loaded from the language-neutral
 * fixture examples/fixture.json (schema: schemas/fixture.json, ADR-014). Any
 * implementation reproduces it without this file: start from an empty state, merge
 * the records of the fixture it extends and then its own, and add the clock to every
 * clock-relative field.
 */
export type FixtureName = 'fixture' | 'kbFixture';
type Collection = 'actors' | 'grants' | 'knowledge' | 'contexts' | 'roles' | 'groups' | 'containers' | 'constraints' | 'destinations' | 'runtimeProfiles';
export type FixtureFile = {
  format: 'akac-fixture/1'; description: string;
  clockRelative: [Collection, string][];
  bindings: Record<'intern' | 'chief' | 'lead', Binding>;
  fixtures: Record<FixtureName, { description?: string; extends?: FixtureName; records: Partial<Record<Collection, Record<string, unknown>>> }>;
};
export const FIXTURE_URL = new URL('./fixture.json', import.meta.url);
const data = JSON.parse(readFileSync(FIXTURE_URL, 'utf8')) as FixtureFile;
if (data.format !== 'akac-fixture/1') throw new Error('Unsupported fixture format');
/** The parsed fixture file (a copy: callers may not change the shared source). */
export const fixtureData = (): FixtureFile => structuredClone(data);

export const bindings: Record<'intern' | 'chief' | 'lead', Binding> = structuredClone(data.bindings);

/** A fresh state of the named fixture at clock `now`. */
export function loadFixture(name: FixtureName, now: number): State {
  const s = emptyState();
  const chain: FixtureName[] = [];
  for (let n: FixtureName | undefined = name; n !== undefined; n = data.fixtures[n]?.extends) {
    if (chain.includes(n) || !data.fixtures[n]) throw new Error('Invalid fixture chain');
    chain.unshift(n);
  }
  const collections = s as unknown as Record<Collection, Record<string, unknown>>;
  for (const n of chain) {
    for (const [collection, records] of Object.entries(data.fixtures[n]!.records) as [Collection, Record<string, unknown>][]) {
      if (!collections[collection] || typeof collections[collection] !== 'object') throw new Error('Invalid fixture collection');
      for (const [id, record] of Object.entries(records)) collections[collection][id] = structuredClone(record);
    }
  }
  for (const [collection, field] of data.clockRelative) {
    for (const record of Object.values(collections[collection] ?? {}) as Record<string, number>[]) {
      if (Object.hasOwn(record, field)) record[field] = now + record[field]!;
    }
  }
  return s;
}
export function fixture(now = Date.now()): State { return loadFixture('fixture', now); }
/**
 * Fixture for the AKAC-KB/0.3 profile: a role hierarchy, an (inactive) group,
 * separation-of-duty constraints and a knowledge base with nested folders.
 * Base decisions of fixture() are unchanged.
 */
export function kbFixture(now = Date.now()): State { return loadFixture('kbFixture', now); }
