import type { Audit, Store } from './types.ts';
import { auditLeaf } from './audit.ts';
import { consistencyRanges, inclusionRanges, keyOf, leafLookup, perfectKeys, rangeHash, rootKeys, treeRoot } from './merkle.ts';
import type { NodeKey, Range } from './merkle.ts';
import { validId } from './validation.ts';

/** Signed-tree-head content before signing: the tenant stream, its size and RFC 9162 root. */
export type TreeHead = { stream: string; treeSize: number; rootHash: string };
/** RFC 9162 §2.1.3 inclusion proof of the entry with sequence `leafIndex + 1`. */
export type InclusionProof = { stream: string; leafIndex: number; treeSize: number; leafHash: string; rootHash: string; path: string[] };
/** RFC 9162 §2.1.4 consistency proof between two sizes of one stream. */
export type ConsistencyProof = { stream: string; first: number; second: number; firstRoot: string; secondRoot: string; path: string[] };

/** Leaf hashes of a complete in-memory stream (reference stores; O(n)). */
export function treeFromEntries(entries: readonly Audit[], keys: readonly NodeKey[]): { size: number; hashes: string[] } {
  const lookup = leafLookup(entries.map(auditLeaf));
  return { size: entries.length, hashes: keys.map(lookup) };
}
/** Store-backed tree read; stores without `auditTree` are read in full through auditLog (O(n)). */
async function nodes(store: Store, tenant: string, keys: NodeKey[]): Promise<{ size: number; lookup: (k: NodeKey) => string }> {
  let found: { size: number; hashes: string[] };
  if (store.auditTree) found = await store.auditTree(tenant, keys);
  else {
    const entries: Audit[] = [];
    for (let after = 0; ;) {
      const page = await store.auditLog(tenant, after, 10_000);
      entries.push(...page);
      if (page.length < 10_000) break;
      after = page.at(-1)!.sequence;
    }
    found = treeFromEntries(entries, keys);
  }
  if (!found || found.hashes.length !== keys.length) throw new Error('Incomplete audit tree read');
  const map = new Map(keys.map((k, i) => [keyOf(k), found.hashes[i]!]));
  return { size: found.size, lookup: k => { const h = map.get(keyOf(k)); if (!h) throw new Error('Missing audit tree node'); return h; } };
}
const unique = (keys: NodeKey[]) => [...new Map(keys.map(k => [keyOf(k), k])).values()];
const keysOf = (ranges: Range[]) => ranges.flatMap(perfectKeys);

/**
 * Current tree head. Perfect subtrees never change once complete, so reading the
 * size and then the root nodes of that size is consistent even under appends.
 */
export async function treeHead(store: Store, tenant: string): Promise<TreeHead> {
  if (!validId(tenant)) throw new Error('Invalid tenant');
  const { size } = await nodes(store, tenant, []);
  const keys = rootKeys(size);
  const { lookup } = await nodes(store, tenant, keys);
  return { stream: tenant, treeSize: size, rootHash: treeRoot(lookup, size) };
}
/** Cost: O(log n) perfect-subtree reads (one store round trip) and O(log n) hashing. */
export async function inclusionProof(store: Store, tenant: string, leafIndex: number, treeSize: number): Promise<InclusionProof> {
  const ranges = inclusionRanges(leafIndex, treeSize);
  const keys = unique([{ level: 0, index: leafIndex }, ...keysOf(ranges), ...rootKeys(treeSize)]);
  const { size, lookup } = await nodes(store, tenant, keys);
  if (treeSize > size) throw new RangeError('tree size beyond stream');
  return { stream: tenant, leafIndex, treeSize, leafHash: lookup({ level: 0, index: leafIndex }), rootHash: treeRoot(lookup, treeSize),
    path: ranges.map(r => rangeHash(lookup, r)) };
}
/** Cost: O(log^2 n) perfect-subtree reads in one round trip. */
export async function consistencyProof(store: Store, tenant: string, first: number, second: number): Promise<ConsistencyProof> {
  const ranges = consistencyRanges(first, second);
  const keys = unique([...keysOf(ranges), ...rootKeys(first), ...rootKeys(second)]);
  const { size, lookup } = await nodes(store, tenant, keys);
  if (second > size) throw new RangeError('tree size beyond stream');
  return { stream: tenant, first, second, firstRoot: treeRoot(lookup, first), secondRoot: treeRoot(lookup, second),
    path: ranges.map(r => rangeHash(lookup, r)) };
}
