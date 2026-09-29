import { createHash } from 'node:crypto';
/**
 * RFC 9162 §2.1 Merkle tree (SHA-256): leaf = H(0x00 || data), interior node =
 * H(0x01 || left || right), MTH of n > 1 leaves splits at k, the largest power of
 * two smaller than n. Hashes are lowercase hex. Leaf indexes are 0-based.
 *
 * A perfect subtree (level, index) covers leaves [index * 2^level, (index + 1) * 2^level).
 * Every range the RFC 9162 proof algorithms need decomposes into O(log n) perfect
 * subtrees, and a perfect subtree never changes once complete, so stores can keep
 * them and answer proofs in O(log^2 n) lookups without re-reading entries.
 */
export type NodeKey = { level: number; index: number };
export type Range = [start: number, end: number];
const HEX = /^[a-f0-9]{64}$/;
const sha = (...parts: Uint8Array[]) => createHash('sha256').update(Buffer.concat(parts)).digest('hex');
export const isHash = (x: unknown): x is string => typeof x === 'string' && HEX.test(x);
/** MTH({}) = SHA-256 of the empty string. */
export const EMPTY_ROOT = sha();
export const leafHash = (data: Uint8Array): string => sha(Buffer.of(0), data);
export const nodeHash = (left: string, right: string): string => sha(Buffer.of(1), Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
export const keyOf = (k: NodeKey) => `${k.level}:${k.index}`;
const size = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;
/** Largest power of two strictly smaller than n (n >= 2). Plain arithmetic: indexes exceed 32 bits. */
function split(n: number): number { let k = 1; while (k * 2 < n) k *= 2; return k; }
const power = (n: number) => n >= 1 && split(n + 1) === n;
const odd = (n: number) => n % 2 === 1;
const half = (n: number) => Math.floor(n / 2);

/** Naive RFC 9162 MTH over leaf hashes (reference and fallback; O(n)). */
export function rootOf(leaves: readonly string[], start = 0, end = leaves.length): string {
  const n = end - start;
  if (n === 0) return EMPTY_ROOT;
  if (n === 1) return leaves[start]!;
  const k = split(n);
  return nodeHash(rootOf(leaves, start, start + k), rootOf(leaves, start + k, end));
}
/** RFC 9162 §2.1.3.1 PATH(m, D[n]) as the ranges whose MTH forms the audit path, in order. */
export function inclusionRanges(m: number, n: number): Range[] {
  if (!size(m) || !size(n) || m >= n) throw new RangeError('leaf index outside tree');
  const path = (i: number, s: number, e: number): Range[] => {
    if (e - s === 1) return [];
    const k = split(e - s);
    return i < k ? [...path(i, s, s + k), [s + k, e]] : [...path(i - k, s + k, e), [s, s + k]];
  };
  return path(m, 0, n);
}
/** RFC 9162 §2.1.4.1 PROOF(m, D[n]) as ranges, for 1 <= m <= n (m = n: empty proof). */
export function consistencyRanges(m: number, n: number): Range[] {
  if (!size(m) || !size(n) || m < 1 || m > n) throw new RangeError('invalid tree sizes');
  const sub = (i: number, s: number, e: number, complete: boolean): Range[] => {
    if (i === e - s) return complete ? [] : [[s, e]];
    const k = split(e - s);
    return i <= k ? [...sub(i, s, s + k, complete), [s + k, e]] : [...sub(i - k, s + k, e, false), [s, s + k]];
  };
  return sub(m, 0, n, true);
}
/** Perfect subtrees of a range the RFC recursion produces (its start is aligned to its split). */
export function perfectKeys([s, e]: Range): NodeKey[] {
  const n = e - s;
  if (!size(s) || !size(e) || n < 1) throw new RangeError('empty range');
  if (power(n)) {
    if (s % n !== 0) throw new RangeError('unaligned range');
    return [{ level: Math.round(Math.log2(n)), index: s / n }];
  }
  const k = split(n);
  return [...perfectKeys([s, s + k]), ...perfectKeys([s + k, e])];
}
/** MTH of a range from perfect-subtree hashes (the same recursion as perfectKeys). */
export function rangeHash(lookup: (key: NodeKey) => string, [s, e]: Range): string {
  const n = e - s;
  if (power(n)) return lookup(perfectKeys([s, e])[0]!);
  const k = split(n);
  return nodeHash(rangeHash(lookup, [s, s + k]), rangeHash(lookup, [s + k, e]));
}
/** Keys needed for the root of a tree of n leaves (its compact range, at most one per level). */
export const rootKeys = (n: number): NodeKey[] => n === 0 ? [] : perfectKeys([0, n]);
export const treeRoot = (lookup: (key: NodeKey) => string, n: number): string => n === 0 ? EMPTY_ROOT : rangeHash(lookup, [0, n]);

/**
 * Incremental append over the compact range (frontier) of a tree: at most one
 * perfect subtree per level. Appending a leaf returns every perfect subtree it
 * completes (O(log n)), which a store persists next to the leaf.
 */
export class Frontier {
  private nodes: Map<number, string>;
  private count: number;
  /** `nodes`: level -> hash of the frontier of a tree of `count` leaves (rootKeys(count)). */
  constructor(count = 0, nodes: Map<number, string> = new Map()) {
    const expected = rootKeys(count);
    if (!size(count) || expected.length !== nodes.size || expected.some(k => !isHash(nodes.get(k.level)))) throw new Error('Inconsistent Merkle frontier');
    this.count = count; this.nodes = new Map(nodes);
  }
  get size() { return this.count; }
  append(leaf: string): (NodeKey & { hash: string })[] {
    if (!isHash(leaf)) throw new Error('Invalid leaf hash');
    let hash = leaf, level = 0, index = this.count;
    const created = [{ level, index, hash }];
    while (odd(index)) {
      hash = nodeHash(this.nodes.get(level)!, hash);
      this.nodes.delete(level); level++; index = half(index);
      created.push({ level, index, hash });
    }
    this.nodes.set(level, hash); this.count++;
    return created;
  }
  root(): string {
    let root: string | undefined;
    for (const level of [...this.nodes.keys()].sort((a, b) => a - b)) root = root === undefined ? this.nodes.get(level)! : nodeHash(this.nodes.get(level)!, root);
    return root ?? EMPTY_ROOT;
  }
}
/** Perfect-subtree lookup over an in-memory leaf list (memoized; O(n) total). */
export function leafLookup(leaves: readonly string[]): (key: NodeKey) => string {
  const memo = new Map<string, string>();
  const get = (k: NodeKey): string => {
    const width = 2 ** k.level, start = k.index * width;
    if (!size(start) || start + width > leaves.length) throw new RangeError('node outside tree');
    if (k.level === 0) return leaves[k.index]!;
    const id = keyOf(k); let h = memo.get(id);
    if (!h) { h = nodeHash(get({ level: k.level - 1, index: k.index * 2 }), get({ level: k.level - 1, index: k.index * 2 + 1 })); memo.set(id, h); }
    return h;
  };
  return get;
}

/** RFC 9162 §2.1.3.2: verify an inclusion proof for `leaf` at `index` in a tree of `treeSize` with `root`. */
export function verifyInclusion(leaf: string, index: number, treeSize: number, path: readonly string[], root: string): boolean {
  if (!isHash(leaf) || !isHash(root) || !size(index) || !size(treeSize) || index >= treeSize
    || !Array.isArray(path) || path.length > 64 || !path.every(isHash)) return false;
  let fn = index, sn = treeSize - 1, r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      r = nodeHash(p, r);
      if (!odd(fn)) while (!odd(fn) && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else r = nodeHash(r, p);
    fn = half(fn); sn = half(sn);
  }
  return sn === 0 && r === root;
}
/** RFC 9162 §2.1.4.2: verify that the tree of `second` leaves extends the tree of `first` leaves. */
export function verifyConsistency(first: number, second: number, firstRoot: string, secondRoot: string, path: readonly string[]): boolean {
  if (!size(first) || !size(second) || first > second || !isHash(firstRoot) || !isHash(secondRoot)
    || !Array.isArray(path) || path.length > 64 || !path.every(isHash)) return false;
  if (first === 0) return path.length === 0 && firstRoot === EMPTY_ROOT;
  if (first === second) return path.length === 0 && firstRoot === secondRoot;
  if (!path.length) return false;
  const proof = power(first) ? [firstRoot, ...path] : [...path];
  let fn = first - 1, sn = second - 1;
  while (odd(fn)) { fn = half(fn); sn = half(sn); }
  let fr = proof[0]!, sr = proof[0]!;
  for (const c of proof.slice(1)) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      if (!odd(fn)) while (!odd(fn) && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else sr = nodeHash(sr, c);
    fn = half(fn); sn = half(sn);
  }
  return fr === firstRoot && sr === secondRoot && sn === 0;
}
