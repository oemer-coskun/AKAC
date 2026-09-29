"""RFC 9162 section 2.1 Merkle tree (SHA-256), inclusion and consistency proofs and their verification."""
import hashlib
import re

from .js import safe_number

_HEX = re.compile(r"[a-f0-9]{64}")


def _sha(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.hexdigest()


def is_hash(x):
    return isinstance(x, str) and _HEX.fullmatch(x) is not None


EMPTY_ROOT = _sha()


def leaf_hash(data):
    return _sha(b"\x00", bytes(data))


def node_hash(left, right):
    return _sha(b"\x01", bytes.fromhex(left), bytes.fromhex(right))


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _power(n):
    return n >= 1 and _split(n + 1) == n


def root_of(leaves, start=0, end=None):
    end = len(leaves) if end is None else end
    n = end - start
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaves[start]
    k = _split(n)
    return node_hash(root_of(leaves, start, start + k), root_of(leaves, start + k, end))


def inclusion_ranges(m, n):
    if not safe_number(m) or not safe_number(n) or m >= n:
        raise ValueError("leaf index outside tree")

    def path(i, s, e):
        if e - s == 1:
            return []
        k = _split(e - s)
        return path(i, s, s + k) + [(s + k, e)] if i < k else path(i - k, s + k, e) + [(s, s + k)]
    return path(m, 0, n)


def consistency_ranges(m, n):
    if not safe_number(m) or not safe_number(n) or m < 1 or m > n:
        raise ValueError("invalid tree sizes")

    def sub(i, s, e, complete):
        if i == e - s:
            return [] if complete else [(s, e)]
        k = _split(e - s)
        return sub(i, s, s + k, complete) + [(s + k, e)] if i <= k else sub(i - k, s + k, e, False) + [(s, s + k)]
    return sub(m, 0, n, True)


def range_hash(leaves, rng):
    """MTH of the leaf range [s, e)."""
    return root_of(leaves, rng[0], rng[1])


def inclusion_proof(leaves, m, n):
    return [range_hash(leaves, r) for r in inclusion_ranges(m, n)]


def consistency_proof(leaves, m, n):
    return [range_hash(leaves, r) for r in consistency_ranges(m, n)]


def verify_inclusion(leaf, index, tree_size, path, root):
    """RFC 9162 section 2.1.3.2."""
    if (not is_hash(leaf) or not is_hash(root) or not safe_number(index) or not safe_number(tree_size) or index >= tree_size
            or not isinstance(path, list) or len(path) > 64 or not all(is_hash(p) for p in path)):
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            r = node_hash(r, p)
        fn //= 2
        sn //= 2
    return sn == 0 and r == root


def verify_consistency(first, second, first_root, second_root, path):
    """RFC 9162 section 2.1.4.2."""
    if (not safe_number(first) or not safe_number(second) or first > second or not is_hash(first_root) or not is_hash(second_root)
            or not isinstance(path, list) or len(path) > 64 or not all(is_hash(p) for p in path)):
        return False
    if first == 0:
        return len(path) == 0 and first_root == EMPTY_ROOT
    if first == second:
        return len(path) == 0 and first_root == second_root
    if not path:
        return False
    proof = [first_root] + list(path) if _power(first) else list(path)
    fn, sn = first - 1, second - 1
    while fn % 2 == 1:
        fn //= 2
        sn //= 2
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            sr = node_hash(sr, c)
        fn //= 2
        sn //= 2
    return fr == first_root and sr == second_root and sn == 0
