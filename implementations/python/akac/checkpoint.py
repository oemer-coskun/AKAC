"""Format 2 audit checkpoint verification (Ed25519 over the JCS form, RFC 9162 roots).

Signature verification needs the optional `cryptography` package
(`pip install "akac[crypto]"`). Without it, `available()` is False and
`verify_checkpoint_v2` raises CryptoUnavailable: a verifier never reports a
signature as valid that it could not check.
"""
import base64
import re

from .audit import audit_leaf, verify_audit
from .jcs import canonical_bytes
from .merkle import is_hash, root_of, verify_consistency
from .validation import exact_keys, safe_number, safe_text

try:  # optional dependency
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except ImportError:  # pragma: no cover - exercised when the extra is absent
    Ed25519PublicKey = None

_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}")


class CryptoUnavailable(RuntimeError):
    """The optional `cryptography` dependency is not installed."""


def available():
    return Ed25519PublicKey is not None


def _b64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def public_key(key):
    """An Ed25519 public key from a JWK dict (kty OKP, crv Ed25519) or an SPKI PEM string; None for any other key."""
    if not available():
        raise CryptoUnavailable("install the 'crypto' extra (cryptography) to verify checkpoint signatures")
    try:
        if isinstance(key, dict):
            if key.get("kty") != "OKP" or key.get("crv") != "Ed25519" or not isinstance(key.get("x"), str):
                return None
            raw = _b64url(key["x"])
            return Ed25519PublicKey.from_public_bytes(raw) if len(raw) == 32 else None
        loaded = load_pem_public_key(key.encode("ascii") if isinstance(key, str) else key)
        return loaded if isinstance(loaded, Ed25519PublicKey) else None
    except (ValueError, TypeError):
        return None


def _unsigned(r):
    return canonical_bytes({"format": r["format"], "stream": r["stream"], "treeSize": r["treeSize"], "rootHash": r["rootHash"],
                            "issuedAt": r["issuedAt"], "keyId": r["keyId"]})


def verify_checkpoint_v2(record, key, expected_stream, expected_key_id, entries=None, minimum_size=None):
    """Closed shape, expected stream and key, Ed25519 signature, no rollback below `minimum_size`, optional root check."""
    pk = public_key(key)
    try:
        minimum = 0 if minimum_size is None else minimum_size
        if (not exact_keys(record, ["format", "stream", "treeSize", "rootHash", "issuedAt", "keyId", "signature"])
                or record["format"] != "akac-audit-checkpoint/2" or record["stream"] != expected_stream or record["keyId"] != expected_key_id
                or not safe_text(record["stream"], 128) or not safe_text(record["keyId"], 128) or not safe_number(record["treeSize"])
                or not safe_number(record["issuedAt"]) or not safe_number(minimum) or record["treeSize"] < minimum or not is_hash(record["rootHash"])
                or not isinstance(record["signature"], str) or _SIGNATURE.fullmatch(record["signature"]) is None):
            return False
        if pk is None:
            return False
        try:
            pk.verify(_b64url(record["signature"]), _unsigned(record))
        except InvalidSignature:
            return False
        if entries is None:
            return True
        return (verify_audit(entries) and all(e.get("tenant") == entries[0].get("tenant") for e in entries) and len(entries) >= record["treeSize"]
                and (not entries or entries[0].get("tenant") == expected_stream)
                and root_of([audit_leaf(e) for e in entries[:record["treeSize"]]]) == record["rootHash"])
    except (ValueError, TypeError, KeyError):
        return False


def verify_checkpoint_extension(older, newer, path):
    """Append-only check between two verified format 2 checkpoints of one stream (RFC 9162 consistency)."""
    return (older.get("stream") == newer.get("stream") and older.get("format") == "akac-audit-checkpoint/2"
            and newer.get("format") == "akac-audit-checkpoint/2"
            and verify_consistency(older.get("treeSize"), newer.get("treeSize"), older.get("rootHash"), newer.get("rootHash"), path))


# ---------------------------------------------------------------------------------------------------------------------
# Format 3 (0.6, ADR-021): format 2 content plus `alg`; registered algorithms; hybrid = both signatures must verify.
# Verification of algorithms the installed `cryptography` provides: Ed25519 always; ML-DSA-44/65/87 when the package ships
# `mldsa` (the hybrid needs Ed25519 + ML-DSA-65). SLH-DSA is not provided by `cryptography`: those vectors are
# NOT_APPLICABLE here (AlgorithmUnavailable), never a pass. A verifier that cannot check a signature never accepts it.
# ---------------------------------------------------------------------------------------------------------------------
try:  # optional, newer cryptography releases only
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
except ImportError:  # pragma: no cover - depends on the installed cryptography
    _mldsa = None

# id -> (kind, component key types in signature order, component signature lengths)
ALGORITHMS = {
    "ed25519": ("classical", ("ed25519",), (64,)),
    "ml-dsa-44": ("pq", ("ml-dsa-44",), (2420,)),
    "ml-dsa-65": ("pq", ("ml-dsa-65",), (3309,)),
    "ml-dsa-87": ("pq", ("ml-dsa-87",), (4627,)),
    "slh-dsa-sha2-128s": ("pq", ("slh-dsa-sha2-128s",), (7856,)),
    "slh-dsa-sha2-256s": ("pq", ("slh-dsa-sha2-256s",), (29792,)),
    "ed25519+ml-dsa-65": ("hybrid", ("ed25519", "ml-dsa-65"), (64, 3309)),
}
_PEM = re.compile(r"-----BEGIN ([A-Z ]+)-----[A-Za-z0-9+/=\s]+?-----END \1-----")
_KEY_ID = re.compile(r"[A-Za-z0-9._:+-]{1,128}")


class AlgorithmUnavailable(RuntimeError):
    """The algorithm is registered but the installed `cryptography` cannot verify it: not applicable, never a pass."""


def _component_class(name):
    if Ed25519PublicKey is None:
        return None
    if name == "ed25519":
        return Ed25519PublicKey
    if name.startswith("ml-dsa-") and _mldsa is not None:
        return {"ml-dsa-44": _mldsa.MLDSA44PublicKey, "ml-dsa-65": _mldsa.MLDSA65PublicKey, "ml-dsa-87": _mldsa.MLDSA87PublicKey}[name]
    return None


def supported_algorithms():
    """Registered algorithms this installation can verify."""
    return [a for a, (_k, comps, _l) in ALGORITHMS.items() if all(_component_class(c) is not None for c in comps)]


def parse_policy(value):
    """{algorithms: [...], allowClassicalAfterPq?: bool} or ValueError. None allows every registered algorithm (and no classical after PQ)."""
    if value is None:
        return {"algorithms": list(ALGORITHMS), "allowClassicalAfterPq": False}
    if (not exact_keys(value, ["algorithms"], ["allowClassicalAfterPq"]) or not isinstance(value["algorithms"], list) or not value["algorithms"]
            or not all(isinstance(a, str) and a in ALGORITHMS for a in value["algorithms"])
            or not isinstance(value.get("allowClassicalAfterPq", False), bool)):
        raise ValueError("invalid verifier policy")
    return {"algorithms": list(dict.fromkeys(value["algorithms"])), "allowClassicalAfterPq": value.get("allowClassicalAfterPq", False)}


def _v3_public_keys(alg, pem):
    """Public key objects of `alg` from PEM text (hybrid: Ed25519 block then ML-DSA-65 block), or None when the material does not match."""
    if not isinstance(pem, str) or len(pem) > 16384:
        return None
    found = [m.group(0) for m in _PEM.finditer(pem)]
    comps = ALGORITHMS[alg][1]
    if len(found) != len(comps) or any(not b.startswith("-----BEGIN PUBLIC KEY-----") for b in found):
        return None
    keys = []
    for block, name in zip(found, comps):
        cls = _component_class(name)
        try:
            loaded = load_pem_public_key(block.encode("ascii"))
        except Exception:  # noqa: BLE001 - unsupported key types raise varied errors
            return None
        if cls is None or not isinstance(loaded, cls):
            return None
        keys.append(loaded)
    return keys


def _unsigned_v3(r):
    return canonical_bytes({"format": r["format"], "alg": r["alg"], "stream": r["stream"], "treeSize": r["treeSize"], "rootHash": r["rootHash"],
                            "issuedAt": r["issuedAt"], "keyId": r["keyId"]})


def _decode_signature_v3(alg, text):
    if not isinstance(text, str) or len(text) > 40000 or re.fullmatch(r"[A-Za-z0-9_-]+", text) is None:
        return None
    raw = _b64url(text)
    if len(raw) != sum(ALGORITHMS[alg][2]) or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != text:
        return None
    return raw


def verify_checkpoint_v3(record, key, expected_stream, expected_key_id, entries=None, minimum_size=None, policy=None):
    """Closed shape, registered and allowed algorithm, key id `<alg>:<label>`, every component signature, no rollback below
    `minimum_size`, optional chain and root check. Raises AlgorithmUnavailable for a registered, allowed algorithm this installation lacks."""
    try:
        pol = parse_policy(policy)
        minimum = 0 if minimum_size is None else minimum_size
        if (not exact_keys(record, ["format", "alg", "stream", "treeSize", "rootHash", "issuedAt", "keyId", "signature"])
                or record["format"] != "akac-audit-checkpoint/3" or not isinstance(record["alg"], str) or record["alg"] not in ALGORITHMS
                or record["alg"] not in pol["algorithms"] or record["stream"] != expected_stream or record["keyId"] != expected_key_id
                or not isinstance(record["keyId"], str) or _KEY_ID.fullmatch(record["keyId"]) is None
                or not record["keyId"].startswith(record["alg"] + ":") or len(record["keyId"]) <= len(record["alg"]) + 1
                or not safe_text(record["stream"], 128) or not safe_number(record["treeSize"]) or not safe_number(record["issuedAt"])
                or not safe_number(minimum) or record["treeSize"] < minimum or not is_hash(record["rootHash"])):
            return False
        alg = record["alg"]
        if any(_component_class(c) is None for c in ALGORITHMS[alg][1]):
            raise AlgorithmUnavailable(f"the installed cryptography package cannot verify {alg}")
        signature = _decode_signature_v3(alg, record["signature"])
        keys = _v3_public_keys(alg, key)
        if signature is None or keys is None:
            return False
        message, offset = _unsigned_v3(record), 0
        for pk, length in zip(keys, ALGORITHMS[alg][2]):
            try:
                pk.verify(signature[offset:offset + length], message)
            except InvalidSignature:
                return False
            offset += length
        if entries is None:
            return True
        return (verify_audit(entries) and all(e.get("tenant") == entries[0].get("tenant") for e in entries) and len(entries) >= record["treeSize"]
                and (not entries or entries[0].get("tenant") == expected_stream)
                and root_of([audit_leaf(e) for e in entries[:record["treeSize"]]]) == record["rootHash"])
    except AlgorithmUnavailable:
        raise
    except (ValueError, TypeError, KeyError):
        return False


def _has_pq(alg):
    return ALGORITHMS[alg][0] != "classical"


def verify_checkpoint_history(items, expected_stream, policy=None):
    """No-downgrade check of several checkpoints of one stream. `items`: [{checkpoint, publicKey}] (format 2 or 3, each with its trusted
    key). Every checkpoint must verify under the policy; then no classical-only checkpoint may be newer or larger than the earliest
    verified checkpoint with a post-quantum component, unless policy.allowClassicalAfterPq. Raises AlgorithmUnavailable when an
    algorithm cannot be verified here."""
    try:
        pol = parse_policy(policy)
        if not isinstance(items, list) or not items:
            return False
        heads = []
        for item in items:
            cp = item["checkpoint"]
            if cp.get("format") == "akac-audit-checkpoint/3":
                ok = verify_checkpoint_v3(cp, item["publicKey"], expected_stream, cp.get("keyId"), policy=policy)
                alg = cp["alg"]
            elif cp.get("format") == "akac-audit-checkpoint/2" and "ed25519" in pol["algorithms"]:
                ok = verify_checkpoint_v2(cp, item["publicKey"], expected_stream, cp.get("keyId"))
                alg = "ed25519"
            else:
                return False
            if not ok:
                return False
            heads.append((alg, cp["issuedAt"], cp["treeSize"]))
        pq = [(t, s) for a, t, s in heads if _has_pq(a)]
        if not pq or pol["allowClassicalAfterPq"]:
            return True
        first_time, first_size = min(pq)
        return all(_has_pq(a) or (t < first_time and s <= first_size) for a, t, s in heads)
    except AlgorithmUnavailable:
        raise
    except (ValueError, TypeError, KeyError, AttributeError):
        return False
