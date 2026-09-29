"""Audit entry hashing and chain verification (format 1 and format 2, AKAC 0.4 evidence)."""
import hashlib
import json

from .decision import classify, valid_decision_id, valid_findings, valid_obligation, valid_trace_id
from .jcs import canonical_bytes
from .js import safe_number
from .merkle import leaf_hash
from .validation import valid_id

GENESIS = "0" * 64
V1 = ["sequence", "time", "tenant", "actor", "operation", "decision", "reason", "policyVersion", "epoch", "previous"]
V2 = V1 + ["formatVersion", "decisionId", "reasonCode", "policyDigest", "obligations"]
V2_OPTIONAL = ["runId", "traceId", "executionId", "runtimeRevision", "findings", "actorChain", "breakGlass"]
MAX_ACTOR_CHAIN = 5


def valid_actor_chain(x):
    """RFC 8693 actor chain (0.6, R145): 1..5 printable ASCII identifiers of at most 256 characters."""
    return (isinstance(x, list) and 1 <= len(x) <= MAX_ACTOR_CHAIN
            and all(isinstance(a, str) and 1 <= len(a) <= 256 and all(0x21 <= ord(c) <= 0x7e for c in a) for a in x))


def _collation_key(name):
    # Format 1 sorts member names with an English locale collation; for the ASCII
    # identifiers of audit members that is case-insensitive order, lowercase first.
    return (name.lower(), name.swapcase())


def _stringify(value):
    """ECMAScript JSON.stringify for the values of format 1 entries (members in insertion order)."""
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _stringify(v) for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_stringify(v) for v in value) + "]"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if type(value) is float:
        return str(int(value)) if value.is_integer() and abs(value) < 1e21 else repr(value)
    return json.dumps(value, ensure_ascii=False)


def audit_hash(entry):
    """Format 1: SHA-256 over JSON with top-level members sorted (0.1-0.3)."""
    ordered = "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _stringify(entry[k]) for k in sorted(entry, key=_collation_key)) + "}"
    return hashlib.sha256(ordered.encode("utf-8", "surrogatepass")).hexdigest()


def _v2_shape(body):
    code = classify(body.get("reason")) if isinstance(body.get("reason"), str) else None
    obligations = body.get("obligations")
    return (all(k in body for k in V2) and all(k in V2 or k in V2_OPTIONAL for k in body)
            and body["formatVersion"] == 2 and type(body["formatVersion"]) is int and valid_decision_id(body["decisionId"])
            and code is not None and code["code"] == body["reasonCode"]
            and (body["decision"] == "allow") == ("category" not in code) and body["decision"] in ("allow", "deny")
            and isinstance(body["policyDigest"], str) and len(body["policyDigest"]) == 64 and all(c in "0123456789abcdef" for c in body["policyDigest"])
            and isinstance(obligations, list) and len(obligations) <= 16 and all(valid_obligation(o) for o in obligations)
            and (body["decision"] == "allow" or len(obligations) == 0)
            and ("runId" not in body or valid_id(body["runId"])) and ("traceId" not in body or valid_trace_id(body["traceId"]))
            and ("executionId" not in body or valid_id(body["executionId"])) and ("runtimeRevision" not in body or valid_id(body["runtimeRevision"]))
            and ("findings" not in body or valid_findings(body["findings"]))
            and ("actorChain" not in body or valid_actor_chain(body["actorChain"])) and ("breakGlass" not in body or body["breakGlass"] is True))


def audit_hash_v2(entry):
    """Format 2: SHA-256 over the RFC 8785 (JCS) form of the body, which includes formatVersion 2."""
    return hashlib.sha256(canonical_bytes(entry)).hexdigest()


def entry_hash(body):
    """Hash of an entry body under its own format; None for an unknown format or a malformed format 2 body."""
    try:
        if "formatVersion" not in body:
            return audit_hash(body)
        return audit_hash_v2(body) if _v2_shape(body) else None
    except (ValueError, TypeError, KeyError):
        return None


def audit_leaf(entry):
    """RFC 9162 leaf of an entry: H(0x00 || JCS(entry including hash))."""
    return leaf_hash(canonical_bytes(entry))


def verify_audit(entries, window=False):
    """Per-tenant streams from sequence 1 (or the first supplied entry with window); no downgrade to format 1."""
    heads = {}
    ok = True
    for entry in entries:
        if not isinstance(entry, dict):
            return False
        body = {k: v for k, v in entry.items() if k != "hash"}
        h = entry.get("hash")
        head = heads.get(entry.get("tenant"))
        sequence = head["sequence"] + 1 if head else (entry.get("sequence") if window else 1)
        previous = head["hash"] if head else (entry.get("previous") if window else GENESIS)
        v2 = "formatVersion" in entry
        valid = (safe_number(entry.get("sequence")) and entry["sequence"] >= 1 and entry["sequence"] == sequence
                 and entry.get("previous") == previous and not (head and head["v2"] and not v2) and entry_hash(body) == h)
        heads[entry.get("tenant")] = {"sequence": entry.get("sequence"), "hash": h, "v2": v2 or bool(head and head["v2"])}
        if not valid:
            ok = False
            break
    return ok
