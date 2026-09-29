"""Closed reason codes, categories and obligations (AKAC 0.4 decisions, 0.5 runtime obligations)."""
import copy
import re

from .js import safe_integer
from .validation import valid_id

LEVELS = ["public", "internal", "confidential", "restricted"]
ALLOW_CODES = ["AUTHORIZED", "PROTECTED_DERIVATION", "AUTHORIZED_RECIPIENT", "ATTENUATED", "IDEMPOTENT_REPLAY"]
REASON_CODES = ALLOW_CODES + [
    "INVALID_REQUEST", "NOT_AUTHORIZED", "INVALID_CONTEXT", "IDENTITY_BOUNDARY", "INVALID_DELEGATION", "OUT_OF_SCOPE",
    "UNSUPPORTED_OBLIGATION", "SOD_VIOLATION", "KNOWLEDGE_BOUNDARY",
    "RISK_CAP",
    "POLICY_DENIED", "POLICY_UNAVAILABLE",
    "STALE_CONTEXT", "STALE_SOURCE", "EXPIRED", "RECIPIENT", "CANDIDATES_UNAVAILABLE", "BUDGET_EXCEEDED", "STORE_ERROR",
    "RELEASE_FILTER", "SANITIZER", "VOLUME_EXCEEDED", "APPROVAL_REQUIRED", "RETRIEVAL_DISABLED",
    # knowledge semantics (0.6, ADR-022)
    "LINEAGE_DEPTH", "RESIDENCY", "COMBINATION", "WRITE_DOWN",
    "NOT_ADMIN", "CONFLICT", "IDEMPOTENCY_KEY_REUSED"]
OBLIGATION_TYPES = ["audit_level", "max_context_ttl_ms", "no_persist", "destination_restricted", "runtime_profile", "max_output_classification",
                    "release_filter", "approval_required"]
RUNTIME_DOMAINS = ["network", "filesystem", "tool", "credential"]
OBLIGATION_LIMIT = 16


def _only(x, keys):
    return all(k in keys for k in x) and all(k in x for k in keys)


def valid_obligation(x):
    if not isinstance(x, dict):
        return False
    t = x.get("type")
    if t == "audit_level":
        return _only(x, ["type", "value"]) and x["value"] == "full" and isinstance(x["value"], str)
    if t == "max_context_ttl_ms":
        return _only(x, ["type", "value"]) and safe_integer(x["value"]) and x["value"] >= 1
    if t == "no_persist":
        return _only(x, ["type"])
    if t == "destination_restricted":
        v = x.get("value")
        return (_only(x, ["type", "value"]) and isinstance(v, list) and 1 <= len(v) <= 64 and all(valid_id(d) for d in v)
                and len(set(v)) == len(v))
    if t == "runtime_profile":
        return _only(x, ["type", "domain", "profile"]) and isinstance(x["domain"], str) and x["domain"] in RUNTIME_DOMAINS and valid_id(x["profile"])
    if t == "max_output_classification":
        return _only(x, ["type", "value"]) and isinstance(x["value"], str) and x["value"] in LEVELS
    if t == "release_filter":
        v = x.get("value")
        return (_only(x, ["type", "value"]) and isinstance(v, list) and 1 <= len(v) <= 16 and all(valid_id(d) for d in v)
                and len(set(v)) == len(v))
    if t == "approval_required":
        return _only(x, ["type", "value"]) and valid_id(x["value"])
    return False


def unsatisfiable(obligations):
    """A destination_restricted with no destination left, or two different runtime profiles for one domain."""
    profiles = {}
    for o in obligations:
        if o["type"] == "destination_restricted" and not o["value"]:
            return True
        if o["type"] == "release_filter" and len(o["value"]) > 16:
            return True
        if o["type"] == "runtime_profile":
            prior = profiles.get(o["domain"])
            if prior is not None and prior != o["profile"]:
                return True
            profiles[o["domain"]] = o["profile"]
    return False


def merge(*lists):
    """Restrictive combination: shortest TTL, destination intersection, highest output label, stable order."""
    by_type, profiles = {}, {}
    for o in (o for lst in lists for o in lst):
        if o["type"] == "runtime_profile":
            lst = profiles.setdefault(o["domain"], [])
            if not any(p["profile"] == o["profile"] for p in lst):
                lst.append(copy.deepcopy(o))
            continue
        prior = by_type.get(o["type"])
        if prior is None:
            by_type[o["type"]] = copy.deepcopy(o)
            continue
        if o["type"] == "max_context_ttl_ms":
            prior["value"] = min(prior["value"], o["value"])
        if o["type"] == "destination_restricted":
            # An empty intersection is kept as an impossible restriction, which no PEP can satisfy: deny.
            prior["value"] = [d for d in prior["value"] if d in o["value"]]
        if o["type"] == "max_output_classification" and LEVELS.index(o["value"]) > LEVELS.index(prior["value"]):
            prior["value"] = o["value"]
        if o["type"] == "release_filter":
            prior["value"] = sorted(set(prior["value"]) | set(o["value"]))
    out = []
    for t in OBLIGATION_TYPES:
        if t == "runtime_profile":
            for d in RUNTIME_DOMAINS:
                out.extend(profiles.get(d, []))
        elif t in by_type:
            out.append(by_type[t])
    for o in out:
        if o["type"] == "release_filter":
            o["value"] = sorted(o["value"])
    return out


def parse_obligations(x):
    """At most 16 known, well-formed, satisfiable obligations (merged), else None (UNSUPPORTED_OBLIGATION)."""
    if not isinstance(x, list) or len(x) > OBLIGATION_LIMIT or not all(valid_obligation(o) for o in x):
        return None
    merged = merge(copy.deepcopy(x))
    return None if unsatisfiable(merged) else merged


def enforceable(obligations, supported):
    return (isinstance(obligations, list) and all(valid_obligation(o) and o["type"] in supported for o in obligations)
            and not unsatisfiable(obligations))


_REASON = re.compile(r"(DENIED|DEFERRED):([A-Z_]+)")


def classify(reason):
    """`DENIED:X` / `DEFERRED:X` / allow reason -> {"code", "category"?}; None outside the closed set."""
    if not isinstance(reason, str):
        return None
    match = _REASON.fullmatch(reason)
    code = match.group(2) if match else reason
    if code not in REASON_CODES:
        return None
    allow = code in ALLOW_CODES
    if (allow if match else not allow):
        return None
    return {"code": code, "category": "deny" if match.group(1) == "DENIED" else "defer"} if match else {"code": code}


def valid_decision_id(x):
    return isinstance(x, str) and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", x) is not None


_FINDING = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def valid_findings(x):
    """Closed audit findings (0.6): at most 32 strings of A-Z a-z 0-9 . _ : -, each 1-128 characters."""
    return isinstance(x, list) and 1 <= len(x) <= 32 and all(isinstance(f, str) and _FINDING.fullmatch(f) is not None for f in x)


def valid_trace_id(x):
    return isinstance(x, str) and re.fullmatch(r"[0-9a-f]{32}", x) is not None and re.fullmatch(r"0+", x) is None


__all__ = ["REASON_CODES", "ALLOW_CODES", "OBLIGATION_TYPES", "RUNTIME_DOMAINS", "valid_obligation", "unsatisfiable", "merge",
           "parse_obligations", "enforceable", "classify", "valid_decision_id", "valid_trace_id", "valid_findings"]
