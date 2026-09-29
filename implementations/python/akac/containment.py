"""Runtime containment derivation (AKAC 0.5 draft, R106-R112): runtime_profile and max_output_classification obligations."""
from .decision import RUNTIME_DOMAINS
from .js import UNDEF, coalesce, entries, prop
from .policy import DESTINATION_CLASSES, LEVELS
from .validation import exact_keys, valid_id

RUNTIME_PROFILE_LIMIT = 256


def valid_runtime_profile(p):
    if not exact_keys(p, ["id", "tenant", "classification", "profiles", "active"], ["destinationClass"]):
        return False
    profiles = p["profiles"]
    dc = p.get("destinationClass", UNDEF)
    return (valid_id(p["id"]) and valid_id(p["tenant"]) and isinstance(p["classification"], str) and p["classification"] in LEVELS
            and (dc is UNDEF or (isinstance(dc, str) and dc in DESTINATION_CLASSES))
            and exact_keys(profiles, [], RUNTIME_DOMAINS) and len(profiles) >= 1 and all(valid_id(v) for v in profiles.values())
            and type(p["active"]) is bool)


def containment(state, tenant, level, destination=None):
    """Runtime obligations of a decision over material of highest classification `level` to class `destination`.

    {"ok": True, "obligations": [...]} or {"ok": False, "reason": ...}. A tenant without an active policy gets none.
    """
    records = [(k, p) for k, p in entries(coalesce(prop(state, "runtimeProfiles"), {}))
               if isinstance(p, dict) and isinstance(p.get("tenant"), str) and p["tenant"] == tenant]
    if len(records) > RUNTIME_PROFILE_LIMIT:
        return {"ok": False, "reason": "DEFERRED:BUDGET_EXCEEDED"}
    if any(not valid_runtime_profile(p) or p["id"] != k for k, p in records):
        return {"ok": False, "reason": "DEFERRED:INVALID_CONTEXT"}
    active = [p for _, p in records if p["active"] is True]
    if not active:
        return {"ok": True, "obligations": []}
    if not level or level not in LEVELS:
        return {"ok": False, "reason": "DEFERRED:INVALID_CONTEXT"}
    top = LEVELS.index(level)
    applicable = [p for p in active if LEVELS.index(p["classification"]) <= top
                  and ("destinationClass" not in p or p["destinationClass"] == destination)]
    obligations = []
    for domain in RUNTIME_DOMAINS:
        best, conflict = None, False
        for p in applicable:
            profile = p["profiles"].get(domain)
            if profile is None:
                continue
            rank = LEVELS.index(p["classification"]) * 2 + (1 if "destinationClass" in p else 0)
            if best is None or rank > best[0]:
                best, conflict = (rank, profile), False
            elif rank == best[0] and profile != best[1]:
                conflict = True
        if conflict:
            return {"ok": False, "reason": "DENIED:UNSUPPORTED_OBLIGATION"}
        if best is not None:
            obligations.append({"type": "runtime_profile", "domain": domain, "profile": best[1]})
    obligations.append({"type": "max_output_classification", "value": level})
    return {"ok": True, "obligations": obligations}


def containment_across(state, tenant, level, classes):
    """Share/export of unknown destination class (R109): merged over every class it may reach; a conflict denies (R110).

    No reachable class (a run restricted to Destination ids that resolve to nothing) denies with RECIPIENT
    (0.6 R122); it never falls back to the unnarrowed derivation.
    """
    if not isinstance(classes, list) or not classes:
        return {"ok": False, "reason": "DENIED:RECIPIENT"}
    merged, label = {}, None
    for d in classes:
        c = containment(state, tenant, level, d)
        if not c["ok"]:
            return c
        for o in c["obligations"]:
            if o["type"] == "max_output_classification":
                label = o
                continue
            if o["type"] != "runtime_profile":
                continue
            prior = merged.get(o["domain"])
            if prior is not None and prior["profile"] != o["profile"]:
                return {"ok": False, "reason": "DENIED:UNSUPPORTED_OBLIGATION"}
            merged[o["domain"]] = o
    return {"ok": True, "obligations": [merged[d] for d in RUNTIME_DOMAINS if d in merged] + ([label] if label else [])}
