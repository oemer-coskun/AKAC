"""Knowledge semantics of AKAC 0.6 (spec/AKAC-0.6.md, R182-R196): closure facts, depth limit,
combination rules, residency admission, the placement (no write-down) rule and session scopes.

Pure functions over one snapshot, following the normative text rule by rule. Each either computes an attribute
or adds a condition; none can allow anything. Anything that cannot be established returns None (fail closed).
"""
import re

from .js import UNDEF, get, is_array, key, prop, safe_integer, safe_number, sort_default, strict_eq
from .policy import LEVELS, LIMITS, Unestablished, container_chain, effective_label
from .validation import exact_keys, valid_id

KNOWLEDGE = {"defaultDepth": 16, "maxDepth": 127, "tags": 32, "residency": 32, "combinationRules": 256,
             "ephemeralTtlMs": 3_600_000, "ephemeralMaxTtlMs": 86_400_000, "ephemeralRecords": 1000, "ephemeralTenant": 10_000}
MODALITIES = ["text", "image", "audio", "video", "table", "code", "other"]
_CODE = re.compile(r"[A-Z][A-Z0-9-]{1,15}")


def _unique(xs):
    return len(set(xs)) == len(xs)


def valid_tags(x):
    return is_array(x) and len(x) <= KNOWLEDGE["tags"] and all(valid_id(t) for t in x) and _unique(x)


def valid_residency(x):
    return (is_array(x) and len(x) <= KNOWLEDGE["residency"] and all(isinstance(c, str) and _CODE.fullmatch(c) is not None for c in x)
            and _unique(x))


def valid_region(x):
    return isinstance(x, str) and _CODE.fullmatch(x) is not None


def valid_model(x):
    return exact_keys(x, ["id", "version"]) and valid_id(x["id"]) and valid_id(x["version"])


def valid_ephemeral(x):
    return exact_keys(x, ["sessionId", "run", "expiresAt"]) and valid_id(x["sessionId"]) and valid_id(x["run"]) and safe_number(x["expiresAt"])


def _intersect(a, b):
    if a is None:
        return None if b is None else set(b)
    return a if b is None else {x for x in a if x in b}


def _new():
    return {"level": 0, "tags": set(), "residency": None, "generation": 0, "ephemeral": []}


def _join(into, frm, generation):
    into["level"] = max(into["level"], frm["level"])
    into["tags"] |= frm["tags"]
    into["residency"] = _intersect(into["residency"], frm["residency"])
    into["generation"] = max(into["generation"], generation)
    for e in frm["ephemeral"]:
        if not any(x["sessionId"] == e["sessionId"] and x["run"] == e["run"] and x["expiresAt"] == e["expiresAt"] for x in into["ephemeral"]):
            into["ephemeral"].append(e)


def lineage_facts(state, root):
    """Level, union of tags, intersection of residency, generation and session scopes over the closure (R182..R190); None if unknown."""
    done, visiting = {}, set()
    counters = {"nodes": 0, "edges": 0}

    def visit(k, depth):
        kid = key(prop(k, "id"))
        if depth >= LIMITS["path"] or kid in visiting:
            raise Unestablished("cycle")
        if kid in done:
            return done[kid]
        counters["nodes"] += 1
        label = effective_label(state, k) if counters["nodes"] <= LIMITS["nodes"] else None
        chain = container_chain(state, k) if label is not None else None
        if label is None or chain is None or not is_array(prop(k, "sources")):
            raise Unestablished("label")
        facts = _new()
        facts["level"] = LEVELS.index(label["classification"])
        for x in [k] + chain:
            tags, residency = prop(x, "tags"), prop(x, "residency")
            if tags is not UNDEF:
                if not valid_tags(tags):
                    raise Unestablished("tags")
                facts["tags"] |= set(tags)
            if residency is not UNDEF:
                if not valid_residency(residency):
                    raise Unestablished("residency")
                facts["residency"] = _intersect(facts["residency"], set(residency))
        eph = prop(k, "ephemeral")
        if eph is not UNDEF:
            if not valid_ephemeral(eph):
                raise Unestablished("ephemeral")
            facts["ephemeral"].append(eph)
        visiting.add(kid)
        for ref in prop(k, "sources"):
            counters["edges"] += 1
            rid = prop(ref, "id") if isinstance(ref, dict) else UNDEF
            if counters["edges"] > LIMITS["edges"] or not valid_id(rid):
                raise Unestablished("budget")
            source = get(prop(state, "knowledge"), rid)
            if (source is UNDEF or not isinstance(source, dict) or not strict_eq(prop(source, "tenant"), prop(k, "tenant"))
                    or not strict_eq(prop(source, "version"), prop(ref, "version"))):
                raise Unestablished("source")
            f = visit(source, depth + 1)
            _join(facts, f, f["generation"] + 1)
        visiting.discard(kid)
        done[kid] = facts
        return facts

    try:
        return visit(root, 0)
    except (Unestablished, TypeError, KeyError, ValueError, AttributeError, RecursionError):
        return None


def facts_of(state, ids):
    out = _new()
    for rid in ids:
        k = get(prop(state, "knowledge"), rid)
        f = lineage_facts(state, k) if isinstance(k, dict) else None
        if f is None:
            return None
        _join(out, f, f["generation"])
    return out


def sorted_tags(tags):
    return sort_default(list(tags))


def sorted_residency(residency):
    return None if residency is None else sort_default(list(residency))


def lineage_depth_of(state, tenant):
    """R182: settings.lineageDepth (default 16); None when malformed."""
    settings = prop(state, "settings")
    s = get(settings, tenant) if isinstance(settings, dict) else UNDEF
    v = prop(s, "lineageDepth") if isinstance(s, dict) and strict_eq(prop(s, "tenant"), tenant) else UNDEF
    if v is UNDEF:
        return KNOWLEDGE["defaultDepth"]
    return v if safe_integer(v) and 1 <= v <= KNOWLEDGE["maxDepth"] else None


def valid_combination_rule(r):
    if not (exact_keys(r, ["id", "tenant", "tagsA", "tagsB", "effect", "active"], ["upliftTo"]) and valid_id(r["id"]) and valid_id(r["tenant"])
            and valid_tags(r["tagsA"]) and len(r["tagsA"]) >= 1 and valid_tags(r["tagsB"]) and len(r["tagsB"]) >= 1 and isinstance(r["active"], bool)):
        return False
    up = r.get("upliftTo", UNDEF)
    if r["effect"] == "deny":
        return up is UNDEF
    return r["effect"] == "uplift" and (up is UNDEF or (isinstance(up, str) and up in LEVELS))


def combination(state, tenant, tags, level):
    """R188: {"deny", "level"} or None when a rule of the tenant is malformed or there are too many."""
    deny, out, count = False, level, 0
    rules = prop(state, "combinationRules")
    for r in (list(rules.values()) if isinstance(rules, dict) else []):
        if not isinstance(r, dict) or not strict_eq(r.get("tenant", UNDEF), tenant):
            continue
        count += 1
        if count > KNOWLEDGE["combinationRules"] or not valid_combination_rule(r):
            return None
        if not r["active"] or not any(t in tags for t in r["tagsA"]) or not any(t in tags for t in r["tagsB"]):
            continue
        if r["effect"] == "deny":
            deny = True
        else:
            out = max(out, LEVELS.index(r["upliftTo"]) if "upliftTo" in r else min(level + 1, len(LEVELS) - 1))
    return {"deny": deny, "level": out}


def residency_admits(state, target, tenant, residency):
    """R187."""
    if residency is None:
        return True
    if target["kind"] != "profile":
        return False
    destinations = prop(state, "destinations")
    d = get(destinations, target["id"]) if isinstance(destinations, dict) else UNDEF
    return (isinstance(d, dict) and strict_eq(d.get("id", UNDEF), target["id"]) and strict_eq(d.get("tenant", UNDEF), tenant)
            and d.get("active", UNDEF) is True and valid_region(d.get("region", UNDEF)) and d["region"] in residency)


def _narrower(d, c):
    return all(x in c["readers"] for x in d["readers"]) and all(x in c["readerRoles"] for x in d["readerRoles"])


def placement_allowed(state, tenant, sources, own, classification, container):
    """R192 (no write-down): True when the placement keeps every source's static audience."""
    chain = container_chain(state, {"tenant": tenant, "container": container})
    if not chain:
        return False
    clauses = [own] + [{"readers": c["readers"], "readerRoles": c["readerRoles"]} for c in chain]
    level = max([LEVELS.index(classification)] + [LEVELS.index(c["classification"]) for c in chain])
    projects = set(own["projects"]) | {p for c in chain for p in c["projects"]}
    for s in sources:
        label = effective_label(state, s)
        if label is None or LEVELS.index(label["classification"]) > level or not all(p in projects for p in label["projects"]):
            return False
        if not all(any(_narrower(d, c) for d in clauses) for c in label["audiences"]):
            return False
    return True


def session_of(facts, run, now, run_expires, requested=None):
    """R190: {"ok": True, "ephemeral"?} or {"ok": False, "reason"}."""
    if requested is not None:
        ttl = requested.get("ttlMs", UNDEF)
        if not valid_id(requested.get("sessionId", UNDEF)) or (ttl is not UNDEF and not (safe_integer(ttl) and 1000 <= ttl <= KNOWLEDGE["ephemeralMaxTtlMs"])):
            return {"ok": False, "reason": "DEFERRED:INVALID_REQUEST"}
    sessions = []
    for e in facts["ephemeral"]:
        if e["sessionId"] not in sessions:
            sessions.append(e["sessionId"])
    if requested is not None and requested["sessionId"] not in sessions:
        sessions.append(requested["sessionId"])
    if not sessions:
        return {"ok": True}
    if len(sessions) > 1 or any(e["run"] != run for e in facts["ephemeral"]):
        return {"ok": False, "reason": "DENIED:OUT_OF_SCOPE"}
    candidates = [run_expires] + [e["expiresAt"] for e in facts["ephemeral"]]
    if requested is not None:
        candidates.append(now + requested.get("ttlMs", KNOWLEDGE["ephemeralTtlMs"]))
    expires = min(candidates)
    if not safe_number(expires) or expires <= now:
        return {"ok": False, "reason": "DENIED:EXPIRED"}
    return {"ok": True, "ephemeral": {"sessionId": sessions[0], "run": run, "expiresAt": expires}}
