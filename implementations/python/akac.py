"""AKAC Core/KB 0.3, independent Python decision implementation (stdlib only).

This implementation shares the specification and test data, not TypeScript code.
It is produced by the same project; it is NOT an independent external audit.
Input: JSON {"cases": [{"state": ..., "request": ...}]}; output: decision list.
"""
import json
import re
import sys

LEVELS = ["public", "internal", "confidential", "restricted"]
ACTIONS = ["read", "derive", "write_memory", "share", "export", "declassify"]
ORIGINS = ["human", "system", "model"]
MAX_ROLES, MAX_ROLE_DEPTH, MAX_CONTAINER_DEPTH = 64, 16, 32


class Unestablished(Exception):
    """Role graph cannot be established (cycle, budget, malformed)."""


def integer(x):
    return type(x) is int and 0 <= x <= 9007199254740991


def identifier(x):
    return isinstance(x, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}", x) is not None and x not in ("constructor", "prototype", "__proto__")


def subset(small, large):
    return all("*" in large or value in large for value in small)


def valid_chain(state, grant, now):
    seen = set()
    while True:
        subject = state["actors"].get(grant["subject"])
        agent = state["actors"].get(grant["agent"])
        if not subject or not agent or not subject["active"] or not agent["active"]:
            return False
        if subject["kind"] != "user" or agent["kind"] != "agent" or subject["tenant"] != grant["tenant"] or agent["tenant"] != grant["tenant"]:
            return False
        if grant["id"] in seen or len(seen) >= 32 or not grant["active"]:
            return False
        if not integer(grant["notBefore"]) or not integer(grant["expiresAt"]) or not grant["notBefore"] <= now < grant["expiresAt"]:
            return False
        if not grant["actions"] or any(action not in ACTIONS for action in grant["actions"]):
            return False
        if "activeRoles" in grant:
            active = grant["activeRoles"]
            if not isinstance(active, list) or len(active) > MAX_ROLES or any(not isinstance(r, str) or not r for r in active):
                return False
        seen.add(grant["id"])
        if not grant.get("parent"):
            return True
        parent = state["grants"].get(grant["parent"])
        if not parent or parent["tenant"] != grant["tenant"] or parent["subject"] != grant["subject"]:
            return False
        if any(not subset(grant[key], parent[key]) for key in ("actions", "resources", "purposes")):
            return False
        if grant["notBefore"] < parent["notBefore"] or grant["expiresAt"] > parent["expiresAt"]:
            return False
        if "activeRoles" in parent and ("activeRoles" not in grant or any(r not in parent["activeRoles"] for r in grant["activeRoles"])):
            return False
        grant = parent


def close_roles(state, tenant, seeds):
    # Recursive with memoized heights; order-independent result.
    held, heights, path = set(), {}, set()

    def visit(name):
        if not isinstance(name, str) or not name:
            raise Unestablished()
        found = state["roles"].get(name)
        role = found if found is not None and found["tenant"] == tenant else None
        if role is not None and role["active"] is not True:
            return 0
        if name in path:
            raise Unestablished()
        if name in heights:
            return heights[name]
        held.add(name)
        if len(held) > MAX_ROLES:
            raise Unestablished()
        path.add(name)
        height = 1
        if role is not None:
            if not isinstance(role["inherits"], list):
                raise Unestablished()
            for junior in role["inherits"]:
                height = max(height, 1 + visit(junior))
        path.discard(name)
        if height > MAX_ROLE_DEPTH:
            raise Unestablished()
        heights[name] = height
        return height

    try:
        for seed in seeds:
            visit(seed)
        return held
    except Unestablished:
        return None


def effective_roles(state, actor):
    seeds = []
    for group in state["groups"].values():
        if group["tenant"] != actor["tenant"]:
            continue
        if not isinstance(group["members"], list) or not isinstance(group["roles"], list):
            return None
        if group["active"] is True and actor["id"] in group["members"]:
            seeds.extend(group["roles"])
    if not isinstance(actor["roles"], list):
        return None
    return close_roles(state, actor["tenant"], list(actor["roles"]) + seeds)


def session_roles(state, user, held, grant):
    if "activeRoles" not in grant:
        return set(held)
    active = grant["activeRoles"]
    if not isinstance(active, list) or any(not isinstance(r, str) or r not in held for r in active):
        return None
    return close_roles(state, user["tenant"], active)


def sod_violated(state, tenant, kind, roles):
    for c in state["constraints"].values():
        if c["tenant"] != tenant:
            continue
        cardinality = c["cardinality"]
        if c["kind"] not in ("static", "dynamic") or type(cardinality) is not int or cardinality < 2 or not isinstance(c["roles"], list):
            return True
        if c["kind"] == kind and len({r for r in c["roles"] if r in roles}) >= cardinality:
            return True
    return False


def container_chain(state, resource):
    # Iterative walk to the knowledge-base root.
    chain = []
    if "container" not in resource:
        return chain
    name = resource["container"]
    while True:
        if not identifier(name) or len(chain) >= MAX_CONTAINER_DEPTH or any(c["id"] == name for c in chain):
            return None
        c = state["containers"].get(name)
        if c is None or c["tenant"] != resource["tenant"] or c["id"] != name:
            return None
        if c["kind"] == "knowledge-base":
            if "parent" in c:
                return None
        elif c["kind"] != "folder" or "parent" not in c:
            return None
        chain.append(c)
        if "parent" not in c:
            return chain
        name = c["parent"]


def admits(actor, roles, obj):
    if not actor["active"] or actor["tenant"] != obj["tenant"] or actor["clearance"] not in LEVELS or obj["classification"] not in LEVELS:
        return False
    if LEVELS.index(actor["clearance"]) < LEVELS.index(obj["classification"]):
        return False
    if not all(project in actor["projects"] for project in obj["projects"]):
        return False
    return actor["id"] in obj["readers"] or bool(roles.intersection(obj["readerRoles"]))


def visible(state, actor, root, now, roles):
    # Discover once, then peel leaves. This differs from the TypeScript DFS.
    pending = [root]
    graph = {}
    edges = 0
    while pending:
        resource = pending.pop()
        name = resource["id"]
        if name in graph:
            continue
        if len(graph) >= 1024 or not resource["active"] or not integer(resource["version"]) or resource["version"] < 1:
            return False
        if "accessExpiresAt" in resource and (not integer(resource["accessExpiresAt"]) or now >= resource["accessExpiresAt"]):
            return False
        if resource.get("origin") not in ORIGINS or not admits(actor, roles, resource):
            return False
        chain = container_chain(state, resource)
        if chain is None or not all(c["active"] is True and admits(actor, roles, c) for c in chain):
            return False
        graph[name] = []
        for ref in resource["sources"]:
            edges += 1
            if edges > 4096 or not identifier(ref["id"]):
                return False
            source = state["knowledge"].get(ref["id"])
            if not source or source["version"] != ref["version"]:
                return False
            graph[name].append(ref["id"])
            pending.append(source)
    heights = {}
    while len(heights) < len(graph):
        changed = False
        for name, children in graph.items():
            if name in heights or any(child not in heights for child in children):
                continue
            height = 1 + max((heights[child] for child in children), default=0)
            if height > 128:
                return False
            heights[name] = height
            changed = True
        if not changed:
            return False
    return True


def decide(state, request):
    def deny(code):
        return {"effect": "deny", "code": code, "category": "deny"}

    def defer(code):
        return {"effect": "deny", "code": code, "category": "defer"}
    try:
        if set(request) != {"binding", "action", "resource", "purpose", "now"}:
            return defer("INVALID_REQUEST")
        binding = request["binding"]
        if set(binding) != {"tenant", "subject", "agent", "grant"} or not all(map(identifier, binding.values())):
            return defer("INVALID_REQUEST")
        now = request["now"]
        if not identifier(request["resource"]) or request["action"] not in ACTIONS or not isinstance(request["purpose"], str) or not 1 <= len(request["purpose"]) <= 128 or not integer(now):
            return defer("INVALID_REQUEST")
        user = state["actors"].get(binding["subject"])
        agent = state["actors"].get(binding["agent"])
        grant = state["grants"].get(binding["grant"])
        resource = state["knowledge"].get(request["resource"])
        if not all((user, agent, grant, resource)):
            return defer("NOT_AUTHORIZED")
        if user["kind"] != "user" or agent["kind"] != "agent" or not user["active"] or not agent["active"] or any(obj["tenant"] != binding["tenant"] for obj in (user, agent, grant, resource)):
            return deny("IDENTITY_BOUNDARY")
        if grant["subject"] != user["id"] or grant["agent"] != agent["id"] or not valid_chain(state, grant, now):
            return deny("INVALID_DELEGATION")
        if request["action"] not in grant["actions"] or not subset([request["resource"]], grant["resources"]) or not subset([request["purpose"]], grant["purposes"]):
            return deny("OUT_OF_SCOPE")
        if request["action"] == "declassify":
            return deny("UNSUPPORTED_OBLIGATION")
        user_roles, agent_roles = effective_roles(state, user), effective_roles(state, agent)
        if user_roles is None or agent_roles is None:
            return defer("INVALID_CONTEXT")
        session = session_roles(state, user, user_roles, grant)
        if session is None:
            return deny("INVALID_DELEGATION")
        tenant = binding["tenant"]
        if sod_violated(state, tenant, "static", user_roles) or sod_violated(state, tenant, "static", agent_roles) or sod_violated(state, tenant, "dynamic", session):
            return deny("SOD_VIOLATION")
        if resource.get("origin") not in ORIGINS or container_chain(state, resource) is None:
            return defer("INVALID_CONTEXT")
        if not visible(state, user, resource, now, session) or not visible(state, agent, resource, now, agent_roles):
            return deny("KNOWLEDGE_BOUNDARY")
        return {"effect": "allow", "code": "AUTHORIZED"}
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        return defer("INVALID_CONTEXT")


if __name__ == "__main__":
    data = json.load(sys.stdin)
    print(json.dumps([decide(case["state"], case["request"]) for case in data["cases"]]))
