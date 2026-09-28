"""AKAC Core 0.2, independent Python decision implementation (stdlib only).

This implementation shares the specification and test data, not TypeScript code.
It is produced by the same project; it is NOT an independent external audit.
Input: JSON {"cases": [{"state": ..., "request": ...}]}; output: decision list.
"""
import json
import re
import sys

LEVELS = ["public", "internal", "confidential", "restricted"]
ACTIONS = ["read", "derive", "write_memory", "share", "export", "declassify"]


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
        grant = parent


def visible(state, actor, root, now):
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
        if not actor["active"] or actor["tenant"] != resource["tenant"] or actor["clearance"] not in LEVELS or resource["classification"] not in LEVELS:
            return False
        if LEVELS.index(actor["clearance"]) < LEVELS.index(resource["classification"]):
            return False
        if not all(project in actor["projects"] for project in resource["projects"]):
            return False
        if actor["id"] not in resource["readers"] and not set(actor["roles"]).intersection(resource["readerRoles"]):
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
        return {"effect": "deny", "code": code}
    try:
        if set(request) != {"binding", "action", "resource", "purpose", "now"}:
            return deny("INVALID_REQUEST")
        binding = request["binding"]
        if set(binding) != {"tenant", "subject", "agent", "grant"} or not all(map(identifier, binding.values())):
            return deny("INVALID_REQUEST")
        now = request["now"]
        if not identifier(request["resource"]) or request["action"] not in ACTIONS or not isinstance(request["purpose"], str) or not 1 <= len(request["purpose"]) <= 128 or not integer(now):
            return deny("INVALID_REQUEST")
        user = state["actors"].get(binding["subject"])
        agent = state["actors"].get(binding["agent"])
        grant = state["grants"].get(binding["grant"])
        resource = state["knowledge"].get(request["resource"])
        if not all((user, agent, grant, resource)):
            return deny("NOT_AUTHORIZED")
        if user["kind"] != "user" or agent["kind"] != "agent" or not user["active"] or not agent["active"] or any(obj["tenant"] != binding["tenant"] for obj in (user, agent, grant, resource)):
            return deny("IDENTITY_BOUNDARY")
        if grant["subject"] != user["id"] or grant["agent"] != agent["id"] or not valid_chain(state, grant, now):
            return deny("INVALID_DELEGATION")
        if request["action"] not in grant["actions"] or not subset([request["resource"]], grant["resources"]) or not subset([request["purpose"]], grant["purposes"]):
            return deny("OUT_OF_SCOPE")
        if request["action"] == "declassify":
            return deny("UNSUPPORTED_OBLIGATION")
        if not visible(state, user, resource, now) or not visible(state, agent, resource, now):
            return deny("KNOWLEDGE_BOUNDARY")
        return {"effect": "allow", "code": "AUTHORIZED"}
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        return deny("INVALID_CONTEXT")


if __name__ == "__main__":
    data = json.load(sys.stdin)
    print(json.dumps([decide(case["state"], case["request"]) for case in data["cases"]]))
