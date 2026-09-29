"""The pure decision function (R29) and the rules it is built from.

Follows the specification (AKAC 0.6, spec/AKAC-0.6.md) and the reference
behaviour rule by rule, and is checked against the shared vectors and by
differential testing; it shares no code with the reference at run time. Rule
order, bounds and fail-closed behaviour follow the normative text: every rule that
"cannot be established" denies.
"""
from .js import (UNDEF, coalesce, every, flat_map, ge, get, includes, index, index_of, is_array, iterate, key, le, lt, opt, prop,
                 safe_integer, safe_number, some, sort_default, strict_eq, to_string, truthy, unique, utf16_length, values)
from .validation import exact_keys, valid_id

ACTIONS = ["read", "derive", "write_memory", "share", "export", "declassify"]
LEVELS = ["public", "internal", "confidential", "restricted"]
ORIGINS = ["human", "system", "model"]
DESTINATION_CLASSES = ["internal-user", "internal-service", "model-provider", "tool", "external"]
MAX_RESULTS = 64
LIMITS = {"roles": 64, "roleDepth": 16, "containerDepth": 32, "nodes": 1024, "edges": 4096, "path": 128, "grants": 32}
# Identity and authority (0.6, R147, R149, R151).
HEARTBEAT = {"minTtlMs": 1000, "maxTtlMs": 86_400_000}
BREAK_GLASS = {"maxTtlMs": 7_200_000, "resources": 64}
RISK_LEVELS = ["none", "low", "medium", "high", "critical"]
DEFAULT_RISK_CAPS = {"none": "restricted", "low": "restricted", "medium": "confidential", "high": "internal", "critical": "deny"}


class Unestablished(Exception):
    """A closure or label cannot be established within its bounds."""


def deny(code):
    return {"effect": "deny", "code": code, "category": "deny"}


def defer(code):
    """Authorization could not be established (malformed, missing or over budget); still a deny."""
    return {"effect": "deny", "code": code, "category": "defer"}


ALLOW = {"effect": "allow", "code": "AUTHORIZED"}


def subset(small, large):
    return every(small, lambda x: includes(large, "*") or includes(large, x))


def level_of(x):
    return index_of(LEVELS, x)


def _has(roles, name):
    return isinstance(name, str) and name in roles


def audience(actor, roles, r, limit=len(LEVELS) - 1, open_=False):
    """`limit`: the actor's risk cap (a LEVELS index). `open_` (break-glass, R149) drops the reader, reader-role and project clauses."""
    clearance = min(level_of(prop(actor, "clearance")), limit)
    classification = level_of(prop(r, "classification"))
    return (prop(actor, "active") is True and strict_eq(prop(actor, "tenant"), prop(r, "tenant")) and classification >= 0
            and clearance >= classification
            and (open_ or (every(prop(r, "projects"), lambda p: includes(prop(actor, "projects"), p))
                           and (includes(prop(r, "readers"), prop(actor, "id")) or some(prop(r, "readerRoles"), lambda role: _has(roles, role))))))


def risk_limit(state, actor, now):
    """Risk cap of a principal (R151) as a LEVELS index; -1 denies. Raises Unestablished when malformed."""
    level = 0
    for signal in values(coalesce(prop(state, "riskSignals"), {})):
        if not strict_eq(opt(signal, "tenant"), prop(actor, "tenant")) or not strict_eq(prop(signal, "principal"), prop(actor, "id")):
            continue
        rank = index_of(RISK_LEVELS, prop(signal, "level"))
        if rank < 0 or not safe_number(prop(signal, "expiresAt")):
            raise Unestablished("risk")
        if lt(now, prop(signal, "expiresAt")):
            level = max(level, rank)
    if level == 0:
        return len(LEVELS) - 1
    found = get(coalesce(prop(state, "settings"), {}), prop(actor, "tenant"))
    caps = prop(found, "riskCaps") if strict_eq(opt(found, "tenant"), prop(actor, "tenant")) else UNDEF
    if caps is not UNDEF and not isinstance(caps, dict):
        raise Unestablished("risk")
    limit = len(LEVELS) - 1
    for rank, name in enumerate(RISK_LEVELS):
        if rank > level:
            break
        cap = "deny" if name == "critical" else (caps[name] if isinstance(caps, dict) and name in caps else DEFAULT_RISK_CAPS[name])
        idx = -1 if strict_eq(cap, "deny") else index_of(LEVELS, cap)
        if not strict_eq(cap, "deny") and idx < 0:
            raise Unestablished("risk")
        limit = min(limit, idx)
    return limit


def close_roles(state, tenant, seeds):
    """Closure over the role hierarchy (R22): None when cyclic, over 64 roles or deeper than 16."""
    held, height, path = set(), {}, set()

    def visit(name):
        if not isinstance(name, str) or not name:
            raise Unestablished("role")
        found = get(prop(state, "roles"), name)
        role = found if strict_eq(opt(found, "tenant"), tenant) else UNDEF
        if truthy(role) and prop(role, "active") is not True:
            return 0
        if name in path:
            raise Unestablished("cycle")
        if name in height:
            return height[name]
        held.add(name)
        if len(held) > LIMITS["roles"]:
            raise Unestablished("budget")
        path.add(name)
        h = 1
        if truthy(role) and not is_array(prop(role, "inherits")):
            raise Unestablished("role")
        juniors = coalesce(opt(role, "inherits"), [])
        for junior in iterate(juniors):
            h = max(h, 1 + visit(junior))
        path.discard(name)
        if h > LIMITS["roleDepth"]:
            raise Unestablished("depth")
        height[name] = h
        return h

    try:
        for seed in seeds:
            visit(seed)
        return held
    except (Unestablished, TypeError, KeyError, RecursionError):
        return None


def effective_roles(state, actor):
    """Direct roles plus roles of active same-tenant groups, closed over the hierarchy; None if unestablished."""
    try:
        seeds = []
        for g in values(prop(state, "groups")):
            if not strict_eq(prop(g, "tenant"), prop(actor, "tenant")):
                continue
            if not is_array(prop(g, "members")) or not is_array(prop(g, "roles")):
                raise Unestablished("group")
            if prop(g, "active") is True and includes(prop(g, "members"), prop(actor, "id")):
                seeds.append(g)
        roles = prop(actor, "roles")
        if not is_array(roles):
            return None
        return close_roles(state, prop(actor, "tenant"), list(roles) + [r for g in seeds for r in prop(g, "roles")])
    except (Unestablished, TypeError, KeyError, RecursionError):
        return None


def session_roles(state, user, held, grant):
    """Activated roles and their juniors (R24), else every effective role; None when not a subset."""
    active = prop(grant, "activeRoles")
    if active is UNDEF:
        return set(held)
    if not is_array(active) or not all(isinstance(r, str) and r in held for r in active):
        return None
    return close_roles(state, prop(user, "tenant"), active)


def sod_violated(state, tenant, kind, roles):
    """True when the role set meets a constraint of this kind; a malformed constraint fails closed (R26)."""
    for c in values(prop(state, "constraints")):
        if not strict_eq(prop(c, "tenant"), tenant):
            continue
        cardinality = prop(c, "cardinality")
        if not includes(["static", "dynamic"], prop(c, "kind")) or not safe_integer(cardinality) or cardinality < 2 or not is_array(prop(c, "roles")):
            return True
        if strict_eq(prop(c, "kind"), kind) and len(unique([r for r in prop(c, "roles") if _has(roles, r)])) >= cardinality:
            return True
    return False


def standing_roles(state, actor):
    roles = effective_roles(state, actor)
    return roles if roles is not None and not sod_violated(state, prop(actor, "tenant"), "static", roles) else None


def count_sod_holders(state, tenant, constraints, role=None):
    view = dict(state, roles=dict(prop(state, "roles"), **{role["id"]: role})) if role else state
    holders = 0
    for actor in values(prop(state, "actors")):
        if not strict_eq(prop(actor, "tenant"), tenant) or prop(actor, "active") is not True:
            continue
        roles = effective_roles(view, actor)
        if roles is None:
            return "unknown"
        if any(len(unique([r for r in c["roles"] if _has(roles, r)])) >= c["cardinality"] for c in constraints):
            holders += 1
    return holders


def container_chain(state, k):
    """Ancestor chain, nearest first (R27); None when missing, cyclic, cross-tenant, too deep or malformed."""
    chain = []
    cid = prop(k, "container")
    while cid is not UNDEF:
        if not valid_id(cid) or len(chain) >= LIMITS["containerDepth"] or any(strict_eq(prop(c, "id"), cid) for c in chain):
            return None
        c = get(prop(state, "containers"), cid)
        if not truthy(c) or not strict_eq(prop(c, "tenant"), prop(k, "tenant")) or not strict_eq(prop(c, "id"), cid):
            return None
        kind, parent = prop(c, "kind"), prop(c, "parent")
        if not (parent is UNDEF if strict_eq(kind, "knowledge-base") else strict_eq(kind, "folder") and parent is not UNDEF):
            return None
        chain.append(c)
        cid = parent
    return chain


def effective_label(state, k):
    """Highest classification, union of projects, every ancestor ACL (R27); None when not established."""
    chain = container_chain(state, k)
    levels = [level_of(prop(x, "classification")) for x in [k] + (chain or [])]
    if chain is None or any(level < 0 for level in levels) or not includes(ORIGINS, prop(k, "origin")):
        return None
    nodes = [k] + chain
    return {"classification": LEVELS[max(levels)],
            "projects": sort_default(unique(flat_map(nodes, lambda x: prop(x, "projects")))),
            "audiences": [{"readers": list(iterate(prop(x, "readers"))), "readerRoles": list(iterate(prop(x, "readerRoles")))} for x in nodes],
            "containers": [prop(c, "id") for c in chain]}


def transitive_classification(state, root):
    """Highest effective classification over an object and every transitive source (R25); None if unknown."""
    done, visiting = {}, set()
    counters = {"nodes": 0, "edges": 0}

    def visit(k, depth):
        kk = key(prop(k, "id"))
        if depth >= LIMITS["path"] or kk in visiting:
            raise Unestablished("cycle")
        if kk in done:
            return done[kk]
        counters["nodes"] += 1
        label = effective_label(state, k) if counters["nodes"] <= LIMITS["nodes"] else None
        if label is None or not is_array(prop(k, "sources")):
            raise Unestablished("label")
        level = level_of(label["classification"])
        visiting.add(kk)
        for ref in prop(k, "sources"):
            counters["edges"] += 1
            if counters["edges"] > LIMITS["edges"] or not valid_id(opt(ref, "id")):
                raise Unestablished("budget")
            source = get(prop(state, "knowledge"), prop(ref, "id"))
            if not truthy(source) or not strict_eq(prop(source, "tenant"), prop(k, "tenant")) or not strict_eq(prop(source, "version"), prop(ref, "version")):
                raise Unestablished("source")
            level = max(level, visit(source, depth + 1))
        visiting.discard(kk)
        done[kk] = level
        return level

    try:
        level = visit(root, 0)
        return LEVELS[level] if 0 <= level < len(LEVELS) else None
    except (Unestablished, TypeError, KeyError, RecursionError):
        return None


def principal_tokens(state, actor, active_roles=UNDEF):
    held = standing_roles(state, actor)
    if held is None:
        return None
    if truthy(active_roles):
        roles = close_roles(state, prop(actor, "tenant"), active_roles) if every(active_roles, lambda r: _has(held, r)) else False
    else:
        roles = held
    if roles is None or roles is False:
        return None
    return ([f"user:{prop(actor, 'id')}"] + [f"role:{r}" for r in sort_default(list(roles))]
            + [f"project:{to_string(p)}" for p in sort_default(iterate(prop(actor, "projects")))])


def effective_clearance(user, agent):
    level = min(level_of(prop(user, "clearance")), level_of(prop(agent, "clearance")))
    return LEVELS[level] if level >= 0 else None


def context_fresh(state, c, now, revision):
    """A context is usable only in its tenant's current epoch, under the current revision, before expiry (R13)."""
    epoch = coalesce(index(prop(state, "epochs"), prop(c, "tenant")), 0)
    return (prop(c, "active") is True and strict_eq(prop(c, "epoch"), epoch) and strict_eq(prop(c, "policyVersion"), revision)
            and safe_number(now) and lt(now, prop(c, "expiresAt")))


def destination_list(x):
    """A well-formed grant destination list: 1..64 distinct ids (destination classes are ids too)."""
    return is_array(x) and 1 <= len(x) <= 64 and all(valid_id(v) for v in x) and len(set(x)) == len(x)


def _heartbeat_live(grant, now):
    """R147: a heartbeat-bound grant is valid while its last heartbeat is younger than its TTL and not in the future."""
    ttl = prop(grant, "heartbeatTtlMs")
    if ttl is UNDEF:
        return True
    last = prop(grant, "lastHeartbeatAt")
    return (safe_integer(ttl) and HEARTBEAT["minTtlMs"] <= ttl <= HEARTBEAT["maxTtlMs"]
            and safe_integer(last) and last <= now and now - last < ttl)


def _break_glass_shape(grant):
    """R149: read only, 1..64 named resources, at most two hours, a root grant."""
    flag = prop(grant, "breakGlass")
    if flag is UNDEF:
        return True
    actions, resources = prop(grant, "actions"), prop(grant, "resources")
    return (flag is True and prop(grant, "parent") is UNDEF and is_array(actions) and len(actions) == 1 and strict_eq(actions[0], "read")
            and is_array(resources) and 1 <= len(resources) <= BREAK_GLASS["resources"] and all(valid_id(x) for x in resources)
            and prop(grant, "expiresAt") - prop(grant, "notBefore") <= BREAK_GLASS["maxTtlMs"])


def _grant_valid(state, grant, now, seen):
    actors = prop(state, "actors")
    subject, agent = get(actors, prop(grant, "subject")), get(actors, prop(grant, "agent"))
    if (not truthy(opt(subject, "active")) or not truthy(opt(agent, "active")) or not strict_eq(prop(subject, "kind"), "user")
            or not strict_eq(prop(agent, "kind"), "agent") or not strict_eq(prop(subject, "tenant"), prop(grant, "tenant"))
            or not strict_eq(prop(agent, "tenant"), prop(grant, "tenant"))):
        return False
    gid = prop(grant, "id")
    if (key(gid) in seen or len(seen) >= LIMITS["grants"] or not truthy(prop(grant, "active")) or not safe_integer(now)
            or not safe_integer(prop(grant, "notBefore")) or not safe_integer(prop(grant, "expiresAt"))
            or now < prop(grant, "notBefore") or now >= prop(grant, "expiresAt") or not truthy(prop(prop(grant, "actions"), "length"))
            or some(prop(grant, "actions"), lambda a: not includes(ACTIONS, a))):
        return False
    active = prop(grant, "activeRoles")
    if active is not UNDEF and (not is_array(active) or len(active) > LIMITS["roles"] or any(not isinstance(r, str) or not r for r in active)):
        return False
    destinations = prop(grant, "destinations")
    if destinations is not UNDEF and not destination_list(destinations):
        return False
    limit = prop(grant, "maxResults")
    if limit is not UNDEF and not (safe_integer(limit) and 1 <= limit <= MAX_RESULTS):
        return False
    if not _heartbeat_live(grant, now) or not _break_glass_shape(grant):
        return False
    seen.add(key(gid))
    if not truthy(prop(grant, "parent")):
        return True
    parent = get(prop(state, "grants"), prop(grant, "parent"))
    if not truthy(parent) or not strict_eq(prop(parent, "tenant"), prop(grant, "tenant")) or not strict_eq(prop(parent, "subject"), prop(grant, "subject")):
        return False
    # A break-glass grant is never delegated (R149); a heartbeat-bound parent needs a child bound at most as long (R147).
    if prop(grant, "breakGlass") is not UNDEF or prop(parent, "breakGlass") is not UNDEF:
        return False
    parent_ttl = prop(parent, "heartbeatTtlMs")
    if parent_ttl is not UNDEF and not (prop(grant, "heartbeatTtlMs") is not UNDEF and le(prop(grant, "heartbeatTtlMs"), parent_ttl)):
        return False
    if not (subset(prop(grant, "actions"), prop(parent, "actions")) and subset(prop(grant, "resources"), prop(parent, "resources"))
            and subset(prop(grant, "purposes"), prop(parent, "purposes"))):
        return False
    if not ge(prop(grant, "notBefore"), prop(parent, "notBefore")) or not le(prop(grant, "expiresAt"), prop(parent, "expiresAt")):
        return False
    parent_active = prop(parent, "activeRoles")
    if parent_active is not UNDEF and not (active is not UNDEF and every(active, lambda r: includes(parent_active, r))):
        return False
    # Destinations and result limits only narrow (R68): a restricted parent needs a restricted child.
    parent_destinations = prop(parent, "destinations")
    if parent_destinations is not UNDEF and not (destinations is not UNDEF and every(destinations, lambda d: includes(parent_destinations, d))):
        return False
    parent_limit = prop(parent, "maxResults")
    if parent_limit is not UNDEF and not (limit is not UNDEF and le(limit, parent_limit)):
        return False
    return _grant_valid(state, parent, now, seen)


def grant_valid(state, grant, now):
    """Delegation-chain validity: liveness, time, attenuation, session-role, destination and result-limit narrowing."""
    return _grant_valid(state, grant, now, set())


def valid_grant_chain(state, grant, now):
    try:
        return grant_valid(state, grant, now)
    except (TypeError, KeyError, RecursionError):
        return False


def ephemeral_live(k, now, run=UNDEF):
    """R190: a session-scoped record is live only while well-formed, before expiry and, when a run is given, for that run."""
    e = prop(k, "ephemeral")
    if e is UNDEF:
        return True
    return (exact_keys(e, ["sessionId", "run", "expiresAt"]) and valid_id(e["sessionId"]) and valid_id(e["run"]) and safe_number(e["expiresAt"])
            and safe_number(now) and now < e["expiresAt"] and (run is UNDEF or strict_eq(e["run"], run)))


def visible(state, actor, r, now, roles=None, open_=False, risk=True, run=UNDEF):
    """Memoized DAG traversal (R25-R28, R45): every node and every ancestor container must admit the actor.

    Any lifecycle value (quarantined, erased or unknown) hides the node and, through the
    traversal, every record derived from it (R-LIFE-1; review finding #1).
    """
    held = roles if roles is not None else standing_roles(state, actor)
    if held is None:
        return False
    try:
        limit = risk_limit(state, actor, now) if risk else len(LEVELS) - 1
    except (TypeError, KeyError, RecursionError, Unestablished):
        return False
    visiting, completed, admitted = set(), {}, {}
    counters = {"nodes": 0, "edges": 0}
    path = LIMITS["path"]

    def contained(resource):
        chain = container_chain(state, resource)
        if chain is None:
            return False
        for c in chain:
            ck = key(prop(c, "id"))
            if ck not in admitted:
                admitted[ck] = prop(c, "active") is True and audience(actor, held, c, limit, open_)
            if not admitted[ck]:
                return False
        return True

    def visit(resource, depth):
        rk = key(prop(resource, "id"))
        if depth >= path or rk in visiting:
            return False
        if rk in completed:
            return depth + completed[rk] <= path
        counters["nodes"] += 1
        expires = prop(resource, "accessExpiresAt")
        version = prop(resource, "version")
        if (counters["nodes"] > LIMITS["nodes"] or not truthy(prop(resource, "active")) or prop(resource, "lifecycle") is not UNDEF
                or prop(resource, "unreadable") is not UNDEF
                or not safe_number(version) or version < 1 or not includes(ORIGINS, prop(resource, "origin"))
                or (expires is not UNDEF and (not safe_number(expires) or now >= expires))
                or not ephemeral_live(resource, now, run)
                or not audience(actor, held, resource, limit, open_) or not contained(resource)):
            return False
        visiting.add(rk)
        height = 1
        for ref in iterate(prop(resource, "sources")):
            counters["edges"] += 1
            if counters["edges"] > LIMITS["edges"] or not valid_id(prop(ref, "id")):
                return False
            source = get(prop(state, "knowledge"), prop(ref, "id"))
            if not truthy(source) or not strict_eq(prop(source, "version"), prop(ref, "version")) or not visit(source, depth + 1):
                return False
            height = max(height, 1 + completed[key(prop(source, "id"))])
        visiting.discard(rk)
        completed[rk] = height
        return depth + height <= path

    try:
        return safe_number(now) and visit(r, 0)
    except (TypeError, KeyError, RecursionError, Unestablished):
        return False


def lineage_live(state, root, now):
    """A record and every transitive source are active, not in a lifecycle state, not expired and resolvable."""
    done, visiting = set(), set()
    counters = {"nodes": 0, "edges": 0}

    def visit(k, depth):
        kk = key(prop(k, "id"))
        counters["nodes"] += 1
        if depth >= LIMITS["path"] or kk in visiting or counters["nodes"] > LIMITS["nodes"]:
            return False
        if kk in done:
            return True
        expires = prop(k, "accessExpiresAt")
        if (prop(k, "active") is not True or prop(k, "lifecycle") is not UNDEF or prop(k, "unreadable") is not UNDEF or not is_array(prop(k, "sources")) or not ephemeral_live(k, now)
                or (expires is not UNDEF and (not safe_number(expires) or now >= expires))):
            return False
        visiting.add(kk)
        for ref in prop(k, "sources"):
            counters["edges"] += 1
            if counters["edges"] > LIMITS["edges"] or not valid_id(opt(ref, "id")):
                return False
            source = get(prop(state, "knowledge"), prop(ref, "id"))
            if (not truthy(source) or not strict_eq(prop(source, "tenant"), prop(k, "tenant"))
                    or not strict_eq(prop(source, "version"), prop(ref, "version")) or not visit(source, depth + 1)):
                return False
        visiting.discard(kk)
        done.add(kk)
        return True

    try:
        return safe_number(now) and visit(root, 0)
    except (TypeError, KeyError, RecursionError):
        return False


def decide(state, request):
    """No I/O and no model output: identical authoritative snapshots give identical decisions (R29)."""
    try:
        return _evaluate(state, request)
    except (TypeError, KeyError, AttributeError, ValueError, RecursionError, Unestablished):
        return defer("INVALID_CONTEXT")


def _evaluate(state, request):
    b = prop(request, "binding")
    resource, action, purpose, now = prop(request, "resource"), prop(request, "action"), prop(request, "purpose"), prop(request, "now")
    if (not exact_keys(request, ["binding", "resource", "action", "purpose", "now"])
            or not exact_keys(b, ["tenant", "subject", "agent", "grant"]) or not all(valid_id(v) for v in b.values())
            or not valid_id(resource) or not includes(ACTIONS, action) or not isinstance(purpose, str) or not purpose
            or utf16_length(purpose) > 128 or not safe_number(now)):
        return defer("INVALID_REQUEST")
    actors = prop(state, "actors")
    user, agent = get(actors, b["subject"]), get(actors, b["agent"])
    grant, r = get(prop(state, "grants"), b["grant"]), get(prop(state, "knowledge"), resource)
    if not truthy(user) or not truthy(agent) or not truthy(grant) or not truthy(r):
        return defer("NOT_AUTHORIZED")
    if (not strict_eq(prop(user, "kind"), "user") or not strict_eq(prop(agent, "kind"), "agent") or not truthy(prop(user, "active"))
            or not truthy(prop(agent, "active"))
            or any(not strict_eq(prop(x, "tenant"), b["tenant"]) for x in (user, agent, grant, r))):
        return deny("IDENTITY_BOUNDARY")
    if not strict_eq(prop(grant, "subject"), prop(user, "id")) or not strict_eq(prop(grant, "agent"), prop(agent, "id")) or not grant_valid(state, grant, now):
        return deny("INVALID_DELEGATION")
    if not includes(prop(grant, "actions"), action) or not subset([resource], prop(grant, "resources")) or not subset([purpose], prop(grant, "purposes")):
        return deny("OUT_OF_SCOPE")
    # Declassification is not implemented in the reference profile.
    if action == "declassify":
        return deny("UNSUPPORTED_OBLIGATION")
    user_roles, agent_roles = effective_roles(state, user), effective_roles(state, agent)
    if user_roles is None or agent_roles is None:
        return defer("INVALID_CONTEXT")
    session = session_roles(state, user, user_roles, grant)
    if session is None:
        return deny("INVALID_DELEGATION")
    # Dynamic SoD applies to the activated set; without activation every held role is active.
    tenant = b["tenant"]
    if sod_violated(state, tenant, "static", user_roles) or sod_violated(state, tenant, "static", agent_roles) or sod_violated(state, tenant, "dynamic", session):
        return deny("SOD_VIOLATION")
    if not includes(ORIGINS, prop(r, "origin")) or container_chain(state, r) is None:
        return defer("INVALID_CONTEXT")
    # Risk caps (R151): critical denies outright; otherwise the cap lowers the clearance in visible().
    top = len(LEVELS) - 1
    risky = risk_limit(state, user, now) < top or risk_limit(state, agent, now) < top
    if risk_limit(state, user, now) < 0 or risk_limit(state, agent, now) < 0:
        return deny("RISK_CAP")
    # A valid break-glass grant lifts the audience clauses only (R149).
    open_ = prop(grant, "breakGlass") is True
    # R190: a session-scoped record (and anything derived from one) is visible to its own run only.
    run = b["grant"]
    if not visible(state, user, r, now, session, open_, True, run) or not visible(state, agent, r, now, agent_roles, open_, True, run):
        if risky and visible(state, user, r, now, session, open_, False, run) and visible(state, agent, r, now, agent_roles, open_, False, run):
            return deny("RISK_CAP")
        return deny("KNOWLEDGE_BOUNDARY")
    return dict(ALLOW)


def can_delegate(state, parent, child, now):
    grants = dict(prop(state, "grants"))
    grants[prop(child, "id")] = child
    nxt = dict(state, grants=grants)
    agent = get(prop(nxt, "actors"), prop(child, "agent"))
    return (not strict_eq(prop(child, "id"), prop(parent, "id")) and strict_eq(prop(child, "parent"), prop(parent, "id"))
            and strict_eq(prop(child, "tenant"), prop(parent, "tenant")) and strict_eq(prop(child, "subject"), prop(parent, "subject"))
            and truthy(agent) and strict_eq(prop(agent, "tenant"), prop(child, "tenant")) and strict_eq(prop(agent, "kind"), "agent")
            and truthy(prop(agent, "active")) and grant_valid(nxt, child, now))


# Destination gate (R-DEST-3..7, ADR-008).

def target_of(actor):
    if prop(actor, "destination") is not UNDEF:
        return {"kind": "profile", "id": prop(actor, "destination")}
    return {"kind": "implicit-user"} if strict_eq(prop(actor, "kind"), "user") else {"kind": "none"}


def evaluation_target_named(action, destination=UNDEF):
    """0.6 R121: a read-only share/export evaluation must name the Destination the enforcement point sends to."""
    return (action != "share" and action != "export") or destination is not UNDEF


def destination_gate(state, grant, target, tenant, top, purpose):
    """Pure destination gate of share/export: {"ok": False} or {"ok": True, "restrict"?, "destination"?}."""
    try:
        restrict = prop(grant, "destinations")
        if restrict is not UNDEF and not destination_list(restrict):
            return {"ok": False}
        if not top or not includes(LEVELS, top):
            return {"ok": False}
        kind = target["kind"]
        if kind == "profile":
            tid = target["id"]
            d = get(coalesce(prop(state, "destinations"), {}), tid)
            if (not truthy(d) or not valid_id(tid) or tid in DESTINATION_CLASSES or not strict_eq(prop(d, "id"), tid)
                    or not strict_eq(prop(d, "tenant"), tenant) or prop(d, "active") is not True
                    or not includes(DESTINATION_CLASSES, prop(d, "class")) or not includes(LEVELS, prop(d, "maxClassification"))
                    or not is_array(prop(d, "purposes"))):
                return {"ok": False}
            if restrict is not UNDEF and not includes(restrict, d["class"]) and not includes(restrict, d["id"]):
                return {"ok": False}
            if LEVELS.index(top) > LEVELS.index(d["maxClassification"]) or not includes(d["purposes"], purpose):
                return {"ok": False}
            return {"ok": True, "restrict": [d["class"], d["id"]], "destination": {"id": d["id"], "class": d["class"]}}
        if kind == "implicit-user":
            if restrict is not UNDEF and not includes(restrict, "internal-user"):
                return {"ok": False}
            return {"ok": True, "restrict": ["internal-user"], "destination": {"class": "internal-user"}} if restrict is not UNDEF else {"ok": True}
        if kind == "none":
            return {"ok": False} if restrict is not UNDEF else {"ok": True}
        if kind == "unspecified":
            return {"ok": True, "restrict": list(restrict)} if restrict is not UNDEF else {"ok": True}
        return {"ok": False}
    except (TypeError, KeyError, ValueError):
        return {"ok": False}


def top_level(state, ids):
    """Highest transitive effective classification over these records (R25); None when not established."""
    top = 0
    knowledge = prop(state, "knowledge")
    for rid in ids:
        record = get(knowledge, rid)
        level = transitive_classification(state, record) if record is not UNDEF else None
        if not level:
            return None
        top = max(top, LEVELS.index(level))
    return LEVELS[top]


__all__ = ["decide", "visible", "grant_valid", "valid_grant_chain", "effective_roles", "session_roles", "sod_violated", "standing_roles",
           "container_chain", "effective_label", "transitive_classification", "principal_tokens", "effective_clearance", "context_fresh",
           "can_delegate", "target_of", "ephemeral_live", "destination_gate", "evaluation_target_named", "top_level", "lineage_live", "count_sod_holders", "subset"]
