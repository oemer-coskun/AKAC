"""Operation-level decisions over one tenant snapshot: evaluate, open, retrieve, derive, release, delegate, revoke.

These are the gates of the specification (R29-R45, R60-R70 destinations, R100-R112
runtime containment) composed exactly as an AKAC gateway applies them, including
the core obligations: audit_level full from confidential, no_persist from
restricted, max_context_ttl_ms for disclosures, destination_restricted, and the
runtime_profile / max_output_classification obligations derived from the tenant's
runtime profile policies. There is no transport, persistence or audit writer here:
an operation mutates the snapshot it is given (contexts, derived records, grants,
epochs) and returns its decision. No supplemental policy hook is modelled.

Every result is {"ok", "code", "category"?, "obligations", "value"?, "audited"}.
`audited` is False for requests the gateway refuses before any tenant transaction.
"""
import copy
import math
import re
import uuid

from .containment import containment, containment_across
from .decision import OBLIGATION_TYPES, classify, merge, unsatisfiable
from .js import (UNDEF, coalesce, get, gt, has_own, index, is_array, iterate, key, le, opt, prop, safe_integer, strict_eq, to_number, to_string,
                 truthy, unique, utf16_length, values)
from .policy import (DESTINATION_CLASSES, LEVELS, can_delegate, context_fresh, decide, destination_gate, effective_clearance,
                     effective_label, evaluation_target_named, principal_tokens, standing_roles, target_of, top_level, transitive_classification, visible)
from .validation import valid_id
from .knowledge import (KNOWLEDGE, MODALITIES, combination, facts_of, lineage_depth_of, placement_allowed, residency_admits, session_of,
                        sorted_residency, sorted_tags, valid_model)
from .policy import container_chain, subset

CORE_VERSION = "akac-reference/0.6.0"
RETRIEVAL = {"corpus": 1000, "candidates": 100, "contentBytes": 64 * 1024 * 1024}
# Combination window (0.6b, R188): the maximum context lifetime.
COMBINATION_WINDOW_MS = 300_000
RANK = {"confidential": 2, "restricted": 3}
# ECMAScript \s (WhiteSpace and LineTerminator).
_WS = "".join(chr(c) for c in [9, 10, 11, 12, 13, 32, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF])
_SPLIT = re.compile("[" + re.escape(_WS) + "]+")


def locale_key(s):
    """Approximates the root collation used to order ids: punctuation < digits < letters, case-insensitive first."""
    s = to_string(s)
    primary, tertiary = [], []
    for ch in s:
        if ch.isdigit():
            primary.append((1, ch))
        elif ch.isalpha():
            primary.append((2, ch.lower()))
        else:
            primary.append((0, ch))
        tertiary.append(0 if not ch.isalpha() or ch.islower() else 1)
    return (tuple(primary), tuple(tertiary), s)


def _fail(reason):
    return {"ok": False, "reason": reason}


def _reason_of(d):
    return "AUTHORIZED" if d["effect"] == "allow" else f"{'DEFERRED' if d.get('category') == 'defer' else 'DENIED'}:{d['code']}"


def _same(a, b):
    return all(strict_eq(prop(a, k), prop(b, k)) for k in ("tenant", "subject", "agent", "grant"))


def binding_valid(b):
    return truthy(b) and isinstance(b, dict) and all(valid_id(b.get(k, UNDEF)) for k in ("tenant", "subject", "agent", "grant"))


def _restrict_to(obligations, restrict):
    if restrict is None:
        return obligations
    merged = merge(obligations, [{"type": "destination_restricted", "value": restrict}])
    return None if unsatisfiable(merged) else merged


def _admits(obligations, names):
    return all(o["type"] != "destination_restricted" or any(v in names for v in o["value"]) for o in obligations)


def _js_min(*xs):
    nums = [to_number(x) for x in xs]
    if any(type(n) is float and math.isnan(n) for n in nums):
        return math.nan
    return min(nums)


class Engine:
    """Gateway decisions over one snapshot at a fixed clock. `candidates`: an untrusted candidate list (indexed retrieval)."""

    def __init__(self, state, now, core_version=CORE_VERSION, memory_review="none", candidates=None, ids=None, unenforceable=None, model=None):
        self.s, self.now, self.core_version = state, now, core_version
        # Trusted model identity recorded on derived content (R191); operator configuration, never request data.
        self.model = model
        # Obligation types the calling enforcement point cannot enforce (0.6 R123): an allow carrying one is
        # refused (UNSUPPORTED_OBLIGATION) and nothing of the operation persists. A malformed value refuses every allow.
        self.unenforceable = unenforceable
        self.memory_review = "none" if memory_review == "none" else "quarantine"
        self.candidates = candidates
        self._ids = ids or (lambda: str(uuid.uuid4()))

    def revision(self):
        return f"{self.core_version}|{to_string(prop(self.s, 'policyVersion'))}|core-only"

    # Outcome helpers.
    def _finish(self, outcome):
        if outcome["ok"]:
            reason = outcome.get("reason", "AUTHORIZED")
            return {"ok": True, "code": classify(reason)["code"], "obligations": outcome["obligations"], "value": outcome.get("value"), "audited": True}
        c = classify(outcome["reason"])
        return {"ok": False, "code": c["code"], "category": c["category"], "obligations": [], "audited": True}

    @staticmethod
    def _bad():
        return {"ok": False, "code": "NOT_AUTHORIZED", "obligations": [], "audited": False}

    def _obligations(self, ids, policy, ttl=None):
        level = top_level(self.s, ids)
        if not level:
            return None
        top = LEVELS.index(level)
        own = []
        if top >= RANK["confidential"]:
            own.append({"type": "audit_level", "value": "full"})
        if top >= RANK["restricted"]:
            own.append({"type": "no_persist"})
        if ttl is not None:
            own.append({"type": "max_context_ttl_ms", "value": max(1, ttl)})
        merged = merge(own, policy)
        return None if unsatisfiable(merged) else merged

    def _contain(self, tenant, ids, obligations, destination=None):
        level = top_level(self.s, ids)
        c = containment_across(self.s, tenant, level, destination) if isinstance(destination, list) else containment(self.s, tenant, level, destination)
        if not c["ok"]:
            return _fail(c["reason"])
        merged = merge(obligations, c["obligations"])
        return _fail("DENIED:UNSUPPORTED_OBLIGATION") if unsatisfiable(merged) else {"ok": True, "value": merged, "obligations": merged}

    def _reachable(self, b):
        restrict = opt_destinations(self.s, b)
        if restrict is UNDEF:
            return list(DESTINATION_CLASSES)
        classes = []
        destinations = coalesce(prop(self.s, "destinations"), None)
        for v in iterate(restrict):
            if v in DESTINATION_CLASSES:
                if v not in classes:
                    classes.append(v)
                continue
            d = destinations[v] if isinstance(destinations, dict) and isinstance(v, str) and v in destinations else UNDEF
            if (truthy(d) and strict_eq(prop(d, "id"), v) and strict_eq(prop(d, "tenant"), b["tenant"]) and prop(d, "active") is True
                    and prop(d, "class") in DESTINATION_CLASSES and prop(d, "class") not in classes):
                classes.append(prop(d, "class"))
        return classes

    def _authorize(self, b, resource, action, purpose):
        # 0.6b (R195): a record whose content could not be opened is a deferred denial.
        record = index(prop(self.s, "knowledge"), resource)
        if isinstance(record, dict) and "unreadable" in record:
            return {"effect": "deny", "code": "STORE_ERROR", "category": "defer"}
        return decide(self.s, {"binding": b, "resource": resource, "action": action, "purpose": purpose, "now": self.now})

    # Disclosure (R30-R34) and the run's result limit (R68).
    def _projection(self, b, ids, purpose):
        s = self.s
        if not ids or len(ids) > 64:
            return _fail("DEFERRED:INVALID_REQUEST")
        grant = index(prop(s, "grants"), b["grant"])
        cap = prop(grant, "maxResults") if grant is not UNDEF and grant is not None else UNDEF
        if cap is not UNDEF and len(unique(ids)) > to_number(cap):
            return _fail("DENIED:OUT_OF_SCOPE")
        existing = [c for c in values(prop(s, "contexts")) if _same(c, b)]
        if any(not context_fresh(s, c, self.now, self.revision()) for c in existing):
            return _fail("DENIED:STALE_CONTEXT")
        order = {key(i): i for i in ids}
        for c in existing:
            for ref in iterate(prop(c, "sources")):
                if not strict_eq(_version(s, prop(ref, "id")), prop(ref, "version")):
                    return _fail("DENIED:STALE_SOURCE")
                order.setdefault(key(prop(ref, "id")), prop(ref, "id"))
        every_id = list(order.values())
        if len(every_id) > 128:
            return _fail("DEFERRED:BUDGET_EXCEEDED")
        for rid in every_id:
            d = self._authorize(b, rid, "read", purpose)
            if d["effect"] != "allow":
                return _fail(_reason_of(d))
        # Combination rules (R188) over everything the run has read, this disclosure included, and (0.6b) everything the
        # same user and agent read under any other grant within the combination window (default 300 000 ms).
        across = {key(i): i for i in every_id}
        since = self.now - COMBINATION_WINDOW_MS
        for c in values(prop(s, "contexts")):
            if (not strict_eq(prop(c, "tenant"), b["tenant"]) or not strict_eq(prop(c, "subject"), b["subject"]) or not strict_eq(prop(c, "agent"), b["agent"])
                    or strict_eq(prop(c, "grant"), b["grant"]) or not gt(prop(c, "expiresAt"), since) or not is_array(prop(c, "sources"))):
                continue
            for ref in prop(c, "sources"):
                rid = opt(ref, "id")
                if valid_id(rid) and has_own(prop(s, "knowledge"), rid):
                    across.setdefault(key(rid), rid)
        combined = self._combined(b, list(across.values()))
        if combined is not None:
            return combined
        grant = index(prop(s, "grants"), b["grant"])
        cid = self._ids()
        expires = _js_min(prop(grant, "expiresAt"), self.now + 300_000, *[prop(c, "expiresAt") for c in existing])
        context = dict(b, id=cid, purpose=purpose,
                       sources=[{"id": k, "version": prop(get(prop(s, "knowledge"), k), "version")} for k in sorted(every_id, key=lambda x: to_string(x).encode("utf-16-be", "surrogatepass"))],
                       expiresAt=expires, epoch=coalesce(index(prop(s, "epochs"), b["tenant"]), 0), policyVersion=self.revision(), active=True)
        if self.now >= expires:
            return _fail("DENIED:EXPIRED")
        for rid in every_id:
            d = self._authorize(b, rid, "read", purpose)
            if d["effect"] != "allow":
                return _fail(_reason_of(d))
        core = self._obligations(every_id, [], expires - self.now)
        if core is None:
            return _fail("DEFERRED:INVALID_CONTEXT")
        contained = self._contain(b["tenant"], every_id, core)
        if not contained["ok"]:
            return contained
        s["contexts"][cid] = context
        knowledge = prop(s, "knowledge")
        documents = [{"id": knowledge[k]["id"], "version": knowledge[k]["version"], "content": knowledge[k]["content"]} for k in unique(ids)]
        return {"ok": True, "obligations": contained["value"], "value": {"context": cid, "expiresAt": expires, "documents": documents}}

    def _open_context_op(self, b, ids, purpose):
        if not binding_valid(b) or not is_array(ids) or len(ids) > 64 or not all(valid_id(i) for i in ids):
            return self._bad()
        return self._finish(self._projection(b, ids, purpose))

    def _retrieve_op(self, b, query, purpose, limit=5):
        if not binding_valid(b):
            return self._bad()
        valid = (isinstance(query, str) and bool(query.strip(_WS))
                 and utf16_length(query) <= 4096 and safe_integer(limit) and 1 <= limit <= 20)
        query = query if valid else ""
        return self._indexed(b, query, purpose, limit) if self.candidates is not None else self._lexical(b, query, purpose, limit)

    def _capped(self, b, limit):
        grants = prop(self.s, "grants")
        cap = prop(grants[b["grant"]], "maxResults") if has_own(grants, b["grant"]) else UNDEF
        return min(limit, cap) if safe_integer(cap) and cap >= 1 else limit

    def _lexical(self, b, query, purpose, limit):
        s = self.s
        if not query:
            return self._finish(_fail("DEFERRED:INVALID_REQUEST"))
        limit = self._capped(b, limit)
        candidates = [r for r in values(prop(s, "knowledge")) if strict_eq(prop(r, "tenant"), b["tenant"])]
        if len(candidates) > RETRIEVAL["corpus"]:
            return self._finish(_fail("DEFERRED:BUDGET_EXCEEDED"))
        size = sum(len(r["content"].encode("utf-8", "surrogatepass")) for r in candidates if isinstance(prop(r, "content"), str))
        if size > RETRIEVAL["contentBytes"]:
            return self._finish(_fail("DEFERRED:BUDGET_EXCEEDED"))
        eligible = [r for r in candidates if self._authorize(b, prop(r, "id"), "read", purpose)["effect"] == "allow"]
        terms = unique([t for t in _SPLIT.split(query.lower()) if t])
        scored = [(r, sum(1 for t in terms if t in r["content"].lower())) for r in eligible]
        scored = sorted([x for x in scored if x[1] > 0], key=lambda x: (-x[1], locale_key(x[0]["id"])))
        ids = [x[0]["id"] for x in scored[:limit]]
        return self._finish(self._projection(b, ids, purpose))

    def _indexed(self, b, query, purpose, limit):
        s = self.s
        probe = None
        if query:
            actors, grants = prop(s, "actors"), prop(s, "grants")
            user, agent, grant = index(actors, b["subject"]), index(actors, b["agent"]), index(grants, b["grant"])
            if truthy(user) and truthy(agent) and truthy(grant) and strict_eq(prop(user, "tenant"), b["tenant"]) and strict_eq(prop(agent, "tenant"), b["tenant"]):
                tokens, clearance = principal_tokens(s, user, prop(grant, "activeRoles")), effective_clearance(user, agent)
                probe = {"tokens": tokens, "maxClassification": clearance} if tokens and clearance else None
        ids, unavailable = [], False
        if probe:
            found = self.candidates
            if not is_array(found):
                unavailable = True
            else:
                ids = unique([x for x in found if valid_id(x)])[:RETRIEVAL["candidates"]]
        if not query:
            return self._finish(_fail("DEFERRED:INVALID_REQUEST"))
        if unavailable:
            return self._finish(_fail("DEFERRED:CANDIDATES_UNAVAILABLE"))
        limit = self._capped(b, limit)
        eligible = []
        for rid in ids:
            if len(eligible) >= limit:
                break
            if self._authorize(b, rid, "read", purpose)["effect"] == "allow":
                eligible.append(rid)
        return self._finish(self._projection(b, eligible, purpose))

    def _context_sources(self, b, context_id, action):
        s = self.s
        if not valid_id(context_id):
            return _fail("DEFERRED:INVALID_REQUEST")
        contexts = prop(s, "contexts")
        selected = contexts[context_id] if has_own(contexts, context_id) else UNDEF
        if not truthy(selected) or not _same(selected, b):
            return _fail("DEFERRED:NOT_AUTHORIZED")
        refs = {}
        for c in [c for c in values(contexts) if _same(c, b)]:
            if not context_fresh(s, c, self.now, self.revision()) or not strict_eq(prop(c, "purpose"), prop(selected, "purpose")):
                return _fail("DENIED:STALE_CONTEXT")
            for ref in iterate(prop(c, "sources")):
                if not strict_eq(_version(s, prop(ref, "id")), prop(ref, "version")):
                    return _fail("DENIED:STALE_SOURCE")
                d = self._authorize(b, prop(ref, "id"), action, prop(selected, "purpose"))
                if d["effect"] != "allow":
                    return _fail(_reason_of(d))
                refs[key(prop(ref, "id"))] = ref
        if not refs or le(prop(selected, "expiresAt"), self.now):
            return _fail("DENIED:EXPIRED")
        for ref in refs.values():
            d = self._authorize(b, prop(ref, "id"), action, prop(selected, "purpose"))
            if d["effect"] != "allow":
                return _fail(_reason_of(d))
        obligations = self._obligations([prop(r, "id") for r in refs.values()], [])
        if obligations is None:
            return _fail("DEFERRED:INVALID_CONTEXT")
        return {"ok": True, "value": sorted(refs.values(), key=lambda r: locale_key(prop(r, "id"))), "obligations": obligations}

    def _derive_op(self, b, context_id, content, kind="artifact", options=None):
        if not binding_valid(b):
            return self._bad()
        return self._finish(self._derive(b, context_id, content, kind, {} if options is None else options))

    def _combined(self, b, ids):
        facts = facts_of(self.s, ids)
        verdict = combination(self.s, b["tenant"], facts["tags"], facts["level"]) if facts is not None else None
        if verdict is None:
            return _fail("DEFERRED:INVALID_CONTEXT")
        return _fail("DENIED:COMBINATION") if verdict["deny"] else None

    def _semantics(self, b, ids, own, options):
        """Knowledge semantics of a derivation (R182..R192): the level the result carries at least and the fields it inherits."""
        s = self.s
        if not isinstance(options, dict):
            return _fail("DEFERRED:INVALID_REQUEST")
        modality, container, session = options.get("modality", UNDEF), options.get("container", UNDEF), options.get("session", UNDEF)
        if ((modality is not UNDEF and modality not in MODALITIES) or (container is not UNDEF and not valid_id(container))
                or (session is not UNDEF and not isinstance(session, dict))):
            return _fail("DEFERRED:INVALID_REQUEST")
        facts, depth = facts_of(s, ids), lineage_depth_of(s, b["tenant"])
        if facts is None or depth is None:
            return _fail("DEFERRED:INVALID_CONTEXT")
        if facts["generation"] + 1 > depth:
            return _fail("DENIED:LINEAGE_DEPTH")
        combo = combination(s, b["tenant"], facts["tags"], facts["level"])
        if combo is None:
            return _fail("DEFERRED:INVALID_CONTEXT")
        if combo["deny"]:
            return _fail("DENIED:COMBINATION")
        if len(facts["tags"]) > KNOWLEDGE["tags"] or (facts["residency"] is not None and len(facts["residency"]) > KNOWLEDGE["residency"]):
            return _fail("DEFERRED:BUDGET_EXCEEDED")
        model = self.model
        if model is not None and not valid_model(model):
            return _fail("DEFERRED:INVALID_CONTEXT")
        grant = index(prop(s, "grants"), b["grant"])
        requested = None
        if session is not UNDEF:
            requested = {"sessionId": session.get("id", UNDEF)}
            if "ttlMs" in session:
                requested["ttlMs"] = session["ttlMs"]
        scope = session_of(facts, b["grant"], self.now, grant["expiresAt"], requested)
        if not scope["ok"]:
            return _fail(scope["reason"])
        eph = scope.get("ephemeral")
        if eph is not None:
            live = [k for k in values(prop(s, "knowledge")) if isinstance(k, dict) and strict_eq(k.get("tenant", UNDEF), b["tenant"])
                    and isinstance(k.get("ephemeral"), dict) and safe_integer(k["ephemeral"].get("expiresAt")) and self.now < k["ephemeral"]["expiresAt"]]
            mine = [k for k in live if k["ephemeral"].get("run") == b["grant"] and k["ephemeral"].get("sessionId") == eph["sessionId"]]
            if len(live) + 1 > KNOWLEDGE["ephemeralTenant"] or len(mine) + 1 > KNOWLEDGE["ephemeralRecords"]:
                return _fail("DEFERRED:BUDGET_EXCEEDED")
        if container is not UNDEF:
            chain = container_chain(s, {"tenant": b["tenant"], "container": container})
            if chain is None:
                return _fail("DEFERRED:INVALID_REQUEST")
            if not subset([container], prop(grant, "resources")) or any(prop(c, "active") is not True for c in chain):
                return _fail("DENIED:OUT_OF_SCOPE")
            knowledge = prop(s, "knowledge")
            if not placement_allowed(s, b["tenant"], [knowledge[i] for i in ids], own, LEVELS[combo["level"]], container):
                return _fail("DENIED:WRITE_DOWN")
        fields = {}
        if facts["tags"]:
            fields["tags"] = sorted_tags(facts["tags"])
        residency = sorted_residency(facts["residency"])
        if residency is not None:
            fields["residency"] = residency
        if modality is not UNDEF:
            fields["modality"] = modality
        if model is not None:
            fields["model"] = {"id": model["id"], "version": model["version"]}
        if eph is not None:
            fields["ephemeral"] = eph
        if container is not UNDEF:
            fields["container"] = container
        return {"ok": True, "value": {"level": combo["level"], "fields": fields}, "obligations": []}

    def _derive(self, b, context_id, content, kind, options=None):
        options = {} if options is None else options
        s = self.s
        if not truthy(content) or gt(prop(content, "length"), 100_000) or kind not in ("memory", "artifact"):
            return _fail("DEFERRED:INVALID_REQUEST")
        refs = self._context_sources(b, context_id, "derive")
        if not refs["ok"]:
            return refs
        obligations = refs["obligations"]
        if kind == "memory":
            memory = self._context_sources(b, context_id, "write_memory")
            if not memory["ok"]:
                return memory
            obligations = merge(obligations, memory["obligations"])
            if unsatisfiable(obligations):
                return _fail("DENIED:UNSUPPORTED_OBLIGATION")
        ids = [prop(r, "id") for r in refs["value"]]
        contained = self._contain(b["tenant"], ids, obligations)
        if not contained["ok"]:
            return contained
        obligations = contained["value"]
        knowledge = prop(s, "knowledge")
        labels = [{"source": knowledge[i], "label": effective_label(s, knowledge[i]), "top": transitive_classification(s, knowledge[i])} for i in ids]
        if any(x["label"] is None or not x["top"] for x in labels):
            return _fail("DEFERRED:INVALID_CONTEXT")
        own = {"readers": unique([r for x in labels for r in _flat(prop(x["source"], "readers"))]),
               "readerRoles": unique([r for x in labels for r in _flat(prop(x["source"], "readerRoles"))]),
               "projects": unique([p for x in labels for p in x["label"]["projects"]])}
        extra = self._semantics(b, ids, own, options)
        if not extra["ok"]:
            return extra
        rid = self._ids()
        # Effective labels include container floors and every transitive source: derivation never lowers a classification (R35);
        # a combination uplift (R188) only raises it.
        classification = LEVELS[max([extra["value"]["level"]] + [LEVELS.index(x["top"]) for x in labels])]
        record = {"id": rid, "tenant": b["tenant"], "version": 1, "kind": kind, "origin": "model", "content": content,
                  "classification": classification,
                  "projects": sorted(unique([p for x in labels for p in x["label"]["projects"]]), key=lambda p: to_string(p).encode("utf-16-be", "surrogatepass")),
                  "readerRoles": unique([r for x in labels for r in _flat(prop(x["source"], "readerRoles"))]),
                  "readers": unique([r for x in labels for r in _flat(prop(x["source"], "readers"))]),
                  "sources": copy.deepcopy(refs["value"]), "active": True, **copy.deepcopy(extra["value"]["fields"])}
        retain = [prop(x["source"], "retainUntil") for x in labels if safe_integer(prop(x["source"], "retainUntil"))]
        if retain:
            record["retainUntil"] = min(retain)
        quarantined = kind == "memory" and self.memory_review != "none"
        if quarantined:
            record.update(lifecycle="quarantined", lifecycleAt=self.now, quarantineReason="memory_review")
        knowledge[rid] = record
        value = {"id": rid, "classification": classification, **({"quarantined": True} if quarantined else {})}
        eph = extra["value"]["fields"].get("ephemeral")
        if eph is not None:
            value["ephemeral"] = {"sessionId": eph["sessionId"], "expiresAt": eph["expiresAt"]}
        return {"ok": True, "value": value, "obligations": obligations, "reason": "PROTECTED_DERIVATION"}

    def _close_session_op(self, b, session_id):
        """R190: removes every session-scoped record of the caller's run and session; audited."""
        if not binding_valid(b):
            return self._bad()
        if not valid_id(session_id):
            return self._finish(_fail("DEFERRED:INVALID_REQUEST"))
        knowledge = prop(self.s, "knowledge")
        gone = [rid for rid, k in knowledge.items() if isinstance(k, dict) and strict_eq(k.get("tenant", UNDEF), b["tenant"])
                and isinstance(k.get("ephemeral"), dict) and k["ephemeral"].get("run") == b["grant"] and k["ephemeral"].get("sessionId") == session_id]
        for rid in gone:
            del knowledge[rid]
        return self._finish({"ok": True, "value": {"closed": len(gone)}, "obligations": []})

    def _release_op(self, b, context_id, recipient_id, content, action="share"):
        if not binding_valid(b):
            return self._bad()
        return self._finish(self._release(b, context_id, recipient_id, content, action))

    def _release(self, b, context_id, recipient_id, content, action):
        s = self.s
        actors = prop(s, "actors")
        recipient = actors[recipient_id] if valid_id(recipient_id) and has_own(actors, recipient_id) else UNDEF
        refs = self._context_sources(b, context_id, action)
        if not refs["ok"]:
            return refs
        ids = [prop(r, "id") for r in refs["value"]]
        knowledge = prop(s, "knowledge")
        if (not truthy(content) or gt(prop(content, "length"), 100_000) or not truthy(recipient)
                or not strict_eq(prop(recipient, "tenant"), b["tenant"]) or any(not visible(s, recipient, index(knowledge, i), self.now) for i in ids)):
            return _fail("DENIED:RECIPIENT")
        # Destination gate (R-DEST-3..7): everything released, with its transitive sources, against the recipient's profile and the run.
        target = target_of(recipient)
        gate = destination_gate(s, index(prop(s, "grants"), b["grant"]), target, b["tenant"], top_level(s, ids), prop(prop(s, "contexts")[context_id], "purpose"))
        if not gate["ok"]:
            return _fail("DENIED:RECIPIENT")
        # Residency (R187): content whose effective residency is set leaves only to a destination whose region is in it.
        scope = facts_of(s, ids)
        if scope is None:
            return _fail("DEFERRED:INVALID_CONTEXT")
        if not residency_admits(s, target, b["tenant"], scope["residency"]):
            return _fail("DENIED:RESIDENCY")
        obligations = _restrict_to(refs["obligations"], gate.get("restrict"))
        # A restriction from any origin must admit the actual recipient (R66).
        destination = gate.get("destination") or ({"class": "internal-user"} if target["kind"] == "implicit-user" else None)
        names = ([destination["class"]] + ([destination["id"]] if "id" in destination else [])) if destination else []
        if obligations is None or not _admits(obligations, names):
            return _fail("DENIED:RECIPIENT")
        restricted = any(o["type"] == "destination_restricted" for o in obligations)
        contained = self._contain(b["tenant"], ids, obligations, destination["class"] if destination else self._reachable(b))
        if not contained["ok"]:
            return contained
        value = {"recipient": recipient_id, "content": content, **({"destination": destination} if destination and (gate.get("destination") or restricted) else {})}
        return {"ok": True, "value": value, "obligations": contained["value"], "reason": "AUTHORIZED_RECIPIENT"}

    def _evaluate_op(self, b, resource, action, purpose, destination=UNDEF):
        """Read-only decision for an external enforcement point (AuthZEN, egress proxies): {"effect", "code", "category"?, "obligations"}."""
        if not binding_valid(b):
            return {"effect": "deny", "code": "INVALID_REQUEST", "obligations": [], "audited": False}
        outcome = self._evaluation(b, resource, action, purpose, destination)
        r = self._finish(outcome)
        out = {"effect": "allow" if r["ok"] else "deny", "code": r["code"], "obligations": r["obligations"], "audited": True}
        if not r["ok"]:
            out["category"] = r["category"]
        return out

    def _evaluation(self, b, resource, action, purpose, destination):
        s = self.s
        if destination is not UNDEF and not valid_id(destination):
            return _fail("DEFERRED:INVALID_REQUEST")
        d = self._authorize(b, resource, action, purpose)
        if d["effect"] != "allow":
            return _fail(_reason_of(d))
        combined = self._combined(b, [resource])
        if combined is not None:
            return combined
        obligations = self._obligations([resource], [])
        if obligations is None:
            return _fail("DEFERRED:INVALID_CONTEXT")
        if action not in ("share", "export") and destination is UNDEF:
            return self._contain(b["tenant"], [resource], obligations)
        # 0.6 R121: a share/export evaluation must name the Destination the enforcement point sends to.
        if not evaluation_target_named(action, destination) or destination is UNDEF:
            return _fail("DENIED:RECIPIENT")
        gate = destination_gate(s, index(prop(s, "grants"), b["grant"]), {"kind": "profile", "id": destination}, b["tenant"], top_level(s, [resource]), purpose)
        restricted = _restrict_to(obligations, gate.get("restrict")) if gate["ok"] and gate.get("destination") else None
        if restricted is None:
            return _fail("DENIED:RECIPIENT")
        # Residency (R187) against the named destination.
        scope = facts_of(s, [resource])
        if scope is None:
            return _fail("DEFERRED:INVALID_CONTEXT")
        if not residency_admits(s, {"kind": "profile", "id": destination}, b["tenant"], scope["residency"]):
            return _fail("DENIED:RESIDENCY")
        return self._contain(b["tenant"], [resource], restricted, gate["destination"]["class"])

    def _delegate_op(self, b, child):
        if not binding_valid(b) or not truthy(child) or not isinstance(child, (dict, list)) or not valid_id(prop(child, "id")):
            return self._bad()
        s = self.s
        grants, actors = prop(s, "grants"), prop(s, "actors")
        parent, user, agent = index(grants, b["grant"]), index(actors, b["subject"]), index(actors, b["agent"])
        # R147: a heartbeat-bound child starts alive at delegation; a caller-supplied heartbeat time is never kept.
        if isinstance(child, dict) and prop(child, "heartbeatTtlMs") is not UNDEF:
            child = dict(child, lastHeartbeatAt=self.now)
        if (has_own(grants, child["id"]) or not truthy(parent) or not strict_eq(prop(parent, "subject"), b["subject"])
                or not strict_eq(prop(parent, "agent"), b["agent"]) or not strict_eq(prop(parent, "tenant"), b["tenant"])
                or not truthy(_opt(user, "active")) or not truthy(_opt(agent, "active")) or not can_delegate(s, parent, child, self.now)):
            return self._finish(_fail("DENIED:INVALID_DELEGATION"))
        grants[child["id"]] = copy.deepcopy(child)
        return self._finish({"ok": True, "value": {"id": child["id"]}, "obligations": [], "reason": "ATTENUATED"})

    def _revoke_op(self, tenant, admin_id, kind, rid):
        """Control plane (security-admin): deactivates the target and advances only this tenant's epoch (R13)."""
        s = self.s
        if not valid_id(tenant):
            return self._bad()
        actors = prop(s, "actors")
        admin = actors[admin_id] if valid_id(admin_id) and has_own(actors, admin_id) else UNDEF
        roles = (standing_roles(s, admin) if strict_eq(_opt(admin, "kind"), "user") and truthy(prop(admin, "active"))
                 and strict_eq(prop(admin, "tenant"), tenant) else None)
        if roles is None or "security-admin" not in roles:
            return self._finish(_fail("DENIED:NOT_ADMIN"))
        collection = {"grant": prop(s, "grants"), "knowledge": prop(s, "knowledge"), "actor": actors}.get(kind, {})
        target = collection[rid] if valid_id(rid) and has_own(collection, rid) else UNDEF
        if not truthy(target) or not strict_eq(prop(target, "tenant"), tenant):
            return self._finish(_fail("DENIED:INVALID_REQUEST"))
        target["active"] = False
        epochs = s["epochs"]
        epochs[tenant] = coalesce(epochs.get(tenant, UNDEF), 0) + 1
        if kind == "knowledge" and coalesce(target.get("revokedAt", UNDEF), None) is None:
            target["revokedAt"] = self.now
        return self._finish({"ok": True, "value": {"epoch": epochs[tenant]}, "obligations": []})

    # Public operations. Each consumes one decision id first (the id of its audited decision), as a gateway does.
    def _run(self, fn, *args):
        self._ids()
        snapshot = copy.deepcopy(self.s) if self.unenforceable is not None else None
        r = fn(*args)
        refused = self.unenforceable is not None and r.get("ok", r.get("effect") == "allow") and r.get("audited", True) and (
            not isinstance(self.unenforceable, list) or not all(t in OBLIGATION_TYPES for t in self.unenforceable)
            or any(o["type"] in self.unenforceable for o in r["obligations"]))
        if not refused:
            return r
        self.s.clear()
        self.s.update(snapshot)
        if "effect" in r:
            return {"effect": "deny", "code": "UNSUPPORTED_OBLIGATION", "obligations": [], "audited": True, "category": "deny"}
        return {"ok": False, "code": "UNSUPPORTED_OBLIGATION", "category": "deny", "obligations": [], "audited": True}

    def open_context(self, b, ids, purpose):
        return self._run(self._open_context_op, b, ids, purpose)

    def retrieve(self, b, query, purpose, limit=5):
        return self._run(self._retrieve_op, b, query, purpose, limit)

    def derive(self, b, context_id, content, kind="artifact", options=None):
        return self._run(self._derive_op, b, context_id, content, kind, options)

    def close_session(self, b, session_id):
        return self._run(self._close_session_op, b, session_id)

    def release(self, b, context_id, recipient_id, content, action="share"):
        return self._run(self._release_op, b, context_id, recipient_id, content, action)

    def evaluate(self, b, resource, action, purpose, destination=UNDEF):
        return self._run(self._evaluate_op, b, resource, action, purpose, destination)

    def delegate(self, b, child):
        return self._run(self._delegate_op, b, child)

    def revoke(self, tenant, admin_id, kind, rid):
        return self._run(self._revoke_op, tenant, admin_id, kind, rid)


def _opt(obj, name):
    return UNDEF if obj is None or obj is UNDEF else prop(obj, name)


def _flat(x):
    return x if isinstance(x, list) else [x]


def _version(s, rid):
    record = index(prop(s, "knowledge"), rid)
    return UNDEF if record is None or record is UNDEF else prop(record, "version")


def opt_destinations(s, b):
    grant = index(prop(s, "grants"), b["grant"])
    return _opt(grant, "destinations")


# Tenant partitioning of a whole-state snapshot, as a store hands each transaction only its own tenant.
COLLECTIONS = ["actors", "grants", "knowledge", "contexts", "roles", "groups", "containers", "constraints", "destinations", "runtimeProfiles",
               "settings", "combinationRules"]


def blank_state(policy_version=CORE_VERSION):
    return {"schema": "akac-state/0.3", "policyVersion": policy_version, "epochs": {}, **{c: {} for c in COLLECTIONS}, "audits": []}


class Shards:
    """Per-tenant snapshots: each transaction sees and writes only its own tenant's records."""

    def __init__(self, state):
        self.policy_version = state.get("policyVersion", CORE_VERSION)
        self.shards = {}
        for collection in COLLECTIONS:
            for rid, record in (state.get(collection) or {}).items():
                tenant = to_string(record.get("tenant", UNDEF) if isinstance(record, dict) else UNDEF)
                self.tenant(tenant)[collection][rid] = record
        for tenant, epoch in state.get("epochs", {}).items():
            self.tenant(tenant)["epochs"][tenant] = epoch

    def tenant(self, tenant):
        if tenant not in self.shards:
            self.shards[tenant] = blank_state(self.policy_version)
        return self.shards[tenant]
