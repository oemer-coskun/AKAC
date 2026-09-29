"""Standalone conformance runner: every shared vector file, evaluated by this implementation only.

Outcomes follow spec/CONFORMANCE.md: SUCCESS, SAFE_BLOCK, FAILURE (expected allow,
denied, or a wrong code), UNSAFE_SUCCESS (expected deny, allowed: a leak). Vectors
this implementation does not cover are reported as NOT_APPLICABLE with the reason;
they are never counted as passes.
"""
import itertools
import re

from . import checkpoint
from .audit import audit_leaf, entry_hash, verify_audit
from .authzen import map_evaluation
from .containment import containment, containment_across
from .decision import classify, parse_obligations
from .engine import Engine, Shards
from .fixture import VECTOR_DIR, apply, bindings as fixture_bindings, load_fixture
from .jcs import canonicalize
from .js import UNDEF, load
from .merkle import consistency_proof, inclusion_proof, leaf_hash, root_of, verify_consistency, verify_inclusion
from .policy import LEVELS, context_fresh, decide, destination_gate, evaluation_target_named, target_of, transitive_classification

OUTCOMES = ["SUCCESS", "SAFE_BLOCK", "FAILURE", "UNSAFE_SUCCESS"]
FILES = ["vectors.json", "vectors-0.3.json", "vectors-0.4.json", "vectors-authzen.json", "vectors-destinations.json",
         "vectors-runtime.json", "vectors-redteam.json", "vectors-0.6-crypto.json", "vectors-0.6-identity.json", "vectors-0.6-release.json",
         "vectors-0.6-knowledge.json"]


def outcome_of(expect_allow, allowed, passed=True):
    o = ("SUCCESS" if allowed else "FAILURE") if expect_allow else ("UNSAFE_SUCCESS" if allowed else "SAFE_BLOCK")
    return "FAILURE" if not passed and o in ("SUCCESS", "SAFE_BLOCK") else o


def _row(vid, kind, expected, actual, passed, outcome, tags=None):
    row = {"id": vid, "kind": kind, "expected": expected, "actual": actual, "pass": passed, "outcome": outcome}
    if tags:
        row["tags"] = tags
    return row


def _read(directory, name):
    with open(directory / name, encoding="utf-8") as f:
        return load(f)


def _state(name, clock, fixture=None):
    return load_fixture(name or "fixture", clock, fixture)


def _binding(bindings, name, grant=None):
    b = dict(bindings[name])
    if grant:
        b["grant"] = grant
    return b


def _top(state, sources):
    levels = [transitive_classification(state, state["knowledge"][i]) if i in state["knowledge"] else None for i in sources]
    return None if any(not level for level in levels) else LEVELS[max(LEVELS.index(level) for level in levels)]


def run_decisions(directory, fixture, bindings, name):
    data = _read(directory, name)
    rows = []
    for v in data["cases"]:
        state = _state(data.get("fixture"), data["clock"], fixture)
        apply(state, v["patch"])
        if v.get("kind") == "context":
            revision = v["revision"]
            actual = "valid" if context_fresh(state, v["context"], data["clock"], revision) else "invalid"
            passed = actual == v["expected"]
            rows.append(_row(v["id"], "context", v["expected"], actual, passed, outcome_of(v["expected"] == "valid", actual == "valid", passed), v.get("tags")))
            continue
        d = decide(state, {"binding": _binding(bindings, v["binding"], v.get("grant")), "action": v["action"], "resource": v["resource"],
                           "purpose": v["purpose"], "now": data["clock"]})
        passed = d["effect"] == v["expected"] and ("code" not in v or d["code"] == v["code"])
        rows.append(_row(v["id"], "decision", v["expected"], d["effect"], passed, outcome_of(v["expected"] == "allow", d["effect"] == "allow", passed), v.get("tags")))
    return rows


def run_evidence(directory, fixture, bindings):
    data = _read(directory, "vectors-0.4.json")
    rows = []
    for v in data["cases"]:
        kind = v["kind"]
        actual = None
        try:
            def leaves():
                return [leaf_hash(bytes.fromhex(h)) for h in v["leaves"]]
            if kind == "merkle-root":
                actual = root_of(leaves()[:v["size"]])
            elif kind == "inclusion":
                lv = leaves()[:v["size"]]
                actual = inclusion_proof(lv, v["index"], v["size"])
                if not verify_inclusion(lv[v["index"]], v["index"], v["size"], actual, root_of(lv)):
                    actual = "unverifiable"
            elif kind == "consistency":
                lv = leaves()[:v["second"]]
                actual = consistency_proof(lv, v["first"], v["second"])
                if not verify_consistency(v["first"], v["second"], root_of(lv[:v["first"]]), root_of(lv), actual):
                    actual = "unverifiable"
            elif kind == "jcs":
                try:
                    actual = canonicalize(v["input"])
                except ValueError:
                    actual = None
            elif kind == "audit-hash":
                actual = entry_hash(v["entry"])
            elif kind == "audit-leaf":
                actual = audit_leaf(v["entry"])
            elif kind == "audit-chain":
                actual = verify_audit(v["entries"])
            elif kind == "obligations":
                actual = parse_obligations(v["input"])
            elif kind == "reason":
                actual = classify(v["reason"])
            elif kind == "verify-inclusion":
                actual = verify_inclusion(leaf_hash(bytes.fromhex(v["leaf"])), v["index"], v["size"], v["path"], v["root"])
            elif kind == "verify-consistency":
                actual = verify_consistency(v["first"], v["second"], v["firstRoot"], v["secondRoot"], v["path"])
            elif kind == "checkpoint-v2":
                if not checkpoint.available():
                    rows.append(_row(v["id"], kind, "accept" if v["expected"] else "reject", "not-applicable", False, "NOT_APPLICABLE"))
                    rows[-1]["reason"] = "optional dependency 'cryptography' is not installed"
                    continue
                actual = checkpoint.verify_checkpoint_v2(v["checkpoint"], v["publicKey"], v["stream"], v["keyId"], minimum_size=v.get("minimumSize"))
            elif kind == "decision":
                state = _state("kbFixture", v["clock"], fixture)
                apply(state, v["patch"])
                d = decide(state, {"binding": bindings[v["binding"]], "resource": v["resource"], "action": v["action"], "purpose": v["purpose"], "now": v["clock"]})
                actual = {"effect": d["effect"], "code": d["code"]}
            else:
                actual = "unknown vector kind"
        except Exception as error:  # a harness error is a FAILURE, never a pass
            actual = f"error: {error}"
        passed = actual == v["expected"] and _same_types(actual, v["expected"])
        if kind == "decision":
            want, got = v["expected"].get("effect"), actual.get("effect") if isinstance(actual, dict) else actual
            rows.append(_row(v["id"], "lifecycle-decision", want, got, passed, outcome_of(want == "allow", got == "allow", passed)))
        elif kind in ("verify-inclusion", "verify-consistency", "checkpoint-v2"):
            rows.append(_row(v["id"], kind, "accept" if v["expected"] else "reject", "accept" if actual is True else "reject" if actual is False else actual,
                             passed, outcome_of(v["expected"] is True, actual is True, passed)))
        else:
            rows.append(_row(v["id"], kind, "match", "match" if passed else "mismatch", passed, "SUCCESS" if passed else "FAILURE"))
    return rows


def _same_types(a, b):
    """Deep equality without Python's bool/int conflation (True == 1)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same_types(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same_types(x, y) for x, y in zip(a, b))
    return a == b


def run_authzen(directory, fixture, bindings):
    data = _read(directory, "vectors-authzen.json")
    rows = []
    for v in data["cases"]:
        mapped = map_evaluation(v["tenant"], v["request"])
        code = None
        if not mapped["ok"]:
            actual = mapped["kind"]
        else:
            d = decide(_state("kbFixture", data["clock"], fixture), {"binding": mapped["binding"], "resource": mapped["resource"], "action": mapped["action"],
                                                                   "purpose": mapped["purpose"], "now": data["clock"]})
            actual, code = d["effect"], d["code"]
            # 0.6 R121: a share/export evaluation that names no Destination is denied (RECIPIENT) whatever decide() says.
            if not evaluation_target_named(mapped["action"], mapped.get("destination", UNDEF)):
                actual, code = "deny", "RECIPIENT"
        passed = (actual == v["expected"] and ("code" not in v or code == v["code"])
                  and ("binding" not in v or (mapped["ok"] and mapped["binding"] == v["binding"])))
        rows.append(_row(v["id"], "authzen", v["expected"], actual, passed, outcome_of(v["expected"] == "allow", actual == "allow", passed), v.get("tags")))
    return rows


def run_destinations(directory, fixture, bindings):
    data = _read(directory, "vectors-destinations.json")
    rows = []
    for v in data["cases"]:
        try:
            state = _state("kbFixture", data["clock"], fixture)
            apply(state, v["patch"])
            b = _binding(bindings, v["binding"], v.get("grant"))
            if v["kind"] == "decision":
                d = decide(state, {"binding": b, "resource": v["resource"], "action": v["action"], "purpose": v["purpose"], "now": data["clock"]})
                actual = {"effect": d["effect"], "code": d["code"]}
            else:
                target = {"kind": "unspecified"} if v["recipient"] is None else target_of(state["actors"][v["recipient"]])
                g = destination_gate(state, state["grants"][b["grant"]], target, b["tenant"], _top(state, v["sources"]), v["purpose"])
                actual = {"ok": True, **({"restrict": g["restrict"]} if "restrict" in g else {})} if g["ok"] else {"ok": False}
        except Exception as error:
            actual = f"error: {error}"
        passed = _same_types(actual, v["expected"])
        want = v["expected"].get("effect") == "allow" if v["kind"] == "decision" else v["expected"].get("ok") is True
        got = isinstance(actual, dict) and (actual.get("effect") == "allow" if v["kind"] == "decision" else actual.get("ok") is True)
        rows.append(_row(v["id"], f"destination-{v['kind']}", "allow" if want else "deny", "allow" if got else "deny", passed,
                         outcome_of(want, got, passed), v.get("tags")))
    return rows


def run_identity(directory, fixture, bindings):
    """Identity and authority vectors (0.6, ADR-019): decide() over the kbFixture; riskSignals and settings start empty."""
    data = _read(directory, "vectors-0.6-identity.json")
    rows = []
    for v in data["cases"]:
        try:
            state = _state("kbFixture", data["clock"], fixture)
            state.setdefault("riskSignals", {})
            state.setdefault("settings", {})
            apply(state, v["patch"])
            b = _binding(bindings, v["binding"], v.get("grant"))
            d = decide(state, {"binding": b, "resource": v["resource"], "action": v["action"], "purpose": v["purpose"], "now": data["clock"]})
            actual = {"effect": d["effect"], "code": d["code"]}
        except Exception as error:
            actual = f"error: {error}"
        passed = _same_types(actual, v["expected"])
        want, got = v["expected"]["effect"] == "allow", isinstance(actual, dict) and actual.get("effect") == "allow"
        rows.append(_row(v["id"], "identity-decision", "allow" if want else "deny", "allow" if got else "deny", passed, outcome_of(want, got, passed), v.get("tags")))
    return rows


def run_release(directory, fixture, bindings):
    """Release protection vectors (0.6, ADR-020): the pure closed sets (obligation parsing and merging, reason codes). The engine-level
    kinds (release filters, sanitizers, hints, volume budgets, decision cache) need the engine hooks of the TypeScript reference and are
    NOT_APPLICABLE here with that reason: they are never counted as passes."""
    data = _read(directory, "vectors-0.6-release.json")
    rows = []
    for v in data["cases"]:
        if v["kind"] not in ("obligations", "reason"):
            row = _row(v["id"], "release-" + v["kind"], "n/a", "not-applicable", False, "NOT_APPLICABLE", v.get("tags"))
            row["reason"] = "the Python engine has no release filter, sanitizer, hint, volume budget or decision cache hooks"
            rows.append(row)
            continue
        try:
            actual = parse_obligations(v["input"]) if v["kind"] == "obligations" else classify(v["input"])
        except Exception as error:
            actual = f"error: {error}"
        passed = _same_types(actual, v["expected"]) and actual == v["expected"]
        rows.append(_row(v["id"], "release-" + v["kind"], "allow", "allow" if passed else "deny", passed, outcome_of(True, passed, passed), v.get("tags")))
    return rows


_RECORD_FIELDS = ["classification", "tags", "residency", "modality", "model", "container", "kind", "origin"]


def run_knowledge_steps(clock, v, fixture, bindings):
    """Knowledge semantics steps (0.6, ADR-022): gateway operations in order over one snapshot; session-scoped records stay in it."""
    state = _state("kbFixture", clock, fixture)
    state.setdefault("settings", {})
    state.setdefault("combinationRules", {})
    apply(state, v["patch"])
    engine = Engine(state, clock, model=v.get("model"))
    saved, out = {}, []

    def sub(x):
        return saved.get(x[1:], x) if isinstance(x, str) and x.startswith("$") else x

    for step in v["steps"]:
        b = bindings[step["as"]] if isinstance(step["as"], str) else step["as"]
        op = step["op"]
        if op == "open":
            r = engine.open_context(b, [sub(x) for x in step.get("resources", [])], step.get("purpose", "work"))
        elif op == "derive":
            options = {k: step[k] for k in ("modality", "session", "container") if k in step}
            r = engine.derive(b, sub(step["context"]), step.get("content", "Synthetic derived note."), step.get("kind", "artifact"), options)
        elif op == "release":
            r = engine.release(b, sub(step["context"]), step["recipient"], step.get("content", "Synthetic answer."), step.get("action", "share"))
        elif op == "evaluate":
            e = engine.evaluate(b, sub(step["resource"]), step["action"], step.get("purpose", "work"), step["destination"] if "destination" in step else UNDEF)
            r = {"ok": e["effect"] == "allow", "code": e["code"], "audited": e["audited"]}
        elif op == "close":
            r = engine.close_session(b, step["session"]["id"])
        else:
            raise ValueError("unknown step")
        result = {"effect": "allow" if r["ok"] else "deny", **({"code": r["code"]} if r.get("audited") else {})}
        want = step["expected"].get("record")
        if r["ok"] and op == "derive" and want is not None:
            record = state["knowledge"].get(r["value"]["id"], {})
            result["record"] = {k: ("ephemeral" in record) if k == "ephemeral" else record.get(k) if k in _RECORD_FIELDS else None for k in want}
        if r["ok"] and step.get("save"):
            saved[step["save"]] = r["value"]["context"] if op == "open" else r["value"]["id"]
        out.append(result)
    return out


def _knowledge_match(actual, expected):
    return (actual["effect"] == expected["effect"] and ("code" not in expected or actual.get("code") == expected["code"])
            and ("record" not in expected or actual.get("record") == expected["record"]))


def run_knowledge(directory, fixture, bindings):
    """Knowledge semantics vectors (0.6, ADR-022): decide() and gateway step sequences over the kbFixture."""
    data = _read(directory, "vectors-0.6-knowledge.json")
    rows = []
    for v in data["cases"]:
        passed, got, want = False, False, False
        try:
            if v["kind"] == "decision":
                state = _state("kbFixture", data["clock"], fixture)
                state.setdefault("settings", {})
                state.setdefault("combinationRules", {})
                apply(state, v["patch"])
                d = decide(state, {"binding": _binding(bindings, v["binding"], v.get("grant")), "resource": v["resource"], "action": v["action"],
                                   "purpose": v.get("purpose", "work"), "now": data["clock"]})
                want, got = v["expected"]["effect"] == "allow", d["effect"] == "allow"
                passed = _knowledge_match({"effect": d["effect"], "code": d["code"]}, v["expected"])
            elif v["kind"] == "steps":
                results = run_knowledge_steps(data["clock"], v, fixture, bindings)
                want, got = v["steps"][-1]["expected"]["effect"] == "allow", bool(results) and results[-1]["effect"] == "allow"
                passed = len(results) == len(v["steps"]) and all(_knowledge_match(a, s["expected"]) for a, s in zip(results, v["steps"]))
        except Exception:  # noqa: BLE001 - a harness error is a failure, never a pass
            passed = False
        rows.append(_row(v["id"], "knowledge-" + v["kind"], "allow" if want else "deny", "allow" if got else "deny", passed, outcome_of(want, got, passed), v.get("tags")))
    return rows


def run_crypto(directory, fixture, bindings):
    """Crypto agility vectors (0.6). A vector whose algorithm the installed cryptography package cannot verify (SLH-DSA; ML-DSA on older
    releases) is NOT_APPLICABLE with the reason: it is never counted as a pass."""
    data = _read(directory, "vectors-0.6-crypto.json")
    rows = []
    for v in data["cases"]:
        try:
            if not checkpoint.available():
                raise checkpoint.AlgorithmUnavailable("optional dependency 'cryptography' is not installed")
            if v["kind"] == "checkpoint-v3":
                actual = checkpoint.verify_checkpoint_v3(v["checkpoint"], v["publicKey"], v["stream"], v["keyId"], minimum_size=v.get("minimumSize"), policy=v.get("policy"))
            else:
                actual = checkpoint.verify_checkpoint_history(v["items"], v["stream"], v.get("policy"))
        except checkpoint.AlgorithmUnavailable as error:
            rows.append(_row(v["id"], v["kind"], "accept" if v["expected"] else "reject", "not-applicable", False, "NOT_APPLICABLE", v.get("tags")))
            rows[-1]["reason"] = str(error)
            continue
        except Exception as error:  # a harness error is a FAILURE, never a pass
            actual = f"error: {error}"
        passed = actual == v["expected"] and _same_types(actual, v["expected"])
        rows.append(_row(v["id"], v["kind"], "accept" if v["expected"] else "reject", "accept" if actual is True else "reject" if actual is False else actual,
                         passed, outcome_of(v["expected"] is True, actual is True, passed), v.get("tags")))
    return rows


def _runtime_only(obligations):
    return [o for o in obligations if o["type"] in ("runtime_profile", "max_output_classification")]


def _weaker(expected, actual):
    for e in expected:
        if e["type"] == "runtime_profile":
            if not any(a["type"] == "runtime_profile" and a["domain"] == e["domain"] and a["profile"] == e["profile"] for a in actual) \
                    or any(a["type"] == "runtime_profile" and a["domain"] == e["domain"] and a["profile"] != e["profile"] for a in actual):
                return True
        if e["type"] == "max_output_classification":
            got = next((a for a in actual if a["type"] == "max_output_classification"), None)
            if not got or LEVELS.index(got["value"]) < LEVELS.index(e["value"]):
                return True
    return False


def run_runtime(directory, fixture, bindings):
    data = _read(directory, "vectors-runtime.json")
    rows = []
    for v in data["cases"]:
        expect_allow = v["expected"].get("ok", v["expected"].get("effect") == "allow")
        if v["kind"] == "enforcer":
            row = _row(v["id"], "runtime-enforcer", "allow" if expect_allow else "deny", "not-applicable", False, "NOT_APPLICABLE", v.get("tags"))
            row["reason"] = "runtime enforcer protocol (ProtectedRuntime): outside a decision implementation"
            rows.append(row)
            continue
        allowed, obligations = False, None
        try:
            state = _state("kbFixture", data["clock"], fixture)
            apply(state, v["patch"])
            if v["kind"] == "profiles":
                top = _top(state, v["sources"])
                c = (containment_across(state, "acme", top, v["destinationClasses"]) if "destinationClasses" in v
                     else containment(state, "acme", top, v.get("destinationClass")))
                actual = {"ok": True, "obligations": c["obligations"]} if c["ok"] else {"ok": False, "reason": c["reason"]}
                allowed, obligations = c["ok"], c.get("obligations")
            else:
                engine = Engine(Shards(state).tenant("acme"), data["clock"])
                b, purpose, op = bindings[v["binding"]], v.get("purpose", "work"), v["operation"]
                if op == "evaluate":
                    r = engine.evaluate(b, v["resources"][0], v["action"], purpose, v["destination"] if "destination" in v else UNDEF)
                    result = {"ok": r["effect"] == "allow", "code": r["code"], "obligations": r["obligations"]}
                else:
                    result = engine.open_context(b, v["resources"], purpose)
                    if result["ok"] and op == "release":
                        result = engine.release(b, result["value"]["context"], v["recipient"], "Synthetic answer", "share")
                    if result["ok"] and op == "derive":
                        result = engine.derive(b, result["value"]["context"], "Synthetic note", "artifact")
                allowed = result["ok"]
                obligations = _runtime_only(result["obligations"]) if allowed else None
                actual = {"effect": "allow" if allowed else "deny", **({"obligations": obligations} if allowed else {}),
                          **({"code": result["code"]} if "code" in v["expected"] else {})}
        except Exception as error:
            actual, allowed = f"error: {error}", False
        passed = _same_types(actual, v["expected"])
        outcome = outcome_of(expect_allow, allowed, passed)
        if expect_allow and allowed and v["expected"].get("obligations") and _weaker(v["expected"]["obligations"], obligations or []):
            outcome = "UNSAFE_SUCCESS"
        rows.append(_row(v["id"], f"runtime-{v['kind']}", "allow" if expect_allow else "deny", "allow" if allowed else "deny", passed, outcome, v.get("tags")))
    return rows


def _subst(value, saved, clock):
    if isinstance(value, str):
        if value.startswith("$"):
            if value[1:] not in saved:
                raise ValueError(f"Unknown variable {value}")
            return saved[value[1:]]
        m = re.fullmatch(r"clock([+-]\d+)?", value)
        return clock + int(m.group(1) or 0) if m else value
    if isinstance(value, list):
        return [_subst(v, saved, clock) for v in value]
    if isinstance(value, dict):
        return {k: _subst(v, saved, clock) for k, v in value.items()}
    return value


def run_scenario(v, fixture, bindings, counter=None):
    """Executes one red-team scenario over per-tenant snapshots; returns (row, steps) with each step's effect and code."""
    counter = counter or itertools.count(1)
    shards = Shards(_state(v.get("fixture") or "kbFixture", v["clock"], fixture))
    saved, steps = {}, []

    def engine(tenant):
        return Engine(shards.tenant(tenant), v["clock"], memory_review=v.get("memoryReview", "none"), candidates=v.get("candidates"),
                      ids=lambda: f"00000000-0000-4000-8000-{next(counter):012d}")

    def row(actual, passed, allowed):
        return _row(v["id"], "scenario", v["expected"], actual, passed, outcome_of(v["expected"] == "allow", allowed, passed), v.get("tags"))

    for raw in v["steps"]:
        step = _subst(raw, saved, v["clock"])
        who = bindings[step["as"]] if isinstance(step.get("as"), str) else step.get("as")
        op = step["op"]
        try:
            if op == "open":
                r = engine(who["tenant"]).open_context(who, step["resources"], step["purpose"])
                allowed = r["ok"] and (not step.get("target") or any(d["id"] in step["target"] for d in r["value"]["documents"]))
            elif op == "retrieve":
                r = engine(who["tenant"]).retrieve(who, step["query"], step["purpose"])
                allowed = r["ok"] and (any(d["id"] in step["target"] for d in r["value"]["documents"]) if step.get("target") else len(r["value"]["documents"]) > 0)
            elif op == "derive":
                r = engine(who["tenant"]).derive(who, step["context"], step["content"], step.get("kind", "artifact"))
                allowed = r["ok"]
            elif op == "release":
                r = engine(who["tenant"]).release(who, step["context"], step["recipient"], step["content"], step.get("action", "share"))
                allowed = r["ok"]
            elif op == "delegate":
                r = engine(who["tenant"]).delegate(who, step["child"])
                allowed = r["ok"]
            elif op == "revoke":
                r = engine(step["tenant"]).revoke(step["tenant"], step["admin"], step["type"], step["id"])
                allowed = r["ok"]
            elif op == "patch":
                apply(shards.tenant("acme"), step["patch"])
                r, allowed = {"ok": True, "code": None}, True
            else:
                raise ValueError("Unknown step")
        except Exception as error:
            return row(f"error: {error}", False, False), steps
        steps.append({"op": op, "allowed": bool(allowed), "code": r.get("code")})
        if r["ok"] and step.get("save"):
            saved[step["save"]] = r["value"].get("context") if op in ("open", "retrieve") else r["value"]["id"]
        if step.get("probe"):
            return row("allow" if allowed else "deny", True, allowed), steps
        if step.get("expect") and (step["expect"] == "allow") != bool(allowed):
            return row(f"setup: {op} {'allowed' if allowed else 'denied'}", False, False), steps
    return row("no probe", False, False), steps


def run_scenarios(directory, fixture, bindings):
    data = _read(directory, "vectors-redteam.json")
    return [run_scenario(v, fixture, bindings)[0] for v in data["cases"]]


def run_all(directory=None, fixture=None):
    directory = directory or VECTOR_DIR
    bindings = fixture_bindings(fixture)
    rows = []
    for name in ("vectors.json", "vectors-0.3.json"):
        rows += [dict(r, file=name) for r in run_decisions(directory, fixture, bindings, name)]
    for name, fn in (("vectors-0.4.json", run_evidence), ("vectors-authzen.json", run_authzen), ("vectors-destinations.json", run_destinations),
                     ("vectors-runtime.json", run_runtime), ("vectors-redteam.json", run_scenarios),
                     ("vectors-0.6-crypto.json", run_crypto), ("vectors-0.6-identity.json", run_identity), ("vectors-0.6-release.json", run_release),
                     ("vectors-0.6-knowledge.json", run_knowledge)):
        rows += [dict(r, file=name) for r in fn(directory, fixture, bindings)]
    return rows


def summarize(rows):
    counted = [r for r in rows if r["outcome"] != "NOT_APPLICABLE"]
    counts = {o: sum(1 for r in counted if r["outcome"] == o) for o in OUTCOMES}
    tenant = [r for r in counted if "cross-tenant" in (r.get("tags") or [])]
    gates = {"unsafe_success_zero": counts["UNSAFE_SUCCESS"] == 0, "failure_zero": counts["FAILURE"] == 0,
             "cross_tenant_vectors": len(tenant), "cross_tenant_leaks_zero": len(tenant) > 0 and all(r["outcome"] != "UNSAFE_SUCCESS" for r in tenant)}
    gates["pass"] = gates["unsafe_success_zero"] and gates["failure_zero"] and gates["cross_tenant_leaks_zero"]
    return {"total": len(rows), "not_applicable": len(rows) - len(counted), **counts, "gates": gates}


def by_file(rows):
    out = {}
    for r in rows:
        c = out.setdefault(r["file"], {**{o: 0 for o in OUTCOMES}, "NOT_APPLICABLE": 0})
        c[r["outcome"]] += 1
    return out


def table(rows):
    summary, files = summarize(rows), by_file(rows)
    header = ["file"] + OUTCOMES + ["NOT_APPLICABLE", "total"]
    lines = [header] + [[f] + [str(c[o]) for o in OUTCOMES + ["NOT_APPLICABLE"]] + [str(sum(c.values()))] for f, c in files.items()]
    lines.append(["ALL"] + [str(summary[o]) for o in OUTCOMES] + [str(summary["not_applicable"]), str(summary["total"])])
    width = [max(len(line[i]) for line in lines) for i in range(len(header))]
    text = "\n".join("  ".join(c.ljust(width[i]) if i == 0 else c.rjust(width[i]) for i, c in enumerate(line)) for line in lines)
    g = summary["gates"]
    return text + "\n\n" + "\n".join([
        f"gate unsafe_success == 0          {'PASS' if g['unsafe_success_zero'] else 'FAIL'}",
        f"gate failure == 0                 {'PASS' if g['failure_zero'] else 'FAIL'}",
        f"gate cross-tenant leaks == 0      {'PASS' if g['cross_tenant_leaks_zero'] else 'FAIL'} ({g['cross_tenant_vectors']} vectors)",
        f"conformance                       {'PASS' if g['pass'] else 'FAIL'}"])


def report(rows):
    return {"implementation": "akac-python/0.6.0", "independentCertification": False, "summary": summarize(rows), "byFile": by_file(rows),
            "results": rows}


__all__ = ["run_all", "summarize", "table", "report", "run_scenario"]
