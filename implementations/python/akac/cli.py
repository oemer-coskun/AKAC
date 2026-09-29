"""Command line: the language-neutral runner contract and the standalone conformance run.

    python -m akac eval < cases.json          # {"cases": [...]} on stdin -> JSON array on stdout
    python -m akac conformance [--json] [--vectors DIR] [--fixture FILE]

Runner contract (docs/IMPLEMENTATIONS.md): each case names an `op` (default
"decide") and carries the full state it is evaluated over. A case that makes the
implementation fail with an unexpected error yields {"thrown": true}; the harness
compares that like any other result.
"""
import itertools
import re
import sys
from pathlib import Path

from . import checkpoint, conformance
from .audit import audit_leaf, entry_hash, verify_audit
from .authzen import map_evaluation
from .containment import containment, containment_across
from .decision import classify, parse_obligations
from .engine import CORE_VERSION, Engine
from .fixture import bindings as fixture_bindings
from .jcs import canonicalize
from .js import UNDEF, dumps, load, loads
from .merkle import consistency_proof, inclusion_proof, leaf_hash, root_of, verify_consistency, verify_inclusion
from .policy import (context_fresh, decide, destination_gate, evaluation_target_named, target_of, top_level,
                     transitive_classification)


def _record(state, rid):
    r = state["knowledge"][rid]
    keys = ["classification", "projects", "readerRoles", "readers", "sources", "retainUntil", "lifecycle", "quarantineReason",
            "tags", "residency", "modality", "container", "ephemeral"]
    return {k: r[k] for k in keys if k in r}


def _result(state, op, r):
    out = {"effect": "allow" if r["ok"] else "deny", "code": r["code"], "obligations": r["obligations"], "audited": r["audited"]}
    if not r["ok"] and r["audited"]:
        out["category"] = r["category"]
    value = r.get("value") if r["ok"] else None
    if value is not None:
        if op in ("open", "retrieve"):
            out["documents"] = [d["id"] for d in value["documents"]]
        elif op == "derive":
            out["record"] = _record(state, value["id"])
            if value.get("quarantined"):
                out["quarantined"] = True
        elif op == "release" and "destination" in value:
            out["destination"] = value["destination"]
    return out


_VAR = re.compile(r"\$([A-Za-z0-9_]+)")


def _subst(value, saved):
    if isinstance(value, str) and value.startswith("$") and value[1:] in saved:
        return saved[value[1:]]
    if isinstance(value, list):
        return [_subst(v, saved) for v in value]
    if isinstance(value, dict):
        return {k: _subst(v, saved) for k, v in value.items()}
    return value


def _operation(engine, step):
    op = step["op"]
    if op == "open":
        return engine.open_context(step["binding"], step["resources"], step["purpose"])
    if op == "retrieve":
        return engine.retrieve(step["binding"], step["query"], step["purpose"], step.get("limit", 5))
    if op == "derive":
        return engine.derive(step["binding"], step["context"], step["content"], step.get("kind", "artifact"), step.get("options", {}))
    if op == "close":
        return engine.close_session(step["binding"], step["session"])
    if op == "release":
        return engine.release(step["binding"], step["context"], step["recipient"], step["content"], step.get("action", "share"))
    if op == "delegate":
        return engine.delegate(step["binding"], step["child"])
    if op == "revoke":
        return engine.revoke(step["tenant"], step["admin"], step["type"], step["id"])
    raise ValueError(f"unknown operation {op!r}")


def _leaves(case):
    return [leaf_hash(bytes.fromhex(h)) for h in case["leaves"]]


def _jcs(case):
    try:
        return canonicalize(case["input"])
    except ValueError:
        return None


def _checkpoint(case):
    if not checkpoint.available():
        return {"unavailable": "cryptography"}
    return checkpoint.verify_checkpoint_v2(case["checkpoint"], case["publicKey"], case["stream"], case["keyId"], minimum_size=case.get("minimumSize"))


def _checkpoint_v3(case):
    if not checkpoint.available():
        return {"unavailable": "cryptography"}
    try:
        return checkpoint.verify_checkpoint_v3(case["checkpoint"], case["publicKey"], case["stream"], case["keyId"], minimum_size=case.get("minimumSize"), policy=case.get("policy"))
    except checkpoint.AlgorithmUnavailable:
        return {"unavailable": case["checkpoint"].get("alg")}


def _checkpoint_history(case):
    if not checkpoint.available():
        return {"unavailable": "cryptography"}
    try:
        return checkpoint.verify_checkpoint_history(case["items"], case["stream"], case.get("policy"))
    except checkpoint.AlgorithmUnavailable:
        return {"unavailable": "algorithm"}


EVIDENCE = {
    "jcs": _jcs,
    "merkleRoot": lambda c: root_of(_leaves(c)[:c["size"]]),
    "inclusionProof": lambda c: inclusion_proof(_leaves(c)[:c["size"]], c["index"], c["size"]),
    "consistencyProof": lambda c: consistency_proof(_leaves(c)[:c["second"]], c["first"], c["second"]),
    "verifyInclusion": lambda c: verify_inclusion(leaf_hash(bytes.fromhex(c["leaf"])), c["index"], c["size"], c["path"], c["root"]),
    "verifyConsistency": lambda c: verify_consistency(c["first"], c["second"], c["firstRoot"], c["secondRoot"], c["path"]),
    "auditHash": lambda c: entry_hash(c["entry"]),
    "auditLeaf": lambda c: audit_leaf(c["entry"]),
    "auditChain": lambda c: verify_audit(c["entries"]),
    "obligations": lambda c: parse_obligations(c["input"]),
    "reason": lambda c: classify(c["reason"]),
    "checkpointV2": _checkpoint,
    "checkpointV3": _checkpoint_v3,
    "checkpointHistory": _checkpoint_history,
}


def evaluate_case(case):
    op = case.get("op", "decide")
    state, core = case.get("state"), case.get("coreVersion", CORE_VERSION)
    if op == "decide":
        return decide(state, case["request"])
    if op == "evaluate":
        q = case["request"]
        engine = Engine(state, q["now"], core)
        return engine.evaluate(q["binding"], q["resource"], q["action"], q["purpose"], case["destination"] if "destination" in case else UNDEF)
    if op == "gate":
        # Destination gate for the binding's grant, the recipient's target (null: unspecified) and the sources' top level.
        b = case["binding"]
        target = {"kind": "unspecified"} if case.get("recipient") is None else target_of(state["actors"][case["recipient"]])
        g = destination_gate(state, state["grants"][b["grant"]], target, b["tenant"], top_level(state, case["sources"]), case["purpose"])
        return {"ok": True, **({"restrict": g["restrict"]} if "restrict" in g else {})} if g["ok"] else {"ok": False}
    if op == "containment":
        level = top_level(state, case["sources"]) if "sources" in case else case["level"]
        if "classes" in case:
            return containment_across(state, case["tenant"], level, case["classes"])
        return containment(state, case["tenant"], level, case.get("destinationClass"))
    if op == "authzen":
        mapped = map_evaluation(case["tenant"], case["request"])
        if not mapped["ok"]:
            return {"mapped": mapped["kind"]}
        d = decide(state, {"binding": mapped["binding"], "resource": mapped["resource"], "action": mapped["action"], "purpose": mapped["purpose"], "now": case["now"]})
        if not evaluation_target_named(mapped["action"], mapped.get("destination", UNDEF)):
            d = {"effect": "deny", "code": "RECIPIENT", "category": "deny"}
        engine = Engine(state, case["now"], core)
        verdict = engine.evaluate(mapped["binding"], mapped["resource"], mapped["action"], mapped["purpose"], mapped.get("destination", UNDEF))
        return {"mapped": "ok", "binding": mapped["binding"], "decision": d, "evaluate": verdict}
    if op == "scenario":
        row, steps = conformance.run_scenario(case["scenario"], None, fixture_bindings(), itertools.count(1))
        return {"outcome": row["outcome"], "steps": steps}
    if op in EVIDENCE:
        return EVIDENCE[op](case)
    if op == "fresh":
        return context_fresh(state, case["context"], case["now"], case["revision"])
    if op == "classification":
        return transitive_classification(state, state["knowledge"][case["id"]])
    if op == "steps":
        counter = itertools.count(1)
        engine = Engine(state, case["now"], core, memory_review=case.get("memoryReview", "none"), candidates=case.get("candidates"),
                        ids=lambda: f"00000000-0000-4000-8000-{next(counter):012d}", unenforceable=case.get("unenforceable"),
                        model=case.get("model"))
        saved, results = {}, []
        for raw in case["steps"]:
            step = _subst(raw, saved)
            try:
                r = _operation(engine, step)
            except Exception:  # noqa: BLE001 - reported, never masked as a decision
                results.append({"thrown": True})
                break
            results.append(_result(state, step["op"], r))
            if r["ok"] and step.get("save"):
                saved[step["save"]] = r["value"]["context"] if step["op"] in ("open", "retrieve") else r["value"]["id"]
        return results
    raise ValueError(f"unknown op {op!r}")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv.pop(0) if argv else "eval"
    if command == "eval":
        data = load(sys.stdin)
        cases = data["cases"] if isinstance(data, dict) else data
        out = []
        for case in cases:
            try:
                out.append(evaluate_case(case))
            except Exception:  # noqa: BLE001
                out.append({"thrown": True})
        sys.stdout.write(dumps(out))
        return 0
    if command == "serve":
        # One JSON case per input line, one JSON result per output line (for property-based differential testing).
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                result = evaluate_case(loads(line))
            except Exception:  # noqa: BLE001
                result = {"thrown": True}
            sys.stdout.write(dumps(result) + chr(10))
            sys.stdout.flush()
        return 0
    if command == "conformance":
        directory = Path(argv[argv.index("--vectors") + 1]) if "--vectors" in argv else None
        fixture = Path(argv[argv.index("--fixture") + 1]) if "--fixture" in argv else None
        rows = conformance.run_all(directory, fixture)
        if "--json" in argv:
            sys.stdout.write(dumps(conformance.report(rows)) + "\n")
        else:
            print(conformance.table(rows))
            for r in rows:
                if r["outcome"] in ("FAILURE", "UNSAFE_SUCCESS"):
                    print(f"{r['outcome']} {r['id']} expected={r['expected']} actual={r['actual']}", file=sys.stderr)
        return 0 if conformance.summarize(rows)["gates"]["pass"] else 1
    print(__doc__, file=sys.stderr)
    return 2
