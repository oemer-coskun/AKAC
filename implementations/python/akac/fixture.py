"""Loader of the language-neutral conformance fixture (examples/fixture.json, schemas/fixture.json) and vector patches."""
import copy
from pathlib import Path

from .engine import CORE_VERSION, blank_state
from .js import load

REPO = Path(__file__).resolve().parents[3]
FIXTURE_PATH = REPO / "examples" / "fixture.json"
VECTOR_DIR = REPO / "conformance"
_cache = {}


def fixture_data(path=None):
    path = Path(path or FIXTURE_PATH)
    if path not in _cache:
        with open(path, encoding="utf-8") as f:
            data = load(f)
        if data.get("format") != "akac-fixture/1":
            raise ValueError("Unsupported fixture format")
        _cache[path] = data
    return copy.deepcopy(_cache[path])


def bindings(path=None):
    return fixture_data(path)["bindings"]


def load_fixture(name, now, path=None, policy_version=CORE_VERSION):
    """A fresh state of the named fixture at clock `now`: base records first, then the extension, then clock offsets."""
    data = fixture_data(path)
    chain, n = [], name
    while n is not None:
        if n in chain or n not in data["fixtures"]:
            raise ValueError("Invalid fixture chain")
        chain.insert(0, n)
        n = data["fixtures"][n].get("extends")
    state = blank_state(policy_version)
    for n in chain:
        for collection, records in data["fixtures"][n]["records"].items():
            if collection not in state or not isinstance(state[collection], dict):
                raise ValueError("Invalid fixture collection")
            for rid, record in records.items():
                state[collection][rid] = copy.deepcopy(record)
    for collection, field in data["clockRelative"]:
        for record in state.get(collection, {}).values():
            if field in record:
                record[field] = now + record[field]
    return state


OPTIONAL = ["container", "activeRoles", "parent", "accessExpiresAt", "lifecycle", "lifecycleAt", "quarantineReason", "retainUntil",
            "legalHolds", "revokedAt", "destination", "destinations", "maxResults"]


def apply(state, patch):
    """Vector patches: [collection, id, field, value] sets a field; [collection, id, record] inserts or replaces a record."""
    for entry in patch:
        if len(entry) == 3:
            collection, rid, value = entry
            if not isinstance(state.get(collection), dict):
                raise ValueError("Invalid trusted test vector")
            state[collection][rid] = copy.deepcopy(value)
            continue
        collection, rid, field, value = entry
        target = state.get(collection, {}).get(rid) if isinstance(state.get(collection), dict) else None
        if not isinstance(target, dict) or (field not in target and field not in OPTIONAL):
            raise ValueError("Invalid trusted test vector")
        target[field] = copy.deepcopy(value)
