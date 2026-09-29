"""AKAC decision and evidence verification in Python (second implementation of the AKAC 0.5 draft).

Written by the AKAC project following the specification and the reference behaviour;
it shares no code with the TypeScript reference at run time. It is same-project
evidence, not an independent external implementation, and carries no certification.
"""
from .audit import audit_leaf, entry_hash, verify_audit
from .authzen import map_evaluation
from .containment import containment, containment_across, valid_runtime_profile
from .decision import classify, merge, parse_obligations, unsatisfiable, valid_obligation
from .engine import CORE_VERSION, Engine, Shards
from .fixture import apply, load_fixture
from .jcs import canonicalize
from .js import loads
from .merkle import root_of, verify_consistency, verify_inclusion
from .policy import (context_fresh, decide, destination_gate, effective_label, grant_valid, target_of, transitive_classification,
                     visible)

__version__ = "0.6.0"
__all__ = ["decide", "visible", "grant_valid", "effective_label", "transitive_classification", "context_fresh", "destination_gate",
           "target_of", "containment", "containment_across", "valid_runtime_profile", "Engine", "Shards", "CORE_VERSION",
           "parse_obligations", "merge", "unsatisfiable", "valid_obligation", "classify", "canonicalize", "root_of",
           "verify_inclusion", "verify_consistency", "entry_hash", "audit_leaf", "verify_audit", "map_evaluation",
           "load_fixture", "apply", "loads"]
