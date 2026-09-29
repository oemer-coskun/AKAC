"""Unit tests of the Python implementation (stdlib unittest; run: python -m unittest discover -s tests)."""
import copy
import unittest

from akac import checkpoint
from akac.conformance import run_all, summarize
from akac.containment import containment_across
from akac.engine import Engine
from akac.fixture import apply, bindings, load_fixture
from akac.jcs import canonicalize
from akac.js import UNDEF, loads, strict_eq, truthy
from akac.merkle import EMPTY_ROOT, consistency_proof, inclusion_proof, leaf_hash, root_of, verify_consistency, verify_inclusion
from akac.policy import decide, visible

NOW = 1_800_000_000_000


def request(name="chief", resource="strategy", action="read", **binding):
    return {"binding": {**bindings()[name], **binding}, "action": action, "resource": resource, "purpose": "work", "now": NOW}


class Json(unittest.TestCase):
    def test_integral_numbers_are_integers(self):
        # Review finding 14: 1.0 and 1e0 are the number 1, as in every JSON reader of the reference.
        self.assertIs(type(loads("1.0")), int)
        self.assertEqual(loads('{"a": 1e3, "b": -0.0, "c": 1.5}'), {"a": 1000, "b": 0, "c": 1.5})
        self.assertIs(type(loads("-0.0")), int)
        with self.assertRaises(ValueError):
            loads("NaN")
        with self.assertRaises(ValueError):
            loads("[Infinity]")

    def test_value_semantics(self):
        self.assertFalse(strict_eq(1, True))
        self.assertFalse(strict_eq(None, UNDEF))
        self.assertTrue(truthy([]) and truthy({}))
        self.assertFalse(truthy("") or truthy(0) or truthy(None))

    def test_float_versions_decide_like_integers(self):
        state = load_fixture("kbFixture", NOW)
        state["knowledge"]["strategy"]["version"] = loads("1.0")
        self.assertEqual(decide(state, request())["effect"], "allow")


class Decisions(unittest.TestCase):
    def test_fixture_positive_control(self):
        self.assertEqual(decide(load_fixture("fixture", NOW), request()), {"effect": "allow", "code": "AUTHORIZED"})
        self.assertEqual(decide(load_fixture("fixture", NOW), request("intern")),
                         {"effect": "deny", "code": "KNOWLEDGE_BOUNDARY", "category": "deny"})

    def test_lifecycle_hides_record_and_lineage(self):
        # Review finding 1 (R45/R46, R-LIFE-1): any lifecycle value on the object or any source denies.
        for value in ("quarantined", "erased", "unknown-state", None):
            state = load_fixture("kbFixture", NOW)
            state["knowledge"]["strategy"]["lifecycle"] = value
            self.assertEqual(decide(state, request())["code"], "KNOWLEDGE_BOUNDARY", value)
            state = load_fixture("kbFixture", NOW)
            state["knowledge"]["handbook"]["lifecycle"] = value
            state["knowledge"]["strategy"]["sources"] = [{"id": "handbook", "version": 1}]
            self.assertEqual(decide(state, request())["code"], "KNOWLEDGE_BOUNDARY", value)
        state = load_fixture("kbFixture", NOW)
        state["containers"]["f-executive"]["lifecycle"] = "quarantined"  # containers carry no lifecycle: unchanged
        self.assertEqual(decide(state, request(resource="board-notes"))["effect"], "allow")

    def test_delegation_narrows_destinations_and_result_limits(self):
        # Review finding 2 (R68): a restricted parent needs a child restricted to a subset.
        base = load_fixture("kbFixture", NOW)
        parent = base["grants"]["chief-run"]
        child = dict(copy.deepcopy(parent), id="chief-child", parent="chief-run")
        cases = [({"destinations": ["tool"]}, {}, "INVALID_DELEGATION"),
                 ({"destinations": ["tool"]}, {"destinations": ["tool", "external"]}, "INVALID_DELEGATION"),
                 ({"destinations": ["tool", "external"]}, {"destinations": ["tool"]}, "AUTHORIZED"),
                 ({"maxResults": 3}, {}, "INVALID_DELEGATION"),
                 ({"maxResults": 3}, {"maxResults": 4}, "INVALID_DELEGATION"),
                 ({"maxResults": 3}, {"maxResults": 3}, "AUTHORIZED"),
                 ({}, {"maxResults": 65}, "INVALID_DELEGATION"),
                 ({}, {"destinations": []}, "INVALID_DELEGATION")]
        for parent_fields, child_fields, code in cases:
            state = copy.deepcopy(base)
            state["grants"]["chief-run"].update(parent_fields)
            state["grants"]["chief-child"] = {**copy.deepcopy(child), **child_fields}
            self.assertEqual(decide(state, request(grant="chief-child"))["code"], code, (parent_fields, child_fields))

    def test_visible_without_roles_uses_standing_roles(self):
        state = load_fixture("kbFixture", NOW)
        self.assertTrue(visible(state, state["actors"]["chief"], state["knowledge"]["strategy"], NOW))
        self.assertFalse(visible(state, state["actors"]["intern"], state["knowledge"]["strategy"], NOW))


class Operations(unittest.TestCase):
    def test_open_carries_core_and_runtime_obligations(self):
        state = load_fixture("kbFixture", NOW)
        apply(state, [["runtimeProfiles", "rt", {"id": "rt", "tenant": "acme", "classification": "confidential",
                                                 "profiles": {"network": "deny-all"}, "active": True}]])
        r = Engine(state, NOW).open_context(bindings()["chief"], ["strategy"], "work")
        self.assertTrue(r["ok"])
        self.assertEqual([o["type"] for o in r["obligations"]],
                         ["audit_level", "max_context_ttl_ms", "no_persist", "runtime_profile", "max_output_classification"])

    def test_evaluate_share_requires_a_named_destination(self):
        state = load_fixture("kbFixture", NOW)
        r = Engine(state, NOW).evaluate(bindings()["chief"], "handbook", "share", "work")
        self.assertEqual((r["effect"], r["code"]), ("deny", "RECIPIENT"))

    def test_no_reachable_destination_class_denies(self):
        self.assertEqual(containment_across(load_fixture("kbFixture", NOW), "acme", "public", []),
                         {"ok": False, "reason": "DENIED:RECIPIENT"})


class Evidence(unittest.TestCase):
    def test_jcs(self):
        self.assertEqual(canonicalize({"b": [True, None, -0], "a": {}, "\u20ac": 1, "\r": 2}), '{"\\r":2,"a":{},"b":[true,null,0],"\u20ac":1}')
        for bad in (1.5, 2 ** 53, "\ud800", {1: 2}):
            with self.assertRaises(ValueError):
                canonicalize(bad)

    def test_merkle_proofs(self):
        leaves = [leaf_hash(bytes([i])) for i in range(7)]
        root = root_of(leaves)
        self.assertEqual(root_of([]), EMPTY_ROOT)
        for m in range(7):
            self.assertTrue(verify_inclusion(leaves[m], m, 7, inclusion_proof(leaves, m, 7), root))
            self.assertFalse(verify_inclusion(leaves[m], m, 7, inclusion_proof(leaves, m, 7), leaves[0]))
        for m in range(1, 8):
            self.assertTrue(verify_consistency(m, 7, root_of(leaves[:m]), root, consistency_proof(leaves, m, 7)))

    @unittest.skipUnless(checkpoint.available(), "optional dependency 'cryptography' is not installed")
    def test_checkpoint_signature(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        import base64
        key = Ed25519PrivateKey.generate()  # generated per run: no key material in the repository
        record = {"format": "akac-audit-checkpoint/2", "stream": "acme", "treeSize": 0, "rootHash": EMPTY_ROOT, "issuedAt": NOW, "keyId": "k1"}
        signature = key.sign(canonicalize(record).encode())
        record["signature"] = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        self.assertTrue(checkpoint.verify_checkpoint_v2(record, pem, "acme", "k1"))
        self.assertFalse(checkpoint.verify_checkpoint_v2(dict(record, treeSize=1), pem, "acme", "k1"))
        self.assertFalse(checkpoint.verify_checkpoint_v2(record, pem, "acme", "k1", minimum_size=1))


@unittest.skipUnless(checkpoint.available(), "optional dependency 'cryptography' is not installed")
class CheckpointV3(unittest.TestCase):
    """Format 3 (0.6): keys are generated per run; ML-DSA cases run only where the installed cryptography ships it."""

    @staticmethod
    def _sign(alg, message, private):
        import base64
        return base64.urlsafe_b64encode(private.sign(message)).decode().rstrip("=")

    def _record(self, alg, **over):
        return dict({"format": "akac-audit-checkpoint/3", "alg": alg, "stream": "acme", "treeSize": 3, "rootHash": EMPTY_ROOT, "issuedAt": NOW, "keyId": alg + ":k1"}, **over)

    @staticmethod
    def _pem(public):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

    def test_ed25519_v3_and_policy(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        record = self._record("ed25519")
        record["signature"] = self._sign("ed25519", checkpoint._unsigned_v3(dict(record, signature="")), key)
        pem = self._pem(key.public_key())
        self.assertTrue(checkpoint.verify_checkpoint_v3(record, pem, "acme", "ed25519:k1"))
        self.assertFalse(checkpoint.verify_checkpoint_v3(dict(record, alg="ml-dsa-65"), pem, "acme", "ed25519:k1"))
        self.assertFalse(checkpoint.verify_checkpoint_v3(record, pem, "acme", "ed25519:k1", policy={"algorithms": ["ml-dsa-65"]}))
        self.assertFalse(checkpoint.verify_checkpoint_v3(dict(record, keyId="k1"), pem, "acme", "k1"))
        self.assertFalse(checkpoint.verify_checkpoint_v3(dict(record, format="akac-audit-checkpoint/2"), pem, "acme", "ed25519:k1"))
        with self.assertRaises(ValueError):
            checkpoint.parse_policy({"algorithms": ["rsa"]})

    def test_unavailable_algorithm_is_not_a_pass(self):
        # SLH-DSA is not provided by cryptography: the verifier says so instead of accepting or silently rejecting.
        record = self._record("slh-dsa-sha2-128s", signature="A" * 10476)
        with self.assertRaises(checkpoint.AlgorithmUnavailable):
            checkpoint.verify_checkpoint_v3(record, "-----BEGIN PUBLIC KEY-----" + chr(10) + "AAAA" + chr(10) + "-----END PUBLIC KEY-----" + chr(10), "acme", "slh-dsa-sha2-128s:k1")
        self.assertNotIn("slh-dsa-sha2-128s", checkpoint.supported_algorithms())

    @unittest.skipUnless("ml-dsa-65" in checkpoint.supported_algorithms(), "installed cryptography has no ML-DSA")
    def test_mldsa_hybrid_and_downgrade(self):
        from cryptography.hazmat.primitives.asymmetric import mldsa
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import base64
        ed, ml = Ed25519PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
        alg = "ed25519+ml-dsa-65"
        record = self._record(alg)
        message = checkpoint._unsigned_v3(dict(record, signature=""))
        raw = ed.sign(message) + ml.sign(message)
        pem = self._pem(ed.public_key()) + self._pem(ml.public_key())
        good = dict(record, signature=base64.urlsafe_b64encode(raw).decode().rstrip("="))
        self.assertTrue(checkpoint.verify_checkpoint_v3(good, pem, "acme", alg + ":k1"))
        for broken in (bytes([raw[0] ^ 1]) + raw[1:], raw[:100] + bytes([raw[100] ^ 1]) + raw[101:], raw[:64], raw[64:]):
            self.assertFalse(checkpoint.verify_checkpoint_v3(dict(record, signature=base64.urlsafe_b64encode(broken).decode().rstrip("=")), pem, "acme", alg + ":k1"))
        self.assertFalse(checkpoint.verify_checkpoint_v3(good, self._pem(ml.public_key()), "acme", alg + ":k1"), "one key block only")
        # No downgrade: a classical checkpoint after a hybrid one is refused unless the policy permits it.
        crecord = {"format": "akac-audit-checkpoint/2", "stream": "acme", "treeSize": 4, "rootHash": EMPTY_ROOT, "issuedAt": NOW + 5, "keyId": "legacy"}
        crecord["signature"] = base64.urlsafe_b64encode(ed.sign(canonicalize(crecord).encode())).decode().rstrip("=")
        items = [{"checkpoint": good, "publicKey": pem}, {"checkpoint": crecord, "publicKey": self._pem(ed.public_key())}]
        self.assertFalse(checkpoint.verify_checkpoint_history(items, "acme"))
        self.assertTrue(checkpoint.verify_checkpoint_history(items, "acme", {"algorithms": list(checkpoint.ALGORITHMS), "allowClassicalAfterPq": True}))
        self.assertTrue(checkpoint.verify_checkpoint_history(items[1:], "acme"))


class Conformance(unittest.TestCase):
    def test_shared_vectors_pass(self):
        rows = run_all()
        summary = summarize(rows)
        self.assertTrue(summary["gates"]["pass"], [r for r in rows if r["outcome"] in ("FAILURE", "UNSAFE_SUCCESS")])
        for r in rows:
            if r["outcome"] == "NOT_APPLICABLE":
                self.assertTrue(r["kind"] == "runtime-enforcer" or r["kind"].startswith("release-") or (r["kind"] == "checkpoint-v2" and not checkpoint.available())
                                or r["kind"] in ("checkpoint-v3", "checkpoint-history"), r["id"])
                if r["outcome"] == "NOT_APPLICABLE" and r["kind"] in ("checkpoint-v3", "checkpoint-history"):
                    self.assertFalse(r["pass"], "an unavailable algorithm is never a pass")


if __name__ == "__main__":
    unittest.main()
