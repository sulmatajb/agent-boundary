"""Durability and authorization invariants; no model or API key required."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from agent_boundary.errors import BoundaryError
from agent_boundary.store import Store


READ = [["document.read", "source"]]
WRITE = [["document.append", "draft"]]


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "broker.sqlite"
        self.store = Store(self.path)
        self.store.register("admin", "admin-secret", admin=True)
        self.store.register("alice", "alice-secret")
        self.store.register("bob", "bob-secret")

    def tearDown(self):
        self.directory.cleanup()

    def root(self, budget=3, scopes=None, owner="alice"):
        return self.store.issue_root("admin", owner, scopes or READ, budget)

    def denied(self, code, function, *args, **kwargs):
        with self.assertRaises(BoundaryError) as error:
            function(*args, **kwargs)
        self.assertEqual(error.exception.code, code)

    def test_credentials_are_hashed_and_audit_omits_hashes(self):
        self.assertEqual(self.store.authenticate("alice-secret"), {"principal": "alice", "admin": False})
        self.denied("unauthorized", self.store.authenticate, "wrong-secret")
        with sqlite3.connect(self.path) as connection:
            digest = connection.execute("SELECT credential_digest FROM principals WHERE name='alice'").fetchone()[0]
        self.assertEqual(len(digest), 64)
        self.assertNotEqual(digest, "alice-secret")
        self.assertNotIn(digest, str(self.store.snapshot("admin")))
        self.assertNotIn(b"alice-secret", self.path.read_bytes())

    def test_duplicate_principals_and_credentials_rejected(self):
        self.denied("duplicate_principal", self.store.register, "alice", "different")
        self.denied("duplicate_principal", self.store.register, "other", "alice-secret")
        self.assertEqual(self.store.snapshot("admin")["principals"], ["admin", "alice", "bob"])

    def test_admin_required_for_root_and_audit(self):
        self.denied("forbidden", self.store.issue_root, "alice", "alice", READ, 3)
        self.denied("forbidden", self.store.snapshot, "alice")
        self.denied("unknown_principal", self.store.issue_root, "admin", "nobody", READ, 3)
        self.assertEqual(self.store.snapshot("admin")["capabilities"], {})

    def test_delegation_attenuates_owner_scope_and_budget(self):
        root = self.root(scopes=READ + WRITE)
        child = self.store.delegate("alice", root, "bob", WRITE, 2)
        self.denied("forbidden", self.store.delegate, "bob", root, "bob", READ, 1)
        self.denied("scope_denied", self.store.delegate, "bob", child, "alice", READ, 1)
        self.denied("budget_exceeded", self.store.delegate, "alice", root, "bob", READ, 4)
        self.denied("unknown_principal", self.store.delegate, "alice", root, "unknown", READ, 1)
        snapshot = self.store.snapshot("admin")
        self.assertEqual(snapshot["capabilities"][root]["spent"], 0)
        self.assertEqual(snapshot["capabilities"][child]["parent"], root)

    def test_siblings_share_all_ancestor_quota(self):
        root = self.root(budget=2)
        a = self.store.delegate("alice", root, "bob", READ, 2)
        b = self.store.delegate("alice", root, "alice", READ, 2)
        self.store.reserve("bob", a, "one", "document.read", "source")
        self.store.reserve("alice", b, "two", "document.read", "source")
        self.denied("budget_exceeded", self.store.reserve, "bob", a, "three", "document.read", "source")
        snapshot = self.store.snapshot("admin")
        self.assertEqual([snapshot["capabilities"][c]["spent"] for c in (root, a, b)], [2, 1, 1])
        self.assertEqual(len(snapshot["actions"]), 2)

    def test_delegation_checks_remaining_ancestor_budget(self):
        root = self.root(budget=2)
        child = self.store.delegate("alice", root, "bob", READ, 2)
        self.store.reserve("alice", root, "one", "document.read", "source")
        self.denied("budget_exceeded", self.store.delegate, "bob", child, "alice", READ, 2)
        self.store.delegate("bob", child, "alice", READ, 1)

    def test_replay_is_bound_to_payload_and_owner_even_after_revoke(self):
        root = self.root(budget=1, scopes=READ + WRITE)
        first = self.store.reserve("alice", root, "one", "document.read", "source")
        self.store.revoke("alice", root)
        replay = self.store.reserve("alice", root, "one", "document.read", "source")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["action_id"], first["action_id"])
        self.denied("forbidden", self.store.reserve, "bob", root, "one", "document.read", "source")
        self.denied("request_conflict", self.store.reserve, "alice", root, "one", "document.append", "draft", "x")
        self.denied("revoked", self.store.reserve, "alice", root, "two", "document.read", "source")
        self.assertEqual(self.store.snapshot("admin")["capabilities"][root]["spent"], 1)

    def test_request_ids_are_scoped_to_capability(self):
        a, b = self.root(), self.root()
        first = self.store.reserve("alice", a, "same", "document.read", "source")
        second = self.store.reserve("alice", b, "same", "document.read", "source")
        self.assertNotEqual(first["action_id"], second["action_id"])

    def test_revoked_ancestor_blocks_all_descendants(self):
        root = self.root()
        child = self.store.delegate("alice", root, "bob", READ, 3)
        self.denied("forbidden", self.store.revoke, "bob", root)
        self.store.revoke("admin", root)
        self.store.revoke("alice", root)
        self.denied("revoked", self.store.reserve, "bob", child, "one", "document.read", "source")
        self.denied("revoked", self.store.delegate, "bob", child, "alice", READ, 0)

    def test_pending_survives_restart_and_is_never_refunded(self):
        root = self.root(budget=1)
        original = self.store.reserve("alice", root, "one", "document.read", "source")
        restarted = Store(self.path)
        self.assertEqual(restarted.pending()[0]["action_id"], original["action_id"])
        self.denied("budget_exceeded", restarted.reserve, "alice", root, "two", "document.read", "source")
        restarted.revoke("admin", root)
        restarted.complete(original["action_id"], {"resource": "source", "content": "old", "version": 0})
        self.assertEqual(restarted.pending(), [])
        self.assertEqual(restarted.snapshot("admin")["capabilities"][root]["spent"], 1)

    def test_completion_is_immutable_idempotent_and_detached(self):
        root = self.root()
        action = self.store.reserve("alice", root, "one", "document.read", "source")
        result = {"content": "source", "nested": [1, {"key": True}]}
        self.store.complete(action["action_id"], result)
        self.store.complete(action["action_id"], {"nested": [1, {"key": True}], "content": "source"})
        result["nested"].append("mutated")
        replay = self.store.reserve("alice", root, "one", "document.read", "source")
        self.assertEqual(replay["result"]["nested"], [1, {"key": True}])
        replay["result"]["nested"].clear()
        self.assertEqual(self.store.snapshot("admin")["actions"][0]["result"]["nested"], [1, {"key": True}])
        self.denied("result_conflict", self.store.complete, action["action_id"], {"content": "new"})
        self.denied("unknown_action", self.store.complete, "act_unknown", {})

    def test_zero_budget_never_admits(self):
        root = self.root(budget=0)
        self.store.delegate("alice", root, "bob", READ, 0)
        self.denied("budget_exceeded", self.store.reserve, "alice", root, "one", "document.read", "source")

    def test_inputs_are_exact_json_types_and_catalogue_ids(self):
        for budget in (True, False, 1.0, "1", -1, 100001):
            with self.subTest(budget=budget):
                self.denied("invalid_input", self.store.issue_root, "admin", "alice", READ, budget)
        for scopes in ([], (("document.read", "source"),), [("document.read", "source")],
                       READ + READ, [["shell", "source"]], [["document.read", "../private"]]):
            with self.subTest(scopes=scopes):
                self.denied("invalid_input", self.store.issue_root, "admin", "alice", scopes, 1)
        self.denied("invalid_input", self.store.register, "bad/name", "token")
        self.denied("invalid_input", self.store.register, "new", "token", admin=1)

    def test_invalid_operations_never_charge(self):
        root = self.root(scopes=READ + WRITE)
        cases = [("document.read", "source", "not-null"), ("document.read", "file:///private", None),
                 ("shell", "source", None), ("document.append", "draft", None),
                 ("document.append", "draft", 1), ("document.append", "draft", "x" * 4097),
                 ("document.append", "draft", "\ud800")]
        for operation, resource, value in cases:
            with self.subTest(operation=operation, resource=resource):
                self.denied("invalid_input", self.store.reserve, "alice", root, "one", operation, resource, value)
        self.denied("scope_denied", self.store.reserve, "alice", root, "one", "document.read", "private")
        self.denied("invalid_input", self.store.reserve, "alice", root, "bad/id", "document.read", "source")
        self.assertEqual(self.store.snapshot("admin")["capabilities"][root]["spent"], 0)

    def test_invalid_result_never_completes(self):
        root = self.root()
        action = self.store.reserve("alice", root, "one", "document.read", "source")
        for result in ([], {"nan": float("nan")}, {"inf": float("inf")}, {1: "key"}, {"tuple": (1,)}, {"text": "\udfff"}):
            with self.subTest(result=result):
                self.denied("invalid_input", self.store.complete, action["action_id"], result)
        self.assertEqual(len(self.store.pending()), 1)

    def test_depth_limit_and_capability_limit_fail_closed(self):
        cap = self.root(budget=1)
        for _ in range(31):
            cap = self.store.delegate("alice", cap, "alice", READ, 1)
        self.denied("depth_limit", self.store.delegate, "alice", cap, "alice", READ, 1)
        self.store.reserve("alice", cap, "one", "document.read", "source")
        self.assertTrue(all(row["spent"] == 1 for row in self.store.snapshot("admin")["capabilities"].values()))
        with patch("agent_boundary.store.MAX_CAPABILITIES", 32):
            self.denied("capability_limit", self.store.issue_root, "admin", "alice", READ, 1)

    def test_pending_and_snapshot_return_detached_objects(self):
        root = self.root()
        self.store.reserve("alice", root, "one", "document.read", "source")
        snapshot = self.store.snapshot("admin")
        snapshot["capabilities"][root]["scopes"][0][1] = "private"
        pending = self.store.pending()
        pending[0]["resource"] = "private"
        self.assertEqual(self.store.pending()[0]["resource"], "source")
        self.assertEqual(self.store.snapshot("admin")["capabilities"][root]["scopes"], READ)
        self.denied("invalid_input", self.store.pending, True)

    def test_sql_failure_rolls_back_debits_and_outbox_together(self):
        root = self.root()
        with sqlite3.connect(self.path) as connection:
            connection.execute("CREATE TRIGGER reject_action BEFORE INSERT ON actions BEGIN SELECT RAISE(ABORT, 'test'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.reserve("alice", root, "one", "document.read", "source")
        snapshot = self.store.snapshot("admin")
        self.assertEqual(snapshot["actions"], [])
        self.assertEqual(snapshot["capabilities"][root]["spent"], 0)

    def test_concurrent_siblings_cannot_overspend_root(self):
        root = self.root(budget=9)
        children = [self.store.delegate("alice", root, "bob", READ, 9) for _ in range(3)]

        def attempt(index):
            try:
                return self.store.reserve("bob", children[index % 3], str(index), "document.read", "source")
            except BoundaryError as error:
                self.assertEqual(error.code, "budget_exceeded")
                return None

        with ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(attempt, range(36)))
        self.assertEqual(sum(result is not None for result in results), 9)
        snapshot = self.store.snapshot("admin")
        self.assertEqual(snapshot["capabilities"][root]["spent"], 9)
        self.assertEqual(sum(snapshot["capabilities"][child]["spent"] for child in children), 9)
        self.assertEqual(len(snapshot["actions"]), 9)

    def test_concurrent_replay_creates_one_immutable_action(self):
        root = self.root(budget=1)
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(lambda _: self.store.reserve("alice", root, "one", "document.read", "source"), range(20)))
        self.assertEqual(len({result["action_id"] for result in results}), 1)
        self.assertEqual(sum(not result["replayed"] for result in results), 1)
        self.assertEqual(self.store.snapshot("admin")["capabilities"][root]["spent"], 1)


if __name__ == "__main__":
    unittest.main()
