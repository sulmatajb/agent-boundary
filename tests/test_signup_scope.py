"""Deny-by-default secret listing and network probe, plus explicit-grant allow paths.

Deterministic fixtures only. No model calls, live credentials, or network scans.
"""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from agent_boundary.catalogue import FIXTURE_SECRET_NAMES
from agent_boundary.codex_adapter import validate_proposal
from agent_boundary.errors import BoundaryError
from agent_boundary.receipts import is_action_receipt
from agent_boundary.server import _deliver
from agent_boundary.store import Store
from agent_boundary.tool_service import ToolStore
from agent_boundary.transport import StrictHTTPServer, StrictJSONHandler


ROOT = Path(__file__).resolve().parents[1]
SIGNUP = [["document.read", "source"]]
EXPLICIT = [["network.probe", "signup-net"], ["secret.list", "env"]]


def load_example():
    specification = importlib.util.spec_from_file_location(
        "signup_scope_example", ROOT / "examples/signup_scope_boundary.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class ScopeAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name) / "broker.sqlite")
        self.tool = ToolStore(Path(self.directory.name) / "tool.sqlite")
        self.store.register("admin", "admin-secret", admin=True)
        self.store.register("tester", "tester-secret")
        self.store.register("peer", "peer-secret")

    def denied(self, code, function, *args):
        before = self.store.snapshot("admin")
        with self.assertRaises(BoundaryError) as error:
            function(*args)
        self.assertEqual(error.exception.code, code)
        self.assertEqual(self.store.snapshot("admin")["actions"], before["actions"])
        self.assertEqual(
            {key: row["spent"] for key, row in self.store.snapshot("admin")["capabilities"].items()},
            {key: row["spent"] for key, row in before["capabilities"].items()})
        return error.exception

    def test_signup_scope_denies_secret_and_network_before_any_action(self):
        signup = self.store.issue_root("admin", "tester", SIGNUP, 4)
        proposals = (
            ("list-env", "secret.list", "env", None, "scope_denied"),
            ("probe-net", "network.probe", "signup-net", None, "scope_denied"),
            ("probe-address", "network.probe", "signup-net", "203.0.113.10", "invalid_input"),
            ("list-named", "secret.list", "env", "CUSTOMER_SECRET", "invalid_input"),
            ("cross-secret", "secret.list", "source", None, "invalid_input"),
            ("cross-probe", "network.probe", "env", None, "invalid_input"),
            ("host-resource", "network.probe", "203.0.113.10", None, "invalid_input"),
            ("shell", "shell.exec", "env", None, "invalid_input"),
        )
        for request_id, operation, resource, value, code in proposals:
            with self.subTest(operation=operation, resource=resource, value=value):
                self.denied(code, self.store.reserve, "tester", signup, request_id, operation, resource, value)
        self.denied("scope_denied", self.store.delegate, "tester", signup, "peer", [["secret.list", "env"]], 1)
        self.assertEqual(self.tool.snapshot()["operations"], [])
        admitted = self.store.reserve("tester", signup, "signup-read", "document.read", "source")
        self.assertEqual(admitted["status"], "pending")
        self.assertEqual(self.store.snapshot("admin")["capabilities"][signup]["spent"], 1)

    def test_explicit_scope_admits_ancestor_charge_and_rejects_the_other_pair(self):
        parent = self.store.issue_root("admin", "tester", EXPLICIT, 2)
        secret_only = self.store.delegate("tester", parent, "peer", [["secret.list", "env"]], 1)
        self.denied("scope_denied", self.store.reserve, "peer", secret_only, "probe", "network.probe", "signup-net", None)
        listed = self.store.reserve("peer", secret_only, "list", "secret.list", "env", None)
        self.assertFalse(listed["replayed"])
        snapshot = self.store.snapshot("admin")
        self.assertEqual(snapshot["capabilities"][parent]["spent"], 1)
        self.assertEqual(snapshot["capabilities"][secret_only]["spent"], 1)
        replay = self.store.reserve("peer", secret_only, "list", "secret.list", "env", None)
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["action_id"], listed["action_id"])
        self.assertEqual(self.store.snapshot("admin")["capabilities"][parent]["spent"], 1)
        probed = self.store.reserve("tester", parent, "probe", "network.probe", "signup-net", None)
        self.assertEqual(self.store.snapshot("admin")["capabilities"][parent]["spent"], 2)
        self.denied("budget_exceeded", self.store.reserve, "tester", parent, "again", "network.probe", "signup-net", None)
        list_receipt = self.tool.apply(listed["action_id"], "secret.list", "env", None)
        probe_receipt = self.tool.apply(probed["action_id"], "network.probe", "signup-net", None)
        self.assertTrue(is_action_receipt(list_receipt, "secret.list", "env"))
        self.assertTrue(is_action_receipt(probe_receipt, "network.probe", "signup-net"))
        self.store.complete(listed["action_id"], list_receipt)
        self.store.complete(probed["action_id"], probe_receipt)
        self.assertEqual(self.tool.apply(listed["action_id"], "secret.list", "env", None), list_receipt)
        self.assertEqual(len(self.tool.snapshot()["operations"]), 2)
        self.assertEqual(self.store.pending_count(), 0)

    def test_workflow_schema_still_rejects_secret_and_network_proposals(self):
        for operation, resource in (("secret.list", "env"), ("network.probe", "signup-net")):
            proposal = {"kind": "tool", "operation": operation, "resource": resource, "value": None,
                        "message": "schema is not authorization"}
            with self.assertRaises(BoundaryError) as error:
                validate_proposal(proposal)
            self.assertEqual(error.exception.code, "invalid_proposal")


class FixtureToolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tool = ToolStore(Path(self.directory.name) / "tool.sqlite")

    def test_list_ignores_environment_and_probe_opens_no_socket(self):
        def refused(*_args, **_kwargs):
            raise AssertionError("socket used")

        with patch.dict(os.environ, {"FIXTURE_SIGNUP_KEY": "not-read", "AWS_SECRET_ACCESS_KEY": "not-read"}):
            with patch("socket.socket", refused), patch("socket.create_connection", refused):
                listed = self.tool.apply("list", "secret.list", "env", None)
                probed = self.tool.apply("probe", "network.probe", "signup-net", None)
        self.assertEqual(listed, {"resource": "env", "names": list(FIXTURE_SECRET_NAMES), "version": 0})
        self.assertEqual(probed, {"resource": "signup-net", "opened": False, "ports": []})
        self.assertNotIn("not-read", json.dumps(self.tool.snapshot()))
        documents = self.tool.snapshot()["documents"]
        self.assertEqual(documents["private"]["content"], "CANARY_PRIVATE")
        self.assertEqual(documents["source"]["version"], 0)

    def test_non_null_values_and_replays_do_not_extend_the_fixture(self):
        self.tool.apply("list", "secret.list", "env", None)
        before = self.tool.snapshot()
        for payload in (
            ("list", "secret.list", "env", "CUSTOMER_SECRET"),
            ("other", "network.probe", "signup-net", "203.0.113.10"),
            ("other", "network.probe", "source", None),
            ("other", "secret.list", "private", None),
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(BoundaryError):
                    self.tool.apply(*payload)
        self.assertEqual(self.tool.snapshot(), before)


class ReceiptGateTests(unittest.TestCase):
    def test_non_fixture_replies_are_not_success_and_exact_replies_complete(self):
        cases = (
            ({"resource": "signup-net", "opened": True, "ports": []}, False),
            ({"resource": "signup-net", "opened": False, "ports": [80]}, False),
            ({"resource": "signup-net", "opened": False, "ports": [], "host": "203.0.113.10"}, False),
            ({"resource": "env", "names": ["FIXTURE_SIGNUP_KEY", "AWS_SECRET_ACCESS_KEY"], "version": 0}, False),
            ({"resource": "env", "names": ["FIXTURE_SIGNUP_KEY"], "version": 0, "values": {"FIXTURE_SIGNUP_KEY": "x"}}, False),
            ({"resource": "env", "names": list(FIXTURE_SECRET_NAMES), "version": 0}, True),
            ({"resource": "signup-net", "opened": False, "ports": []}, True),
        )
        for body, accepted in cases:
            operation = "secret.list" if "names" in body else "network.probe"
            resource = "env" if operation == "secret.list" else "signup-net"
            self.assertEqual(is_action_receipt(body, operation, resource), accepted)
        self.assertTrue(is_action_receipt(
            {"resource": "draft", "version": 1}, "document.append", "draft"))

    def test_broker_leaves_bad_probe_receipt_pending_and_completes_fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = Store(Path(directory.name) / "broker.sqlite")
        store.register("admin", "admin-secret", admin=True)
        store.register("tester", "tester-secret")
        capability = store.issue_root("admin", "tester", [["network.probe", "signup-net"]], 2)
        bad = store.reserve("tester", capability, "bad", "network.probe", "signup-net", None)
        good = store.reserve("tester", capability, "good", "network.probe", "signup-net", None)

        class Sink(StrictJSONHandler):
            def do_POST(self):
                payload = self.read_json_object({"action_id", "operation", "resource", "value"})
                if payload["action_id"] == bad["action_id"]:
                    result = {"resource": "signup-net", "opened": True, "ports": [22]}
                else:
                    result = {"resource": "signup-net", "opened": False, "ports": []}
                self.send_json(200, result)

        server = StrictHTTPServer(("127.0.0.1", 0), Sink)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        self.addCleanup(lambda: worker.join(3))
        url = f"http://127.0.0.1:{server.server_address[1]}"
        self.assertIsNone(_deliver(store, bad, url, "fixture-token"))
        self.assertEqual(_deliver(store, good, url, "fixture-token"),
                         {"resource": "signup-net", "opened": False, "ports": []})
        pending = store.pending()
        self.assertEqual([row["action_id"] for row in pending], [bad["action_id"]])
        self.assertEqual(store.snapshot("admin")["capabilities"][capability]["spent"], 2)


class SignupDemoTests(unittest.TestCase):
    def test_report_shows_broker_denial_and_explicit_grant(self):
        example = load_example()
        report = example.run_demo()
        steps = {step["request_id"]: step for step in report["steps"]}
        self.assertEqual(report["backend"], "deterministic")
        self.assertEqual(report["model_calls"], 0)
        self.assertTrue(report["temporary_databases_removed"])
        self.assertEqual(steps["list-env"]["code"], "scope_denied")
        self.assertFalse(steps["list-env"]["dispatched"])
        self.assertEqual(steps["probe-net"]["code"], "scope_denied")
        self.assertFalse(steps["probe-net"]["dispatched"])
        self.assertEqual(steps["probe-address"]["code"], "invalid_input")
        self.assertEqual(steps["broaden-secret-list"]["code"], "scope_denied")
        self.assertEqual(steps["signup-read"]["outcome"], "completed")
        self.assertTrue(steps["signup-read"]["dispatched"])
        self.assertEqual(steps["explicit-list"]["receipt"]["names"], ["FIXTURE_SIGNUP_KEY"])
        self.assertFalse(steps["explicit-probe"]["receipt"]["opened"])
        self.assertEqual(steps["explicit-probe"]["receipt"]["ports"], [])
        self.assertEqual(steps["explicit-probe"]["outcome"], "replayed")
        self.assertFalse(steps["explicit-probe"]["dispatched"])
        self.assertEqual(report["tool_effects"],
                         {"document.read": 1, "document.append": 0, "secret.list": 1, "network.probe": 1})
        self.assertEqual(report["admitted_operations"], ["document.read", "network.probe", "secret.list"])
        encoded = json.dumps(report)
        self.assertNotIn("CANARY_PRIVATE", encoded)
        self.assertNotIn("203.0.113.10", encoded)
        self.assertNotIn("CUSTOMER_SECRET", encoded)

    def test_cli_json_is_the_same_public_report(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = "src"
        completed = subprocess.run(
            [sys.executable, "examples/signup_scope_boundary.py", "--json"],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        report = json.loads(completed.stdout)
        self.assertEqual(report["demonstration"], "signup_scope_boundary")
        self.assertEqual(report["tool_effects"]["secret.list"], 1)
        self.assertEqual(report["tool_effects"]["network.probe"], 1)
        text = subprocess.run(
            [sys.executable, "examples/signup_scope_boundary.py"],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertEqual(text.stdout, load_example().transcript(report) + "\n")
        self.assertIn("scope_denied", text.stdout)
        self.assertIn("not dispatched", text.stdout)
        self.assertNotIn(str(ROOT), text.stdout)
        rejected = subprocess.run(
            [sys.executable, "examples/signup_scope_boundary.py", "--not-a-flag"],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(rejected.stdout, "")
        self.assertEqual(rejected.stderr, "Invalid arguments. Use --help.\n")


class SocketModuleGuardTests(unittest.TestCase):
    def test_reference_tool_module_does_not_bind_socket(self):
        import agent_boundary.tool_service as tool_service
        self.assertNotIn("socket", tool_service.__dict__)
