"""Deterministic process-crash and concurrent HTTP delivery regressions.

These are not model evaluations. Broker and document adapter are real CLI
subprocesses; only the disposable loopback proxy is a test fixture. A proxy
handshake selects each crash window without sleeps or production failpoints.
SIGKILL return codes prove an actual process crash. Independent read-only SQL
checks examine reservations, ancestor debits, effects, and durable ledgers.
"""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import contextlib
import json
import queue
import signal
import sqlite3
import threading
import unittest

from agent_boundary.client import BrokerClient
from agent_boundary.errors import BoundaryError
from agent_boundary.runtime import LocalSystem
from agent_boundary.transport import StrictHTTPServer, StrictJSONHandler, request_json


APPEND_DRAFT = [["document.append", "draft"]]


class DeliveryGate:
    """Hold one delivery before forwarding or after a real sink's HTTP reply.

    The proxy never acknowledges the broker. It reports the selected window to
    the test, then waits for the test's explicit release. Its upstream, if any,
    is only the freshly created document-service subprocess.
    """

    def __init__(self, upstream=None):
        self.upstream = upstream
        self.arrivals = queue.Queue()
        self.release = threading.Event()

    def __enter__(self):
        gate = self

        class Handler(StrictJSONHandler):
            def do_POST(self):
                try:
                    if self.path != "/apply":
                        raise AssertionError("Unexpected fixture proxy route")
                    token = self.require_bearer()
                    payload = self.read_json_object({"action_id", "operation", "resource", "value"})
                    result = None
                    if gate.upstream:
                        result = request_json(gate.upstream + "/apply", token, payload=payload)
                    gate.arrivals.put((payload, result, None))
                    # This is a bounded failure guard, not timing-based ordering.
                    if not gate.release.wait(15):
                        return
                    self.close_connection = True
                except Exception as error:
                    gate.arrivals.put((None, None, type(error).__name__))
                    self.close_connection = True

        self.server = StrictHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def reached(self):
        payload, result, error = self.arrivals.get(timeout=10)
        if error:
            raise AssertionError("Delivery gate failed: " + error)
        return payload, result

    def __exit__(self, *_):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


@unittest.skipUnless(hasattr(signal, "SIGKILL"), "Requires SIGKILL process semantics")
class ProcessRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.system = LocalSystem()
        self.system.__enter__()
        self.addCleanup(self.system.close)

    @contextlib.contextmanager
    def read_database(self, name):
        path = self.system.directory / name
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN")
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            yield connection
        finally:
            connection.close()

    def durable_state(self):
        """No Store/ToolStore snapshot implementation participates in the oracle."""
        with self.read_database("broker.db") as connection:
            capabilities = {row["id"]: dict(row) for row in connection.execute(
                "SELECT id, parent, quota, spent, revoked FROM capabilities"
            )}
            actions = [dict(row) for row in connection.execute(
                "SELECT action_id, capability, request_id, principal, operation, resource, "
                "value, status, result FROM actions ORDER BY action_id"
            )]
        with self.read_database("tool.db") as connection:
            documents = {row["resource"]: dict(row) for row in connection.execute(
                "SELECT resource, content, version FROM documents"
            )}
            operations = [dict(row) for row in connection.execute(
                "SELECT action_id, operation, resource, value, result FROM operations ORDER BY action_id"
            )]
        return {"capabilities": capabilities, "actions": actions,
                "documents": documents, "operations": operations}

    def kill(self, name):
        process = self.system.processes[name]
        self.assertIsNone(process.poll(), "The intended crash target must still be running")
        self.system.stop(name, kill=True)
        self.assertEqual(process.returncode, -signal.SIGKILL)

    def extra_broker(self, name):
        url = self.system._start(name, "agent_boundary.server", [
            "--db", self.system.directory / "broker.db",
            "--credentials", self.system.directory / "credentials.json",
            "--sink-url", self.system.tool_url,
            "--sink-token-file", self.system.directory / "tool-token", "--port", 0,
        ])
        return {role: BrokerClient(url, token, timeout=15)
                for role, token in self.system.tokens.items()}

    def assert_pending(self, state, lineage, action_id, effect_count):
        self.assertEqual(len(state["actions"]), 1)
        action = state["actions"][0]
        self.assertEqual((action["action_id"], action["status"], action["result"]),
                         (action_id, "pending", None))
        for capability in lineage:
            self.assertEqual(state["capabilities"][capability]["spent"], 1)
        self.assertEqual(len(state["operations"]), effect_count)
        self.assertEqual(state["documents"]["draft"]["version"], effect_count)

    def assert_single_completed_effect(self, lineage, action_id, value):
        state = self.durable_state()
        self.assertEqual(len(state["actions"]), 1)
        self.assertEqual(len(state["operations"]), 1)
        action, operation = state["actions"][0], state["operations"][0]
        self.assertEqual(action["action_id"], action_id)
        self.assertEqual(operation["action_id"], action_id)
        self.assertEqual(action["status"], "completed")
        expected = {"resource": "draft", "content": value, "version": 1}
        self.assertEqual(state["documents"]["draft"], expected)
        expected_result = {"resource": "draft", "version": 1}
        self.assertEqual(json.loads(action["result"]), expected_result)
        self.assertEqual(json.loads(operation["result"]), expected_result)
        for capability in lineage:
            self.assertEqual(state["capabilities"][capability]["spent"], 1)
        return state

    def crash_at_gate(self, gate, role, capability, request_id, value):
        """Kill before releasing the proxy, while execute lacks an acknowledgment."""
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.system.clients[role].execute,
                                 capability, request_id, "document.append", "draft", value)
            try:
                payload, sink_result = gate.reached()
                self.kill("broker")
            finally:
                gate.release.set()
            with self.assertRaises(BoundaryError) as raised:
                future.result(timeout=10)
            self.assertEqual(raised.exception.code, "transport_error")
            return payload, sink_result

    def test_sigkill_with_offline_sink_retains_all_ancestor_debits_then_drains_once(self):
        real_tool_url = self.system.tool_url
        # There is no reachable real sink during this crash window.
        self.kill("tool")
        with DeliveryGate() as gate:
            self.system.tool_url = gate.url
            self.system.restart_broker()
            clients = self.system.clients
            root = clients["admin"].root("writer", APPEND_DRAFT, 1)["capability"]
            middle = clients["writer"].delegate(root, "researcher", APPEND_DRAFT, 1)["capability"]
            leaf = clients["researcher"].delegate(middle, "reviewer", APPEND_DRAFT, 1)["capability"]
            payload, sink_result = self.crash_at_gate(gate, "reviewer", leaf, "offline", "reserved")
            self.assertIsNone(sink_result)
            lineage = (root, middle, leaf)
            self.assert_pending(self.durable_state(), lineage, payload["action_id"], effect_count=0)

        self.system.tool_url = real_tool_url
        self.system.restart_tool()
        self.system.restart_broker()
        # Revocation is not a refund and does not cancel an already admitted intent.
        self.system.clients["admin"].revoke(root)
        self.assertEqual(self.system.clients["admin"].drain(),
                         {"attempted": 1, "completed": 1, "pending": 0})
        replay = self.system.clients["reviewer"].execute(
            leaf, "offline", "document.append", "draft", "reserved")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["action_id"], payload["action_id"])
        for _ in range(3):
            self.assertEqual(self.system.clients["admin"].drain(),
                             {"attempted": 0, "completed": 0, "pending": 0})
        with self.assertRaises(BoundaryError) as raised:
            self.system.clients["reviewer"].execute(
                leaf, "after-crash-new", "document.append", "draft", "forbidden")
        self.assertEqual(raised.exception.code, "revoked")
        self.assert_single_completed_effect(lineage, payload["action_id"], "reserved")

    def test_sigkill_after_sink_commit_before_ack_replays_exactly_one_adapter_effect(self):
        real_tool_url = self.system.tool_url
        with DeliveryGate(upstream=real_tool_url) as gate:
            self.system.tool_url = gate.url
            self.system.restart_broker()
            root = self.system.clients["admin"].root("writer", APPEND_DRAFT, 1)["capability"]
            payload, sink_result = self.crash_at_gate(gate, "writer", root, "lost-ack", "once")
            self.assertEqual(sink_result, {"resource": "draft", "version": 1})
            state = self.durable_state()
            self.assert_pending(state, (root,), payload["action_id"], effect_count=1)
            self.assertEqual(state["operations"][0]["action_id"], payload["action_id"])

        # Also crash the adapter after its commit: recovery must use its durable
        # ledger, not memory in the old process or a cached proxy response.
        self.kill("tool")
        self.system.tool_url = real_tool_url
        self.system.restart_tool()
        self.system.restart_broker()
        peer = self.extra_broker("broker-peer")
        clients = (self.system.clients, peer)
        barrier = threading.Barrier(9)

        def retry(index):
            barrier.wait(timeout=10)
            if index % 2:
                return clients[index % 2]["admin"].drain()
            return clients[index % 2]["writer"].execute(
                root, "lost-ack", "document.append", "draft", "once")

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(retry, index) for index in range(8)]
            barrier.wait(timeout=10)
            results = [future.result(timeout=15) for future in futures]
        for index, result in enumerate(results):
            if index % 2:
                self.assertEqual(result["pending"], 0)
            else:
                self.assertEqual(result["status"], "completed")
                self.assertTrue(result["replayed"])
                self.assertEqual(result["action_id"], payload["action_id"])
                self.assertEqual(result["result"], sink_result)
        self.assert_single_completed_effect((root,), payload["action_id"], "once")

    def test_three_broker_processes_share_ancestor_budget_under_replay_storm(self):
        brokers = [self.system.clients, self.extra_broker("broker-peer-a"),
                   self.extra_broker("broker-peer-b")]
        pids = {self.system.processes[name].pid for name in (
            "broker", "broker-peer-a", "broker-peer-b", "tool")}
        self.assertEqual(len(pids), 4)
        root = brokers[0]["admin"].root("writer", APPEND_DRAFT, 11)["capability"]
        branches = {
            role: brokers[0]["writer"].delegate(root, role, APPEND_DRAFT, 8)["capability"]
            for role in ("researcher", "reviewer")
        }
        # Each logical request is raced through all three independent brokers.
        jobs = [(role, f"storm-{role}-{number}", f"[{role}-{number}]")
                for number in range(12) for role in branches for _ in range(3)]
        barrier = threading.Barrier(13)

        def worker(index):
            clients = brokers[index % len(brokers)]
            barrier.wait(timeout=10)
            results = []
            for role, request_id, value in jobs[index::12]:
                try:
                    result = clients[role].execute(
                        branches[role], request_id, "document.append", "draft", value)
                except BoundaryError as error:
                    results.append((role, request_id, value, None, error.code))
                else:
                    results.append((role, request_id, value, result, None))
            return results

        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = [pool.submit(worker, index) for index in range(12)]
            barrier.wait(timeout=10)
            outcomes = [outcome for future in futures for outcome in future.result(timeout=30)]
        admitted = {}
        denied = Counter()
        new_reservations = 0
        for role, request_id, value, result, error in outcomes:
            if error:
                self.assertEqual(error, "budget_exceeded")
                denied[request_id] += 1
                continue
            self.assertEqual(result["status"], "completed")
            new_reservations += not result["replayed"]
            expected = admitted.setdefault(request_id, (role, value, result["action_id"], result["result"]))
            self.assertEqual((role, value, result["action_id"], result["result"]), expected)
        self.assertEqual(len(admitted), 11)
        self.assertEqual(new_reservations, 11)
        self.assertEqual(len(denied), 13)
        self.assertEqual(set(denied.values()), {3})
        self.assertFalse(set(denied).intersection(admitted))
        self.assertEqual(len(outcomes), 72)

        state = self.durable_state()
        self.assertEqual(state["capabilities"][root]["spent"], 11)
        by_role = Counter(entry[0] for entry in admitted.values())
        for role, capability in branches.items():
            self.assertEqual(state["capabilities"][capability]["spent"], by_role[role])
            self.assertLessEqual(by_role[role], 8)
        self.assertEqual(len(state["actions"]), 11)
        self.assertEqual(len(state["operations"]), 11)
        self.assertTrue(all(action["status"] == "completed" for action in state["actions"]))
        action_ids = {entry[2] for entry in admitted.values()}
        self.assertEqual({row["action_id"] for row in state["actions"]}, action_ids)
        self.assertEqual({row["action_id"] for row in state["operations"]}, action_ids)
        ordered = sorted(state["operations"], key=lambda row: json.loads(row["result"])["version"])
        self.assertEqual([json.loads(row["result"])["version"] for row in ordered], list(range(1, 12)))
        self.assertEqual(state["documents"]["draft"]["content"], "".join(row["value"] for row in ordered))
        self.assertEqual(state["documents"]["draft"]["version"], 11)
        self.assertEqual(Counter(row["value"] for row in ordered), Counter(entry[1] for entry in admitted.values()))

        # A second replay wave after restarting both services uses durable state.
        self.system.stop("broker-peer-a")
        self.system.stop("broker-peer-b")
        self.system.restart_tool()
        self.system.restart_broker()
        for request_id, (role, value, action_id, result) in admitted.items():
            replay = self.system.clients[role].execute(
                branches[role], request_id, "document.append", "draft", value)
            self.assertTrue(replay["replayed"])
            self.assertEqual((replay["action_id"], replay["result"]), (action_id, result))
        self.assertEqual(self.system.clients["admin"].drain(),
                         {"attempted": 0, "completed": 0, "pending": 0})
        self.assertEqual(self.durable_state(), state)


if __name__ == "__main__":
    unittest.main()
