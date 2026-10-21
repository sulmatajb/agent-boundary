"""Malformed successful tool receipts remain recoverable through real HTTP."""
import contextlib
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from agent_boundary.client import BrokerClient
from agent_boundary.codex_adapter import BoundToolChannel, tool_proposal
from agent_boundary.errors import BoundaryError
from agent_boundary.server import create_server
from agent_boundary.store import Store
from agent_boundary.tool_service import MAX_DOCUMENT_BYTES, ToolStore
from agent_boundary.transport import StrictHTTPServer, StrictJSONHandler


@contextlib.contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        if thread.is_alive():
            raise RuntimeError("Disposable receipt fixture did not stop")


class ReceiptRecoveryTests(unittest.TestCase):
    def exercise(self, operation, corrupt, *, expected_initial="pending", content=None):
        with tempfile.TemporaryDirectory(prefix="boundary-receipt-test-") as tmp:
            broker_path, tool_path = Path(tmp) / "broker.db", Path(tmp) / "tool.db"
            store, tool = Store(broker_path), ToolStore(tool_path)
            store.register("admin", "synthetic-admin", admin=True)
            store.register("parent", "synthetic-parent")
            store.register("worker", "synthetic-worker")
            scope = [[operation, "draft"]]
            parent = store.issue_root("admin", "parent", scope, 1)
            child = store.delegate("parent", parent, "worker", scope, 1)
            if content is not None:
                for i in range(0, len(content), 4096):
                    tool.apply(f"seed-{i}", "document.append", "draft", content[i:i + 4096])
            deliveries = []
            value = "text" if operation == "document.append" else None

            class Sink(StrictJSONHandler):
                def do_POST(self):
                    self.require_bearer()
                    payload = self.read_json_object({"action_id", "operation", "resource", "value"})
                    deliveries.append(payload["action_id"])
                    receipt = tool.apply(**payload)
                    self.send_json(200, corrupt(receipt) if len(deliveries) == 1 else receipt)

            with running(StrictHTTPServer(("127.0.0.1", 0), Sink)) as sink_url:
                with running(create_server(store, sink_url=sink_url, sink_token="synthetic-dispatch")) as url:
                    with self.assertRaises(BoundaryError) as denied:
                        BrokerClient(url, "synthetic-wrong").execute(child, "unauthorized", operation, "draft", value)
                    self.assertEqual(denied.exception.status, 401)
                    self.assertEqual(deliveries, [])
                    reply = BoundToolChannel(BrokerClient(url, "synthetic-worker"), child).execute(tool_proposal(operation, "draft", value))
                    self.assertEqual(reply["status"], expected_initial)
                    if expected_initial == "pending":
                        self.assertEqual(reply, {"status": "pending", "result": None})

                # Independent SQL and a reopened Store/server distinguish durable
                # completion from a supervisor-only response classification.
                with sqlite3.connect(broker_path) as db:
                    rows = db.execute("SELECT action_id, request_id, status, result FROM actions").fetchall()
                    self.assertEqual(len(rows), 1)
                    action_id, request_id, status, saved = rows[0]
                    self.assertEqual(status, expected_initial)
                    if expected_initial == "pending": self.assertIsNone(saved)
                    self.assertEqual(sorted(db.execute("SELECT id, spent FROM capabilities").fetchall()), sorted([(parent, 1), (child, 1)]))
                reopened = Store(broker_path)
                with running(create_server(reopened, sink_url=sink_url, sink_token="synthetic-dispatch")) as url:
                    drain = BrokerClient(url, "synthetic-admin").drain()
                    count = 1 if expected_initial == "pending" else 0
                    self.assertEqual(drain, {"attempted": count, "completed": count, "pending": 0})
                    replay = BrokerClient(url, "synthetic-worker").execute(child, request_id, operation, "draft", value)
                    self.assertEqual(replay["status"], "completed")
                    self.assertEqual(replay["action_id"], action_id)
                    self.assertEqual(deliveries, [action_id] * (1 + count))
                    with self.assertRaises(BoundaryError):
                        BrokerClient(url, "synthetic-worker").execute(child, "replacement", operation, "draft", value)
                    self.assertEqual(len(deliveries), 1 + count)
                with sqlite3.connect(broker_path) as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM actions").fetchone()[0], 1)
                    self.assertEqual(sorted(row[0] for row in db.execute("SELECT spent FROM capabilities")), [1, 1])
                with sqlite3.connect(tool_path) as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM operations WHERE action_id=?", (action_id,)).fetchone()[0], 1)
                    if operation == "document.append":
                        self.assertEqual(db.execute("SELECT content, version FROM documents WHERE resource='draft'").fetchone(), ("text", 1))
                return replay["result"]

    def test_zero_append_version_stays_pending_then_recovers_same_effect(self):
        result = self.exercise("document.append", lambda r: {**r, "version": 0})
        self.assertEqual(result, {"resource": "draft", "version": 1})

    def test_invalid_unicode_read_stays_pending_then_recovers_original_snapshot(self):
        result = self.exercise("document.read", lambda r: {**r, "content": "\ud800"})
        self.assertEqual(result, {"resource": "draft", "version": 0, "content": ""})

    def test_oversize_utf8_read_stays_pending_then_recovers_original_snapshot(self):
        result = self.exercise("document.read", lambda r: {**r, "content": "é" * (MAX_DOCUMENT_BYTES // 2 + 1)})
        self.assertEqual(result, {"resource": "draft", "version": 0, "content": ""})

    def test_exact_utf8_limit_read_is_completed_without_recovery(self):
        content = "é" * (MAX_DOCUMENT_BYTES // 2)
        result = self.exercise("document.read", lambda r: r, expected_initial="completed", content=content)
        self.assertEqual(result["content"], content)
        self.assertEqual(result["version"], 8)

    def test_empty_version_zero_read_is_completed_without_recovery(self):
        result = self.exercise("document.read", lambda r: r, expected_initial="completed")
        self.assertEqual(result, {"resource": "draft", "version": 0, "content": ""})

    def test_positive_append_receipt_is_completed_without_recovery(self):
        result = self.exercise("document.append", lambda r: r, expected_initial="completed")
        self.assertEqual(result, {"resource": "draft", "version": 1})


if __name__ == "__main__":
    unittest.main()
