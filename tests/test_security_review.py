"""Independent deterministic security regressions using disposable local fixtures.

These exercise real HTTP and subprocess boundaries; they are not live model
evaluations. The fake CLI never opens account state or contacts a network.
"""

import contextlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from agent_boundary.client import BrokerClient
from agent_boundary.codex_adapter import CodexBackend, MAX_CLI_OUTPUT_BYTES, SUPPORTED_CODEX_VERSION
from agent_boundary.errors import BoundaryError
from agent_boundary.server import create_server
from agent_boundary.store import Store
from agent_boundary.tool_service import ToolStore, create_tool_server
from agent_boundary.transport import MAX_RESPONSE


@contextlib.contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


class IndependentSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="boundary-security-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.store = Store(self.directory / "broker.db")
        self.store.register("admin", "fixture-admin", admin=True)
        self.store.register("writer", "fixture-writer")
        self.tool = ToolStore(self.directory / "tool.db")

    def launch(self, sink=True):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        sink_url = stack.enter_context(running(create_tool_server(self.tool, "fixture-sink"))) if sink else None
        self.url = stack.enter_context(running(create_server(
            self.store, sink_url=sink_url, sink_token="fixture-sink" if sink else None)))
        self.admin = BrokerClient(self.url, "fixture-admin")
        self.writer = BrokerClient(self.url, "fixture-writer")

    def test_empty_append_cannot_read_preexisting_private_content(self):
        self.launch()
        cap = self.admin.root("writer", [["document.append", "private"]], 1)["capability"]
        with self.assertRaises(BoundaryError):
            self.writer.execute(cap, "forbidden-read", "document.read", "private")
        result = self.writer.execute(cap, "empty-append", "document.append", "private", "")
        self.assertEqual(result["status"], "completed")
        self.assertNotIn("CANARY_PRIVATE", json.dumps(result))
        self.assertEqual(result["result"], {"resource": "private", "version": 1})
        self.assertEqual(self.writer.execute(cap, "empty-append", "document.append", "private", "")["result"],
                         result["result"])
        self.assertEqual(self.admin.audit()["capabilities"][cap]["spent"], 1)

    def test_document_limit_counts_utf8_bytes_and_rejects_before_mutation(self):
        # Each permitted input has 4,096 Unicode characters but 16 KiB of UTF-8.
        value = "\U0001f642" * 4096
        for index in range(4):
            self.tool.apply(f"fit-{index}", "document.append", "draft", value)
        with self.assertRaises(BoundaryError):
            self.tool.apply("overflow", "document.append", "draft", value)
        snapshot = self.tool.snapshot()
        self.assertEqual(len(snapshot["documents"]["draft"]["content"].encode("utf-8")), 64 * 1024)
        self.assertEqual(snapshot["documents"]["draft"]["version"], 4)
        self.assertEqual(len(snapshot["operations"]), 4)

    def test_large_read_history_keeps_http_audit_bounded(self):
        # A 64 KiB document serializes to 192 KiB because of JSON escaping.
        # The previous full-history audit exceeded 16 MiB after only 90 reads.
        value = "\U0001f642" * 4096
        for index in range(4):
            self.tool.apply(f"seed-{index}", "document.append", "draft", value)
        self.launch()
        cap = self.admin.root("writer", [["document.read", "draft"]], 90)["capability"]
        for index in range(90):
            action = self.writer.execute(cap, f"read-{index}", "document.read", "draft")
            self.assertEqual(action["status"], "completed")
        audit = self.admin.audit()
        self.assertEqual(audit["total_actions"], 90)
        self.assertEqual(audit["capabilities"][cap]["spent"], 90)
        self.assertLess(len(json.dumps(audit).encode("utf-8")), MAX_RESPONSE)
        self.assertTrue(all("value" not in action and "result" not in action for action in audit["actions"]))
        self.assertNotIn(value, json.dumps(audit, ensure_ascii=False))
        # This proves the fixture actually reaches the old endpoint's failure
        # threshold; snapshot is intentionally the trusted, unbounded API.
        self.assertGreater(len(json.dumps(self.store.snapshot("admin")).encode("utf-8")), MAX_RESPONSE)

    def test_audit_pagination_preserves_every_action_once(self):
        cap = self.store.issue_root("admin", "writer", [["document.append", "draft"]], 237)
        expected = []
        for index in range(237):
            action = self.store.reserve("writer", cap, f"page-{index}", "document.append", "draft", "payload")
            expected.append(action["action_id"])
        self.launch(sink=False)
        page = self.admin.audit()
        self.assertEqual(len(page["actions"]), 100)
        self.assertEqual(page["next_offset"], 100)
        seen = [action["action_id"] for action in page["actions"]]
        while page["next_offset"] is not None:
            page = self.admin.audit(offset=page["next_offset"], limit=31)
            self.assertEqual(page["total_actions"], 237)
            self.assertLessEqual(len(page["actions"]), 31)
            seen.extend(action["action_id"] for action in page["actions"])
        self.assertEqual(seen, expected)
        self.assertEqual(len(set(seen)), 237)
        self.assertEqual(self.admin.audit(offset=237)["actions"], [])

    def test_audit_paging_requires_admin_and_exact_bounded_integers(self):
        self.launch(sink=False)
        with self.assertRaises(BoundaryError) as caught:
            self.writer.audit(offset=0, limit=10)
        self.assertEqual(caught.exception.status, 403)
        for offset, limit in [(False, 1), (-1, 1), (2**63, 1), (0, True), (0, 0), (0, 1001), (0, 100.0)]:
            with self.subTest(offset=offset, limit=limit), self.assertRaises(BoundaryError) as caught:
                self.admin.audit(offset=offset, limit=limit)
            self.assertEqual(caught.exception.status, 400)

    def test_drain_counts_pending_without_materializing_full_snapshot(self):
        self.launch(sink=False)
        cap = self.admin.root("writer", [["document.append", "draft"]], 1)["capability"]
        self.writer.execute(cap, "pending", "document.append", "draft", "x")
        with patch.object(self.store, "snapshot", side_effect=AssertionError("Unbounded snapshot forbidden")):
            self.assertEqual(self.admin.drain(), {"attempted": 1, "completed": 0, "pending": 1})

    def test_permanent_failure_prefix_cannot_starve_later_pending_read(self):
        for index in range(16):
            self.tool.apply(f"fill-{index}", "document.append", "draft", "X" * 4096)
        cap = self.store.issue_root("admin", "writer", [
            ["document.append", "draft"], ["document.read", "source"]], 101)
        for index in range(100):
            self.store.reserve("writer", cap, f"overflow-{index}", "document.append", "draft", "X")
        read = self.store.reserve("writer", cap, "recoverable-read", "document.read", "source")
        self.launch()
        self.assertEqual(self.admin.drain(), {"attempted": 100, "completed": 0, "pending": 101})
        second = self.admin.drain()
        self.assertGreaterEqual(second["completed"], 1)
        self.assertEqual(second["pending"], 100)
        audit = self.store.snapshot("admin")
        self.assertEqual(audit["capabilities"][cap]["spent"], 101)
        outcome = next(action for action in audit["actions"] if action["action_id"] == read["action_id"])
        self.assertEqual(outcome["status"], "completed")
        self.assertEqual(outcome["result"]["content"], "Sample source text.")

    def test_cli_output_limit_terminates_writer_before_its_timeout(self):
        # A size guard after communicate() returns would wait for this sleep
        # and incorrectly report timeout; the pipe must be drained with a cap.
        executable = self.directory / "fixture-codex"
        executable.write_text(
            f"#!{sys.executable}\n"
            "import sys, time\n"
            "if '--version' in sys.argv:\n"
            f"    print({SUPPORTED_CODEX_VERSION!r})\n"
            "else:\n"
            "    sys.stdin.read()\n"
            f"    sys.stdout.buffer.write(b'x' * {MAX_CLI_OUTPUT_BYTES + 1024})\n"
            "    sys.stdout.buffer.flush()\n"
            "    time.sleep(3)\n",
            encoding="utf-8")
        executable.chmod(0o700)
        backend = CodexBackend(timeout=1, executable=str(executable))
        with self.assertRaises(BoundaryError) as caught:
            backend.propose({"role": "researcher", "history": []})
        self.assertEqual(caught.exception.code, "codex_output_limit")
        self.assertEqual(backend.calls, [])

    @unittest.skipUnless(os.name == "posix", "Live CLI adapter requires a POSIX process group")
    def test_cli_timeout_kills_descendant_that_keeps_stdout_open(self):
        marker = self.directory / "descendant-survived"
        started = self.directory / "descendant-started"
        child = ("import pathlib,time; "
                 f"pathlib.Path({str(started)!r}).write_text('started'); "
                 "time.sleep(0.8); "
                 f"pathlib.Path({str(marker)!r}).write_text('survived')")
        executable = self.directory / "descendant-fixture-codex"
        executable.write_text(
            f"#!{sys.executable}\n"
            "import subprocess, sys\n"
            "if '--version' in sys.argv:\n"
            f"    print({SUPPORTED_CODEX_VERSION!r})\n"
            "else:\n"
            # Child inherits stdout. Direct CLI exits; deadline cleanup must
            # still kill this same-session child instead of blocking on EOF.
            f"    subprocess.Popen([sys.executable, '-c', {child!r}])\n",
            encoding="utf-8")
        executable.chmod(0o700)
        backend = CodexBackend(timeout=0.4, executable=str(executable))
        with self.assertRaises(BoundaryError) as caught:
            backend.propose({"role": "researcher"})
        self.assertEqual(caught.exception.code, "codex_timeout")
        self.assertTrue(started.exists(), "Descendant must start for this probe to be meaningful")
        time.sleep(0.8)
        self.assertFalse(marker.exists(), "Timed-out CLI descendant survived process-group cleanup")
        self.assertEqual(backend.calls, [])


if __name__ == "__main__":
    unittest.main()
