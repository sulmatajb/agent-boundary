"""Real socket and SQLite tests for the separately deployed tool adapter."""

from concurrent.futures import ThreadPoolExecutor
import contextlib
import http.client
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from agent_boundary.errors import BoundaryError
from agent_boundary.tool_service import ToolStore, create_tool_server


class ToolStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "nested" / "tool.sqlite3"
        self.store = ToolStore(self.path)

    def test_seed_literal_append_and_durable_replay(self):
        text = "$(touch PWNED); <script>ignored()</script>\n\\x00\u2603"
        first = self.store.apply("a1", "document.append", "draft", text)
        self.assertEqual(first, {"resource": "draft", "version": 1})
        reopened = ToolStore(self.path)
        self.assertEqual(reopened.apply("a1", "document.append", "draft", text), first)
        snapshot = reopened.snapshot()
        self.assertEqual(snapshot["documents"]["draft"]["content"], text)
        self.assertEqual(snapshot["documents"]["private"]["content"], "CANARY_PRIVATE")
        self.assertEqual(len(snapshot["operations"]), 1)

    def test_old_read_result_survives_later_write_and_reopen(self):
        original = self.store.apply("read", "document.read", "draft", None)
        self.store.apply("write", "document.append", "draft", "later")
        reopened = ToolStore(self.path)
        self.assertEqual(reopened.apply("read", "document.read", "draft", None), original)
        self.assertEqual(reopened.apply("new-read", "document.read", "draft", None)["content"], "later")

    def test_conflicting_replay_is_denied_without_side_effect(self):
        self.store.apply("same", "document.append", "draft", "once")
        before = self.store.snapshot()
        for operation, resource, value in [
            ("document.append", "draft", "twice"),
            ("document.append", "source", "once"),
            ("document.read", "draft", None),
        ]:
            with self.subTest(operation=operation, resource=resource):
                with self.assertRaises(BoundaryError) as error:
                    self.store.apply("same", operation, resource, value)
                self.assertEqual(error.exception.status, 409)
        self.assertEqual(self.store.snapshot(), before)

    def test_concurrent_duplicate_delivery_has_one_effect(self):
        with ThreadPoolExecutor(max_workers=12) as workers:
            outcomes = list(workers.map(lambda _: self.store.apply("same", "document.append", "draft", "X"), range(64)))
        self.assertTrue(all(item == outcomes[0] for item in outcomes))
        snapshot = self.store.snapshot()
        self.assertEqual(snapshot["documents"]["draft"], {"content": "X", "version": 1})
        self.assertEqual(len(snapshot["operations"]), 1)

    def test_concurrent_distinct_deliveries_preserve_all_effects(self):
        with ThreadPoolExecutor(max_workers=12) as workers:
            list(workers.map(lambda n: self.store.apply(f"a-{n}", "document.append", "draft", "X"), range(40)))
        snapshot = self.store.snapshot()
        self.assertEqual(snapshot["documents"]["draft"], {"content": "X" * 40, "version": 40})
        self.assertEqual(len(snapshot["operations"]), 40)

    def test_strict_types_catalogue_and_lengths_fail_closed(self):
        invalid = [
            (True, "document.read", "draft", None),
            ("", "document.read", "draft", None),
            ("x" * 129, "document.read", "draft", None),
            ("a/b", "document.read", "draft", None),
            ("a", [], "draft", None),
            ("a", "shell.run", "draft", None),
            ("a", "document.read", [], None),
            ("a", "document.read", "../private", None),
            ("a", "document.read", "https://example.com", None),
            ("a", "document.read", "draft", ""),
            ("a", "document.append", "draft", None),
            ("a", "document.append", "draft", False),
            ("a", "document.append", "draft", "x" * 4097),
            ("a", "document.append", "draft", "\ud800"),
        ]
        before = self.store.snapshot()
        for payload in invalid:
            with self.subTest(payload=repr(payload)[:100]):
                with self.assertRaises(BoundaryError):
                    self.store.apply(*payload)
        self.assertEqual(self.store.snapshot(), before)
        self.store.apply("max", "document.append", "draft", "x" * 4096)

    def test_results_are_detached(self):
        result = self.store.apply("read", "document.read", "source", None)
        result["content"] = "tampered"
        snapshot = self.store.snapshot()
        snapshot["documents"]["source"]["content"] = "tampered"
        snapshot["operations"].clear()
        self.assertEqual(self.store.apply("read", "document.read", "source", None)["content"], "Sample source text.")
        self.assertEqual(len(self.store.snapshot()["operations"]), 1)


class ToolHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = ToolStore(Path(self.tmp.name) / "tool.db")
        self.token = "test-service-token-not-a-secret"
        self.server = create_tool_server(self.store, self.token)
        self.address = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(self, method="POST", path="/apply", payload=None, token=True, raw=None):
        body = raw if raw is not None else json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + (self.token if token is True else token)
        connection = http.client.HTTPConnection(*self.address, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def payload(self, action_id="a", value="X"):
        return {"action_id": action_id, "operation": "document.append", "resource": "draft", "value": value}

    def test_authenticated_socket_delivery_and_replay(self):
        status, result = self.request(payload=self.payload())
        self.assertEqual(status, 200)
        self.assertEqual(result, {"resource": "draft", "version": 1})
        self.assertEqual(self.request(payload=self.payload()), (200, result))
        self.assertEqual(self.request(payload=self.payload(value="other"))[0], 409)
        self.assertEqual(self.store.snapshot()["documents"]["draft"]["content"], "X")

    def test_socket_concurrency_deduplicates(self):
        with ThreadPoolExecutor(max_workers=6) as workers:
            results = list(workers.map(lambda _: self.request(payload=self.payload()), range(18)))
        self.assertTrue(all(status == 200 for status, _ in results))
        self.assertTrue(all(result == results[0][1] for _, result in results))
        self.assertEqual(len(self.store.snapshot()["operations"]), 1)

    def test_auth_required_and_never_logged(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(self.request(payload=self.payload(), token=False)[0], 401)
            self.assertEqual(self.request(payload=self.payload(), token="wrong-token")[0], 401)
            self.assertEqual(self.request(payload=self.payload())[0], 200)
        self.assertNotIn(self.token, stderr.getvalue())
        self.assertNotIn("wrong-token", stderr.getvalue())
        self.assertEqual(len(self.store.snapshot()["operations"]), 1)

    def test_health_is_constant_and_no_http_audit(self):
        self.assertEqual(self.request("GET", "/health", token=False), (200, {"status": "ok"}))
        for method, path in [("GET", "/apply"), ("GET", "/audit"), ("POST", "/audit"), ("PUT", "/apply"), ("DELETE", "/apply")]:
            with self.subTest(method=method, path=path):
                self.assertGreaterEqual(self.request(method, path, self.payload())[0], 400)
        self.assertEqual(len(self.store.snapshot()["operations"]), 0)

    def test_strict_json_and_payload_fields(self):
        bad = [
            b'{"action_id":"a","action_id":"b","operation":"document.append","resource":"draft","value":"X"}',
            b'{"action_id":"a","operation":"document.append","resource":"draft","value":NaN}',
            b'{"action_id":"a","operation":"document.append","resource":"draft","value":"\xff"}',
            b'[]',
            json.dumps({**self.payload(), "actor": "admin"}).encode(),
            json.dumps({key: value for key, value in self.payload().items() if key != "value"}).encode(),
        ]
        for raw in bad:
            with self.subTest(raw=repr(raw)):
                self.assertEqual(self.request(raw=raw)[0], 400)
        self.assertEqual(len(self.store.snapshot()["operations"]), 0)

    def test_ambiguous_headers_and_oversized_body_rejected(self):
        body = json.dumps(self.payload()).encode()
        for headers in [
            f"Content-Length: {len(body)}\r\nContent-Length: {len(body)}\r\n",
            "Content-Length: 9999999\r\n",
            "Transfer-Encoding: chunked\r\n",
            f"Content-Length: {len(body)}\r\nAuthorization: Bearer wrong\r\n",
        ]:
            request = (
                "POST /apply HTTP/1.1\r\nHost: localhost\r\n"
                f"Authorization: Bearer {self.token}\r\nContent-Type: application/json\r\n"
                + headers + "\r\n"
            ).encode() + body
            with self.subTest(headers=headers):
                with socket.create_connection(self.address, timeout=5) as connection:
                    connection.sendall(request)
                    response = connection.recv(4096)
                self.assertGreaterEqual(int(response.split(b" ")[1]), 400)
        self.assertEqual(len(self.store.snapshot()["operations"]), 0)


if __name__ == "__main__":
    unittest.main()
