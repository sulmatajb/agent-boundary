"""Real-socket strict transport and broker/adapter integration regression tests."""
import contextlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from agent_boundary.client import BrokerClient
from agent_boundary.errors import BoundaryError
from agent_boundary.server import bootstrap_credentials, create_server
from agent_boundary.store import Store
from agent_boundary.tool_service import ToolStore, create_tool_server
from agent_boundary.transport import StrictHTTPServer, StrictJSONHandler, request_json, strict_json


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


class GatewayTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "broker.db")
        for principal, admin in [("admin", True), ("alice", False), ("bob", False)]:
            self.store.register(principal, principal + "-credential", admin)
        self.tool_store = ToolStore(Path(self.temp.name) / "tool.db")

    def launch(self, sink=True):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        sink_url = stack.enter_context(running(create_tool_server(self.tool_store, "sink-credential"))) if sink else None
        server = create_server(self.store, sink_url=sink_url, sink_token="sink-credential" if sink else None)
        self.server = server
        self.url = stack.enter_context(running(server))
        self.admin = BrokerClient(self.url, "admin-credential")
        self.alice = BrokerClient(self.url, "alice-credential")
        self.bob = BrokerClient(self.url, "bob-credential")

    def raw(self, body=b"{}", headers=None, path="/v1/drain", method="POST"):
        lines = [f"{method} {path} HTTP/1.1", "Host: localhost"]
        if headers is None:
            headers = [("Authorization", "Bearer admin-credential"), ("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
        lines += [f"{key}: {value}" for key, value in headers]
        data = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
        with socket.create_connection(self.server.server_address, timeout=3) as sock:
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        head, _, response = b"".join(chunks).partition(b"\r\n\r\n")
        return int(head.split()[1]), json.loads(response) if response else None

    def test_real_document_append_and_replay(self):
        self.launch()
        root = self.admin.root("alice", [["document.append", "draft"]], 2)["capability"]
        first = self.alice.execute(root, "write-1", "document.append", "draft", "actual durable text")
        retry = self.alice.execute(root, "write-1", "document.append", "draft", "actual durable text")
        self.assertEqual(first["status"], "completed")
        self.assertEqual(first["result"], {"resource": "draft", "version": 1})
        self.assertEqual(retry["action_id"], first["action_id"])
        self.assertTrue(retry["replayed"])
        audit = self.admin.audit()
        self.assertEqual(audit["capabilities"][root]["spent"], 1)
        self.assertEqual(len(audit["actions"]), 1)

    def test_identity_cannot_be_supplied_in_json(self):
        self.launch()
        root = self.admin.root("alice", [["document.read", "private"]], 1)["capability"]
        with self.assertRaises(BoundaryError):
            self.bob.execute(root, "steal", "document.read", "private")
        with self.assertRaises(BoundaryError):
            request_json(self.url + "/v1/root", "bob-credential", payload={"actor": "admin", "owner": "bob", "scopes": [["document.read", "private"]], "budget": 1})
        self.assertEqual(self.admin.audit()["actions"], [])

    def test_offline_sink_reservations_remain_charged(self):
        self.launch(sink=False)
        root = self.admin.root("alice", [["document.append", "draft"]], 1)["capability"]
        action = self.alice.execute(root, "pending-1", "document.append", "draft", "x")
        self.assertEqual(action["status"], "pending")
        with self.assertRaises(BoundaryError):
            self.alice.execute(root, "pending-2", "document.append", "draft", "y")
        self.assertEqual(self.admin.drain(), {"attempted": 1, "completed": 0, "pending": 1})
        self.assertEqual(self.admin.audit()["capabilities"][root]["spent"], 1)

    def test_bootstrap_exact_identity_is_idempotent(self):
        path = Path(self.temp.name) / "credentials.json"
        path.write_text(json.dumps([{"principal": "admin", "token": "admin-credential", "admin": True}]))
        bootstrap_credentials(self.store, path)
        bootstrap_credentials(self.store, path)
        path.write_text(json.dumps([{"principal": "admin", "token": "admin-credential", "admin": False}]))
        with self.assertRaises(ValueError):
            bootstrap_credentials(self.store, path)

    def test_framing_duplicate_headers_chunking_oversize(self):
        self.launch(sink=False)
        auth = [("Authorization", "Bearer admin-credential"), ("Content-Type", "application/json")]
        cases = [
            (auth + [("Content-Length", "2"), ("Content-Length", "2")], 400),
            (auth + [("Content-Length", "2"), ("Transfer-Encoding", "chunked")], 400),
            (auth + [("Content-Length", "65537")], 413),
            (auth + [("Content-Length", "+2")], 400),
            (auth + [("Content-Length", "2, 2")], 400),
            (auth + [("Content-Length", "2"), ("Authorization", "Bearer bob-credential")], 400),
            (auth, 411),
        ]
        for headers, expected in cases:
            with self.subTest(headers=headers):
                self.assertEqual(self.raw(headers=headers)[0], expected)

    def test_strict_json_and_exact_fields(self):
        self.launch(sink=False)
        for body in [b'{"x":1,"x":2}', b'{"budget":NaN}', b'{"budget":1e999}', b'{"budget":Infinity}', b'[]', b'{}junk', b'"\xff"', b'{"actor":"admin"}']:
            with self.subTest(body=body):
                self.assertEqual(self.raw(body=body)[0], 400)
        status, payload = self.raw(body=b'{"a":1}')
        self.assertNotIn("admin-credential", json.dumps(payload))
        self.assertEqual(status, 400)

    def test_routes_and_methods_fail_closed(self):
        self.launch(sink=False)
        for path in ["/v1/root?x=1", "/v1/%72oot", "/v1/root/", "/apply"]:
            with self.subTest(path=path):
                self.assertEqual(self.raw(path=path)[0], 404)
        for method in ["PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"]:
            with self.subTest(method=method):
                self.assertEqual(self.raw(method=method)[0], 405)
        self.assertEqual(self.raw(body=b"", headers=[], path="/health", method="GET"), (200, {"status": "ok"}))
        self.assertEqual(self.raw(body=b"", headers=[], path="/v1/audit", method="GET")[0], 401)

    def test_redirect_never_receives_bearer(self):
        self.launch(sink=False)
        seen = []
        class Destination(StrictJSONHandler):
            def do_GET(inner):
                seen.append(inner.headers.get("Authorization"))
                inner.send_json(200, {})
        with running(StrictHTTPServer(("127.0.0.1", 0), Destination)) as destination:
            class Redirect(StrictJSONHandler):
                def do_GET(inner):
                    inner.send_response(302)
                    inner.send_header("Location", destination + "/stolen")
                    inner.send_header("Content-Length", "0")
                    inner.send_header("Connection", "close")
                    inner.end_headers()
            with running(StrictHTTPServer(("127.0.0.1", 0), Redirect)) as redirect:
                with self.assertRaises(BoundaryError) as captured:
                    request_json(redirect + "/redirect", "admin-credential", method="GET")
                self.assertEqual(captured.exception.code, "redirect_forbidden")
        self.assertEqual(seen, [])

    def test_environment_proxies_are_ignored(self):
        self.launch(sink=False)
        env = {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1", "NO_PROXY": "", "no_proxy": "", "http_proxy": "http://127.0.0.1:1"}
        with patch.dict(os.environ, env):
            self.assertIn("capabilities", self.admin.audit())

    def test_truncated_sink_response_preserves_pending_intent(self):
        class Truncated(StrictJSONHandler):
            def do_POST(inner):
                inner.send_response(200)
                inner.send_header("Content-Length", "100")
                inner.send_header("Connection", "close")
                inner.end_headers()
                inner.wfile.write(b"{")
        with running(StrictHTTPServer(("127.0.0.1", 0), Truncated)) as sink:
            with running(create_server(self.store, sink_url=sink, sink_token="sink-credential")) as url:
                admin = BrokerClient(url, "admin-credential")
                alice = BrokerClient(url, "alice-credential")
                cap = admin.root("alice", [["document.append", "draft"]], 1)["capability"]
                result = alice.execute(cap, "truncated", "document.append", "draft", "x")
                self.assertEqual(result["status"], "pending")
                self.assertEqual(admin.audit()["capabilities"][cap]["spent"], 1)

    def test_sink_redirect_is_pending_without_token_forwarding(self):
        seen = []
        class Destination(StrictJSONHandler):
            def do_POST(inner):
                seen.append(inner.headers.get("Authorization"))
                inner.send_json(200, {})
        with running(StrictHTTPServer(("127.0.0.1", 0), Destination)) as destination:
            class Redirect(StrictJSONHandler):
                def do_POST(inner):
                    inner.send_response(307)
                    inner.send_header("Location", destination + "/stolen")
                    inner.send_header("Content-Length", "0")
                    inner.send_header("Connection", "close")
                    inner.end_headers()
            with running(StrictHTTPServer(("127.0.0.1", 0), Redirect)) as sink:
                with running(create_server(self.store, sink_url=sink, sink_token="sink-credential")) as url:
                    admin = BrokerClient(url, "admin-credential")
                    alice = BrokerClient(url, "alice-credential")
                    cap = admin.root("alice", [["document.append", "draft"]], 1)["capability"]
                    result = alice.execute(cap, "redirect", "document.append", "draft", "x")
                    self.assertEqual(result["status"], "pending")
        self.assertEqual(seen, [])

    def test_untrusted_destination_extra_field_denied(self):
        self.launch()
        cap = self.admin.root("alice", [["document.read", "source"]], 1)["capability"]
        with self.assertRaises(BoundaryError):
            request_json(self.url + "/v1/execute", "alice-credential", payload={"capability": cap, "request_id": "redirect", "operation": "document.read", "resource": "source", "value": None, "sink_url": "http://127.0.0.1:1"})
        self.assertEqual(self.admin.audit()["actions"], [])


if __name__ == "__main__":
    unittest.main()
