"""Disposable loopback error-body faults; no provider or account access."""
import contextlib
import io
import json
from http.client import HTTPException, IncompleteRead
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from agent_boundary.client import BrokerClient
from agent_boundary.codex_adapter import BoundToolChannel, run_workflow, tool_proposal
from agent_boundary.errors import BoundaryError
from agent_boundary.runtime import LocalSystem
from agent_boundary.tool_service import ToolStore
from agent_boundary.transport import MAX_BODY, request_json


MARKER = "SYNTHETIC_ERROR_BODY_MARKER"


@contextlib.contextmanager
def error_server(*, status=503, stall=False, on_request=None):
    """One controlled fault per request; shutdown releases any stalled handler."""
    stopped = threading.Event()
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append(self.path)
            if on_request is not None:
                on_request(json.loads(body))
            self.send_response(status)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            if stall:
                self.wfile.flush()
                stopped.wait(2)
            else:
                # Declares 128 bytes but closes after a short, incomplete chunk.
                self.wfile.write(b"80\r\n" + MARKER.encode())
                self.wfile.flush()
            self.close_connection = True

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", requests
    finally:
        stopped.set()
        server.shutdown()
        server.server_close()
        thread.join(3)
        if thread.is_alive():
            raise RuntimeError("Disposable error-response fixture did not stop")


class ErrorBodyTransportTests(unittest.TestCase):
    def test_incomplete_error_chunk_is_transport_error_like_success_body(self):
        for status in (200, 403, 503):
            with self.subTest(status=status), error_server(status=status) as (url, requests):
                with self.assertRaises(BoundaryError) as caught:
                    request_json(url + "/fault", "fixture-token", payload={}, timeout=1)
                self.assertEqual(caught.exception.code, "transport_error")
                self.assertEqual(caught.exception.status, 502)
                self.assertNotIn(MARKER, str(caught.exception))
                self.assertEqual(len(requests), 1)

    def test_error_body_socket_timeout_is_pending_without_another_request(self):
        with error_server(stall=True) as (url, requests):
            result = BoundToolChannel(BrokerClient(url, "fixture-token", timeout=0.05), "fixture-cap").execute(
                tool_proposal("document.append", "draft", "Synthetic public text."))
            self.assertEqual(result, {"status": "pending", "error": "transport_error"})
            self.assertEqual(len(requests), 1)

    def test_read_faults_close_http_error_and_return_controlled_error(self):
        faults = [OSError(MARKER), TimeoutError(MARKER), HTTPException(MARKER),
                  IncompleteRead(MARKER.encode(), 128), URLError(MARKER)]
        for fault in faults:
            with self.subTest(fault=type(fault).__name__):
                body = Mock()
                body.read.side_effect = fault
                error = HTTPError("http://127.0.0.1/fault", 503, "Fixture", {}, body)
                opener = Mock()
                opener.open.side_effect = error
                with patch("agent_boundary.transport.build_opener", return_value=opener):
                    with self.assertRaises(BoundaryError) as caught:
                        request_json("http://127.0.0.1/fault", "fixture-token", payload={})
                self.assertEqual((caught.exception.code, caught.exception.status), ("transport_error", 502))
                self.assertNotIn(MARKER, str(caught.exception))
                body.read.assert_called_once_with(MAX_BODY + 1)
                body.close.assert_called_once()
                opener.open.assert_called_once()

    def test_complete_structured_errors_keep_original_code_message_and_status(self):
        for status in (403, 503):
            with self.subTest(status=status):
                body = io.BytesIO(json.dumps({"error": {"code": "fixture_code", "message": "Synthetic controlled message."}}).encode())
                error = HTTPError("http://127.0.0.1/fault", status, "Fixture", {}, body)
                with patch("agent_boundary.transport.build_opener") as build:
                    build.return_value.open.side_effect = error
                    with self.assertRaises(BoundaryError) as caught:
                        request_json("http://127.0.0.1/fault", "fixture-token", payload={})
                self.assertEqual((caught.exception.code, caught.exception.message, caught.exception.status),
                                 ("fixture_code", "Synthetic controlled message.", status))
                self.assertTrue(body.closed)

    def test_malformed_or_oversized_complete_error_body_keeps_status_fallback(self):
        for raw in (b"{broken", b"[]", b"{}", b"x" * (MAX_BODY + 1)):
            with self.subTest(size=len(raw)):
                body = io.BytesIO(raw)
                with patch("agent_boundary.transport.build_opener") as build:
                    build.return_value.open.side_effect = HTTPError("http://127.0.0.1/fault", 403, "Fixture", {}, body)
                    with self.assertRaises(BoundaryError) as caught:
                        request_json("http://127.0.0.1/fault", "fixture-token", payload={})
                self.assertEqual((caught.exception.code, caught.exception.status), ("upstream_status", 403))
                self.assertTrue(body.closed)

    def test_redirect_closes_without_reading_error_body(self):
        body = Mock()
        body.read.side_effect = AssertionError("Redirect body must not be read")
        with patch("agent_boundary.transport.build_opener") as build:
            build.return_value.open.side_effect = HTTPError("http://127.0.0.1/fault", 307, "Fixture", {}, body)
            with self.assertRaises(BoundaryError) as caught:
                request_json("http://127.0.0.1/fault", "fixture-token", payload={})
        self.assertEqual((caught.exception.code, caught.exception.status), ("redirect_forbidden", 502))
        body.read.assert_not_called()
        body.close.assert_called_once()
        build.return_value.open.assert_called_once()

    def test_committed_append_broken_error_stops_workflow_without_replacement(self):
        # Same real-service pattern as the existing malformed-success test. This
        # local shim commits via the real client, then sends a broken 503 body.
        with LocalSystem() as system:
            original = system.clients["writer"]
            deliveries = []

            def commit(payload):
                deliveries.append(payload["request_id"])
                original.execute(payload["capability"], payload["request_id"],
                                 payload["operation"], payload["resource"], payload["value"])

            with error_server(on_request=commit) as (url, requests):
                system.clients["writer"] = BrokerClient(url, "fixture-token", timeout=2)
                report = run_workflow(system)
            self.assertFalse(report["completed"])
            self.assertEqual(report["error"], "tool_outcome_pending")
            self.assertEqual(report["transcript"][-1]["feedback"], {"status": "pending", "error": "transport_error"})
            self.assertEqual(len(requests), 1)
            self.assertEqual(len(deliveries), 1)
            self.assertEqual(report["budget"], {"shared_spent": 2, "role_spent": {"researcher": 1, "writer": 1, "reviewer": 0}})
            state = ToolStore(system.directory / "tool.db").snapshot()
            self.assertEqual(state["documents"]["draft"]["version"], 1)
            self.assertEqual(len(state["operations"]), 2)  # One read plus one append.
            self.assertEqual(sum(row["operation"] == "document.append" for row in state["operations"]), 1)
            self.assertEqual(report["runtime"]["model_calls"], 0)
            self.assertNotIn(MARKER, json.dumps(report))


if __name__ == "__main__":
    unittest.main()
