"""Final audit regressions using disposable services and corrupted responses."""
from contextlib import contextmanager
import importlib.util
from pathlib import Path
import threading
import unittest
from unittest.mock import Mock

from agent_boundary.client import BrokerClient
from agent_boundary.codex_adapter import BoundToolChannel, tool_proposal
from agent_boundary.runtime import LocalSystem
from agent_boundary.tool_service import ToolStore
from agent_boundary.transport import StrictHTTPServer, StrictJSONHandler


@contextmanager
def corrupted_reply_after_commit(system, response):
    """Forward one genuine action, then simulate a damaged successful reply."""
    class ReplyFault(StrictJSONHandler):
        def do_POST(self):
            body = self.read_json_object(
                {"capability", "request_id", "operation", "resource", "value"})
            system.clients["writer"].execute(**body)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response)

    server = StrictHTTPServer(("127.0.0.1", 0), ReplyFault)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield BrokerClient(f"http://127.0.0.1:{server.server_address[1]}",
                           system.tokens["writer"])
    finally:
        server.shutdown()
        server.server_close()
        worker.join(3)


class ReleaseAmbiguityTests(unittest.TestCase):
    def test_malformed_successful_reply_is_ambiguous_after_real_commit(self):
        for response in (b"{", b'{"status":"completed","status":"pending"}', b'"\xff"',
                         b'{}', b'{"status":"completed"}', b'{"status":"denied"}',
                         b'{"status":"completed","result":{"resource":"private","version":1}}'):
            with self.subTest(response=response), LocalSystem() as system:
                capability = system.clients["admin"].root(
                    "writer", [["document.append", "draft"]], 2)["capability"]
                with corrupted_reply_after_commit(system, response) as client:
                    feedback = BoundToolChannel(client, capability).execute(
                        tool_proposal("document.append", "draft", "committed once"))
                state = ToolStore(system.directory / "tool.db").snapshot()
                self.assertEqual(state["documents"]["draft"],
                                 {"content": "committed once", "version": 1})
                self.assertEqual(system.clients["admin"].audit()["capabilities"][capability]["spent"], 1)
                self.assertEqual(len(state["operations"]), 1)
                self.assertEqual(feedback, {"status": "pending", "error": "invalid_response"},
                                 "Malformed successful replies cannot establish denial of a committed intent")


class ContainerEvidenceTests(unittest.TestCase):
    @staticmethod
    def checker_type():
        path = Path(__file__).resolve().parents[1] / "scripts" / "container_check.py"
        specification = importlib.util.spec_from_file_location("release_container_check", path)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module.ContainmentCheck

    def test_unavailable_host_routes_are_not_counted_as_passed_blocks(self):
        check = Mock()
        check.execute.return_value = []
        check.inspect.return_value = {"IPAM": {"Config": [{"Gateway": "172.20.0.1"}]}}
        check.external_connections.return_value = {"host_gateway": False}
        check.untested_network_routes = []
        targets = self.checker_type().host_targets(check, "writer", {"Gateway": "", "NetworkID": "fixture"}, 18080)
        self.assertEqual(targets, [])
        check.require.assert_not_called()
        self.assertEqual(check.untested_network_routes, [
            {"worker": "writer", "route": "host_alias", "reason": "hostname_unavailable"},
            {"worker": "writer", "route": "host_gateway", "reason": "positive_control_unreachable"},
        ])

    def test_gateway_fallback_and_exact_alias_addresses_need_positive_controls(self):
        check = Mock()
        check.execute.return_value = ["192.0.2.2"]
        check.inspect.return_value = {"IPAM": {"Config": [{"Gateway": "172.20.0.1"}]}}
        check.external_connections.return_value = {"host_alias": True, "host_gateway": True}
        check.untested_network_routes = []
        targets = self.checker_type().host_targets(check, "reviewer", {"Gateway": "", "NetworkID": "fixture"}, 18080)
        self.assertEqual(targets, [("host_alias", "192.0.2.2", 18080), ("host_gateway", "172.20.0.1", 18080)])
        check.external_connections.assert_called_once_with(targets)
        self.assertEqual(check.require.call_count, 2)
        self.assertEqual(check.untested_network_routes, [])


if __name__ == "__main__":
    unittest.main()
