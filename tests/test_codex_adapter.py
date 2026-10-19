"""Mocked CLI protocol checks plus real local HTTP workflow integration.

These tests are deterministic. None of them are model evaluations.
"""
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

from agent_boundary.codex_adapter import (
    ACTION_SCHEMA, BoundToolChannel, CodexBackend, DeterministicBackend,
    DISABLED_FEATURES, SUPPORTED_CODEX_VERSION, _parse_cli_events,
    finish_proposal, run_workflow, tool_proposal, validate_proposal,
)
from agent_boundary.errors import BoundaryError
from agent_boundary.runtime import LocalSystem
from agent_boundary.tool_service import MAX_DOCUMENT_BYTES


def events(proposal, *, reasoning="PRIVATE REASONING MUST NOT BE RETAINED"):
    return "\n".join(json.dumps(event) for event in [
        {"type": "thread.started", "thread_id": "not-retained"},
        {"type": "item.completed", "item": {"type": "reasoning", "text": reasoning}},
        {"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(proposal)}},
        {"type": "turn.completed", "usage": {"input_tokens": 42, "output_tokens": 12,
                                                "cached_input_tokens": 0, "unsafe": "private"}},
    ])


class ProposalValidationTests(unittest.TestCase):
    def test_exact_proposal_fields_and_types(self):
        valid = tool_proposal("document.read", "source")
        self.assertEqual(validate_proposal(valid), valid)
        bad = [dict(valid, actor="admin"), dict(valid, capability="chosen"),
               dict(valid, request_id="chosen"), dict(valid, url="http://localhost"),
               dict(valid, operation="shell"), dict(valid, operation=["document.read"]),
               dict(valid, resource="/tmp/source"), dict(valid, value="not-null"),
               dict(valid, message="x" * 4097), dict(valid, message="\ud800"),
               dict(valid, kind="finish"), dict(valid, message=None),
               tool_proposal("document.append", "draft", True),
               tool_proposal("document.append", "draft", "x" * 4097)]
        for proposal in bad:
            with self.subTest(proposal=str(proposal)[:100]), self.assertRaises(BoundaryError):
                validate_proposal(proposal)

    def test_cli_final_only_and_safe_usage(self):
        proposal, usage = _parse_cli_events(events(finish_proposal("public result")))
        self.assertEqual(proposal["message"], "public result")
        self.assertEqual(usage, {"input_tokens": 42, "output_tokens": 12, "cached_input_tokens": 0})
        self.assertNotIn("PRIVATE", json.dumps([proposal, usage]))

    def test_duplicate_json_and_no_completed_turn_fail_closed(self):
        for output in [
            '{"type":"turn.completed","type":"error"}',
            json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "{}"}}),
            json.dumps({"type": "turn.failed", "error": {"message": "SECRET"}}),
            events({"kind": "finish"}),
            "non-json auth log",
        ]:
            with self.subTest(output=output[:80]), self.assertRaises(BoundaryError) as caught:
                _parse_cli_events(output)
            self.assertNotIn("SECRET", str(caught.exception))

    def test_no_fence_or_duplicate_field_acceptance(self):
        event = {"type": "item.completed", "item": {"type": "agent_message", "text":
                 '{"kind":"finish","operation":null,"resource":null,"value":null,"message":"x","message":"y"}'}}
        with self.assertRaises(BoundaryError):
            _parse_cli_events(json.dumps(event) + '\n{"type":"turn.completed"}')

    def test_dispatch_uses_only_prebound_authority_and_generated_request_id(self):
        client = Mock()
        client.execute.return_value = {"status": "completed", "result": {
            "resource": "source", "version": 0, "content": "text"}}
        channel = BoundToolChannel(client, "preselected-capability")
        result = channel.execute(tool_proposal("document.read", "source"))
        args = client.execute.call_args.args
        self.assertEqual(args[0], "preselected-capability")
        self.assertRegex(args[1], r"^workflow-[a-f0-9]{32}$")
        self.assertEqual(args[2:], ("document.read", "source", None))
        self.assertEqual(result, client.execute.return_value)
        with self.assertRaises(BoundaryError):
            channel.execute(dict(tool_proposal("document.read", "private"), actor="admin"))
        self.assertEqual(client.execute.call_count, 1)

    def test_transport_error_is_ambiguous_not_retryable_denial(self):
        client = Mock()
        client.execute.side_effect = BoundaryError("transport_error", "possibly committed", 502)
        self.assertEqual(BoundToolChannel(client, "cap").execute(tool_proposal("document.read", "source")),
                         {"status": "pending", "error": "transport_error"})

    def test_malformed_success_receipts_are_sanitized_ambiguity(self):
        read = tool_proposal("document.read", "source")
        append = tool_proposal("document.append", "draft", "benign fixture")
        cases = [(proposal, action) for proposal in (read, append) for action in (
            None, [], {}, {"status": []}, {"status": "denied"}, {"status": "unknown"},
            {"status": "completed"}, {"status": "completed", "result": None},
            {"status": "completed", "result": []},
            {"status": "pending", "result": {"content": "PRIVATE_REPLY"}},
        )]
        for version in (True, -1, 0, 1.5, "1"):
            cases.append((append, {"status": "completed", "result": {
                "resource": "draft", "version": version}}))
        cases.extend([
            (append, {"status": "completed", "result": {"resource": "private", "version": 1}}),
            (append, {"status": "completed", "result": {"resource": "draft", "version": 1, "content": "PRIVATE_REPLY"}}),
            (read, {"status": "completed", "result": {"resource": "source", "version": 0}}),
            (read, {"status": "completed", "result": {"resource": "source", "version": 0, "content": None}}),
            (read, {"status": "completed", "result": {"resource": "source", "version": 0, "content": "\ud800"}}),
            (read, {"status": "completed", "result": {"resource": "source", "version": 0,
                "content": "é" * (MAX_DOCUMENT_BYTES // 2 + 1)}}),
        ])
        for index, (proposal, action) in enumerate(cases):
            with self.subTest(case=index):
                client = Mock()
                client.execute.return_value = action
                feedback = BoundToolChannel(client, "cap").execute(proposal)
                self.assertEqual(feedback, {"status": "pending", "error": "invalid_response"})
                self.assertNotIn("PRIVATE_REPLY", json.dumps(feedback))
                self.assertEqual(client.execute.call_count, 1)

    def test_valid_read_append_pending_and_http_denial_remain_compatible(self):
        for proposal, response in [
            (tool_proposal("document.read", "source"), {"status": "completed", "result": {
                "resource": "source", "version": 0, "content": "literal λ 🛡"}}),
            (tool_proposal("document.read", "source"), {"status": "completed", "result": {
                "resource": "source", "version": 0, "content": "é" * (MAX_DOCUMENT_BYTES // 2)}}),
            (tool_proposal("document.append", "draft", "text"), {"status": "completed", "result": {
                "resource": "draft", "version": 1}}),
            (tool_proposal("document.append", "draft", "text"), {"status": "pending", "result": None}),
        ]:
            with self.subTest(status=response["status"], operation=proposal["operation"]):
                client = Mock()
                client.execute.return_value = dict(response, action_id="recorded-action", replayed=True)
                self.assertEqual(BoundToolChannel(client, "cap").execute(proposal), response)
                self.assertEqual(client.execute.call_count, 1)
        client = Mock()
        client.execute.side_effect = BoundaryError("scope_denied", "PRIVATE_REPLY", 403)
        self.assertEqual(BoundToolChannel(client, "cap").execute(tool_proposal("document.read", "source")),
                         {"status": "denied", "error": "scope_denied"})


class CodexCLIAdapterTests(unittest.TestCase):
    def mocked_backend(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, SUPPORTED_CODEX_VERSION + "\n", "")
        return CodexBackend(timeout=17)

    @patch("agent_boundary.codex_adapter.shutil.which", return_value="/trusted/codex")
    @patch("agent_boundary.codex_adapter.subprocess.run")
    def test_flags_stdin_environment_and_safe_metadata(self, run, which):
        backend = self.mocked_backend(run)
        context = {"role": "researcher", "history": [], "task": "Read source; literal $(secret) `secret`"}
        proposal = tool_proposal("document.read", "source")

        def respond(command, **kwargs):
            self.assertTrue(Path(kwargs["cwd"]).is_dir())
            self.assertEqual(list(Path(kwargs["cwd"]).iterdir()), [])
            self.assertEqual(json.loads(Path(command[command.index("--output-schema") + 1]).read_text()), ACTION_SCHEMA)
            return subprocess.CompletedProcess(command, 0, events(proposal), None)

        with patch("agent_boundary.codex_adapter._run_bounded_cli", side_effect=respond) as capture, patch.dict(os.environ, {"BROKER_TOKEN": "do-not-pass", "OPENAI_API_KEY": "do-not-pass",
                                    "HTTP_PROXY": "http://proxy", "CODEX_THREAD_ID": "do-not-pass"}):
            self.assertEqual(backend.propose(context, timeout=10), proposal)
        command = capture.call_args.args[0]
        kwargs = capture.call_args.kwargs
        self.assertEqual(command[-1], "-")
        self.assertNotIn("$(secret)", " ".join(command))
        self.assertIn("$(secret)", kwargs["input"])
        self.assertEqual(kwargs["timeout"], 10)
        self.assertNotIn("shell", kwargs)
        for key in ["BROKER_TOKEN", "OPENAI_API_KEY", "HTTP_PROXY", "CODEX_THREAD_ID"]:
            self.assertNotIn(key, kwargs["env"])
        for feature in DISABLED_FEATURES:
            self.assertTrue(any(command[i:i+2] == ["--disable", feature] for i in range(len(command))))
        for flag in ["--ignore-user-config", "--ignore-rules", "--ephemeral", "--skip-git-repo-check"]:
            self.assertIn(flag, command)
        self.assertIn("skip_host_skill_discovery", command)
        self.assertIn('web_search="disabled"', command)
        self.assertIn("project_doc_max_bytes=0", command)
        self.assertNotIn("PRIVATE", json.dumps(backend.metadata()))
        self.assertNotIn("do-not-pass", json.dumps(backend.metadata()))
        self.assertFalse(Path(kwargs["cwd"]).exists())

    @patch("agent_boundary.codex_adapter._run_bounded_cli")
    @patch("agent_boundary.codex_adapter.shutil.which", return_value="/trusted/codex")
    @patch("agent_boundary.codex_adapter.subprocess.run")
    def test_timeout_and_failure_hide_raw_cli_output(self, run, which, capture):
        backend = self.mocked_backend(run)
        capture.side_effect = subprocess.TimeoutExpired("codex", 17, output="PRIVATE", stderr="SECRET")
        with self.assertRaises(BoundaryError) as caught:
            backend.propose({"role": "researcher"})
        self.assertEqual(caught.exception.code, "codex_timeout")
        self.assertNotIn("SECRET", str(caught.exception))
        capture.side_effect = None
        capture.return_value = subprocess.CompletedProcess([], 1, "PRIVATE", "SECRET")
        with self.assertRaises(BoundaryError) as caught:
            backend.propose({"role": "researcher"})
        self.assertEqual(caught.exception.code, "codex_failed")
        self.assertEqual(backend.calls, [])

    @patch("agent_boundary.codex_adapter.shutil.which", return_value="/trusted/codex")
    @patch("agent_boundary.codex_adapter.subprocess.run")
    def test_unknown_cli_version_requires_review(self, run, which):
        run.return_value = subprocess.CompletedProcess([], 0, "codex-cli 9.0.0\n", "")
        with self.assertRaises(BoundaryError) as caught:
            CodexBackend()
        self.assertEqual(caught.exception.code, "codex_version")


class WorkflowIntegrationTests(unittest.TestCase):
    def test_malformed_reply_after_append_stops_without_fresh_dispatch(self):
        with LocalSystem() as system:
            original = system.clients["writer"]
            client = Mock()
            def commit_then_damage(*args):
                original.execute(*args)
                return {"status": "completed", "result": {"content": "PRIVATE_REPLY"}}
            client.execute.side_effect = commit_then_damage
            system.clients["writer"] = client
            report = run_workflow(system)
            self.assertFalse(report["completed"])
            self.assertEqual(report["error"], "tool_outcome_pending")
            self.assertEqual(report["transcript"][-1]["feedback"],
                             {"status": "pending", "error": "invalid_response"})
            self.assertEqual(client.execute.call_count, 1)
            self.assertEqual(report["budget"], {"shared_spent": 2, "role_spent": {
                "researcher": 1, "writer": 1, "reviewer": 0}})
            from agent_boundary.tool_service import ToolStore
            state = ToolStore(system.directory / "tool.db").snapshot()
            self.assertEqual(state["documents"]["draft"]["version"], 1)
            self.assertEqual(len(state["operations"]), 2)  # One read, one append.
            self.assertEqual(len([x for x in state["operations"] if x["operation"] == "document.append"]), 1)
            self.assertNotIn("PRIVATE_REPLY", json.dumps(report))
            self.assertEqual(report["runtime"]["model_calls"], 0)

    def test_real_three_role_document_workflow(self):
        with LocalSystem() as system:
            report = run_workflow(system)
            self.assertTrue(report["completed"])
            self.assertEqual(report["backend"], "deterministic_fixture_not_a_model_evaluation")
            self.assertEqual(list(report["roles"]), ["researcher", "writer", "reviewer"])
            self.assertEqual(report["budget"], {"shared_spent": 3, "role_spent": {
                "researcher": 1, "writer": 1, "reviewer": 1}})
            self.assertIn("Sample source text.", report["transcript"][-2]["feedback"]["result"]["content"])
            encoded = json.dumps(report)
            for token in list(system.tokens.values()) + [system.tool_token]:
                self.assertNotIn(token, encoded)
            self.assertNotIn(system.broker_url, encoded)
            self.assertNotIn(str(system.directory), encoded)

    def test_unauthorized_source_instruction_cannot_expand_role_scope(self):
        class HostileResearcher(DeterministicBackend):
            def propose(self, context, *, timeout=None):
                if context["role"] == "researcher" and context["round"] == 1:
                    return tool_proposal("document.read", "private")
                return super().propose(context, timeout=timeout)
        with LocalSystem() as system:
            report = run_workflow(system, HostileResearcher())
            self.assertTrue(report["completed"])
            self.assertEqual(report["transcript"][0]["feedback"]["status"], "denied")
            self.assertEqual(report["budget"]["shared_spent"], 3)
            self.assertNotIn("CANARY_PRIVATE", json.dumps(report))

    def test_round_limit_stops_repeated_denial(self):
        class AlwaysPrivate(DeterministicBackend):
            def propose(self, context, *, timeout=None):
                return tool_proposal("document.read", "private")
        with LocalSystem() as system:
            report = run_workflow(system, AlwaysPrivate(), max_rounds=2)
            self.assertFalse(report["completed"])
            self.assertEqual(report["error"], "round_limit")
            self.assertEqual(len(report["transcript"]), 2)
            self.assertEqual(report["budget"]["shared_spent"], 0)

    def test_finish_cannot_fake_required_operation(self):
        class PrematureFinish(DeterministicBackend):
            def propose(self, context, *, timeout=None):
                return finish_proposal("I performed the tool action.")
        with LocalSystem() as system:
            report = run_workflow(system, PrematureFinish(), max_rounds=2)
            self.assertFalse(report["completed"])
            self.assertEqual(report["budget"]["shared_spent"], 0)
            self.assertEqual(report["roles"], {})
            self.assertEqual(report["transcript"][0]["feedback"]["error"], "required_tool_not_completed")


if __name__ == "__main__":
    unittest.main()
