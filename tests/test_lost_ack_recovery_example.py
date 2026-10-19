"""Actual recovery-example/store/CLI checks using disposable synthetic databases."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lost_ack_example", ROOT / "examples/lost_ack_recovery.py")
example = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(example)


class LostAckRecoveryExampleTests(unittest.TestCase):
    def test_actual_stages_show_admission_effect_revocation_and_recovery(self):
        report = example.run_demo()
        stages = {row["step"]: row for row in report["steps"]}
        self.assertEqual(len(stages), 10)
        self.assertEqual(stages["delegated"]["budgets"]["parent"]["spent"], 0)
        pending = stages["tool_committed_ack_withheld"]
        self.assertEqual(pending["pending_actions"], 1)
        self.assertEqual(pending["completed_actions"], 0)
        self.assertEqual(pending["tool_ledger_entries"], 1)
        self.assertEqual(pending["draft"], {"content": example.PUBLIC_TEXT, "version": 1})
        for label in ("parent", "writer"):
            self.assertEqual(pending["budgets"][label]["spent"], 1)
            self.assertEqual(pending["budgets"][label]["limit"], 2)
        reopened = stages["stores_reopened"]
        for key in ("budgets", "draft", "pending_actions", "tool_ledger_entries"):
            self.assertEqual(reopened[key], pending[key])
        denied = stages["new_request"]
        self.assertEqual(denied["code"], "revoked")
        self.assertTrue(denied["budgets"]["parent"]["revoked"])
        self.assertEqual(denied["budgets"]["parent"]["spent"], 1)  # capacity still available
        self.assertTrue(stages["identical_request"]["same_action"])
        self.assertEqual(stages["identical_request"]["additional_charge"], 0)
        redelivery = stages["tool_redelivery"]
        self.assertTrue(redelivery["same_receipt"])
        self.assertEqual(redelivery["receipt"], pending["receipt"])
        self.assertEqual(redelivery["direct_tool_apply_calls"], 2)
        self.assertEqual(redelivery["tool_ledger_entries"], 1)
        self.assertEqual(stages["changed_payload"]["code"], "request_conflict")
        final = report["final"]
        self.assertEqual((final["admitted_actions"], final["completed_actions"], final["pending_actions"]), (1, 1, 0))
        self.assertEqual(final["draft"], {"content": example.PUBLIC_TEXT, "version": 1})
        self.assertEqual([row["spent"] for row in final["budgets"].values()], [1, 1])
        self.assertEqual(report["model_calls"], 0)
        self.assertEqual(report["http_requests"], 0)

    def test_independent_sql_counts_cleanup_and_safe_projection(self):
        created, observed = [], []
        real_directory = tempfile.TemporaryDirectory

        def tracking_directory(*args, **kwargs):
            directory = real_directory(*args, **kwargs)
            path = Path(directory.name)
            created.append(path)
            cleanup = directory.cleanup

            def inspect_then_cleanup():
                try:
                    with sqlite3.connect(path / "authority.sqlite") as connection:
                        actions = connection.execute("SELECT status, COUNT(*) FROM actions GROUP BY status").fetchall()
                        budgets = connection.execute("SELECT spent, revoked FROM capabilities ORDER BY rowid").fetchall()
                    with sqlite3.connect(path / "documents.sqlite") as connection:
                        ledger = connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
                        draft = connection.execute("SELECT content, version FROM documents WHERE resource='draft'").fetchone()
                    observed.append((actions, budgets, ledger, draft))
                finally:
                    cleanup()
            directory.cleanup = inspect_then_cleanup
            return directory

        tokens = ["synthetic-supervisor-secret", "synthetic-writer-secret"]
        with patch.object(example.tempfile, "TemporaryDirectory", side_effect=tracking_directory):
            with patch.object(example.secrets, "token_urlsafe", side_effect=tokens):
                report = example.run_demo()
        self.assertEqual(observed, [([("completed", 1)], [(1, 1), (1, 0)], 1, (example.PUBLIC_TEXT, 1))])
        self.assertTrue(created and all(not path.exists() for path in created))
        self.assertTrue(report["temporary_databases_removed"])
        output = json.dumps(report) + example.transcript(report)
        for private in [str(ROOT), *(str(p) for p in created), *tokens,
                        *(hashlib.sha256(t.encode()).hexdigest() for t in tokens),
                        "cap_", "act_", "CANARY_PRIVATE", "credential_digest", "authority.sqlite", "documents.sqlite"]:
            self.assertNotIn(private, output)

    def test_output_is_stable_across_disposable_credentials_and_databases(self):
        self.assertEqual(example.run_demo(), example.run_demo())

    def test_documented_text_and_json_cli(self):
        environment = {**os.environ, "PYTHONPATH": "src", "PYTHONDONTWRITEBYTECODE": "1"}
        outputs = []
        for arguments in ([], ["--json"]):
            result = subprocess.run([sys.executable, "examples/lost_ack_recovery.py", *arguments],
                                    cwd=ROOT, env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            outputs.append(result.stdout)
        report = json.loads(outputs[1])
        self.assertEqual(outputs[0], example.transcript(report) + "\n")
        self.assertIn("not a process crash", outputs[0])
        self.assertIn("request_conflict", outputs[0])
        self.assertIn("revoked", outputs[0])

    def test_no_database_path_argument_and_errors_do_not_echo_input(self):
        result = subprocess.run([sys.executable, "examples/lost_ack_recovery.py", "--db", "/private/sentinel.sqlite"],
                                cwd=ROOT, env={**os.environ, "PYTHONPATH": "src"},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "Invalid arguments. Use --help.\n")

    def test_failure_cleans_up_and_cli_does_not_echo_exception(self):
        created = []
        real_directory = tempfile.TemporaryDirectory

        def tracking_directory(*args, **kwargs):
            directory = real_directory(*args, **kwargs)
            created.append(Path(directory.name))
            return directory

        out, error = io.StringIO(), io.StringIO()
        with patch.object(example.tempfile, "TemporaryDirectory", side_effect=tracking_directory):
            with patch.object(example.ToolStore, "apply", side_effect=OSError("private-failure-sentinel")):
                with redirect_stdout(out), redirect_stderr(error):
                    status = example.main(["--json"])
        self.assertEqual(status, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(error.getvalue(), "Recovery example failed; no report produced.\n")
        self.assertTrue(created and all(not path.exists() for path in created))

    def test_example_refuses_a_second_document_effect(self):
        apply = example.ToolStore.apply
        calls = []

        def broken_replay(store, action_id, *args):
            calls.append(action_id)
            return apply(store, action_id if len(calls) == 1 else "incorrect-new-action", *args)

        with patch.object(example.ToolStore, "apply", broken_replay):
            with self.assertRaisesRegex(RuntimeError, "saved receipt"):
                example.run_demo()

    def test_example_refuses_to_report_completion_when_complete_did_nothing(self):
        with patch.object(example.Store, "complete", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Completion did not persist"):
                example.run_demo()

    def test_example_refuses_an_unexpected_new_admission(self):
        reserve = example.Store.reserve

        def broken_reserve(store, actor, capability, request_id, *args):
            if request_id == "new-note":
                return {"status": "pending"}
            return reserve(store, actor, capability, request_id, *args)

        with patch.object(example.Store, "reserve", broken_reserve):
            with self.assertRaisesRegex(RuntimeError, "expected to be denied"):
                example.run_demo()


if __name__ == "__main__":
    unittest.main()
