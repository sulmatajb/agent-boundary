"""Integration checks for the offline example's production Store calls and CLI."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "shared_budget.py"
SPEC = importlib.util.spec_from_file_location("shared_budget_example", EXAMPLE)
example = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(example)


class SharedBudgetExampleTests(unittest.TestCase):
    def test_actual_store_admissions_replay_and_denials(self):
        report = example.run_demo()
        steps = report["steps"]
        self.assertEqual(
            [step["outcome"] for step in steps],
            ["delegated", "admitted", "admitted", "denied", "replayed", "denied"],
        )
        self.assertEqual(
            [step["budgets"]["parent"]["spent"] for step in steps],
            [0, 1, 2, 2, 2, 2],
        )
        self.assertEqual(steps[3]["code"], "budget_exceeded")
        self.assertEqual(steps[3]["budgets"]["left"], {"limit": 2, "spent": 1})
        self.assertEqual(steps[4]["action"], steps[1]["action"])
        self.assertTrue(steps[4]["same_action"])
        self.assertEqual(steps[4]["additional_charge"], 0)
        self.assertEqual(steps[5]["code"], "request_conflict")
        self.assertEqual(report["final"]["admitted_actions"], 2)
        self.assertEqual(report["final"]["pending_actions"], 2)
        self.assertEqual(report["final"]["budgets"]["right"], {"limit": 2, "spent": 1})
        self.assertEqual(report["tool_calls"], 0)
        self.assertEqual(report["model_calls"], 0)

    def test_fixture_cleanup_and_output_omit_host_paths_and_credentials(self):
        created = []
        temporary_directory = tempfile.TemporaryDirectory

        def track_directory(*args, **kwargs):
            directory = temporary_directory(*args, **kwargs)
            created.append(Path(directory.name))
            return directory

        credentials = ["fixture-supervisor-token", "fixture-left-token", "fixture-right-token"]
        with patch.object(example.tempfile, "TemporaryDirectory", side_effect=track_directory):
            with patch.object(example.secrets, "token_urlsafe", side_effect=credentials):
                report = example.run_demo()

        self.assertTrue(created)
        self.assertTrue(all(not path.exists() for path in created))
        self.assertTrue(report["temporary_database_removed"])
        output = json.dumps(report) + example.transcript(report)
        for private_text in [str(ROOT), *(str(path) for path in created), *credentials, "cap_", "act_"]:
            self.assertNotIn(private_text, output)

    def test_cleanup_when_an_expected_denial_is_unexpectedly_admitted(self):
        created = []
        temporary_directory = tempfile.TemporaryDirectory
        reserve = example.Store.reserve

        def track_directory(*args, **kwargs):
            directory = temporary_directory(*args, **kwargs)
            created.append(Path(directory.name))
            return directory

        def incorrectly_admit(store, actor, capability, request_id, *args, **kwargs):
            if request_id == "left-two":
                return {"status": "pending"}
            return reserve(store, actor, capability, request_id, *args, **kwargs)

        with patch.object(example.tempfile, "TemporaryDirectory", side_effect=track_directory):
            with patch.object(example.Store, "reserve", incorrectly_admit):
                with self.assertRaisesRegex(RuntimeError, "expected to be denied"):
                    example.run_demo()
        self.assertTrue(created)
        self.assertTrue(all(not path.exists() for path in created))

    def test_documented_cli_json_and_transcript(self):
        environment = {**os.environ, "PYTHONPATH": "src", "PYTHONDONTWRITEBYTECODE": "1"}
        results = []
        for arguments in ([], ["--json"]):
            result = subprocess.run(
                [sys.executable, "examples/shared_budget.py", *arguments],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            results.append(result.stdout)
        report = json.loads(results[1])
        self.assertEqual(report["mode"], "offline_store_admission_only")
        self.assertEqual(report["final"]["pending_actions"], 2)
        self.assertEqual(results[0], example.transcript(report) + "\n")
        self.assertIn("budget_exceeded", results[0])
        self.assertIn("request_conflict", results[0])


if __name__ == "__main__":
    unittest.main()
