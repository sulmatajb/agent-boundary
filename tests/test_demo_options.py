"""CLI validation ordering with instrumented services and no live model calls."""
import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from agent_boundary import demo
from agent_boundary.codex_adapter import (
    CodexBackend, SUPPORTED_CODEX_VERSION, run_workflow, validate_workflow_options,
)


class DemoOptionTests(unittest.TestCase):
    def test_invalid_workflow_options_precede_all_backend_and_service_setup(self):
        options = [
            ["--workflow-timeout=" + value]
            for value in ("0", "-1", "nan", "inf", "-inf", "1801")
        ] + [["--max-rounds", value] for value in ("1", "11")]
        for backend in ("deterministic", "codex"):
            for arguments in options:
                with self.subTest(backend=backend, arguments=arguments), \
                     patch.object(demo, "LocalSystem") as system, \
                     patch.object(demo, "CodexBackend") as codex, \
                     patch.object(demo, "DeterministicBackend") as deterministic, \
                     patch.object(demo, "run_workflow") as workflow, \
                     contextlib.redirect_stdout(io.StringIO()) as output, \
                     contextlib.redirect_stderr(io.StringIO()) as error:
                    with self.assertRaises(SystemExit) as caught:
                        demo.main(["--backend", backend, *arguments])
                    self.assertEqual(caught.exception.code, 2)
                    self.assertIn("error:", error.getvalue())
                    self.assertEqual(output.getvalue(), "")
                    system.assert_not_called()
                    codex.assert_not_called()
                    deterministic.assert_not_called()
                    workflow.assert_not_called()

    def test_rounds_error_keeps_priority_when_both_workflow_options_are_invalid(self):
        with patch.object(demo, "LocalSystem") as system, \
             patch.object(demo, "CodexBackend") as codex, \
             contextlib.redirect_stderr(io.StringIO()) as error:
            with self.assertRaises(SystemExit) as caught:
                demo.main(["--backend", "codex", "--max-rounds", "1",
                           "--workflow-timeout", "nan"])
            self.assertEqual(caught.exception.code, 2)
            self.assertIn("max_rounds must be an integer from 2 through 10", error.getvalue())
            system.assert_not_called()
            codex.assert_not_called()

    def test_valid_default_and_boundary_options_are_forwarded(self):
        cases = [([], 4, 600),
                 (["--max-rounds", "2", "--workflow-timeout", "0.001"], 2, 0.001),
                 (["--max-rounds", "10", "--workflow-timeout", "1800"], 10, 1800)]
        for backend in ("deterministic", "codex"):
            for arguments, rounds, timeout in cases:
                with self.subTest(backend=backend, arguments=arguments), \
                     patch.object(demo, "LocalSystem") as system, \
                     patch.object(demo, "CodexBackend") as codex, \
                     patch.object(demo, "DeterministicBackend") as deterministic, \
                     patch.object(demo, "run_workflow", return_value={"completed": True}) as workflow, \
                     contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(demo.main(["--backend", backend, *arguments]), 0)
                    chosen = codex if backend == "codex" else deterministic
                    workflow.assert_called_once_with(
                        system.return_value.__enter__.return_value, chosen.return_value,
                        max_rounds=rounds, workflow_timeout=timeout)
                    system.return_value.__enter__.assert_called_once()
                    system.return_value.__exit__.assert_called_once()
                    self.assertEqual(json.loads(output.getvalue()), {"completed": True})
                    if backend == "codex":
                        codex.assert_called_once_with(timeout=90)
                        deterministic.assert_not_called()
                    else:
                        deterministic.assert_called_once_with()
                        codex.assert_not_called()

    def test_deterministic_backend_still_ignores_codex_only_timeout(self):
        for timeout in ("0", "nan", "inf", "301"):
            with self.subTest(timeout=timeout), patch.object(demo, "LocalSystem"), \
                 patch.object(demo, "CodexBackend") as codex, \
                 patch.object(demo, "run_workflow", return_value={"completed": True}) as workflow, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(demo.main(["--timeout", timeout]), 0)
                codex.assert_not_called()
                workflow.assert_called_once()


class WorkflowOptionTests(unittest.TestCase):
    def test_invalid_direct_rounds_fail_before_deadline_or_system_access(self):
        for rounds in (True, False, 1.5, "4", None, 0, 1, 11):
            with self.subTest(rounds=rounds), \
                 patch("agent_boundary.codex_adapter.time.monotonic") as clock:
                with self.assertRaisesRegex(ValueError, "max_rounds must be an integer"):
                    run_workflow(object(), Mock(), max_rounds=rounds)
                clock.assert_not_called()

    def test_invalid_direct_timeouts_fail_before_deadline_or_system_access(self):
        for timeout in (True, False, "600", None, float("nan"), float("inf"),
                        float("-inf"), 0, -1, 1800.01):
            with self.subTest(timeout=timeout), \
                 patch("agent_boundary.codex_adapter.time.monotonic") as clock:
                with self.assertRaisesRegex(ValueError, "Timeout must be greater than zero"):
                    run_workflow(object(), Mock(), workflow_timeout=timeout)
                clock.assert_not_called()

    def test_valid_workflow_limits_return_normalized_timeout(self):
        for rounds in (2, 4, 10):
            for timeout in (0.001, 600, 1800):
                with self.subTest(rounds=rounds, timeout=timeout):
                    result = validate_workflow_options(rounds, timeout)
                    self.assertIs(type(result), float)
                    self.assertEqual(result, timeout)

    def test_codex_per_proposal_timeout_limit_is_unchanged(self):
        with patch("agent_boundary.codex_adapter.shutil.which", return_value="fixture-codex") as which, \
             patch("agent_boundary.codex_adapter.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                [], 0, SUPPORTED_CODEX_VERSION + "\n", "")
            self.assertEqual(CodexBackend(timeout=300).timeout, 300)
            which.assert_called_once()
            run.assert_called_once()
        for timeout in (True, 0, -1, 300.01, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), \
                 patch("agent_boundary.codex_adapter.shutil.which") as which, \
                 patch("agent_boundary.codex_adapter.subprocess.run") as run:
                with self.assertRaises(ValueError):
                    CodexBackend(timeout=timeout)
                which.assert_not_called()
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
