"""Bounded startup against disposable real Python children; no service/model access."""

import json
import subprocess
import time
import unittest
from unittest.mock import patch

from agent_boundary import runtime
from agent_boundary.runtime import LocalSystem


class StartupTests(unittest.TestCase):
    def launch(self, program, *, timeout=0.25, expect_error=True, decode_delay=0):
        system = LocalSystem()
        self.addCleanup(system.close)
        (system.directory / "startup_fixture.py").write_text(
            "import os, sys, time\n" + program, encoding="utf-8")
        children = []
        real_popen = subprocess.Popen
        real_loads = json.loads

        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        def decode(*args, **kwargs):
            time.sleep(decode_delay)
            return real_loads(*args, **kwargs)

        started = time.monotonic()
        with patch.object(runtime, "STARTUP_TIMEOUT", timeout), \
                patch.object(runtime.subprocess, "Popen", side_effect=spawn), \
                patch.object(runtime.json, "loads", side_effect=decode):
            if expect_error:
                with self.assertRaises(RuntimeError) as raised:
                    system._start("fixture", "startup_fixture", [])
                result = str(raised.exception)
                # The failing _start itself must clean up, including when it is
                # called outside __enter__ during a service restart.
                self.assertNotIn("fixture", system.processes)
                self.assertIsNotNone(children[0].poll())
                self.assertTrue(children[0].stdout.closed)
            else:
                result = system._start("fixture", "startup_fixture", [])
                self.assertIsNone(children[0].poll())
        elapsed = time.monotonic() - started
        # Each child also exits after a short fixed sleep, bounding regressions
        # even if a future implementation blocks past its readiness deadline.
        self.assertLess(elapsed, 1.0)
        logs = list(system.logs)
        directory = system.directory
        system.close()
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)
        self.assertFalse(system.processes)
        self.assertTrue(all(log.closed for log in logs))
        self.assertFalse(directory.exists())
        return result, elapsed

    def test_partial_line_cannot_outlive_total_deadline(self):
        result, elapsed = self.launch("os.write(1, b'{'); time.sleep(1.5)\n")
        self.assertIn("within 0.25 seconds", result)
        self.assertGreaterEqual(elapsed, 0.20)

    def test_no_output_times_out_and_reaps_child(self):
        result, _ = self.launch("time.sleep(1.5)\n")
        self.assertIn("within 0.25 seconds", result)

    def test_trickled_bytes_do_not_renew_deadline(self):
        result, _ = self.launch("for byte in b'{    ':\n    os.write(1, bytes([byte])); time.sleep(0.15)\ntime.sleep(0.75)\n")
        self.assertIn("within 0.25 seconds", result)

    def test_valid_split_line_is_accepted_without_waiting_for_exit(self):
        result, _ = self.launch(
            "os.write(1, b'{\"ready\":'); time.sleep(0.04)\n"
            "os.write(1, b'true,\"port\":12345,\"host\":\"127.0.0.1\"}\\n'); time.sleep(1.5)\n",
            expect_error=False)
        self.assertEqual(result, "http://127.0.0.1:12345")

    def test_validation_must_finish_within_same_deadline(self):
        result, _ = self.launch(
            "os.write(1, b'{\"ready\":true,\"port\":12345}\\n'); time.sleep(1.5)\n",
            timeout=0.10, decode_delay=0.15)
        self.assertIn("within 0.1 seconds", result)

    def test_eof_without_a_complete_line_fails_closed(self):
        for output in [b"", b"{", b'{"ready":true,"port":12345}']:
            with self.subTest(output_length=len(output)):
                result, _ = self.launch(f"os.write(1, {output!r})\n")
                self.assertIn("failed startup", result)

    def test_malformed_line_is_sanitized_and_child_is_reaped(self):
        for output in [b"PRIVATE_FIXTURE_MARKER\n", b"\xff\n", b"[]\n",
                       b'{"ready":false,"port":12345}\n', b'{"ready":true,"port":true}\n']:
            with self.subTest(output_length=len(output)):
                result, _ = self.launch(f"os.write(1, {output!r}); time.sleep(1.5)\n")
                self.assertEqual(result, "fixture failed startup; inspect its private runtime log")
                self.assertNotIn("PRIVATE_FIXTURE_MARKER", result)

    def test_oversized_complete_or_partial_line_is_rejected(self):
        ready = b'{"ready":true,"port":12345}'
        for output in [ready + b" " * (4097 - len(ready)),
                       ready + b" " * (4096 - len(ready)) + b"\n"]:
            with self.subTest(newline=output.endswith(b"\n")):
                result, _ = self.launch(f"os.write(1, {output!r}); time.sleep(1.5)\n")
                self.assertIn("failed startup", result)

    def test_exact_line_limit_accepts_complete_ready_json(self):
        line = b'{"ready":true,"port":12345}'
        line += b" " * (4096 - len(line) - 1) + b"\n"
        result, _ = self.launch(f"os.write(1, {line!r}); time.sleep(1.5)\n", expect_error=False)
        self.assertEqual(result, "http://127.0.0.1:12345")

    def test_following_stdout_does_not_change_first_ready_line(self):
        output = b'{"ready":true,"port":12345}\n' + b"later output" * 400
        result, _ = self.launch(f"os.write(1, {output!r}); time.sleep(1.5)\n", expect_error=False)
        self.assertEqual(result, "http://127.0.0.1:12345")


if __name__ == "__main__":
    unittest.main()
