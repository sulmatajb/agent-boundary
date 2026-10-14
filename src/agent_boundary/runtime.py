"""Trusted supervisor for disposable, actual HTTP service subprocesses.

This convenience runtime uses processes owned by the current user. Docker is
the separately tested filesystem/network boundary for hostile worker code.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import select
import shutil
import subprocess
import sys
import tempfile


ROLES = ("admin", "researcher", "writer", "reviewer", "attacker")


class LocalSystem:
    def __init__(self, directory: str | Path | None = None):
        self._temporary = directory is None
        self.directory = Path(directory) if directory else Path(tempfile.mkdtemp(prefix="agent-boundary-"))
        self.processes = {}
        self.logs = []
        self.tokens = {}
        self.tool_token = ""
        self.broker_url = self.tool_url = ""
        self.clients = {}

    @staticmethod
    def _private_write(path, text):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(text)

    def _start(self, name, module, args):
        log = (self.directory / f"{name}.log").open("ab")
        self.logs.append(log)
        source = str(Path(__file__).resolve().parent.parent)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": source,
               "PYTHONUNBUFFERED": "1", "LANG": "C.UTF-8"}
        process = subprocess.Popen([sys.executable, "-m", module, *map(str, args)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=log, env=env, cwd=self.directory)
        self.processes[name] = process
        ready, _, _ = select.select([process.stdout], [], [], 15)
        if not ready:
            raise RuntimeError(f"{name} did not become ready within 15 seconds")
        line = process.stdout.readline(4097)
        try:
            result = json.loads(line)
            if result.get("ready") is not True or type(result.get("port")) is not int:
                raise ValueError("invalid readiness")
        except (ValueError, TypeError, AttributeError) as error:
            raise RuntimeError(f"{name} failed startup; inspect its private runtime log") from error
        return f"http://127.0.0.1:{result['port']}"

    def __enter__(self):
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            os.chmod(self.directory, 0o700)
            self.tokens = {role: secrets.token_urlsafe(32) for role in ROLES}
            self.tool_token = secrets.token_urlsafe(32)
            credentials = [{"principal": role, "token": token, "admin": role == "admin"}
                           for role, token in self.tokens.items()]
            self._private_write(self.directory / "credentials.json", json.dumps(credentials))
            self._private_write(self.directory / "tool-token", self.tool_token)
            self.tool_url = self._start("tool", "agent_boundary.tool_service", [
                "--db", self.directory / "tool.db", "--token-file", self.directory / "tool-token",
                "--port", 0])
            self.restart_broker()
            return self
        except BaseException:
            self.close()
            raise

    def stop(self, name, *, kill=False):
        process = self.processes.pop(name, None)
        if process:
            if process.poll() is None:
                process.kill() if kill else process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.stdout:
                process.stdout.close()

    def restart_broker(self):
        from .client import BrokerClient
        self.stop("broker")
        self.broker_url = self._start("broker", "agent_boundary.server", [
            "--db", self.directory / "broker.db", "--credentials", self.directory / "credentials.json",
            "--sink-url", self.tool_url, "--sink-token-file", self.directory / "tool-token", "--port", 0])
        self.clients = {role: BrokerClient(self.broker_url, token) for role, token in self.tokens.items()}

    def restart_tool(self):
        port = int(self.tool_url.rsplit(":", 1)[1])
        self.stop("tool")
        self.tool_url = self._start("tool", "agent_boundary.tool_service", [
            "--db", self.directory / "tool.db", "--token-file", self.directory / "tool-token",
            "--port", port])

    def close(self):
        for name in list(self.processes):
            self.stop(name)
        for log in self.logs:
            log.close()
        self.logs.clear()
        if self._temporary:
            shutil.rmtree(self.directory, ignore_errors=True)

    def __exit__(self, *_):
        self.close()
