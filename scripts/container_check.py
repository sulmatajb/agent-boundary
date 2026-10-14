#!/usr/bin/env python3
"""Disposable Docker containment evidence, with an optional supervised model workflow."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
WORKERS = ("researcher", "writer", "reviewer")


def bootstrap(directory: Path) -> None:
    """Create fresh local-only credentials without printing any credential."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or any(directory.iterdir()):
        raise ValueError("Bootstrap requires an empty, real directory")
    directory.chmod(0o700)
    tokens = {role: secrets.token_urlsafe(32) for role in ("admin", *WORKERS)}
    credentials = [{"principal": role, "token": token, "admin": role == "admin"}
                   for role, token in tokens.items()]
    files = {"broker-credentials.json": json.dumps(credentials),
             "tool-token": secrets.token_urlsafe(32),
             **{f"{role}-token": tokens[role] for role in WORKERS}}
    for name, content in files.items():
        # Compose local secrets are bind mounts, so their requested uid/mode is
        # not portable. 0444 permits container uid 10001; the host directory is
        # 0700, and each worker mounts exactly one selected secret file.
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
        (directory / name).chmod(0o444)


CLIENT = r'''
import json, pathlib, sys
from agent_boundary.client import BrokerClient
from agent_boundary.errors import BoundaryError
request = json.load(sys.stdin)
if request.pop("admin", False):
    entries = json.loads(pathlib.Path("/run/secrets/broker_credentials").read_text())
    token = next(entry["token"] for entry in entries if entry["admin"])
    url = "http://127.0.0.1:8765"
else:
    token = pathlib.Path("/run/secrets/worker_token").read_text()
    url = "http://broker:8765"
try:
    result = getattr(BrokerClient(url, token), request["method"])(**request["args"])
    print(json.dumps({"ok": True, "result": result}))
except BoundaryError as error:
    print(json.dumps({"ok": False, "error": error.code, "status": error.status}))
'''

PROBE = r'''
import errno, json, os, pathlib, socket, sys, urllib.error, urllib.request
targets = json.load(sys.stdin)
result = {"uid": os.getuid(), "own_token_readable": bool(pathlib.Path("/run/secrets/worker_token").read_text())}
for name in ("broker_credentials", "tool_token", "researcher_token", "writer_token", "reviewer_token"):
    result["secret_absent_" + name] = not pathlib.Path("/run/secrets", name).exists()
result["database_absent"] = not pathlib.Path("/state/broker.db").exists() and not pathlib.Path("/state/tool.db").exists()
result["docker_socket_absent"] = not pathlib.Path("/var/run/docker.sock").exists()
def inaccessible(path):
    try:
        return not pathlib.Path(path).exists()
    except PermissionError:
        return True
result["host_credentials_inaccessible"] = inaccessible("/root/.codex") and inaccessible("/home/worker/.codex")
try:
    pathlib.Path("/app/worker-write-test").write_text("forbidden")
    result["rootfs_read_only"] = False
except OSError as error:
    result["rootfs_read_only"] = error.errno == errno.EROFS
status = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in line)
result["no_effective_caps"] = int(status["CapEff"].strip(), 16) == 0
result["no_new_privileges"] = status["NoNewPrivs"].strip() == "1"
result["seccomp_filter"] = status["Seccomp"].strip() == "2"
try:
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
    result["raw_socket_denied"] = False
except PermissionError:
    result["raw_socket_denied"] = True
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
result["broker_health"] = opener.open("http://broker:8765/health", timeout=2).status == 200
for suffix, headers in (("missing", {}), ("invalid", {"Authorization": "Bearer invalid-fixture-token"})):
    try:
        opener.open(urllib.request.Request("http://broker:8765/v1/audit", headers=headers), timeout=2)
        result["auth_denied_" + suffix] = False
    except urllib.error.HTTPError as error:
        result["auth_denied_" + suffix] = error.code in (401, 403)
for name, host, port in targets:
    try:
        connection = socket.create_connection((host, port), timeout=1.5)
        connection.close()
        result["blocked_" + name] = False
    except OSError:
        result["blocked_" + name] = True
print(json.dumps(result))
'''

CANARY = r'''
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"disposable-network-canary")
    def log_message(self, *args):
        pass
HTTPServer(("0.0.0.0", 18080), Handler).serve_forever()
'''

CONNECT = r'''
import json, socket, sys
results = {}
for name, host, port in json.load(sys.stdin):
    try:
        with socket.create_connection((host, port), timeout=1.5):
            results[name] = True
    except OSError:
        results[name] = False
print(json.dumps(results))
'''

RESOLVE_HOST = r'''
import json, socket
try:
    addresses = sorted({row[4][0] for row in socket.getaddrinfo("host.docker.internal", None, socket.AF_INET)})
except OSError:
    addresses = []
print(json.dumps(addresses))
'''


class ContainerBrokerClient:
    """Trusted host transport: every HTTP request executes inside its role container."""

    def __init__(self, check, role):
        self.check = check
        self.service = "broker" if role == "admin" else role

    def _call(self, method, **arguments):
        from agent_boundary.errors import BoundaryError
        response = self.check.call(self.service, method, **arguments)
        if not response["ok"]:
            raise BoundaryError(response["error"], "Container broker request denied", response["status"])
        return response["result"]

    def root(self, owner, scopes, budget):
        return self._call("root", owner=owner, scopes=scopes, budget=budget)

    def delegate(self, capability, owner, scopes, budget):
        return self._call("delegate", capability=capability, owner=owner, scopes=scopes, budget=budget)

    def execute(self, capability, request_id, operation, resource, value=None):
        return self._call("execute", capability=capability, request_id=request_id,
                          operation=operation, resource=resource, value=value)

    def audit(self):
        return self._call("audit")


class ContainmentCheck:
    def __init__(self, runtime: Path):
        self.name = "ab-check-" + secrets.token_hex(5)
        self.image = self.name + ":local"
        self.canary = self.name + "-canary"
        self.control_peer = self.name + "-control-peer"
        self.external_network = self.name + "-outside"
        self.env = {**os.environ, "AB_RUNTIME_DIR": str(runtime), "AB_IMAGE": self.image}
        self.checks: list[str] = []
        self.untested_network_routes: list[dict] = []
        self.compose = ["docker", "compose", "-p", self.name, "-f", str(ROOT / "compose.yaml")]

    def run(self, arguments, *, data=None, timeout=120, check=True):
        result = subprocess.run(arguments, cwd=ROOT, env=self.env, input=data,
                                text=True, capture_output=True, timeout=timeout)
        if check and result.returncode:
            # Do not copy service logs, command payloads, or environment to reports.
            raise RuntimeError("Container command failed: " + result.stderr[-1500:])
        return result

    def require(self, condition: bool, label: str):
        if not condition:
            raise AssertionError(label)
        self.checks.append(label)

    def execute(self, service: str, source: str, payload=None):
        result = self.run([*self.compose, "exec", "-T", service, "python", "-c", source],
                          data=json.dumps(payload or {}), timeout=60)
        return json.loads(result.stdout)

    def call(self, service: str, method: str, **args):
        return self.execute(service, CLIENT, {"admin": service == "broker", "method": method, "args": args})

    def inspect(self, identifier: str):
        return json.loads(self.run(["docker", "inspect", identifier]).stdout)[0]

    def healthy_canary(self):
        for _ in range(30):
            response = self.run(["docker", "exec", self.canary, "python", "-c",
                                 "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:18080', timeout=1).read() == b'disposable-network-canary'"], check=False)
            if response.returncode == 0:
                return
            time.sleep(0.1)
        raise RuntimeError("Disposable egress canary did not start")

    def external_connections(self, targets):
        """Verify a route from an ordinary Docker peer before claiming isolation."""
        result = self.run(["docker", "exec", "-i", self.control_peer, "python", "-c", CONNECT],
                          data=json.dumps(targets), timeout=30)
        return json.loads(result.stdout)

    def host_targets(self, worker, endpoint, port):
        """Never count an absent hostname or unverified listener as a passed block."""
        addresses = self.execute(worker, RESOLVE_HOST)
        candidates = []
        if addresses:
            # Probe resolved addresses explicitly so the positive and negative
            # controls address the same host, even with split-horizon DNS.
            candidates.extend(("host_alias" if len(addresses) == 1 else f"host_alias_{i}", address, port)
                              for i, address in enumerate(addresses))
        else:
            self.untested_network_routes.append({"worker": worker, "route": "host_alias",
                                                "reason": "hostname_unavailable"})
        gateway = endpoint.get("Gateway")
        if not gateway:
            network = self.inspect(endpoint["NetworkID"])
            gateways = [config.get("Gateway") for config in network.get("IPAM", {}).get("Config", [])
                        if config.get("Gateway") and ":" not in config["Gateway"]]
            gateway = gateways[0] if gateways else None
        if gateway:
            candidates.append(("host_gateway", gateway, port))
        else:
            self.untested_network_routes.append({"worker": worker, "route": "host_gateway",
                                                "reason": "gateway_unavailable"})
        verified = self.external_connections(candidates) if candidates else {}
        targets = []
        for label, host, port in candidates:
            if verified[label]:
                self.require(True, worker + ":" + label + ":positive_control")
                targets.append((label, host, port))
            else:
                self.untested_network_routes.append({"worker": worker, "route": label,
                                                    "reason": "positive_control_unreachable"})
        return targets

    def check(self):
        self.run(["docker", "build", "--pull=false", "-t", self.image, "."], timeout=240)
        self.run([*self.compose, "up", "-d", "--no-build", "--wait", "--wait-timeout", "60"])
        records = {}
        for service in ("broker", "tool", *WORKERS):
            identifier = self.run([*self.compose, "ps", "-q", service]).stdout.strip()
            records[service] = self.inspect(identifier)
            record = records[service]
            self.require(record["Config"]["User"] == "10001:10001", service + ":nonroot")
            self.require(record["HostConfig"]["ReadonlyRootfs"], service + ":read_only")
            self.require(record["HostConfig"]["CapDrop"] == ["ALL"], service + ":drop_all_caps")
            self.require("no-new-privileges:true" in record["HostConfig"]["SecurityOpt"], service + ":no_new_privileges")
            self.require(not record["HostConfig"].get("Privileged"), service + ":not_privileged")
            self.require(not record["HostConfig"].get("PortBindings"), service + ":no_published_ports")
            self.require(record["HostConfig"]["PidsLimit"] == 64, service + ":pid_limit")
            self.require(record["HostConfig"]["Memory"] == 128 * 1024**2, service + ":memory_limit")
            self.require(record["HostConfig"]["NanoCpus"] == 1_000_000_000, service + ":cpu_limit")
            temporary_mounts = record["HostConfig"]["Tmpfs"]
            self.require(set(temporary_mounts) == {"/tmp"} and all(option in temporary_mounts["/tmp"].split(",") for option in ("noexec", "nosuid", "nodev", "size=16m")), service + ":restricted_tmpfs")
        for network in records["broker"]["NetworkSettings"]["Networks"]:
            self.require(self.inspect(network)["Internal"], "internal_network:" + network.removeprefix(self.name + "_"))
        tool_networks = records["tool"]["NetworkSettings"]["Networks"]
        self.require(len(tool_networks) == 1, "tool:single_private_network")
        tool_ip = next(iter(tool_networks.values()))["IPAddress"]
        broker_mounts = {mount["Destination"]: mount for mount in records["broker"]["Mounts"]}
        tool_mounts = {mount["Destination"]: mount for mount in records["tool"]["Mounts"]}
        self.require(broker_mounts["/state"]["Name"] != tool_mounts["/state"]["Name"], "distinct_database_volumes")
        for worker in WORKERS:
            networks = records[worker]["NetworkSettings"]["Networks"]
            self.require(len(networks) == 1 and not (set(networks) & set(tool_networks)), worker + ":no_tool_network")
            destinations = {mount["Destination"] for mount in records[worker]["Mounts"]}
            # Docker reports tmpfs in HostConfig.Tmpfs separately from Mounts.
            self.require(destinations == {"/run/secrets/worker_token"}, worker + ":only_own_secret_mount")
            own_secret = next(m for m in records[worker]["Mounts"] if m["Destination"] == "/run/secrets/worker_token")
            self.require(not own_secret["RW"], worker + ":secret_read_only")

        # A real listening target, controlled by this test, outside all internal
        # networks. Also publish a random host port to check Docker Desktop's
        # host alias and the bridge gateway, without contacting unrelated hosts.
        self.run(["docker", "network", "create", self.external_network])
        self.run(["docker", "run", "-d", "--name", self.canary, "--network", self.external_network,
                  "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "-p", "127.0.0.1::18080", self.image, "-c", CANARY])
        self.run(["docker", "run", "-d", "--name", self.control_peer, "--network", self.external_network,
                  "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", self.image])
        self.healthy_canary()
        self.require(True, "outside_canary:positive_control")
        canary_record = self.inspect(self.canary)
        canary_ip = canary_record["NetworkSettings"]["Networks"][self.external_network]["IPAddress"]
        canary_port = int(canary_record["NetworkSettings"]["Ports"]["18080/tcp"][0]["HostPort"])
        writer_ip = next(iter(records["writer"]["NetworkSettings"]["Networks"].values()))["IPAddress"]
        self.run([*self.compose, "exec", "-d", "writer", "python", "-c", CANARY])
        self.require(self.execute("writer", "import urllib.request,json; print(json.dumps(urllib.request.urlopen('http://127.0.0.1:18080', timeout=2).status == 200))"), "peer_canary:positive_control")
        self.require(self.external_connections([("outside_ip", canary_ip, 18080)])["outside_ip"],
                     "outside_ip:positive_control_from_external_peer")
        internal_controls = self.execute("broker", CONNECT,
                                         [("tool_ip", tool_ip, 8766), ("peer_worker", writer_ip, 18080)])
        for label, reachable in internal_controls.items():
            self.require(reachable is True, label + ":positive_control_from_broker")
        for worker in WORKERS:
            network = next(iter(records[worker]["NetworkSettings"]["Networks"].values()))
            targets = [("tool_dns", "tool", 8766), ("tool_ip", tool_ip, 8766),
                       ("outside_ip", canary_ip, 18080)]
            targets.extend(self.host_targets(worker, network, canary_port))
            if worker != "writer":
                targets.append(("peer_worker", writer_ip, 18080))
            results = self.execute(worker, PROBE, targets)
            for label, value in results.items():
                self.require(value == 10001 if label == "uid" else value is True, worker + ":" + label)

        scopes = [["document.read", "source"], ["document.append", "draft"], ["document.read", "draft"]]
        root = self.call("broker", "root", owner="researcher", scopes=scopes, budget=3)["result"]["capability"]
        child = self.call("researcher", "delegate", capability=root, owner="writer", scopes=scopes[1:], budget=2)["result"]["capability"]
        leaf = self.call("writer", "delegate", capability=child, owner="reviewer", scopes=[scopes[2]], budget=1)["result"]["capability"]
        read = self.call("researcher", "execute", capability=root, request_id="source", operation="document.read", resource="source")
        self.require(read["ok"] and read["result"]["status"] == "completed", "workflow:researcher_read")
        append_args = dict(capability=child, request_id="draft", operation="document.append", resource="draft", value="Container workflow fixture.")
        append = self.call("writer", "execute", **append_args)
        self.require(append["ok"] and append["result"]["status"] == "completed", "workflow:writer_append")
        replay = self.call("writer", "execute", **append_args)
        self.require(replay["ok"] and replay["result"]["replayed"], "workflow:replay_no_new_action")
        review = self.call("reviewer", "execute", capability=leaf, request_id="review", operation="document.read", resource="draft")
        self.require(review["ok"] and review["result"]["result"]["content"] == "Container workflow fixture.", "workflow:reviewer_read")
        for label, result in (
            ("worker_admin_denied", self.call("writer", "audit")),
            ("capability_theft_denied", self.call("reviewer", "execute", capability=root, request_id="theft", operation="document.read", resource="source")),
            ("private_read_denied", self.call("researcher", "execute", capability=root, request_id="private", operation="document.read", resource="private")),
            ("budget_overrun_denied", self.call("researcher", "execute", capability=root, request_id="extra", operation="document.read", resource="source")),
        ):
            self.require(not result["ok"], "authorization:" + label)
        audit = self.call("broker", "audit")["result"]
        self.require(len(audit["actions"]) == 3 and all(a["status"] == "completed" for a in audit["actions"]), "workflow:three_completed_intents")
        self.require([audit["capabilities"][c]["spent"] for c in (root, child, leaf)] == [3, 2, 1], "workflow:ancestor_accounting")
        sink = self.execute("tool", "import json; from agent_boundary.tool_service import ToolStore; print(json.dumps(ToolStore('/state/tool.db').snapshot()))")
        self.require(len(sink["operations"]) == 3, "sink:three_durable_effects")
        self.require(sink["documents"]["draft"]["version"] == 1, "sink:append_exactly_once_for_adapter")
        self.require(sink["documents"]["private"]["content"] == "CANARY_PRIVATE", "sink:private_unchanged")
        # Restart uses the same isolated durable volumes and repeat delivery IDs.
        self.run([*self.compose, "restart", "tool", "broker"])
        self.run([*self.compose, "up", "-d", "--no-build", "--wait", "--wait-timeout", "60"])
        replay = self.call("writer", "execute", **append_args)
        self.require(replay["ok"] and replay["result"]["replayed"] and replay["result"]["result"]["version"] == 1, "restart:durable_replay")

    def workflow(self, backend_name):
        from agent_boundary.codex_adapter import CodexBackend, DeterministicBackend, run_workflow
        from agent_boundary.errors import BoundaryError
        self.clients = {role: ContainerBrokerClient(self, role) for role in ("admin", *WORKERS)}
        try:
            backend = CodexBackend() if backend_name == "codex" else DeterministicBackend()
            result = run_workflow(self, backend, workflow_timeout=600)
        except BoundaryError as error:
            return {"completed": False, "backend": backend_name, "error": error.code}
        metadata = result["runtime"]
        # Retain counts and budget evidence, never prompts, transcripts, model
        # text, bearer values, action IDs, or document content in this report.
        report = {key: result[key] for key in ("completed", "backend", "budget", "limits")}
        report.update({"completed_roles": len(result["roles"]),
                       "model_calls": len(metadata.get("calls", [])),
                       "runtime_version": metadata.get("runtime_version"),
                       "transport": "role_container_exec_then_authenticated_broker_http"})
        if "error" in result:
            report["error"] = result["error"]
        return report

    def cleanup(self):
        self.run([*self.compose, "down", "--volumes", "--remove-orphans"], check=False)
        self.run(["docker", "rm", "-f", self.canary, self.control_peer], check=False)
        self.run(["docker", "network", "rm", self.external_network], check=False)
        self.run(["docker", "image", "rm", self.image], check=False)
        remaining = self.run(["docker", "ps", "-aq", "--filter", "name=" + self.name]).stdout.strip()
        remaining_networks = self.run(["docker", "network", "ls", "-q", "--filter", "name=" + self.name]).stdout.strip()
        remaining_volumes = self.run(["docker", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project=" + self.name]).stdout.strip()
        self.require(not remaining and not remaining_networks and not remaining_volumes, "cleanup:no_test_containers_networks_or_volumes")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", type=Path, help="Create fresh secrets only; does not start services")
    parser.add_argument("--output", type=Path, help="Write sanitized evidence JSON")
    parser.add_argument("--workflow-backend", choices=("deterministic", "codex"),
                        help="Also run the supervised workflow through container-bound clients; codex uses host ChatGPT sign-in")
    args = parser.parse_args(argv)
    if args.bootstrap:
        bootstrap(args.bootstrap)
        print("Created fresh container credentials in the requested private directory.")
        return 0
    report = {"kind": "deterministic_docker_containment", "live_model_evaluation": False,
              "timestamp_utc": datetime.now(timezone.utc).isoformat(), "passed": False}
    failure = None
    with tempfile.TemporaryDirectory(prefix="agent-boundary-container-") as temporary:
        runtime = Path(temporary) / "secrets"
        bootstrap(runtime)
        check = ContainmentCheck(runtime)
        try:
            check.check()
            if args.workflow_backend:
                report["workflow"] = check.workflow(args.workflow_backend)
                report["live_model_evaluation"] = args.workflow_backend == "codex" and report["workflow"].get("model_calls", 0) > 0
                if report["live_model_evaluation"]:
                    report["kind"] = "docker_containment_with_live_codex_workflow"
                check.require(report["workflow"]["completed"], "workflow_backend:completed")
            report["passed"] = True
        except (AssertionError, RuntimeError, OSError, subprocess.TimeoutExpired, KeyError, ValueError) as error:
            failure = error
            report["failure_type"] = type(error).__name__
            if isinstance(error, AssertionError):
                report["failed_check"] = str(error)
        finally:
            try:
                check.cleanup()
            except (AssertionError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                report["passed"] = False
                report["cleanup_failed"] = True
                failure = failure or error
            report["checks"] = check.checks
            report["checks_passed"] = len(check.checks)
            report["untested_network_routes"] = check.untested_network_routes
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    if failure:
        print(str(failure), file=sys.stderr)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
