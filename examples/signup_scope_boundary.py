#!/usr/bin/env python3
"""Signup task scope denies secret listing and network probe before dispatch.

    PYTHONPATH=src python3 examples/signup_scope_boundary.py
    PYTHONPATH=src python3 examples/signup_scope_boundary.py --json

Disposable local HTTP only. No model calls, account credentials, or sockets.
A proposal is not authorization. The reference tool never reads the process
environment and never opens a port.
"""

import argparse
import json
import os
from pathlib import Path
import secrets
import sys

from agent_boundary.errors import BoundaryError
from agent_boundary.runtime import LocalSystem
from agent_boundary.tool_service import ToolStore


SIGNUP_SCOPES = [["document.read", "source"]]
EXPLICIT_SCOPES = [["network.probe", "signup-net"], ["secret.list", "env"]]
# Documentation values. Any non-null value is invalid; neither string is contacted.
_REJECTED_ADDRESS = "203.0.113.10"
_REJECTED_NAME = "CUSTOMER_SECRET"
_LEDGER = ("document.read", "document.append", "secret.list", "network.probe")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run_demo():
    """Return a public report only after disposable service state is removed."""
    canary = "signup-scope-canary-" + secrets.token_hex(8)
    os.environ["SIGNUP_SCOPE_CANARY"] = canary
    try:
        with LocalSystem() as system:
            report = _scenario(system, canary)
            directory = system.directory
        report["temporary_databases_removed"] = not Path(directory).exists()
        require(report["temporary_databases_removed"], "Disposable fixture cleanup failed.")
        require(canary not in json.dumps(report), "Process environment leaked into the report.")
        return report
    finally:
        os.environ.pop("SIGNUP_SCOPE_CANARY", None)


def _scenario(system, canary):
    admin, tester = system.clients["admin"], system.clients["researcher"]
    signup = admin.root("researcher", SIGNUP_SCOPES, 1)["capability"]
    steps = []

    def ledger():
        snapshot = ToolStore(system.directory / "tool.db").snapshot()
        counts = {name: 0 for name in _LEDGER}
        for row in snapshot["operations"]:
            counts[row["operation"]] = counts.get(row["operation"], 0) + 1
        return counts, snapshot

    def spent(capability):
        row = admin.audit()["capabilities"][capability]
        return row["spent"], row["limit"], row["scopes"]

    def propose(capability, request_id, operation, resource, value):
        before, _ = ledger()
        spent_before = spent(capability)[0]
        try:
            action = tester.execute(capability, request_id, operation, resource, value)
        except BoundaryError as error:
            after, _ = ledger()
            require(after == before, "A denied proposal changed the tool ledger.")
            require(spent(capability)[0] == spent_before, "A denied proposal charged admission.")
            step = {"request_id": request_id, "operation": operation, "resource": resource,
                    "null_value": value is None, "outcome": "denied", "code": error.code,
                    "http_status": error.status, "dispatched": False, "ledger": after,
                    "spent": spent(capability)[0]}
            steps.append(step)
            return step
        after, _ = ledger()
        dispatched = sum(after.values()) == sum(before.values()) + 1
        require(action.get("status") == "completed", "Admitted proposal did not complete.")
        require(dispatched is (action.get("replayed") is False), "Dispatch did not match admission.")
        require(spent(capability)[0] == spent_before + int(dispatched), "Admission charge mismatch.")
        step = {"request_id": request_id, "operation": operation, "resource": resource,
                "null_value": value is None, "outcome": "replayed" if action["replayed"] else "completed",
                "dispatched": dispatched, "replayed": action["replayed"], "ledger": after,
                "spent": spent(capability)[0]}
        if operation == "document.read":
            result = action["result"]
            require(set(result) == {"resource", "content", "version"}, "Unexpected read receipt.")
            require(result["resource"] == "source" and type(result["version"]) is int, "Unexpected source read.")
            step["version"] = result["version"]
        else:
            step["receipt"] = action["result"]
        steps.append(step)
        return step

    before, _ = ledger()
    try:
        tester.delegate(signup, "writer", [["secret.list", "env"]], 1)
    except BoundaryError as error:
        require(error.code == "scope_denied" and error.status == 403, "Scope broadening was not denied.")
        delegation_code = error.code
    else:
        raise RuntimeError("Delegation added secret.list to the signup capability.")
    require(ledger()[0] == before and spent(signup)[0] == 0, "Denied delegation changed state.")
    steps.append({"request_id": "broaden-secret-list", "operation": "delegate", "resource": "env",
                  "null_value": True, "outcome": "denied", "code": delegation_code, "http_status": 403,
                  "dispatched": False, "ledger": ledger()[0], "spent": 0})

    read = propose(signup, "signup-read", "document.read", "source", None)
    require(read["outcome"] == "completed" and read["dispatched"] and read["spent"] == 1, "Signup read failed.")
    listing = propose(signup, "list-env", "secret.list", "env", None)
    probe = propose(signup, "probe-net", "network.probe", "signup-net", None)
    addressed = propose(signup, "probe-address", "network.probe", "signup-net", _REJECTED_ADDRESS)
    named = propose(signup, "list-named", "secret.list", "env", _REJECTED_NAME)
    for step, code, status in ((listing, "scope_denied", 403), (probe, "scope_denied", 403),
                               (addressed, "invalid_input", 400), (named, "invalid_input", 400)):
        require(step["outcome"] == "denied" and step["code"] == code and step["http_status"] == status
                and step["dispatched"] is False and step["spent"] == 1, "Signup denial was not fail-closed.")
    require(listing["ledger"] == {"document.read": 1, "document.append": 0, "secret.list": 0, "network.probe": 0},
            "Denied secret or network proposal produced a tool effect.")

    granted = admin.root("researcher", EXPLICIT_SCOPES, 2)["capability"]
    require(spent(signup)[2] == SIGNUP_SCOPES and spent(granted)[2] == EXPLICIT_SCOPES, "Stored scopes differ.")
    require(spent(granted)[0] == 0, "Issuing a capability charged admission.")
    allowed_list = propose(granted, "explicit-list", "secret.list", "env", None)
    allowed_probe = propose(granted, "explicit-probe", "network.probe", "signup-net", None)
    replay = propose(granted, "explicit-probe", "network.probe", "signup-net", None)
    require(allowed_list["receipt"] == {"resource": "env", "names": ["FIXTURE_SIGNUP_KEY"], "version": 0},
            "Secret list receipt was not the fixture name list.")
    require(allowed_probe["receipt"] == {"resource": "signup-net", "opened": False, "ports": []},
            "Network probe receipt was not the no-contact fixture.")
    require(replay["outcome"] == "replayed" and replay["dispatched"] is False and replay["spent"] == 2,
            "Replay dispatched again or charged again.")
    counts, snapshot = ledger()
    require(counts == {"document.read": 1, "document.append": 0, "secret.list": 1, "network.probe": 1},
            "Final tool ledger does not match the admitted operations.")
    encoded = json.dumps(snapshot)
    require(snapshot["documents"]["private"]["content"] == "CANARY_PRIVATE", "Private fixture changed.")
    require(canary not in encoded and _REJECTED_ADDRESS not in encoded and _REJECTED_NAME not in encoded,
            "Rejected proposal data or process environment reached the tool ledger.")
    actions = admin.audit()["actions"]
    require(sorted(row["operation"] for row in actions) == ["document.read", "network.probe", "secret.list"],
            "Denied proposals were admitted.")
    return {
        "schema_version": 1,
        "demonstration": "signup_scope_boundary",
        "backend": "deterministic",
        "model_calls": 0,
        "task": "test the signup",
        "principal": "researcher",
        "signup_scopes": SIGNUP_SCOPES,
        "explicit_scopes": EXPLICIT_SCOPES,
        "steps": steps,
        "tool_effects": counts,
        "admitted_operations": sorted(row["operation"] for row in actions),
        "limits": [
            "Local authenticated HTTP to the production broker and reference tool. No model is called.",
            "The broker, tool, supervisor, operating system, and storage are trusted. One host user is not isolation for hostile Python.",
            "Proposal JSON is not authorization. scope_denied and invalid_input happen before dispatch and do not charge quota.",
            "secret.list returns the fixture name FIXTURE_SIGNUP_KEY and no values. It does not read the process environment.",
            "network.probe on this tool returns opened false and no ports. It does not open a socket. A replaced sink could still be contacted after admission; a non-fixture reply stays pending and charged.",
            "The same principal is denied on the signup capability and admitted only on a second capability whose scopes list the pair. Delegation cannot add the pair.",
            "This does not reconstruct the November 2026 Railway/Primcloud accounts, defeat prompt injection, or contain an agent acting outside this broker.",
            "Generated credentials, host paths, document text, and the private canary are omitted. Both service databases are removed before printing.",
        ],
    }


def transcript(report):
    lines = [
        "Signup-scope boundary — deterministic local HTTP, 0 model calls",
        'Task "test the signup" scopes: document.read/source',
        "The researcher principal also receives a separate explicit grant. JSON is not authorization.",
    ]
    for step in report["steps"]:
        ledger = step["ledger"]
        detail = step.get("code", step["outcome"])
        dispatch = "dispatched" if step["dispatched"] else "not dispatched"
        lines.append(
            f"{step['request_id']} {step['operation']} {step['resource']}: {detail} | {dispatch} | "
            f"spent {step['spent']} | ledger read {ledger['document.read']}, "
            f"secret.list {ledger['secret.list']}, network.probe {ledger['network.probe']}"
        )
    lines += [
        "Explicit secret.list receipt names: FIXTURE_SIGNUP_KEY (no values).",
        "Explicit network.probe receipt: opened false, ports empty. No socket was opened.",
        "Denied proposals were not admitted and were not dispatched.",
        "Temporary service state was removed before this report.",
        "Limits: " + " ".join(report["limits"]),
    ]
    return "\n".join(lines)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid arguments. Use --help.\n")


def main(argv=None):
    parser = SafeParser(prog="signup_scope_boundary.py", description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print the safe stage report as JSON.")
    args = parser.parse_args(argv)
    try:
        report = run_demo()
    except Exception:
        print("Signup-scope demo failed; no report produced.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2) if args.json else transcript(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
