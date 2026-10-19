#!/usr/bin/env python3
"""Offline admission example using the production Store, not a tool dispatcher.

Run from the checkout: PYTHONPATH=src python3 examples/shared_budget.py [--json]
The database and generated fixture credentials are disposable and never printed.
"""

import argparse
import json
from pathlib import Path
import secrets
import sys
import tempfile

from agent_boundary.errors import BoundaryError
from agent_boundary.store import Store


SCOPES = [["document.append", "draft"]]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run_demo():
    """Return stable, public observations after deleting the temporary database."""
    with tempfile.TemporaryDirectory(prefix="boundary-shared-budget-") as directory:
        path = Path(directory) / "authority.sqlite"
        store = Store(path)
        actors = {}
        for role in ("supervisor", "left", "right"):
            credential = secrets.token_urlsafe(32)
            store.register(role, credential, admin=role == "supervisor")
            # Resolve the actor through the production credential lookup. These
            # are newly generated fixture credentials, never account credentials.
            actors[role] = store.authenticate(credential)["principal"]
        del credential

        parent = store.issue_root(actors["supervisor"], actors["supervisor"], SCOPES, 2)
        left = store.delegate(actors["supervisor"], parent, actors["left"], SCOPES, 2)
        right = store.delegate(actors["supervisor"], parent, actors["right"], SCOPES, 2)
        capabilities = {"parent": parent, "left": left, "right": right}

        def state():
            snapshot = store.snapshot(actors["supervisor"])
            return {
                "budgets": {
                    label: {key: snapshot["capabilities"][capability][key]
                            for key in ("limit", "spent")}
                    for label, capability in capabilities.items()
                },
                "admitted_actions": len(snapshot["actions"]),
                "pending_actions": sum(action["status"] == "pending"
                                       for action in snapshot["actions"]),
            }

        def denied(code, request):
            before = state()
            try:
                request()
            except BoundaryError as error:
                require(error.code == code, "Unexpected denial code.")
            else:
                raise RuntimeError("A request expected to be denied was admitted.")
            require(state() == before, "A denied request changed admission state.")
            return code

        steps = [{"step": "delegate_siblings", "outcome": "delegated", **state()}]
        require(steps[0]["admitted_actions"] == 0, "Delegation reserved admission budget.")

        first = store.reserve(actors["left"], left, "left-one", "document.append", "draft", "Left fixture.")
        require(first["status"] == "pending" and not first["replayed"], "First admission was not new and pending.")
        steps.append({"step": "left_first", "outcome": "admitted", "action": "first", **state()})

        second = store.reserve(actors["right"], right, "right-one", "document.append", "draft", "Right fixture.")
        require(second["status"] == "pending" and not second["replayed"], "Second admission was not new and pending.")
        require(second["action_id"] != first["action_id"], "Sibling admissions reused an action.")
        steps.append({"step": "right_first", "outcome": "admitted", "action": "second", **state()})
        require([state()["budgets"][name]["spent"] for name in capabilities] == [2, 1, 1],
                "Admissions did not charge the shared parent and each sibling.")

        code = denied("budget_exceeded", lambda: store.reserve(
            actors["left"], left, "left-two", "document.append", "draft", "Third fixture."))
        steps.append({"step": "third_distinct", "outcome": "denied", "code": code,
                      "limiting_capability": "parent", **state()})

        # A new Store instance reads the same committed ledger before retrying.
        store = Store(path)
        before = state()
        replay = store.reserve(actors["left"], left, "left-one", "document.append", "draft", "Left fixture.")
        require(replay["replayed"] and replay["action_id"] == first["action_id"],
                "Identical retry did not reuse the durable admission.")
        require(state() == before, "Replay charged budget again.")
        steps.append({"step": "identical_retry_after_reopen", "outcome": "replayed",
                      "action": "first", "same_action": True, "additional_charge": 0, **state()})

        code = denied("request_conflict", lambda: store.reserve(
            actors["left"], left, "left-one", "document.append", "draft", "Changed fixture."))
        steps.append({"step": "changed_payload_retry", "outcome": "denied", "code": code, **state()})
        final = state()
        require(final["admitted_actions"] == final["pending_actions"] == 2,
                "Admissions must remain pending because no tool was called.")
        report = {
            "schema_version": 1,
            "demonstration": "shared_parent_admission_budget",
            "mode": "offline_store_admission_only",
            "identity": "Production Store.authenticate with disposable generated fixture credentials.",
            "tool_calls": 0,
            "model_calls": 0,
            "scope": SCOPES,
            "steps": steps,
            "final": final,
            "limits": [
                "Direct Store calls, not an HTTP authentication or model evaluation.",
                "Admission is not a tool effect: both actions stay pending and charged.",
                "Sequential sibling requests demonstrate a shared ceiling, not fairness.",
                "Reopening Store checks persisted binding, not a crash-injection campaign.",
            ],
        }
    report["temporary_database_removed"] = not path.exists()
    require(report["temporary_database_removed"], "Temporary database was not removed.")
    return report


def transcript(report):
    lines = ["Shared parent budget — offline admission only", "No tool dispatch or model calls."]
    for step in report["steps"]:
        budget = ", ".join(f"{name} {row['spent']}/{row['limit']}"
                           for name, row in step["budgets"].items())
        detail = step.get("code", step["outcome"])
        if step["step"] == "identical_retry_after_reopen":
            detail += "; same action, no extra charge"
        lines.append(f"{step['step']}: {detail} | {budget}")
    lines.append("Final: 2 admitted actions remain pending and charged; no document was changed.")
    lines.append("Temporary database removed. Use --json for the observed counters and limits.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="shared_budget.py", description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print inspectable JSON instead of the transcript.")
    args = parser.parse_args(argv)
    try:
        report = run_demo()
    except Exception as error:
        # Avoid disclosing host paths or fixture credential data on unexpected I/O errors.
        print(f"Shared-budget example failed ({type(error).__name__}).", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False) if args.json else transcript(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
