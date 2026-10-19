#!/usr/bin/env python3
"""Disposable lost-ack walkthrough with the real Store and document ToolStore.

PYTHONPATH=src python3 examples/lost_ack_recovery.py [--json]
No services, model calls, account data, or caller-selected database paths.
"""

import argparse
import json
from pathlib import Path
import secrets
import sys
import tempfile

from agent_boundary.errors import BoundaryError
from agent_boundary.store import Store
from agent_boundary.tool_service import ToolStore


SCOPES = [["document.append", "draft"]]
PUBLIC_TEXT = "Synthetic recovery note.\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run_demo():
    """Return a safe projection only after both disposable databases are removed."""
    with tempfile.TemporaryDirectory(prefix="boundary-lost-ack-") as directory:
        authority_path = Path(directory) / "authority.sqlite"
        document_path = Path(directory) / "documents.sqlite"
        store, tool = Store(authority_path), ToolStore(document_path)
        actors = {}
        for role in ("supervisor", "writer"):
            credential = secrets.token_urlsafe(32)
            store.register(role, credential, admin=role == "supervisor")
            actors[role] = store.authenticate(credential)["principal"]
        del credential
        parent = store.issue_root(actors["supervisor"], actors["supervisor"], SCOPES, 2)
        child = store.delegate(actors["supervisor"], parent, actors["writer"], SCOPES, 2)
        capabilities = {"parent": parent, "writer": child}
        deliveries = 0

        def state():
            authority, documents = store.snapshot(actors["supervisor"]), tool.snapshot()
            draft = documents["documents"]["draft"]
            # Never emit a raw snapshot or unexpected document content.
            require(draft["content"] in ("", PUBLIC_TEXT), "Unexpected fixture document content.")
            return {
                "budgets": {
                    label: {key: authority["capabilities"][capability][key]
                            for key in ("limit", "spent", "revoked")}
                    for label, capability in capabilities.items()
                },
                "admitted_actions": len(authority["actions"]),
                "pending_actions": sum(row["status"] == "pending" for row in authority["actions"]),
                "completed_actions": sum(row["status"] == "completed" for row in authority["actions"]),
                "direct_tool_apply_calls": deliveries,
                "tool_ledger_entries": len(documents["operations"]),
                "draft": {"content": draft["content"], "version": draft["version"]},
            }

        def denied(code, request):
            before = state()
            try:
                request()
            except BoundaryError as error:
                require(error.code == code, "Unexpected denial code.")
            else:
                raise RuntimeError("A request expected to be denied was admitted.")
            require(state() == before, "Denied request changed fixture state.")
            return code

        steps = [{"step": "delegated", "outcome": "no_charge", **state()}]
        require(all(row["spent"] == 0 for row in state()["budgets"].values()), "Delegation charged quota.")
        admitted = store.reserve(actors["writer"], child, "append-note", "document.append", "draft", PUBLIC_TEXT)
        require(not admitted["replayed"] and admitted["status"] == "pending", "Expected a new pending admission.")
        require(all(row["spent"] == 1 for row in state()["budgets"].values()), "Admission did not charge the lineage.")
        steps.append({"step": "admitted", "outcome": "charged_pending", "action": "append_note", **state()})

        receipt = tool.apply(admitted["action_id"], "document.append", "draft", PUBLIC_TEXT)
        deliveries += 1
        require(receipt == {"resource": "draft", "version": 1}, "Unexpected append receipt.")
        # Deliberately withhold Store.complete: model a lost acknowledgment after
        # the tool commit. This is not a killed process or a dropped HTTP packet.
        committed = state()
        require(committed["pending_actions"] == committed["tool_ledger_entries"] == 1,
                "Expected one pending admission and one committed tool entry.")
        require(committed["draft"] == {"content": PUBLIC_TEXT, "version": 1}, "Expected one document effect.")
        steps.append({"step": "tool_committed_ack_withheld", "outcome": "broker_still_pending", "receipt": receipt, **committed})

        store, tool = Store(authority_path), ToolStore(document_path)
        require(state() == committed, "Reopened stores did not retain committed state.")
        steps.append({"step": "stores_reopened", "outcome": "persisted_state_retained", **state()})
        store.revoke(actors["supervisor"], parent)
        steps.append({"step": "parent_revoked", "outcome": "new_admission_blocked", **state()})
        code = denied("revoked", lambda: store.reserve(
            actors["writer"], child, "new-note", "document.append", "draft", "Another synthetic note.\n"))
        steps.append({"step": "new_request", "outcome": "denied", "code": code, **state()})

        before_retry = state()
        replay = store.reserve(actors["writer"], child, "append-note", "document.append", "draft", PUBLIC_TEXT)
        require(replay["replayed"] and replay["action_id"] == admitted["action_id"] and replay["status"] == "pending",
                "Identical retry did not recover the admitted action.")
        require(state() == before_retry, "Admission replay changed counters or effects.")
        steps.append({"step": "identical_request", "outcome": "admission_replayed", "action": "append_note",
                      "same_action": True, "additional_charge": 0, **state()})
        recovered = tool.apply(replay["action_id"], "document.append", "draft", PUBLIC_TEXT)
        deliveries += 1
        require(recovered == receipt, "Tool redelivery did not return the saved receipt.")
        require(state() == {**before_retry, "direct_tool_apply_calls": 2}, "Tool redelivery repeated an effect.")
        steps.append({"step": "tool_redelivery", "outcome": "saved_receipt_returned", "same_receipt": True,
                      "receipt": recovered, **state()})
        store.complete(replay["action_id"], recovered)
        completed = store.reserve(actors["writer"], child, "append-note", "document.append", "draft", PUBLIC_TEXT)
        require(completed["status"] == "completed" and completed["result"] == receipt,
                "Completion did not persist the saved receipt.")
        steps.append({"step": "broker_completed", "outcome": "completed_after_revocation", **state()})

        code = denied("request_conflict", lambda: store.reserve(
            actors["writer"], child, "append-note", "document.append", "draft", "Changed synthetic note.\n"))
        steps.append({"step": "changed_payload", "outcome": "denied", "code": code, **state()})
        final = state()
        require(final["admitted_actions"] == final["completed_actions"] == final["tool_ledger_entries"] == 1
                and final["pending_actions"] == 0 and final["draft"]["version"] == 1,
                "Expected one completed admission and exactly one document effect.")
        require(all(row["spent"] == 1 for row in final["budgets"].values()), "Recovery changed charged quota.")
        report = {
            "schema_version": 1,
            "demonstration": "lost_ack_recovery_after_revocation",
            "mode": "offline_direct_store_and_document_adapter",
            "identity": "Store.authenticate with newly generated disposable fixture credentials.",
            "model_calls": 0,
            "http_requests": 0,
            "scope": SCOPES,
            "steps": steps,
            "final": final,
            "limits": [
                "Acknowledgment loss is modeled by withholding Store.complete after ToolStore.apply commits.",
                "Reopening SQLite-backed stores checks persistence; no process was crashed and no HTTP packet was dropped.",
                "Direct trusted-local Store/ToolStore calls do not test HTTP authentication or concurrent dispatch.",
                "Revocation stops new admission; it does not cancel an already charged pending action.",
                "One-effect replay applies to this document adapter, not arbitrary external tools.",
            ],
        }
    report["temporary_databases_removed"] = not Path(directory).exists()
    require(report["temporary_databases_removed"], "Disposable fixture cleanup failed.")
    return report


def transcript(report):
    lines = ["Lost acknowledgment recovery — disposable document adapter",
             "Modeled lost acknowledgment, not a process crash. No HTTP or model calls."]
    for step in report["steps"]:
        budgets = ", ".join(f"{label} {row['spent']}/{row['limit']}"
                            + (" revoked" if row["revoked"] else "")
                            for label, row in step["budgets"].items())
        lines.append(f"{step['step']}: {step.get('code', step['outcome'])} | {budgets} | "
                     f"pending {step['pending_actions']}, completed {step['completed_actions']}, "
                     f"tool deliveries {step['direct_tool_apply_calls']}, ledger {step['tool_ledger_entries']}, "
                     f"draft version {step['draft']['version']}")
    lines += ["Final: one completed action, one document effect, no extra admission charge.",
              "Revocation blocked the new request; the earlier admitted request completed.",
              "Both temporary databases removed before this report was printed.",
              "Limits: " + " ".join(report["limits"])]
    return "\n".join(lines)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid arguments. Use --help.\n")


def main(argv=None):
    parser = SafeParser(prog="lost_ack_recovery.py", description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print the stable, safe stage report as JSON.")
    args = parser.parse_args(argv)
    try:
        report = run_demo()
    except Exception:
        print("Recovery example failed; no report produced.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2) if args.json else transcript(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
