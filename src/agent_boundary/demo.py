"""Disposable three-agent HTTP workflow; deterministic by default."""
from __future__ import annotations

import argparse
import json

from .codex_adapter import CodexBackend, DeterministicBackend, run_workflow, validate_workflow_options
from .errors import BoundaryError
from .runtime import LocalSystem


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("deterministic", "codex"), default="deterministic",
                        help="deterministic is an integration fixture; codex uses existing ChatGPT sign-in")
    parser.add_argument("--timeout", type=float, default=90, help="Codex seconds per proposal (max 300)")
    parser.add_argument("--workflow-timeout", type=float, default=600, help="Workflow seconds (max 1800)")
    parser.add_argument("--max-rounds", type=int, default=4, help="Proposal rounds per role (2..10)")
    args = parser.parse_args(argv)
    try:
        validate_workflow_options(args.max_rounds, args.workflow_timeout)
        backend = CodexBackend(timeout=args.timeout) if args.backend == "codex" else DeterministicBackend()
        with LocalSystem() as system:
            report = run_workflow(system, backend, max_rounds=args.max_rounds,
                                  workflow_timeout=args.workflow_timeout)
    except BoundaryError as error:
        print(json.dumps({"backend": args.backend, "completed": False, "error": error.code}))
        return 1
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
