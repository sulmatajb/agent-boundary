# Contributing

Start with [AGENTS.md](AGENTS.md) and [the protocol](docs/PROTOCOL.md).
Work on disposable local fixtures. Keep runtime dependencies in Python's
standard library and preserve Python 3.11 support. The live adapter is tested
against Codex CLI 0.158.0 on POSIX; changing its accepted version requires a fresh
review of tool-disabling flags and new live evidence.

## Local development

Use a POSIX host (Linux or macOS) for the process supervisor and test suite.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/release_check.py
```

Tests must remain runnable with `PYTHONPATH=src` and `unittest`. Deterministic
checks require no model access. See the [README](README.md) for separately
labeled live and Docker checks. Run tests relevant to a change, then the full
suite before proposing a security-sensitive change. The GitHub Actions
workflow is prepared locally; its hosted execution has not yet occurred.

Build artifacts using the [release instructions](docs/RELEASE.md). Keep generated
reports under the ignored `work/` directory until reviewed for evidence inclusion.
Never commit local databases, generated credentials, sign-in files, auth logs,
private model reasoning, virtual environments, or host-specific absolute paths.
Reports must clearly distinguish deterministic fixtures from live model calls.

## Changes and review

Explain the concrete failure or behavior change, the affected trust assumptions,
and the validation performed. Reproduce security defects with small disposable
fixtures and regression tests. For a new adapter, specify how it authenticates,
what it returns, when an effect is committed, and how repeated delivery is handled.
Do not infer exactly-once behavior for arbitrary external tools from this adapter.

No remote repository, push, package upload, release, or external announcement is
authorized by these instructions. The maintainer must approve the prepared
repository and release content before publication. Once a contribution channel
exists, submissions are accepted under the project's MIT license; preserve
third-party notices and identify any newly introduced third-party material.
