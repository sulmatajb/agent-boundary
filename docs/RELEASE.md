# Preparing a release

Version 0.1.0 is an alpha reference implementation published at
[sulmatajb/agent-boundary](https://github.com/sulmatajb/agent-boundary) after the
maintainer's confirmation on October 14, 2026. Private vulnerability reporting
is enabled. No package-registry publication is configured. The checklist below
also applies to future release candidates.

## Validate the candidate

From the repository root, with Python 3.11 or later on Linux or macOS:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/release_check.py
python3 -m venv work/build-env
work/build-env/bin/python -m pip install build
work/build-env/bin/python -m build --outdir work/dist
```

The build backend requires setuptools 77 or later for SPDX license metadata.
Runtime installation has no third-party Python dependencies. Building in a
fresh isolated environment may download build tools; that is separate from
runtime requirements.

The default `build` command creates the source distribution and builds the
wheel from that distribution. Inspect both archives. The sdist must include
source, tests, scripts, docs, evidence, container configuration, and the
unmodified profile with its upstream license and notice. The wheel must include
the Python package, console script metadata, project license, and third-party
license/notice texts. Its installation does not include the source-only Docker
and campaign scripts; use a checkout or extracted sdist for those commands.

Install the exact candidate wheel into a new environment, then run outside the
source tree with `PYTHONPATH` unset:

```sh
python3 -m venv work/wheel-env
work/wheel-env/bin/python -m pip install --no-deps work/dist/agent_boundary-0.1.0-py3-none-any.whl
AB_CHECKOUT="$PWD"
AB_SMOKE_DIR="$(mktemp -d)"
(
  cd "$AB_SMOKE_DIR"
  unset PYTHONPATH
  "$AB_CHECKOUT/work/wheel-env/bin/agent-boundary" --help
  "$AB_CHECKOUT/work/wheel-env/bin/agent-boundary" --backend deterministic
  "$AB_CHECKOUT/work/wheel-env/bin/python" -m agent_boundary.server --help
  "$AB_CHECKOUT/work/wheel-env/bin/python" -m agent_boundary.tool_service --help
)
rmdir "$AB_SMOKE_DIR"
```

Reproduce optional live and Docker checks using [the README](../README.md).
Keep the signed-in Codex CLI on the trusted host. The live adapter requires a
POSIX host and exactly CLI 0.158.0, consumes the account's usage limits, and does
not require a provider API key. Do not add account credentials to CI.

## Before requesting publication approval

1. Record the exact candidate revision, local test count, artifact hashes, and
   separately labeled deterministic, Docker, and live evidence. Recheck results
   after changes; do not imply that a previously recorded run covers new code.
2. Review security claims against [the protocol](PROTOCOL.md) and
   [findings](FINDINGS.md). Confirm all published evidence is sanitized.
3. Preserve the Moby profile's source, SHA-256, Apache-2.0 license, and notice.
   Original project code remains MIT licensed.
4. Confirm the intended public owner/name, project description, release notes,
   and optional package-registry destination with the maintainer. Package-name
   availability and remote permissions have not been established by this build.
5. Establish a private security-reporting channel and update [SECURITY.md](../SECURITY.md).
6. Review [the draft announcement](ANNOUNCEMENT.md) and obtain the human's explicit
   confirmation before remote creation, pushing, uploading, releasing, or sharing.

The prepared CI runs deterministic tests, a focused source check, builds, and a
clean wheel smoke on Python 3.11–3.13. GitHub Actions are pinned to verified
upstream commits. Hosted results are available in
[GitHub Actions](https://github.com/sulmatajb/agent-boundary/actions).
The normal CI workflow contains no release, upload, Docker, or signed-in model
step. A separate manually dispatched Docker workflow runs disposable deterministic
container checks on a hosted runner. It also needs no model authentication and
records its results separately from the normal test matrix.

The attempted live adversarial campaign was blocked by automatic safety review:
zero attack cases are verified and partial progress is unverified. Preserve that
evidence gap in release notes; benign live workflow success and deterministic
attack tests must not be described as a passed live adversarial campaign.

## After explicit approval

Create only the approved remote, publish the reviewed candidate, and wait for
hosted CI before describing it as passing. Add verified repository links and
reporting details to package metadata and docs. If releasing artifacts, build
from the approved revision, retain hashes and provenance, and publish only to
the approved destination. Tag and release notes must refer to that revision.
Any material change after review requires fresh validation of the affected work.
