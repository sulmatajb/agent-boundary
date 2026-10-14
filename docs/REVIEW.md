# Publication review packet

**Candidate:** Agent Boundary 0.1.0, an alpha reference implementation for
delegated tool authority, durable budget accounting, and retry-safe document
operations across a three-role agent workflow.

**Proposed public repository:** `sulmatajb/agent-boundary`. No remote repository,
push, public release, package upload, or external announcement has been made.
Publication and sharing require the maintainer's explicit confirmation.

## Verified locally

| Check | Result |
| --- | --- |
| Automated suite | 93 tests passed; source hash in `evidence/tests.json` |
| Seeded HTTP campaign | 2,000 requests; 1,390 denials with zero effects; 198 replays |
| Container checks and deterministic workflow | 151 checks passed |
| Live cooperative workflow through containers | Six actual Codex turns; three roles; three admitted operations |
| Crash recovery | Actual SIGKILL before dispatch and after tool commit; no duplicate document effect |
| Packaging | Source distribution and wheel built; clean installed-wheel smoke |
| Release hygiene | Local links, license/profile provenance, and focused secret/path scan |

The live model path uses Codex CLI 0.158.0 with the operator's existing ChatGPT
sign-in. It requires no provider API key and uses the signed-in account's access
and usage limits. Python 3.11 and Docker were exercised locally. Hosted CI is
prepared for Python 3.11–3.13 but has not run on a remote repository.

## Findings repaired

The review caught append-only access leaking prior document content, oversized
audit responses, unbounded accumulated documents, output limits applied too
late, an unconfined Docker seccomp default, recovery starvation, and ambiguous
HTTP success replies being classified as denials. The implementation and
regression tests now address those cases. See [the findings](FINDINGS.md).

## Material limits

- The live adversarial-model campaign was blocked by automatic safety review.
  It has **zero verified attack cases**. Partial activity is not counted as
  evidence. Live cooperative success and deterministic attack tests do not fill
  that gap.
- Both container reports list six untested host alias/gateway routes because
  positive controls were unavailable. The passing checks do not establish those
  routes as blocked.
- This is not general AGI/ASI alignment, semantic-output verification, a proof
  of Python correctness, or a production-grade availability guarantee. The host,
  supervisor, broker, tool implementation, and storage remain trusted.
- Pending admissions stay charged and can finish after revocation. Some require
  trusted operator intervention. The adapter-specific deduplication guarantee
  does not automatically extend to arbitrary external tools.

## Proposed publication scope

After confirmation: create the approved public GitHub repository, push the
reviewed source, enable a private vulnerability-reporting channel where the
account supports it, update verified repository/reporting links, and run hosted
CI. Present the resulting repository link and approved announcement text.
Publishing to a package registry or posting to a third-party social account is
outside this proposed action and requires a specified destination.

Original project code uses the MIT license. The vendored Moby syscall profile
retains Apache-2.0 terms and upstream notices. See [release instructions](RELEASE.md)
and [the draft announcement](ANNOUNCEMENT.md).
