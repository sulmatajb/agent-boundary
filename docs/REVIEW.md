# Publication review packet

**Candidate:** Agent Boundary 0.1.0, an alpha reference implementation for
delegated tool authority, durable budget accounting, and retry-safe document
operations across a three-role agent workflow.

**Public repository:** [sulmatajb/agent-boundary](https://github.com/sulmatajb/agent-boundary).
The maintainer approved source publication and link sharing on October 14, 2026.
The reviewed implementation is commit
[`00ea334`](https://github.com/sulmatajb/agent-boundary/commit/00ea3347bffc6cd5dc0bdc167effe5a856aad618).
This packet preserves the local validation record; publication documentation is
updated separately. No package-registry upload or social-account posting is implied.

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
configured for Python 3.11–3.13; consult
[GitHub Actions](https://github.com/sulmatajb/agent-boundary/actions) for hosted results.

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

## Approved publication scope

The approved action is to publish the reviewed source in the named GitHub
repository, enable private vulnerability reporting, update repository/reporting
links, run hosted CI, and share the repository link. Private reporting is enabled;
see [the security policy](../SECURITY.md).
Publishing to a package registry or posting to a third-party social account is
outside this action and requires a specified destination.

Original project code uses the MIT license. The vendored Moby syscall profile
retains Apache-2.0 terms and upstream notices. See [release instructions](RELEASE.md)
and [the announcement text](ANNOUNCEMENT.md).
