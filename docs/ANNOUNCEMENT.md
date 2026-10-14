# Agent Boundary announcement text

Agent Boundary is a small Python reference implementation for durable, bounded
tool authority in a three-role agent workflow. A researcher, writer, and
reviewer propose document actions; an authenticated broker enforces delegated
scope and shared ancestor budgets before a separate document service acts.

The implementation includes request/payload binding, durable pending actions,
crash recovery, and a tool-specific idempotency ledger. Deterministic attacks
exercise real HTTP services and process failures. Optional Docker checks test
worker network and filesystem restrictions. A live workflow uses Codex CLI
0.158.0 with the operator's ChatGPT sign-in and no provider API key; it consumes
account service access and usage limits.

The recorded seeded campaign contains 2,000 deterministic requests. The recorded
Docker workflow checks pass, and the live container run records six
model proposals and three admitted document operations. These are bounded
observations, not proof of general prompt-injection resistance, semantic
correctness, or AGI/ASI containment. The attempted live adversarial campaign
was blocked by automatic safety review and has zero verified attack cases;
partial progress is unverified and no passing live adversarial evaluation is claimed.

Project code is MIT licensed, with an Apache-2.0 Moby seccomp profile whose
provenance and notices are included. Twelve engineering agents contributed to
construction and review; the runtime has three model roles.

Repository: [sulmatajb/agent-boundary](https://github.com/sulmatajb/agent-boundary).
The reviewed implementation is
[`00ea334`](https://github.com/sulmatajb/agent-boundary/commit/00ea3347bffc6cd5dc0bdc167effe5a856aad618),
with 93 locally passing tests. Hosted validation is available in
[GitHub Actions](https://github.com/sulmatajb/agent-boundary/actions).
Use [private vulnerability reporting](https://github.com/sulmatajb/agent-boundary/security/advisories/new)
for security issues. This announcement text is included in the repository;
it has not been posted to a third-party social account.
