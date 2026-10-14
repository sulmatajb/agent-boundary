# Security policy

Agent Boundary 0.1.0 is an alpha reference implementation, not a production security
product. The trust boundary and known limitations are documented in
[the protocol](docs/PROTOCOL.md), [findings](docs/FINDINGS.md), and
[container notes](docs/containers.md). Pre-release databases have no supported
migration format; provision fresh state.

## Report an issue

GitHub private vulnerability reporting is enabled for this repository. Submit a
minimal sanitized reproducer through
[Report a vulnerability](https://github.com/sulmatajb/agent-boundary/security/advisories/new).
Do not post credentials or exploitable details in a public issue. Do not assume
a response-time or remediation SLA.

A useful report identifies the affected revision, Python and operating-system
versions, violated invariant, steps against a disposable fixture, expected and
observed effects, and whether the broker and tool ledgers disagree. Never send
sign-in files, bearer tokens, real documents, raw model reasoning, or account
logs. Test only systems and fixtures you own or are explicitly authorized to use.

## Security expectations

Keep the host supervisor, broker, document service, Docker daemon, and their
credentials trusted. Use loopback or the described internal container networks;
this HTTP reference deployment is not configured for public exposure. Model
proposals must never select credentials, destinations, principals, or request
IDs, and workers must not receive the Docker socket or host login state.

Preserve authorization before dispatch, all-ancestor accounting, exact replay
binding, operation-specific result validation, and no refund after ambiguous
outcomes. Revocation does not cancel an already admitted action. Review any
new tool's idempotency and information-return behavior independently.

The focused release scanner catches common accidental secrets and local paths;
it is not a complete secret detector or a security audit. Passing deterministic
or live tests does not establish general AI containment.
