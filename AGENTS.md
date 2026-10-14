# Development rules

This is a security-sensitive reference integration, not an ASI containment claim.
Preserve authorization-before-dispatch, all-ancestor accounting, durable request
binding and the rule that ambiguous outcomes never refund admission budget.

Runtime must work without a provider API key. Live AI uses the separately
installed Codex CLI with the operator's own ChatGPT sign-in; deterministic tests
must not claim to be model evaluations. Do not read or copy account credentials.

Use disposable local fixtures for attacks. Never target unrelated services.
Never commit credentials, databases, local absolute paths, raw model reasoning,
or authentication logs. Tests must run with `PYTHONPATH=src` using unittest.

No publishing, pushing, remote repository creation, releases, or external sharing
until the human explicitly confirms the prepared repository and release content.
No additional agent spawning beyond the coordinator's explicit assignments.
