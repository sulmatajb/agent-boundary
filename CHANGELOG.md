# Changelog

## 0.1.0 — prepared, unreleased

- Added authenticated HTTP delegation and admission with durable SQLite state,
  exact request binding, ancestor quotas, revocation, and a pending-action outbox.
- Added a separate document tool service with a transactional delivery ledger,
  bounded documents, and append receipts that do not disclose existing content.
- Added a researcher/writer/reviewer workflow with deterministic fixtures and
  a live Codex CLI 0.158.0 backend using existing ChatGPT sign-in.
- Added disposable Docker worker isolation with separate networks, secret mounts,
  state volumes, nonroot execution, and an explicit vendored seccomp profile.
- Added adversarial HTTP, concurrency, crash/recovery, seeded campaign, and
  adapter-limit checks, with live and deterministic evidence labeled separately.
- Repaired information disclosure in append results, unbounded audit responses,
  document accumulation, CLI output enforcement, recovery starvation, and the
  assumption that Docker's default seccomp configuration is always enabled.
- Recorded an incomplete live adversarial evaluation: automatic safety review
  blocked the campaign; zero attack cases are verified.
- Prepared source and wheel packaging, license notices, contributor guidance,
  and deterministic CI. No hosted CI or public release is claimed.

Pre-release database formats are disposable and have no migration support.
