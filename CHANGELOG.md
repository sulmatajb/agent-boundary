# Changelog

## Unreleased

- Keep malformed successful tool receipts durably pending and charged so the
  same action can recover through the tool ledger without repeating its effect.
  Broker and supervisor now share the document receipt contract; existing
  malformed completed records are not migrated.
- Reject invalid workflow timeout and round limits before constructing a backend
  or starting disposable services, with the same CLI and direct API bounds.
- Add offline shared-parent budget and lost-acknowledgement examples using the
  production admission store; include the documented examples in source packages.
- Bound each local service readiness wait with one deadline and convert unreadable
  HTTP error bodies into controlled pending outcomes without refunding admission.
- Validate successful broker replies before the supervisor treats a document
  operation as complete. Malformed status or receipt fields now produce
  sanitized pending feedback instead of an exception or false completion;
  committed effects and charged admission remain unchanged.

## 0.1.0 — initial source publication

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
  and deterministic CI. See [release notes](docs/RELEASE.md) for publication scope
  and links to hosted validation; no package-registry release is configured.

Pre-release database formats are disposable and have no migration support.
