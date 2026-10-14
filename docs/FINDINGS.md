# Adversarial findings and repairs

The integration was built and reviewed by twelve engineering agents, scheduled
in waves. The deployed example has three model roles. Those are separate counts.
The checks use disposable documents and services, never unrelated targets.

## Append-only authority accidentally conferred read access

**Trigger:** an append-only principal submits an empty append to a document
containing text it cannot read. The original adapter returned the entire updated
document, including the pre-existing text.

**Repair:** append results contain only the resource and version. Read results
contain content. The dispatcher validates the schema for the admitted operation
before recording success. A regression exercises an append-only capability on
the private canary document and checks both initial delivery and replay.

## Full audit responses grew beyond the transport ceiling

**Trigger:** completed reads retained document snapshots. Returning every stored
result in one audit response produced a 17,723,469-byte response after 90 reads of
a 64 KiB fixture, exceeding the 16 MiB client ceiling.

**Repair:** the HTTP audit performs bounded database queries, returns action
metadata without payloads or results, and supplies explicit pagination. The
same fixture's first response is approximately 23 KiB. Pending counts use SQL
aggregation. Tests traverse 237 actions across pages without loss or duplication.
Trusted local database inspection remains separate from the HTTP API.

## Document accumulation could poison response delivery

**Trigger:** the per-append size limit did not bound the accumulated document.
A sufficiently large document could commit an effect whose result exceeded the
response transport ceiling.

**Repair:** document content is limited to 64 KiB of UTF-8 bytes, checked before
mutation. Appends return a compact receipt. Oversized appends cause no tool
effect; the broker's prior admission stays charged. Tests include multibyte
Unicode at the limit. Operators must still provision storage for the durable
ledger and choose appropriate action budgets.

## Output size was checked after the subprocess finished

**Trigger:** a disposable fake CLI emitted more than the declared 2 MiB output
limit and then slept. The adapter waited until its timeout instead of enforcing
the size limit while reading.

**Repair:** the POSIX adapter streams output through a bounded collector and
terminates its private process group on failure or timeout. Anonymous prefilled
stdin avoids a blocking input write. Tests cover excess output and a descendant
that retains the output pipe. This is process cleanup, not an OS sandbox for an
untrusted CLI executable.

## Docker's default seccomp configuration was unconfined

**Trigger:** the host daemon reported an unconfined default, and a worker reported
`Seccomp: 0`, despite the other container restrictions being active.

**Repair:** Compose explicitly applies the vendored Moby syscall allowlist. Tests
require `Seccomp: 2` in each worker, with no effective capabilities and no new
privileges. The profile's source, hash, license, and notice are preserved in
[`security/README.md`](../security/README.md).

## Permanently rejected intents blocked later recovery work

**Trigger:** 100 pending appends against a full document occupied the entire
drain batch. Repeated drains never attempted a later pending source read.

**Repair:** a durable attempt counter schedules the least-attempted pending
intents first. Later deliverable work can progress, while failed intents retain
their original identity and budget charge. Concurrent dispatch still relies on
the tool's transactional deduplication; the counter is not a delivery lease.

## Additional strictness repairs

A final review found that malformed JSON in an HTTP 200 response inherited the
request parser's `400` status. The supervisor could classify a potentially
committed action as denied. Response decoding now reports an ambiguous `502`
failure, causing the workflow to stop with a pending outcome. Real HTTP
regressions corrupt the reply after an actual document commit using invalid
JSON, duplicate keys, and invalid UTF-8; each preserves the original single
charge and effect.

Transport tests caught the need to reject floating-point exponent overflow such
as `1e999`, which ordinary JSON parsing can convert to infinity. Internal calls
also normalize truncated HTTP responses into explicit ambiguous transport
failures. Redirects and environment proxies cannot redirect authenticated
internal requests. These cases have deterministic regression coverage.

## Interpretation

No tested identity, delegation, replay, revocation, or concurrent-budget attack
obtained an unauthorized document effect after repairs. Crash tests exercise
actual SIGKILL before delivery and after a committed effect with a lost reply.
They verify the two SQLite ledgers independently.

Passing these tests does not establish general ASI containment, semantic output
correctness, production denial-of-service resistance, arbitrary-tool exactly-once
execution, or a universal prompt-injection defense. See
[`PROTOCOL.md`](PROTOCOL.md) for the precise admission and trust assumptions.

This is an initial release candidate. Its disposable pre-release databases are
not a supported migration format; start with newly provisioned state.
