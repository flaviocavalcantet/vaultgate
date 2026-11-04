# ADR 0007: Audit log (append-only, hash-chained)

**Status:** Accepted

## Context

A vault has to answer, after the fact, who did what to which file: who uploaded it,
who downloaded it, who shared it with whom, who released it from quarantine, who
changed a policy, and who tried and was refused. Logs help, but they are spread over
services, rotate, and are written by the same processes an attacker would control. The
record must not be quietly editable, also by someone with access to the database.

Three levels were weighed:

1. **A database guard:** an append-only table. Stops the application, and an attacker
   who controls it, from changing history; not someone with full database rights.
2. **A hash chain on top:** changes stay possible for a database administrator, but
   they can no longer go unnoticed.
3. **An external copy on top:** every event also written to write-once storage (S3
   Object Lock), so a second record survives a full takeover of the database host.

## Decision

**Level 2, with room for level 3 later (M9/M10).**

- **What:** security events only, not every read. Uploads, downloads (issued and
  started), scan verdicts and abandoned scans, quarantine releases and rescans, shares
  (created, codes sent, verifications, downloads, revoked), policy changes (with the
  policy as it stood), first sign-ins, and every refusal: denied by policy, rejected
  intents, downloads or shares refused by the scan, failed verifications.
- **Shape:** who (a user, an outside recipient, the gateway, the scanner, the system),
  the action, the outcome, the target, the client address, the request ID (as in the
  logs and, with M6's tracing, the traces) and details. No foreign keys: the record
  outlives what it names. No file content and no PII found by the scanner; recipients'
  addresses are kept with their shares, because the log must say who received a file.
- **Atomic:** an event is written in the transaction of the action it records, so both
  are stored or neither. A refusal rolls its attempt back, then records the refusal in
  a transaction of its own.
- **Append-only:** a trigger refuses `UPDATE`, `DELETE` and `TRUNCATE` for every role,
  the table's owner included.
- **Hash chain:** each event stores a SHA-256 over its fields and the previous event's
  hash. Writers take a transaction-level advisory lock, so events chain one at a time
  in commit order. `POST /admin/audit/verify` walks the chain and reports the first
  event that was changed or whose predecessor was removed.
- **Anchor:** the API logs the head of the chain every few minutes. The newest events
  are the one place a chain can be rewritten consistently (recompute from the edit to
  the end); a head that disagrees with the logged ones shows it.

## Consequences

- Changing history now takes switching off the trigger, which needs the table owner's
  rights, and then leaves a broken chain or a head the logs contradict.
- Audited writes are serialized by the advisory lock. That is a few milliseconds per
  event, far from a limit at VaultGate's volume; M8's load tests will measure it.
- Verification reads the whole table. Batched, it stays in constant memory; a large
  log takes a while, which is fine for an admin action. Checkpointed verification can
  come if needed.
- Someone with superuser rights and access to the logs could still rewrite both.
  Write-once external storage (level 3) and signing the anchors with keys from the
  M9 PKI are the next steps, when key and trust management arrive.
- The log grows without bound. Retention (export, then archive) is left to an
  operational decision; nothing in the design prevents it.
