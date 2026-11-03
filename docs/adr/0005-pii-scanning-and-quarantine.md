# ADR 0005: PII scanning and quarantine (fail closed)

**Status:** Accepted

## Context

Files in the vault can hold personal data that must not leave without a decision:
payment card numbers and Brazilian CPF numbers first, more kinds later. Every upload
has to be checked, and a file must not be downloadable just because the check has not
happened, could not finish, or could not read the file.

The check reads every byte of potentially large, untrusted documents (Office files,
PDFs, archives), so it cannot run inside the API's or the gateway's request path. The
stored objects are encrypted (ADR 0003), and the decrypted content must not end up on
disk or in logs along the way.

## Decision

**The API owns the scan state; a queue delivers it; a separate Go worker reads files.**

- A completed upload gets a **scan request**: `scan_status = pending` and a fresh
  `scan_id`, sent to an SQS queue. The database is the record of what still needs
  scanning; the queue only delivers it. A resender sends a request again when it never
  reached the queue or got no result in time, and marks the file `unscannable` after
  the last attempt. Messages the worker cannot handle move to a dead-letter queue.
- The **worker** fetches the scan job (object key, wrapped data key) from internal
  routes that take their own secret, has KMS unwrap the key for that file only, and
  reads the object from S3 with range requests, decrypting chunks in memory as the
  text extraction needs them (`vge1.ReaderAt`; plaintext never touches disk). It
  reports only **kinds and counts**; matched values and positions never leave it.
- Results are bound to the `scan_id`, so a late result for an older request cannot
  overwrite a newer one, and a repeated result is accepted only if it is identical.

**Verdicts** are `pending`, `clean`, `quarantined` and `unscannable`, worked out when
read from the findings and `VAULTGATE_QUARANTINE_KINDS` (default `payment_card,br_cpf`;
`email` is only recorded). Changing the setting applies to files already scanned,
without a rescan.

**Quarantine is fail closed: only a clean file can be downloaded.** Pending,
quarantined and unscannable files are refused alike. This holds for every download for
now; M5 will decide whether some kinds only block sharing. The API checks it when it
issues a download intent and again when the gateway consumes the intent, so a verdict
that changes in between (a rescan, new quarantine kinds) still takes effect. A refusal
at consume leaves the intent unspent, as for access policies (ADR 0004).

**What is unscannable:** an encrypted, damaged or truncated document; one nested,
sized or expanding past the extraction limits; a stored object that fails
authentication or does not match its recorded size; and a scan that got no result
after the last resend. Failures that say nothing about the file (the API, KMS or S3
unreachable, a timeout) are retried instead, and the worker keeps the underlying read
error so the extraction cannot mistake a failed read for a damaged document.

**Admins decide on exceptions.** An admin can:

- **release** a quarantined or unscannable file, with a required reason. The owner may
  then download it, and the verdict and findings stay visible. The release records who
  gave it and when. It covers the current scan only.
- **rescan** a file: a new request with a new `scan_id`, findings dropped, any release
  ended. Useful when the scanner learns a format or a failure was transient.
- **list** files by verdict, across all users, to work through the quarantine.

## Consequences

- No file is downloadable before its scan. Uploads are usable after a few seconds for
  small files, longer for large ones; a stopped worker delays downloads but loses
  nothing, because requests wait in the queue and the API resends them.
- Files uploaded before scanning existed are scanned on upgrade and are not
  downloadable until then.
- A file the scanner cannot read stays blocked until an admin releases it. That costs
  admin time for encrypted or exotic documents, and is the point: such files are
  exactly the ones nobody has checked.
- Releases and rescans are logged with the admin and the reason, and counted. The
  append-only audit log (M6) will record them too.
- Detectors without a checksum (emails) would make blocking noisy, so they are only
  recorded. A kind is added to the quarantine kinds only once it has a check that keeps
  false positives low.
