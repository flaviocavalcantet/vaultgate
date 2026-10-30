# ADR 0003: Vault object encryption (VGE1: KMS envelope + chunked AES-256-GCM)

**Status:** Accepted

## Context

The gateway receives uploads of up to 5 GiB as a stream and must encrypt them before
they reach object storage, with memory that does not grow with file size (ADR 0001).
Downloads must be decrypted the same way. Requirements:

- a separate data key per file, wrapped by KMS, so revoking the KMS key or a single
  wrapped key makes data unreadable, and storage never sees plaintext;
- authenticated encryption that also detects reordering, truncation and extension of
  the stream, not just tampering inside a chunk;
- a push-based API: Tornado hands the gateway whatever bytes arrived, in arbitrary
  sizes, and the encryptor must emit ciphertext as it goes.

Off-the-shelf options (AWS Encryption SDK, Tink streaming AEAD) are pull-based and
synchronous, which fits a streaming Tornado handler poorly. Both implement the same
underlying construction, which is small enough to implement directly on a vetted AEAD.

## Decision

Objects use the **VGE1** format, the STREAM construction (Hoang, Reyhanitabar,
Rogaway, Vizár, 2015) over AES-256-GCM from `cryptography` (OpenSSL), as in Tink's
streaming AEAD:

```
object  = header || chunk_0 || ... || chunk_n
header  = "VGE1" || version=1 (1 B) || chunk_size (uint32 BE) || nonce_prefix (7 B random)
chunk_i = AES-256-GCM(key, nonce_i, plaintext_i, aad)        -- ciphertext || 16-byte tag
nonce_i = nonce_prefix || i (uint32 BE) || last (1 B: 0x01 for the final chunk, else 0x00)
aad     = header || file_id (16 B)
```

- Every chunk carries exactly `chunk_size` bytes of plaintext (default 64 KiB), except
  the final one: 0..`chunk_size` bytes, the only chunk with `last = 1`. Every object,
  including an empty one, ends with exactly one final chunk.
- **Keys:** KMS `GenerateDataKey` (AES_256) per file, with encryption context
  `{"file_id": <id>}`. The plaintext key lives only in memory during the transfer; the
  wrapped key is stored by the API with the file. Unwrapping requires the same context,
  so a wrapped key cannot be moved to another file, and every unwrap is attributable.
- **Nonces** never repeat: one data key encrypts one object, and within it the counter
  is unique per chunk. The random prefix also makes two encryptions of the same file
  under the same key (should one ever happen by bug) produce different nonces.

## What it detects

| Attack | Detected by |
|---|---|
| Changed byte in any chunk or tag | that chunk's GCM tag |
| Changed header (version, chunk size, prefix) | every chunk's AAD |
| Reordered or duplicated chunks | counter in the nonce |
| Truncation, including at a chunk boundary | no chunk with the `last` flag at the end |
| Bytes or chunks appended after the end | data after the final chunk is refused |
| Object or chunks moved to another file | file ID in the AAD; KMS encryption context |
| Wrong data key | every tag |

## Consequences

- Ciphertext size is exact and predictable: `16 + n + 16 * max(1, ceil(n / chunk_size))`
  bytes, so 0.024 % overhead at 64 KiB chunks, and multipart parts can be sized ahead.
- A decrypted chunk is authentic when it is returned, but the stream is only complete
  when `finalize()` succeeds. Downloads stream plaintext as they go, so a truncated
  object shows up as an aborted response, never as a short "successful" one: the
  gateway must abort the connection if finalization fails.
- The format is frozen by test vectors (`gateway/tests/vectors/vge1.json`) and checked
  against an independent reference decoder written from this document. A future change
  needs a new version byte and must keep reading VGE1.
- One process encrypts at roughly 500 MiB/s per stream on AES-NI hardware, well above
  what one connection carries.
