"""Streaming envelope encryption for vault objects (format "VGE1"; see ADR 0003).

Each file gets its own 256-bit data key from KMS. The file is encrypted with
AES-256-GCM in fixed-size chunks using the STREAM construction (Hoang, Reyhanitabar,
Rogaway, Vizár, 2015), the same design as Tink's streaming AEAD:

    object  = header || chunk_0 || chunk_1 || ... || chunk_n
    header  = b"VGE1" || version (1 byte) || chunk_size (uint32 BE) || nonce_prefix (7 bytes)
    chunk_i = AES-256-GCM(key, nonce_i, plaintext_i, aad) = ciphertext_i || tag (16 bytes)
    nonce_i = nonce_prefix || i (uint32 BE) || last (1 byte: 1 for the final chunk, else 0)
    aad     = header || file_id (16 bytes)

Every chunk holds exactly chunk_size bytes of plaintext except the final one, which
holds 0..chunk_size bytes and is the only one with last = 1. So an object always ends
with exactly one final chunk, and:

- tampering with any byte, including the header, fails that chunk's tag check;
- reordering chunks fails (the counter is in the nonce);
- truncating fails (no chunk with the last flag at the end), as does appending after it;
- moving an object to another file fails (file ID in the AAD, and KMS binds the
  wrapped key to the file ID through the encryption context).

A data key encrypts one object only, so nonces never repeat under a key. Both sides
are push-based: feed bytes as they arrive, get bytes out, with memory bounded by one
chunk. Decrypted chunks are authentic as soon as they are returned, but a stream is
only complete when finalize() succeeds: callers must treat output as untrusted-length
until then (e.g. a download that fails finalize must be aborted, not finished).
"""

import os
import struct
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"VGE1"
VERSION = 1
DEFAULT_CHUNK_SIZE = 64 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
KEY_SIZE = 32
TAG_SIZE = 16
NONCE_PREFIX_SIZE = 7
_HEADER = struct.Struct(">4sBI7s")
HEADER_SIZE = _HEADER.size  # 16
MAX_CHUNKS = 2**32


class DecryptionError(Exception):
    """The object is not authentic: wrong key or file, tampered, reordered or truncated."""


def _nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter >= MAX_CHUNKS:
        raise ValueError("object too large for this format")
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def _check_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError("data keys are 32 bytes (AES-256)")


class Encryptor:
    """Encrypts one object. Call header() once, update() for each piece of plaintext,
    then finalize() exactly once; concatenate everything they return, in order."""

    def __init__(
        self,
        key: bytes,
        file_id: uuid.UUID,
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        nonce_prefix: bytes | None = None,
    ) -> None:
        _check_key(key)
        if not 0 < chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError(f"chunk_size must be 1..{MAX_CHUNK_SIZE}")
        if nonce_prefix is None:
            nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
        if len(nonce_prefix) != NONCE_PREFIX_SIZE:
            raise ValueError("nonce_prefix is 7 bytes")
        self._aead = AESGCM(key)
        self._chunk_size = chunk_size
        self._prefix = nonce_prefix
        self._header = _HEADER.pack(MAGIC, VERSION, chunk_size, nonce_prefix)
        self._aad = self._header + file_id.bytes
        self._buffer = bytearray()
        self._counter = 0
        self._header_sent = False
        self._finished = False

    def header(self) -> bytes:
        self._header_sent = True
        return self._header

    def update(self, data: bytes) -> bytes:
        """Encrypt what is available. A full chunk is only emitted once more data
        follows it, because the final chunk (which may be full) needs the last flag."""
        if self._finished:
            raise ValueError("encryptor already finalized")
        self._buffer += data
        out = []
        view, offset, size = memoryview(self._buffer), 0, self._chunk_size
        while len(self._buffer) - offset > size:
            out.append(self._seal(view[offset : offset + size], last=False))
            offset += size
        view.release()
        del self._buffer[:offset]  # one move per call, not one per chunk
        return b"".join(out)

    def finalize(self) -> bytes:
        if self._finished:
            raise ValueError("encryptor already finalized")
        if not self._header_sent:
            raise ValueError("header() must be written before the chunks")
        self._finished = True
        final = self._seal(bytes(self._buffer), last=True)
        self._buffer.clear()
        return final

    def _seal(self, chunk: bytes | memoryview, *, last: bool) -> bytes:
        sealed = self._aead.encrypt(_nonce(self._prefix, self._counter, last), chunk, self._aad)
        self._counter += 1
        return sealed

    @property
    def buffered(self) -> int:
        """Plaintext bytes held back (at most one chunk plus the last update)."""
        return len(self._buffer)


class Decryptor:
    """Decrypts one object fed in arbitrary pieces. Raises DecryptionError on any
    authentication failure; finalize() raises if the object is truncated."""

    def __init__(self, key: bytes, file_id: uuid.UUID) -> None:
        _check_key(key)
        self._aead = AESGCM(key)
        self._file_id = file_id
        self._buffer = bytearray()
        self._chunk_size: int | None = None
        self._prefix = b""
        self._aad = b""
        self._counter = 0
        self._finished = False

    def update(self, data: bytes) -> bytes:
        if self._finished:
            raise DecryptionError("data after the final chunk")
        self._buffer += data
        if self._chunk_size is None:
            if len(self._buffer) < HEADER_SIZE:
                return b""
            self._read_header(bytes(self._buffer[:HEADER_SIZE]))
            del self._buffer[:HEADER_SIZE]
        sealed_size = self._chunk_size + TAG_SIZE
        out = []
        view, offset = memoryview(self._buffer), 0
        # Hold back the last complete chunk: until more data arrives it may be final.
        while len(self._buffer) - offset > sealed_size:
            out.append(self._open(view[offset : offset + sealed_size], last=False))
            offset += sealed_size
        view.release()
        del self._buffer[:offset]
        return b"".join(out)

    def finalize(self) -> bytes:
        if self._finished:
            raise DecryptionError("decryptor already finalized")
        if self._chunk_size is None:
            raise DecryptionError("truncated: no header")
        if not TAG_SIZE <= len(self._buffer) <= self._chunk_size + TAG_SIZE:
            raise DecryptionError("truncated: no final chunk")
        self._finished = True
        plaintext = self._open(bytes(self._buffer), last=True)
        self._buffer.clear()
        return plaintext

    def _read_header(self, header: bytes) -> None:
        magic, version, chunk_size, prefix = _HEADER.unpack(header)
        if magic != MAGIC or version != VERSION:
            raise DecryptionError("not a VGE1 object")
        if not 0 < chunk_size <= MAX_CHUNK_SIZE:
            raise DecryptionError("invalid chunk size")
        self._chunk_size = chunk_size
        self._prefix = prefix
        self._aad = header + self._file_id.bytes

    def _open(self, sealed: bytes | memoryview, *, last: bool) -> bytes:
        try:
            plaintext = self._aead.decrypt(
                _nonce(self._prefix, self._counter, last), sealed, self._aad
            )
        except (InvalidTag, ValueError):
            raise DecryptionError("chunk failed authentication") from None
        self._counter += 1
        return plaintext


def ciphertext_size(plaintext_size: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
    """Exact size of the encrypted object for a given plaintext size."""
    # Full chunks, with the last one carrying the final flag; an empty object still has
    # one (empty) final chunk.
    chunks = max(1, -(-plaintext_size // chunk_size))
    return HEADER_SIZE + plaintext_size + chunks * TAG_SIZE
