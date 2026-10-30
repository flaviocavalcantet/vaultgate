"""Independent VGE1 decoder written from the format in ADR 0003, for tests only.

It shares no code with vaultgate_gateway.crypto, so the tests check the implementation
against the documented format rather than against itself.
"""

import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decode(key: bytes, file_id: uuid.UUID, blob: bytes) -> bytes:
    header, body = blob[:16], blob[16:]
    assert header[:4] == b"VGE1" and header[4] == 1
    chunk_size = int.from_bytes(header[5:9], "big")
    prefix = header[9:16]
    aad = header + file_id.bytes
    sealed = chunk_size + 16
    pieces = [body[i : i + sealed] for i in range(0, len(body), sealed)] or [b""]
    out = []
    for i, piece in enumerate(pieces):
        last = i == len(pieces) - 1
        nonce = prefix + i.to_bytes(4, "big") + bytes([1 if last else 0])
        out.append(AESGCM(key).decrypt(nonce, piece, aad))
    return b"".join(out)
