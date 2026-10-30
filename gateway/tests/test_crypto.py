import json
import os
import random
import uuid
from pathlib import Path

import pytest

from tests import vge1_reference
from vaultgate_gateway.crypto import (
    HEADER_SIZE,
    TAG_SIZE,
    DecryptionError,
    Decryptor,
    Encryptor,
    ciphertext_size,
)

KEY = os.urandom(32)
FILE_ID = uuid.uuid4()
CHUNK = 64  # small chunks so tests cover many boundaries quickly


def encrypt(plaintext: bytes, *, chunk_size: int = CHUNK, key=KEY, file_id=FILE_ID, pieces=None):
    enc = Encryptor(key, file_id, chunk_size=chunk_size)
    out = [enc.header()]
    for piece in pieces or [plaintext]:
        out.append(enc.update(piece))
    out.append(enc.finalize())
    return b"".join(out)


def decrypt(blob: bytes, *, key=KEY, file_id=FILE_ID, split: int | None = None) -> bytes:
    dec = Decryptor(key, file_id)
    out = []
    step = split or len(blob) or 1
    for i in range(0, len(blob), step):
        out.append(dec.update(blob[i : i + step]))
    out.append(dec.finalize())
    return b"".join(out)


def random_splits(data: bytes, rng: random.Random) -> list[bytes]:
    pieces, i = [], 0
    while i < len(data):
        n = rng.randint(0, 3 * CHUNK)
        pieces.append(data[i : i + n])
        i += n
    return pieces


# --- round trips ---------------------------------------------------------------


@pytest.mark.parametrize(
    "size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 3 * CHUNK + 7, 1000]
)
def test_round_trip_and_size(size: int) -> None:
    plaintext = os.urandom(size)
    blob = encrypt(plaintext)
    assert len(blob) == ciphertext_size(size, CHUNK)
    assert decrypt(blob) == plaintext
    assert vge1_reference.decode(KEY, FILE_ID, blob) == plaintext


def test_round_trip_with_arbitrary_piece_sizes() -> None:
    rng = random.Random(1234)
    for _ in range(50):
        plaintext = os.urandom(rng.randint(0, 20 * CHUNK))
        blob = encrypt(plaintext, pieces=random_splits(plaintext, rng))
        assert decrypt(blob, split=rng.randint(1, 3 * CHUNK)) == plaintext


def test_default_chunk_size_megabytes() -> None:
    plaintext = os.urandom(3 * 1024 * 1024 + 5)
    enc = Encryptor(KEY, FILE_ID)
    blob = enc.header() + enc.update(plaintext) + enc.finalize()
    assert decrypt(blob, split=100_000) == plaintext
    assert vge1_reference.decode(KEY, FILE_ID, blob) == plaintext


def test_encryptor_memory_is_bounded_by_one_chunk() -> None:
    enc = Encryptor(KEY, FILE_ID, chunk_size=CHUNK)
    enc.header()
    for _ in range(1000):
        enc.update(os.urandom(37))
        assert enc.buffered <= CHUNK


def test_same_plaintext_encrypts_differently_each_time() -> None:
    assert encrypt(b"same") != encrypt(b"same")  # fresh random nonce prefix


# --- tampering --------------------------------------------------------------------


def test_any_flipped_byte_is_detected() -> None:
    blob = bytearray(encrypt(os.urandom(3 * CHUNK + 10)))
    for i in range(len(blob)):
        tampered = bytearray(blob)
        tampered[i] ^= 0x01
        with pytest.raises(DecryptionError):
            decrypt(bytes(tampered))


def chunks_of(blob: bytes, chunk_size: int = CHUNK) -> tuple[bytes, list[bytes]]:
    header, body = blob[:HEADER_SIZE], blob[HEADER_SIZE:]
    sealed = chunk_size + TAG_SIZE
    return header, [body[i : i + sealed] for i in range(0, len(body), sealed)]


def test_reordered_chunks_are_detected() -> None:
    header, chunks = chunks_of(encrypt(os.urandom(3 * CHUNK + 10)))
    swapped = [chunks[1], chunks[0], *chunks[2:]]
    with pytest.raises(DecryptionError):
        decrypt(header + b"".join(swapped))


@pytest.mark.parametrize("keep", [0, 1, 2, 3])
def test_truncation_at_chunk_boundary_is_detected(keep: int) -> None:
    header, chunks = chunks_of(encrypt(os.urandom(3 * CHUNK + 10)))
    with pytest.raises(DecryptionError):
        decrypt(header + b"".join(chunks[:keep]))


def test_truncation_of_an_exact_multiple_is_detected() -> None:
    """With 2 full chunks, dropping the final one leaves a valid-looking full chunk."""
    header, chunks = chunks_of(encrypt(os.urandom(2 * CHUNK)))
    assert len(chunks) == 2
    with pytest.raises(DecryptionError):
        decrypt(header + chunks[0])


def test_cut_inside_a_chunk_is_detected() -> None:
    blob = encrypt(os.urandom(3 * CHUNK))
    for cut in (1, TAG_SIZE, CHUNK, len(blob) - HEADER_SIZE - 1):
        with pytest.raises(DecryptionError):
            decrypt(blob[: len(blob) - cut])


def test_data_after_the_final_chunk_is_detected() -> None:
    blob = encrypt(os.urandom(CHUNK + 5))
    with pytest.raises(DecryptionError):
        decrypt(blob + b"\x00")
    _, chunks = chunks_of(blob)
    with pytest.raises(DecryptionError):
        decrypt(blob + chunks[-1])  # replayed final chunk


def test_wrong_key_or_file_is_detected() -> None:
    blob = encrypt(b"secret contract")
    with pytest.raises(DecryptionError):
        decrypt(blob, key=os.urandom(32))
    with pytest.raises(DecryptionError):
        decrypt(blob, file_id=uuid.uuid4())


def test_chunks_cannot_be_spliced_between_objects() -> None:
    header_a, chunks_a = chunks_of(encrypt(os.urandom(2 * CHUNK + 1)))
    _, chunks_b = chunks_of(encrypt(os.urandom(2 * CHUNK + 1)))
    with pytest.raises(DecryptionError):
        decrypt(header_a + chunks_b[0] + b"".join(chunks_a[1:]))


@pytest.mark.parametrize(
    "header",
    [
        b"",
        b"VGE",
        b"XXXX" + bytes(12),
        b"VGE1\x02" + bytes(11),  # unknown version
        b"VGE1\x01" + (0).to_bytes(4, "big") + bytes(7),  # zero chunk size
    ],
)
def test_bad_headers_are_rejected(header: bytes) -> None:
    with pytest.raises(DecryptionError):
        decrypt(header + bytes(TAG_SIZE))


def test_misuse_is_refused() -> None:
    with pytest.raises(ValueError):
        Encryptor(b"short", FILE_ID)
    enc = Encryptor(KEY, FILE_ID)
    with pytest.raises(ValueError):
        enc.finalize()  # header never written
    enc.header()
    enc.finalize()
    with pytest.raises(ValueError):
        enc.update(b"more")
    with pytest.raises(ValueError):
        enc.finalize()


# --- fixed vectors ------------------------------------------------------------------


VECTORS = json.loads((Path(__file__).parent / "vectors" / "vge1.json").read_text())


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["name"])
def test_format_matches_committed_vectors(vector: dict) -> None:
    """Any change to the on-disk format breaks these: existing objects must stay readable."""
    key = bytes.fromhex(VECTORS["key"])
    file_id = uuid.UUID(VECTORS["file_id"])
    plaintext = bytes.fromhex(vector["plaintext"])
    expected = bytes.fromhex(vector["ciphertext"])
    enc = Encryptor(
        key,
        file_id,
        chunk_size=VECTORS["chunk_size"],
        nonce_prefix=bytes.fromhex(VECTORS["nonce_prefix"]),
    )
    assert enc.header() + enc.update(plaintext) + enc.finalize() == expected
    assert decrypt(expected, key=key, file_id=file_id) == plaintext
    assert vge1_reference.decode(key, file_id, expected) == plaintext
