"""TPM attestation (vaultgate_api.tpm, M11): the TPM's structures, read from real swtpm
output and from a fake TPM made here; and MakeCredential, opened as a TPM would."""

import base64
import hashlib
import hmac
import json
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from vaultgate_api import tpm

SWTPM = json.loads((Path(__file__).parent / "data" / "swtpm.json").read_text())
AK_ATTRS = (
    tpm.FIXED_TPM | tpm.FIXED_PARENT | tpm.SENSITIVE_DATA_ORIGIN | 0x40 | tpm.RESTRICTED | tpm.SIGN
)
KEY_ATTRS = tpm.FIXED_TPM | tpm.FIXED_PARENT | tpm.SENSITIVE_DATA_ORIGIN | 0x40 | tpm.SIGN


def tpm2b(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


class FakeTPM:
    """What a TPM would produce: an RSA EK, an RSA AK, an ECC P-256 key, the AK's
    certification of it, a CSR it signs; and ActivateCredential, with the EK's key."""

    def __init__(self, ak_attrs: int = AK_ATTRS, key_attrs: int = KEY_ATTRS) -> None:
        self.ek = rsa.generate_private_key(65537, 2048)
        self.ak = rsa.generate_private_key(65537, 2048)
        self.key = ec.generate_private_key(ec.SECP256R1())
        n = self.ak.public_key().public_numbers().n.to_bytes(256, "big")
        self.ak_area = (
            struct.pack(">HHI", tpm.ALG_RSA, tpm.ALG_SHA256, ak_attrs) + tpm2b(b"")
            + struct.pack(">HHHH", tpm.ALG_NULL, 0x0014, tpm.ALG_SHA256, 2048)
            + struct.pack(">I", 0) + tpm2b(n)
        )  # fmt: skip
        nums = self.key.public_key().public_numbers()
        self.key_area = (
            struct.pack(">HHI", tpm.ALG_ECC, tpm.ALG_SHA256, key_attrs) + tpm2b(b"")
            + struct.pack(">HHHHH", tpm.ALG_NULL, 0x0018, tpm.ALG_SHA256, tpm.ECC_NIST_P256,
                          tpm.ALG_NULL)
            + tpm2b(nums.x.to_bytes(32, "big")) + tpm2b(nums.y.to_bytes(32, "big"))
        )  # fmt: skip
        self.ak_name = b"\x00\x0b" + hashlib.sha256(self.ak_area).digest()
        self.key_name = b"\x00\x0b" + hashlib.sha256(self.key_area).digest()

    def certify(self, name: bytes | None = None) -> tuple[bytes, bytes]:
        attest = (
            struct.pack(">IH", tpm.ATTEST_MAGIC, tpm.ST_ATTEST_CERTIFY) + tpm2b(self.ak_name)
            + tpm2b(b"") + b"\0" * 17 + b"\0" * 8
            + tpm2b(name or self.key_name) + tpm2b(b"\x00\x0b" + b"q" * 32)
        )  # fmt: skip
        return attest, self.ak.sign(attest, padding.PKCS1v15(), hashes.SHA256())

    def csr(self, key=None) -> str:
        built = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
        return (
            built.sign(key or self.key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode()
        )

    def body(self, **changes) -> dict:
        attest, signature = self.certify()
        b64 = lambda data: base64.b64encode(data).decode()
        return {
            "ek": self.ek.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode(),
            "ak": b64(tpm2b(self.ak_area)),
            "key": b64(tpm2b(self.key_area)),
            "attest": b64(attest),
            "signature": b64(signature),
            "csr": self.csr(),
        } | changes

    def ek_fingerprint(self) -> str:
        from vaultgate_api import nodes

        return nodes.fingerprint(self.ek.public_key())

    def activate(self, credential: bytes, ak_name: bytes | None = None) -> bytes:
        """TPM2_ActivateCredential: the secret, if the credential is for this EK and AK."""
        magic, version = struct.unpack(">II", credential[:8])
        assert (magic, version) == (tpm.CREDENTIAL_MAGIC, tpm.CREDENTIAL_VERSION)
        rest = credential[8:]
        id_len = struct.unpack(">H", rest[:2])[0]
        id_object, rest = rest[2 : 2 + id_len], rest[2 + id_len :]
        seed = self.ek.decrypt(rest[2:], padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"IDENTITY\0"
        ))  # fmt: skip
        name = ak_name or self.ak_name
        hmac_len = struct.unpack(">H", id_object[:2])[0]
        outer, enc = id_object[2 : 2 + hmac_len], id_object[2 + hmac_len :]
        hmac_key = tpm._kdfa(seed, b"INTEGRITY", b"", b"", 256)
        if not hmac.compare_digest(outer, hmac.new(hmac_key, enc + name, hashlib.sha256).digest()):
            raise ValueError("integrity")
        decryptor = Cipher(algorithms.AES(tpm._kdfa(seed, b"STORAGE", name, b"", 128)),
                           tpm.CFB(b"\0" * 16)).decryptor()  # fmt: skip
        plain = decryptor.update(enc) + decryptor.finalize()
        return plain[2 : 2 + struct.unpack(">H", plain[:2])[0]]


def test_real_swtpm_output() -> None:
    """The structures swtpm and tpm2-tools wrote: the AK's name as tpm2-tools computed
    it, and the AK's certification of the node's key, verified."""
    ak = tpm.parse_public(base64.b64decode(SWTPM["ak_pub"]))
    tpm.check_ak(ak)
    assert ak.name == base64.b64decode(SWTPM["ak_name"])
    key = tpm.parse_public(base64.b64decode(SWTPM["node_public"]))
    attest, signature = base64.b64decode(SWTPM["attest"]), base64.b64decode(SWTPM["signature"])
    tpm.check_key(key, attest, signature, ak)
    # The AK can't stand in for the node's key (restricted), nor the key for the AK.
    with pytest.raises(tpm.InvalidAttestation):
        tpm.check_key(ak, attest, signature, ak)
    with pytest.raises(tpm.InvalidAttestation):
        tpm.check_ak(key)


def test_fake_tpm_and_make_credential() -> None:
    fake = FakeTPM()
    ak = tpm.parse_public(tpm2b(fake.ak_area))
    key = tpm.parse_public(tpm2b(fake.key_area))
    assert ak.name == fake.ak_name and key.name == fake.key_name
    attest, signature = fake.certify()
    tpm.check_key(key, attest, signature, ak)
    assert tpm.same_key(key, fake.key.public_key())
    credential = tpm.make_credential(fake.ek.public_key(), ak.name, b"s" * 32)
    assert fake.activate(credential) == b"s" * 32
    # Bound to the AK's name: another name fails the integrity check, as a TPM's would.
    with pytest.raises(ValueError, match="integrity"):
        fake.activate(credential, ak_name=key.name)
    # Another TPM (another EK) can't open it.
    with pytest.raises(ValueError):
        FakeTPM().activate(credential)


@pytest.mark.parametrize(
    "case",
    ["key exportable", "key restricted", "ak not restricted", "other name", "bad signature"],
)
def test_what_attestation_refuses(case) -> None:
    fake = FakeTPM(
        key_attrs=KEY_ATTRS & ~tpm.FIXED_TPM if case == "key exportable"
        else KEY_ATTRS | tpm.RESTRICTED if case == "key restricted" else KEY_ATTRS,
        ak_attrs=AK_ATTRS & ~tpm.RESTRICTED if case == "ak not restricted" else AK_ATTRS,
    )  # fmt: skip
    ak = tpm.parse_public(tpm2b(fake.ak_area))
    key = tpm.parse_public(tpm2b(fake.key_area))
    attest, signature = fake.certify(b"\x00\x0b" + b"x" * 32 if case == "other name" else None)
    if case == "bad signature":
        signature = FakeTPM().ak.sign(attest, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(tpm.InvalidAttestation):
        tpm.check_ak(ak)
        tpm.check_key(key, attest, signature, ak)


def test_garbage_is_refused() -> None:
    for blob in [b"", b"\x00\x05abc", tpm2b(b"\x00\x01\x00\x0c" + b"\0" * 10), b"\xff" * 2000]:
        with pytest.raises(tpm.InvalidAttestation):
            tpm.parse_public(blob)
    with pytest.raises(tpm.InvalidAttestation):
        tpm.certified_name(b"\0" * 40)


def test_invalid_keys_are_refused_not_errors() -> None:
    """A malformed key in a well-formed public area is an attestation refusal (403),
    not an unhandled error (500)."""
    fake = FakeTPM()
    head = fake.key_area[: -(2 + 32 + 2 + 32)]
    off_curve = head + tpm2b(b"\x01" * 32) + tpm2b(b"\x02" * 32)
    too_long = head + tpm2b(b"\x01" * 33) + tpm2b(b"\x02" * 32)
    rsa_head = fake.ak_area[: -(2 + 256)]
    degenerate = rsa_head + tpm2b(b"\x00" * 255 + b"\x01")
    for area in (off_curve, too_long, degenerate):
        with pytest.raises(tpm.InvalidAttestation):
            tpm.parse_public(tpm2b(area))
