"""TPM 2.0 attestation (M11, ADR 0014): what the node's TPM proves, checked from its own
structures, and the credential only that TPM can decrypt.

The chain, as TPM attestation goes (Keylime and SPIRE's TPM attestors do the same):

- The EK (endorsement key) is the TPM's own: an admin registers it, by its public key's
  SHA-256, for one node name.
- The AK (attestation key) is a restricted signing key the node makes in its TPM.
  `make_credential` encrypts a random secret to the EK, bound to the AK's name: a TPM
  decrypts it (TPM2_ActivateCredential) only if it holds that EK and an AK of that name.
  So the node sending the secret back shows the AK is in the registered TPM.
- The node's key, the one its certificate will be for, is certified by the AK
  (TPM2_Certify): a statement, signed by the AK, that an object of that name is in the
  same TPM. Its public area must say it can never leave it (fixedTPM, fixedParent) and
  was made inside it (sensitiveDataOrigin), and the CSR must be for that same key.

Supported: an RSA EK (the usual one: the TCG's default EK template, and swtpm's); an RSA
AK (RSASSA, SHA-256); the node's key ECDSA P-256 (the node role's). Everything else is
refused, with the reason.
"""

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

try:  # CFB moved to the "decrepit" module (still TPM 2.0's mode for credentials)
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:  # older cryptography
    from cryptography.hazmat.primitives.ciphers.modes import CFB

# TPM constants (TPM 2.0 Library, Part 2).
ALG_RSA, ALG_SHA256, ALG_NULL, ALG_ECC = 0x0001, 0x000B, 0x0010, 0x0023
ECC_NIST_P256 = 0x0003
ATTEST_MAGIC, ST_ATTEST_CERTIFY = 0xFF544347, 0x8017
FIXED_TPM, FIXED_PARENT, SENSITIVE_DATA_ORIGIN = 0x00000002, 0x00000010, 0x00000020
RESTRICTED, DECRYPT, SIGN = 0x00010000, 0x00020000, 0x00040000
# tpm2-tools' credential file: what tpm2_makecredential writes and
# tpm2_activatecredential reads.
CREDENTIAL_MAGIC, CREDENTIAL_VERSION = 0xBADCC0DE, 1
MAX_BLOB = 1024


class InvalidAttestation(ValueError):
    pass


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.at = data, 0

    def take(self, n: int) -> bytes:
        if self.at + n > len(self.data):
            raise InvalidAttestation("truncated TPM structure")
        chunk = self.data[self.at : self.at + n]
        self.at += n
        return chunk

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def tpm2b(self) -> bytes:
        return self.take(self.u16())

    def done(self) -> None:
        if self.at != len(self.data):
            raise InvalidAttestation("trailing bytes after a TPM structure")


@dataclass(frozen=True)
class Public:
    """A TPM object's public area."""

    type: int
    attributes: int
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
    name: bytes  # nameAlg || SHA-256(TPMT_PUBLIC)

    def has(self, bits: int) -> bool:
        return self.attributes & bits == bits


def _scheme(r: _Reader) -> int:
    scheme = r.u16()
    if scheme != ALG_NULL:
        r.u16()  # its hash
    return scheme


def parse_public(blob: bytes) -> Public:
    """A TPM2B_PUBLIC (tpm2-tools' -u output): its key, attributes and name."""
    if len(blob) > MAX_BLOB:
        raise InvalidAttestation("public area too large")
    outer = _Reader(blob)
    area = outer.tpm2b()
    outer.done()
    r = _Reader(area)
    kind, name_alg, attributes = r.u16(), r.u16(), r.u32()
    if name_alg != ALG_SHA256:
        raise InvalidAttestation("only SHA-256 names are supported")
    r.tpm2b()  # authPolicy
    if r.u16() != ALG_NULL:  # symmetric: a signing key has none
        r.u16(), r.u16()
    if kind == ALG_RSA:
        _scheme(r)
        r.u16()  # keyBits
        exponent = r.u32() or 65537
        modulus = int.from_bytes(r.tpm2b(), "big")
        try:
            key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        except ValueError:
            raise InvalidAttestation("not a valid RSA public key") from None
    elif kind == ALG_ECC:
        _scheme(r)
        curve = r.u16()
        _scheme(r)  # kdf
        x, y = r.tpm2b(), r.tpm2b()
        if curve != ECC_NIST_P256:
            raise InvalidAttestation("only ECC keys on P-256 are supported")
        if len(x) > 32 or len(y) > 32:
            raise InvalidAttestation("not a P-256 point")
        point = b"\x04" + x.rjust(32, b"\0") + y.rjust(32, b"\0")
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        except ValueError:
            raise InvalidAttestation("not a point on P-256") from None
    else:
        raise InvalidAttestation("only RSA and ECC keys are supported")
    r.done()
    return Public(
        kind, attributes, key, struct.pack(">H", name_alg) + hashlib.sha256(area).digest()
    )


def certified_name(attest: bytes) -> bytes:
    """The name a TPMS_ATTEST of TPM2_Certify vouches for."""
    if len(attest) > MAX_BLOB:
        raise InvalidAttestation("attestation too large")
    r = _Reader(attest)
    if r.u32() != ATTEST_MAGIC or r.u16() != ST_ATTEST_CERTIFY:
        raise InvalidAttestation("not a TPM2_Certify attestation")
    r.tpm2b()  # qualifiedSigner
    r.tpm2b()  # extraData
    r.take(8 + 4 + 4 + 1)  # clockInfo
    r.take(8)  # firmwareVersion
    name = r.tpm2b()
    r.tpm2b()  # qualifiedName
    r.done()
    return name


def check_ak(ak: Public) -> None:
    if ak.type != ALG_RSA:
        raise InvalidAttestation("the AK must be an RSA key")
    if not ak.has(FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | RESTRICTED | SIGN):
        raise InvalidAttestation("the AK must be a restricted signing key fixed to its TPM")
    if ak.has(DECRYPT):
        raise InvalidAttestation("the AK must not decrypt")


def check_key(key: Public, attest: bytes, signature: bytes, ak: Public) -> None:
    """The node's key is in the AK's TPM, for good: the AK certified it, and its public
    area says it was made there and can't leave."""
    if key.type != ALG_ECC:
        raise InvalidAttestation("the node's key must be ECDSA P-256")
    if not key.has(FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | SIGN):
        raise InvalidAttestation("the node's key must be made in its TPM and never leave it")
    if key.has(RESTRICTED) or key.has(DECRYPT):
        raise InvalidAttestation("the node's key must be an unrestricted signing key")
    try:
        ak.key.verify(signature, attest, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise InvalidAttestation(
            "the AK's signature over the certification doesn't verify"
        ) from None
    if not hmac.compare_digest(certified_name(attest), key.name):
        raise InvalidAttestation("the AK certified another object than the node's key")


def same_key(key: Public, other) -> bool:
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    return key.key.public_bytes(*spki) == other.public_bytes(*spki)


def _kdfa(key: bytes, label: bytes, context_u: bytes, context_v: bytes, bits: int) -> bytes:
    """KDFa (TPM 2.0 Part 1, 11.4.10.2): SP 800-108 counter mode with HMAC-SHA-256."""
    out, counter = b"", 1
    while len(out) * 8 < bits:
        out += hmac.new(
            key,
            struct.pack(">I", counter) + label + b"\0" + context_u + context_v
            + struct.pack(">I", bits),
            hashlib.sha256,
        ).digest()  # fmt: skip
        counter += 1
    return out[: bits // 8]


def make_credential(ek: rsa.RSAPublicKey, ak_name: bytes, secret: bytes) -> bytes:
    """TPM2_MakeCredential, done here (no TPM needed): `secret` sealed to the EK for the
    AK `ak_name`, as tpm2-tools' credential file, which tpm2_activatecredential reads."""
    if not isinstance(ek, rsa.RSAPublicKey):
        raise InvalidAttestation("only an RSA EK is supported")
    seed = os.urandom(32)
    encrypted_seed = ek.encrypt(seed, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"IDENTITY\0"
    ))  # fmt: skip
    sym_key = _kdfa(seed, b"STORAGE", ak_name, b"", 128)
    encryptor = Cipher(algorithms.AES(sym_key), CFB(b"\0" * 16)).encryptor()
    enc_identity = encryptor.update(struct.pack(">H", len(secret)) + secret) + encryptor.finalize()
    hmac_key = _kdfa(seed, b"INTEGRITY", b"", b"", 256)
    outer = hmac.new(hmac_key, enc_identity + ak_name, hashlib.sha256).digest()
    id_object = struct.pack(">H", len(outer)) + outer + enc_identity
    return (
        struct.pack(">II", CREDENTIAL_MAGIC, CREDENTIAL_VERSION)
        + struct.pack(">H", len(id_object)) + id_object
        + struct.pack(">H", len(encrypted_seed)) + encrypted_seed
    )  # fmt: skip
