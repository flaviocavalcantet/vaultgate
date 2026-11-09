"""External nodes (M11, ADR 0014): their names and identities, their CSRs and keys, the
one-time codes of admin approval, and the signer that issues their certificates.

A node is named by its operator (a DNS label: lower-case letters, digits and hyphens)
and identified by a URI in its certificate, spiffe://nodes.vaultgate/node/<name>, which
only the nodes' CA may sign. The node generates its key and sends a CSR; VaultGate
checks the CSR's signature (the node holds the key) and its key type, and shows the
key's fingerprint, SHA-256 over its SubjectPublicKeyInfo as "SHA256:<base64>" (the form
OpenSSH uses), so an admin can compare it with what the node shows its operator.

The signer is OpenBao's nodes mount, reached through the pod's OpenBao agent
(settings.openbao_agent_address): the agent adds its own token, whose policy allows
signing under the node role and revoking, nothing else of the nodes' CA. The API never
holds an OpenBao token itself.
"""

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vaultgate_api.config import settings

IDENTITY_PREFIX = "spiffe://nodes.vaultgate/node/"
NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
MAX_CSR_BYTES = 4096

# Codes an operator types: no 0/O, 1/I/L. 10 characters of 32 is 50 bits, with a few
# attempts each.
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 10


class InvalidCSR(ValueError):
    pass


class SignerError(Exception):
    """OpenBao didn't sign or revoke: the node's request can't be served now."""


def identity(name: str) -> str:
    return IDENTITY_PREFIX + name


def name_of(identities: tuple[str, ...]) -> str | None:
    """The node name in a client certificate's URIs, if one is a node's identity."""
    for uri in identities:
        if uri.startswith(IDENTITY_PREFIX):
            name = uri.removeprefix(IDENTITY_PREFIX)
            if NAME_PATTERN.fullmatch(name):
                return name
    return None


def fingerprint(public_key) -> str:
    spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = base64.b64encode(hashlib.sha256(spki).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def check_csr(pem: str) -> str:
    """The CSR's key fingerprint, once the CSR is one, signed by its key, for an ECDSA
    P-256 key (the node role's): else InvalidCSR. The names it asks for don't matter:
    the signer gives the node's identity and nothing else."""
    if len(pem.encode()) > MAX_CSR_BYTES:
        raise InvalidCSR("the CSR is too large")
    try:
        csr = x509.load_pem_x509_csr(pem.encode())
    except ValueError:
        raise InvalidCSR("not a PEM certificate signing request") from None
    if not csr.is_signature_valid:
        raise InvalidCSR("the CSR's signature doesn't verify")
    key = csr.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise InvalidCSR("the key must be ECDSA P-256")
    return fingerprint(key)


# An enrollment token's prefix, so secret scanners (and people) recognize one.
# A public prefix, not a secret (Bandit B105 matches the name).
TOKEN_PREFIX = "vgn_"  # nosec B105


def new_enrollment_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)  # 256 bits


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_code() -> str:
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    return f"{code[:5]}-{code[5:]}"


def normalize_code(code: str) -> str:
    return re.sub(r"[\s-]", "", code).upper()


def hash_code(code: str, salt: str) -> str:
    return hashlib.sha256((salt + normalize_code(code)).encode()).hexdigest()


def code_matches(code: str, salt: str, expected: str) -> bool:
    return hmac.compare_digest(hash_code(code, salt), expected)


def serial_int(serial: str) -> int:
    """A serial number as an integer: OpenBao writes "1b:2e:...", ssl's getpeercert
    "1B2E...", either with or without leading zeros."""
    return int(serial.replace(":", "").replace("-", ""), 16)


@dataclass(frozen=True)
class Issued:
    certificate: str
    chain: list[str]
    serial: str
    expires_at: datetime


class Signer(Protocol):
    async def sign(self, csr: str, identity: str) -> Issued: ...

    async def revoke(self, serial: str) -> None: ...


class OpenBaoSigner:
    def __init__(self, client: httpx.AsyncClient, address: str, mount: str, role: str) -> None:
        self.client = client
        self.base = f"{address.rstrip('/')}/v1/{mount}"
        self.role = role

    async def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        try:
            response = await self.client.request(method, f"{self.base}/{path}", json=body)
        except httpx.HTTPError as e:
            raise SignerError(f"OpenBao {path}: {type(e).__name__}") from None
        if response.status_code not in (200, 204):
            raise SignerError(f"OpenBao {path}: {response.status_code} {response.text[:200]}")
        return response.json() if response.content else {}

    async def sign(self, csr: str, identity: str) -> Issued:
        body = {"csr": csr, "uri_sans": identity}
        data = (await self._call("POST", f"sign/{self.role}", body))["data"]
        return Issued(
            certificate=data["certificate"],
            chain=data.get("ca_chain") or [data["issuing_ca"]],
            serial=data["serial_number"],
            expires_at=datetime.fromtimestamp(data["expiration"], UTC),
        )

    async def revoke(self, serial: str) -> None:
        await self._call("POST", "revoke", {"serial_number": serial})
        # The delta list carries it from now, not at its next scheduled rebuild (OCSP
        # already does). Best effort: the revocation itself has happened.
        try:
            await self._call("GET", "crl/rotate-delta")
        except SignerError:
            pass


def openbao_signer(client: httpx.AsyncClient) -> Signer | None:
    if not settings.openbao_agent_address:
        return None
    return OpenBaoSigner(
        client, settings.openbao_agent_address, settings.nodes_pki_mount, settings.nodes_pki_role
    )
