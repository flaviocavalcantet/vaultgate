"""Cloud instance identity (M11, ADR 0014): a cloud's signed statement of which instance
is asking, for node enrollment without an admin at enrollment time.

AWS first. An EC2 instance reads its instance identity document from the instance
metadata service: JSON naming its account, instance, region and launch time, with an
RSA-SHA256 signature by AWS (the metadata's `signature`, base64). AWS publishes the
certificates that verify it, per region; the operator gives VaultGate the ones for its
regions (settings.node_aws_certificates_file, a PEM bundle). A document that verifies
against none of them is refused.

The document is not a secret (any process on the instance can read it, and it doesn't
change), so what it proves is "an instance of this account in this region", once:
callers record each instance and let it enroll a single node, ever.
"""

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MAX_DOCUMENT_BYTES = 4096
MAX_SIGNATURE_BYTES = 1024


class InvalidIdentity(ValueError):
    pass


@dataclass(frozen=True)
class Instance:
    provider: str
    account: str
    instance: str
    region: str
    launched_at: datetime | None

    @property
    def subject(self) -> str:
        """The instance, as the single-use record keys it."""
        return f"{self.provider}:{self.account}:{self.instance}"

    @property
    def node_name(self) -> str:
        """The node's name: the instance's, so the request can't choose it."""
        return f"{self.provider}-{self.instance}".lower()


@lru_cache(maxsize=4)
def _aws_keys(path: str) -> tuple[rsa.RSAPublicKey, ...]:
    certificates = x509.load_pem_x509_certificates(Path(path).read_bytes())
    keys = tuple(c.public_key() for c in certificates)
    if not keys or not all(isinstance(k, rsa.RSAPublicKey) for k in keys):
        raise ValueError(f"{path}: RSA certificates expected (AWS's for the RSA signature)")
    return keys


def aws_instance(document: str, signature: str, certificates_file: str) -> Instance:
    """The instance an AWS identity document names, once its signature verifies against
    one of the certificates; else InvalidIdentity."""
    raw = document.encode()
    if len(raw) > MAX_DOCUMENT_BYTES or len(signature) > MAX_SIGNATURE_BYTES:
        raise InvalidIdentity("the document or its signature is too large")
    try:
        sig = base64.b64decode("".join(signature.split()), validate=True)
    except (binascii.Error, ValueError):
        raise InvalidIdentity("the signature isn't base64") from None
    for key in _aws_keys(certificates_file):
        try:
            key.verify(sig, raw, padding.PKCS1v15(), hashes.SHA256())
            break
        except InvalidSignature:
            continue
    else:
        raise InvalidIdentity("the document's signature doesn't verify")
    try:
        fields = json.loads(document)
        account, instance, region = (
            str(fields["accountId"]), str(fields["instanceId"]), str(fields["region"])
        )  # fmt: skip
    except (ValueError, KeyError, TypeError):
        raise InvalidIdentity("not an instance identity document") from None
    if not (account.isdigit() and len(account) == 12):
        raise InvalidIdentity("not an AWS account ID")
    if not instance.startswith("i-") or not instance[2:].isalnum() or len(instance) > 40:
        raise InvalidIdentity("not an EC2 instance ID")
    launched = None
    if pending := fields.get("pendingTime"):
        try:
            launched = datetime.fromisoformat(str(pending))
        except ValueError:
            raise InvalidIdentity("the document's pendingTime isn't a time") from None
        if launched.tzinfo is None:
            launched = launched.replace(tzinfo=UTC)
    return Instance("aws", account, instance, region, launched)
