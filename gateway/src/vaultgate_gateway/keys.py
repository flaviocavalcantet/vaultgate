"""Per-file data keys from AWS KMS (LocalStack locally).

GenerateDataKey returns a fresh 256-bit key twice: in plaintext, used to encrypt the
file in memory and then dropped, and wrapped by the KMS key, which is stored in the
API's database. Decrypting a file later needs KMS to unwrap it again, so revoking or
deleting the KMS key makes every file unreadable.

The encryption context {"file_id": ...} is authenticated by KMS: a wrapped key only
unwraps for the file it was made for, and every unwrap names the file in CloudTrail.

boto3 is synchronous; calls run in a thread so the event loop keeps streaming. That
is one call per file, not per chunk.
"""

import asyncio
import uuid
from dataclasses import dataclass
from typing import Protocol

from botocore.exceptions import BotoCoreError, ClientError

from vaultgate_gateway.crypto import KEY_SIZE


@dataclass(frozen=True)
class DataKey:
    plaintext: bytes
    wrapped: bytes
    kms_key_id: str

    def __repr__(self) -> str:  # never print key material
        return f"DataKey(kms_key_id={self.kms_key_id!r}, plaintext=<redacted>, wrapped=<{len(self.wrapped)} bytes>)"


class KeyUnavailable(Exception):
    """KMS refused or could not be reached; the transfer must not proceed."""


class KeyProvider(Protocol):
    async def generate(self, file_id: uuid.UUID) -> DataKey: ...

    async def unwrap(self, file_id: uuid.UUID, wrapped: bytes) -> bytes: ...


def _context(file_id: uuid.UUID) -> dict[str, str]:
    return {"file_id": str(file_id)}


class KmsKeyProvider:
    def __init__(self, client, kms_key_id: str) -> None:
        self._client = client
        self._kms_key_id = kms_key_id

    @classmethod
    def from_settings(cls, *, kms_key_id: str, region: str, endpoint_url: str | None):
        import boto3

        client = boto3.client("kms", region_name=region, endpoint_url=endpoint_url)
        return cls(client, kms_key_id)

    async def generate(self, file_id: uuid.UUID) -> DataKey:
        try:
            response = await asyncio.to_thread(
                self._client.generate_data_key,
                KeyId=self._kms_key_id,
                KeySpec="AES_256",
                EncryptionContext=_context(file_id),
            )
        except (BotoCoreError, ClientError) as exc:  # details may name keys/accounts
            raise KeyUnavailable(type(exc).__name__) from None
        plaintext = response["Plaintext"]
        if len(plaintext) != KEY_SIZE:
            raise KeyUnavailable("unexpected data key size")
        return DataKey(plaintext, response["CiphertextBlob"], response["KeyId"])

    async def unwrap(self, file_id: uuid.UUID, wrapped: bytes) -> bytes:
        try:
            response = await asyncio.to_thread(
                self._client.decrypt,
                CiphertextBlob=wrapped,
                KeyId=self._kms_key_id,
                EncryptionContext=_context(file_id),
            )
        except (BotoCoreError, ClientError) as exc:
            raise KeyUnavailable(type(exc).__name__) from None
        return response["Plaintext"]
