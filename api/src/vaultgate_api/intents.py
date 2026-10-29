"""Transfer intents: short-lived, single-use permissions to move a file's bytes.

The API decides who may upload or download what; the gateway only moves bytes. A
client gets an intent token from the API, presents it to the gateway, and the gateway
asks the API (internal endpoint) to consume it before accepting or sending a byte.

Tokens are 256 random bits, shown once. Only their SHA-256 is stored, so a leaked
database does not yield usable tokens; lookups compare hashes, so timing does not
reveal anything about valid tokens.
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from vaultgate_api.models import File, TransferIntent


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def issue(
    session: AsyncSession, *, file: File, kind: str, user_id: uuid.UUID, ttl: timedelta
) -> tuple[str, datetime]:
    """Create an intent and return (token, expires_at). The token is not stored."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + ttl
    session.add(
        TransferIntent(
            token_hash=hash_token(token),
            kind=kind,
            file_id=file.id,
            created_by=user_id,
            expires_at=expires_at,
        )
    )
    return token, expires_at


class IntentRejected(Exception):
    """The token is unknown, for another file or kind, expired, or already used."""


async def consume(
    session: AsyncSession, *, token: str, kind: str, file_id: uuid.UUID
) -> TransferIntent:
    """Spend an intent exactly once.

    The UPDATE ... WHERE consumed_at IS NULL is atomic, so two gateway requests racing
    with the same token cannot both succeed. Every failure looks the same to the
    caller: the reasons are not for the client to probe.
    """
    now = datetime.now(UTC)
    intent = await session.scalar(
        update(TransferIntent)
        .where(
            TransferIntent.token_hash == hash_token(token),
            TransferIntent.kind == kind,
            TransferIntent.file_id == file_id,
            TransferIntent.consumed_at.is_(None),
            TransferIntent.expires_at > now,
        )
        .values(consumed_at=now)
        .returning(TransferIntent)
    )
    if intent is None:
        raise IntentRejected
    return intent


async def file_for(session: AsyncSession, intent: TransferIntent) -> File:
    return (await session.scalars(select(File).where(File.id == intent.file_id))).one()
