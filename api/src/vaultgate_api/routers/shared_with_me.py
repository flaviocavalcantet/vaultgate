"""Shares addressed to the caller, for internal recipients (M5).

An internal share names a VaultGate user by email address. That user signs in like
for anything else; a share is theirs when the address is the verified email in their
token (OIDC email_verified), so no code is needed and the link itself grants nothing.

Listing needs the caller's `read` action and downloading their `download` action, as
for their own files: a recipient is subject to their own access policies, at the API
and again at the gateway. The share must be active, its owner active and the file
shareable (ADR 0005); the gateway checks all of it again and counts the download.
Someone else's share is reported as not found.
"""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from vaultgate_api import intents, scans
from vaultgate_api.access import DownloaderDep, ReaderDep
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.models import File, Share, User
from vaultgate_api.routers.files import TransferOut
from vaultgate_api.routers.shares import state

router = APIRouter(prefix="/shared-with-me", tags=["shares"])


class SharedFileOut(BaseModel):
    share_id: uuid.UUID
    file_id: uuid.UUID
    name: str
    content_type: str
    size: int | None
    shared_by: str | None  # the owner's username
    expires_at: datetime
    downloads_left: int
    # Whether the file can be downloaded now: false while its scan does not allow
    # sharing (a rescan, say).
    available: bool


def _address(user: User) -> str | None:
    """The caller's address for matching shares: only a verified one."""
    return user.email.lower() if user.email and user.email_verified else None


def _mine(user: User):
    now = datetime.now(UTC)
    return (
        Share.recipient_kind == "internal",
        Share.recipient_email == _address(user),
        Share.revoked_at.is_(None),
        Share.expires_at > now,
        Share.downloads < Share.max_downloads,
    )


@router.get("")
async def list_shared_with_me(user: ReaderDep, session: SessionDep) -> list[SharedFileOut]:
    """Active shares addressed to the caller's verified email, newest first."""
    if _address(user) is None:
        return []
    rows = await session.execute(
        select(Share, File, User)
        .join(File, File.id == Share.file_id)
        .join(User, User.id == Share.created_by)
        .where(*_mine(user), File.status == "uploaded", User.is_active)
        .order_by(Share.created_at.desc(), Share.id)
    )
    return [
        SharedFileOut(
            share_id=share.id,
            file_id=file.id,
            name=file.name,
            content_type=file.content_type,
            size=file.size,
            shared_by=owner.username,
            expires_at=share.expires_at,
            downloads_left=share.max_downloads - share.downloads,
            available=scans.blocked(file, "share") is None,
        )
        for share, file, owner in rows
    ]


@router.post("/{share_id}/download", status_code=status.HTTP_201_CREATED)
async def create_shared_download(
    share_id: uuid.UUID, user: DownloaderDep, session: SessionDep
) -> TransferOut:
    """A single-use download intent for a file shared with the caller."""
    share = await session.get(Share, share_id)
    if (
        share is None
        or share.recipient_kind != "internal"
        or _address(user) is None
        or share.recipient_email != _address(user)
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Share not found")
    if (current := state(share)) != "active":
        raise HTTPException(status.HTTP_410_GONE, detail=f"Share is {current}")
    file = await session.get(File, share.file_id)
    owner = await session.get(User, share.created_by)
    if file is None or file.status != "uploaded" or owner is None or not owner.is_active:
        raise HTTPException(status.HTTP_410_GONE, detail="File is not available")
    if reason := scans.check(file, "share", checked_by="api"):
        raise HTTPException(status.HTTP_409_CONFLICT, detail=reason)
    token, expires_at = await intents.issue(
        session,
        file=file,
        kind="download",
        user_id=user.id,
        ttl=timedelta(seconds=settings.download_intent_ttl_seconds),
        share_id=share.id,
    )
    await session.commit()
    url = f"{settings.gateway_public_url.rstrip('/')}/downloads/{file.id}"
    return TransferOut(url=url, token=token, expires_at=expires_at)
