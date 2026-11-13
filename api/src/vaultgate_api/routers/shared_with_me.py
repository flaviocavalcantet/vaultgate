"""Shares addressed to the caller, for internal recipients (M5; folders M12.6).

An internal share names a VaultGate user by email address. That user signs in like
for anything else; a share is theirs when the address is the verified email in their
token (OIDC email_verified), so no code is needed and the link itself grants nothing.

A share is of a file or of a folder; a folder's contents are listed with
`GET /shared-with-me/{id}/contents` (its subfolders, and the files that can be
downloaded now: vaultgate_api.folder_shares), and a file in it is downloaded by naming
it (`?file_id=`).

Listing needs the caller's `read` action and downloading their `download` action, as
for their own files: a recipient is subject to their own access policies, at the API
and again at the gateway. The share must be active, its owner active and the file
shareable (ADR 0005); the gateway checks all of it again and counts the download.
Someone else's share is reported as not found.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from vaultgate_api import audit, folder_shares, intents, scans
from vaultgate_api.access import DownloaderDep, ReaderDep
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.models import File, Folder, Share, User
from vaultgate_api.routers.files import TransferOut
from vaultgate_api.routers.shares import state

router = APIRouter(prefix="/shared-with-me", tags=["shares"])


class SharedFileOut(BaseModel):
    share_id: uuid.UUID
    # What is shared: a file (file_id) or a folder (folder_id).
    kind: Literal["file", "folder"]
    file_id: uuid.UUID | None
    folder_id: uuid.UUID | None
    name: str
    # A file's; none for a folder.
    content_type: str | None
    size: int | None
    shared_by: str | None  # the owner's username
    expires_at: datetime
    downloads_left: int
    # Whether the file can be downloaded now: false while its scan does not allow
    # sharing (a rescan, say). Always true for a folder, whose files are listed only
    # when they can be.
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
        select(Share, File, Folder, User)
        .outerjoin(File, File.id == Share.file_id)
        .outerjoin(Folder, Folder.id == Share.folder_id)
        .join(User, User.id == Share.created_by)
        .where(
            *_mine(user),
            (File.status == "uploaded") | (Share.folder_id.is_not(None)),
            User.is_active,
        )
        .order_by(Share.created_at.desc(), Share.id)
    )
    shared = []
    for share, file, folder, owner in rows:
        common = {
            "share_id": share.id,
            "shared_by": owner.username,
            "expires_at": share.expires_at,
            "downloads_left": share.max_downloads - share.downloads,
        }
        if folder is not None:
            shared.append(
                SharedFileOut(
                    **common,
                    kind="folder",
                    file_id=None,
                    folder_id=folder.id,
                    name=folder.name,
                    content_type=None,
                    size=None,
                    available=True,
                )
            )
        else:
            shared.append(
                SharedFileOut(
                    **common,
                    kind="file",
                    file_id=file.id,
                    folder_id=None,
                    name=file.name,
                    content_type=file.content_type,
                    size=file.size,
                    available=scans.blocked(file, "share") is None,
                )
            )
    return shared


async def _my_share(session, user: User, share_id: uuid.UUID) -> Share:
    """An active share addressed to the caller, by an active owner, or a refusal."""
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
    owner = await session.get(User, share.created_by)
    if owner is None or not owner.is_active:
        raise HTTPException(status.HTTP_410_GONE, detail="Share is not available")
    return share


@router.get("/{share_id}/contents")
async def shared_contents(
    share_id: uuid.UUID,
    user: ReaderDep,
    session: SessionDep,
    folder_id: uuid.UUID | None = None,
) -> folder_shares.SharedContents:
    """A folder of a folder shared with the caller (none: the shared folder itself):
    its subfolders and the files that can be downloaded now."""
    share = await _my_share(session, user, share_id)
    if share.folder_id is None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="This share is of a file")
    return await folder_shares.contents(session, share, folder_id)


@router.post("/{share_id}/download", status_code=status.HTTP_201_CREATED)
async def create_shared_download(
    share_id: uuid.UUID,
    user: DownloaderDep,
    session: SessionDep,
    file_id: uuid.UUID | None = None,
) -> TransferOut:
    """A single-use download intent for a file shared with the caller, or (`file_id`)
    a file in a folder shared with them."""
    share = await _my_share(session, user, share_id)
    file = await folder_shares.shared_file(session, share, file_id)
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
    await audit.record(
        session,
        "share.download_issued",
        actor_id=user.id,
        target_kind="file",
        target_id=file.id,
        details={"share_id": str(share.id), "recipient_email": share.recipient_email},
    )
    await session.commit()
    url = f"{settings.gateway_public_url.rstrip('/')}/downloads/{file.id}"
    return TransferOut(url=url, token=token, expires_at=expires_at)
