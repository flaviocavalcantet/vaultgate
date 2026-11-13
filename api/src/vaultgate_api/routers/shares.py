"""Share links for the caller's files (M5) and folders (M12.6, ADR 0020).

The owner shares a file, or a folder with all it holds, with one recipient, named by email address, and gets a link
with a single random token, shown once (only its SHA-256 is stored, like intent
tokens). An external recipient will prove they hold the address with a code sent to
it; an internal one signs in with a verified email equal to it. A share ends when it
expires, when its downloads are used up, or when the owner revokes it.

Creating a share needs the `share` action allowed by the access policies and, for a
file, a scan that allows it to be shared: a clean verdict, or an admin's release for
sharing (ADR 0005). A folder's files are checked one by one when the recipient lists
and downloads them (vaultgate_api.folder_shares). Listing needs `read`; revoking needs nothing more than owning the file,
so a user who may no longer share can still take a link back.
"""

import hashlib
import logging
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from vaultgate_api import audit, folders, metrics, scans
from vaultgate_api.access import ReaderDep, SharerDep
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.models import File, Folder, Share
from vaultgate_api.provisioning import CurrentUserDep

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/files/{file_id}/shares", tags=["shares"])
folder_router = APIRouter(prefix="/folders/{folder_id}/shares", tags=["shares"])

# One "@", something on each side, a dot in the domain, no spaces. Whether the address
# exists is for the recipient to prove.
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s.]+$")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


ShareState = Literal["active", "expired", "used", "revoked"]


def state(share: Share, now: datetime | None = None) -> ShareState:
    now = now or datetime.now(UTC)
    if share.revoked_at is not None:
        return "revoked"
    if share.expires_at <= now:
        return "expired"
    if share.downloads >= share.max_downloads:
        return "used"
    return "active"


class ShareCreate(BaseModel):
    recipient_email: str = Field(max_length=320)
    # external: the recipient proves the address with a code sent to it.
    # internal: the recipient signs in; their verified email must be this address.
    recipient_kind: Literal["external", "internal"] = "external"
    expires_in_days: int | None = Field(default=None, ge=1)
    max_downloads: int | None = Field(default=None, ge=1)

    @field_validator("recipient_email")
    @classmethod
    def email_address(cls, value: str) -> str:
        value = value.strip().lower()
        if not _EMAIL.match(value):
            raise ValueError("must be an email address")
        return value


class ShareOut(BaseModel):
    id: uuid.UUID
    # What is shared: a file or a folder.
    file_id: uuid.UUID | None
    folder_id: uuid.UUID | None
    recipient_email: str
    recipient_kind: str
    created_at: datetime
    expires_at: datetime
    max_downloads: int
    downloads: int
    revoked_at: datetime | None
    state: ShareState

    @classmethod
    def of(cls, share: Share) -> "ShareOut":
        return cls(
            id=share.id,
            file_id=share.file_id,
            folder_id=share.folder_id,
            recipient_email=share.recipient_email,
            recipient_kind=share.recipient_kind,
            created_at=share.created_at,
            expires_at=share.expires_at,
            max_downloads=share.max_downloads,
            downloads=share.downloads,
            revoked_at=share.revoked_at,
            state=state(share),
        )


class ShareCreated(BaseModel):
    share: ShareOut
    # The link to send the recipient. The token is in the query string, which is never
    # logged; it is shown only now.
    url: str
    token: str


async def _own_file(session, file_id: uuid.UUID, user_id: uuid.UUID) -> File:
    file = await session.get(File, file_id)
    if file is None or file.owner_id != user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="File not found")
    return file


def _active(now: datetime):
    return (
        Share.revoked_at.is_(None),
        Share.expires_at > now,
        Share.downloads < Share.max_downloads,
    )


def audit_target(share: Share) -> dict:
    """Where a share's audit events point: its file or its folder."""
    if share.folder_id is not None:
        return {"target_kind": "folder", "target_id": share.folder_id}
    return {"target_kind": "file", "target_id": share.file_id}


async def _create(
    session, user, body: ShareCreate, *, file: File | None = None, folder: Folder | None = None
) -> ShareCreated:
    days = body.expires_in_days or settings.share_default_days
    downloads = body.max_downloads or settings.share_default_downloads
    if days > settings.share_max_days:
        raise HTTPException(422, detail=f"Shares last at most {settings.share_max_days} days")
    if downloads > settings.share_max_downloads:
        raise HTTPException(
            422, detail=f"Shares allow at most {settings.share_max_downloads} downloads"
        )
    now = datetime.now(UTC)
    same = Share.file_id == file.id if file is not None else Share.folder_id == folder.id
    active = await session.scalar(
        select(func.count()).select_from(Share).where(same, *_active(now))
    )
    if (active or 0) >= settings.max_active_shares_per_file:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many active shares for this {'file' if file else 'folder'}; "
            "revoke some first",
        )
    token = secrets.token_urlsafe(32)
    share = Share(
        file_id=file.id if file is not None else None,
        folder_id=folder.id if folder is not None else None,
        created_by=user.id,
        recipient_email=body.recipient_email,
        recipient_kind=body.recipient_kind,
        token_hash=hash_token(token),
        expires_at=now + timedelta(days=days),
        max_downloads=downloads,
    )
    session.add(share)
    await session.flush()
    await audit.record(
        session,
        "share.created",
        actor_id=user.id,
        details={
            "share_id": str(share.id),
            "recipient_email": share.recipient_email,
            "recipient_kind": share.recipient_kind,
            "expires_at": share.expires_at.isoformat(),
            "max_downloads": share.max_downloads,
        },
        **audit_target(share),
    )
    await session.commit()
    await session.refresh(share)
    metrics.SHARES_CREATED.labels(body.recipient_kind).inc()
    # The recipient's address is personal data: the log names the share, not them.
    logger.info(
        "share created",
        extra={
            "file_id": str(share.file_id) if share.file_id else None,
            "folder_id": str(share.folder_id) if share.folder_id else None,
            "share_id": str(share.id),
            "recipient_kind": body.recipient_kind,
        },
    )
    url = f"{settings.public_api_url.rstrip('/')}/shares/access?token={token}"
    return ShareCreated(share=ShareOut.of(share), url=url, token=token)


async def _list(session, same) -> list[ShareOut]:
    shares = await session.scalars(
        select(Share).where(same).order_by(Share.created_at.desc(), Share.id)
    )
    return [ShareOut.of(s) for s in shares]


async def _revoke(session, share: Share | None, user, same) -> Response:
    if share is None or not same(share):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Share not found")
    if share.revoked_at is None:
        share.revoked_at = datetime.now(UTC)
        await audit.record(
            session,
            "share.revoked",
            actor_id=user.id,
            details={"share_id": str(share.id), "recipient_email": share.recipient_email},
            **audit_target(share),
        )
        await session.commit()
        metrics.SHARES_REVOKED.inc()
        logger.info("share revoked", extra={"share_id": str(share.id)})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_share(
    file_id: uuid.UUID, body: ShareCreate, user: SharerDep, session: SessionDep
) -> ShareCreated:
    """Share one of the caller's uploaded files with one recipient."""
    file = await _own_file(session, file_id, user.id)
    if file.status != "uploaded":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="File is not available")
    if reason := scans.check(file, "share", checked_by="api"):
        raise HTTPException(status.HTTP_409_CONFLICT, detail=reason)
    return await _create(session, user, body, file=file)


@router.get("")
async def list_shares(file_id: uuid.UUID, user: ReaderDep, session: SessionDep) -> list[ShareOut]:
    """The file's shares, newest first, with their state."""
    await _own_file(session, file_id, user.id)
    return await _list(session, Share.file_id == file_id)


@router.delete("/{share_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_share(
    file_id: uuid.UUID, share_id: uuid.UUID, user: CurrentUserDep, session: SessionDep
) -> Response:
    """Revoke a share at once. Revoking twice is fine."""
    await _own_file(session, file_id, user.id)
    share = await session.get(Share, share_id)
    return await _revoke(session, share, user, lambda s: s.file_id == file_id)


@folder_router.post("", status_code=status.HTTP_201_CREATED)
async def create_folder_share(
    folder_id: uuid.UUID, body: ShareCreate, user: SharerDep, session: SessionDep
) -> ShareCreated:
    """Share one of the caller's folders, with everything in it now and later, with one
    recipient. Its files are checked one by one when the recipient lists and downloads
    them; the share's downloads count across all of them."""
    folder = await folders.own_folder(session, folder_id, user.id)
    return await _create(session, user, body, folder=folder)


@folder_router.get("")
async def list_folder_shares(
    folder_id: uuid.UUID, user: ReaderDep, session: SessionDep
) -> list[ShareOut]:
    """The folder's shares, newest first, with their state."""
    await folders.own_folder(session, folder_id, user.id)
    return await _list(session, Share.folder_id == folder_id)


@folder_router.delete("/{share_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_folder_share(
    folder_id: uuid.UUID, share_id: uuid.UUID, user: CurrentUserDep, session: SessionDep
) -> Response:
    """Revoke a folder's share at once. Revoking twice is fine."""
    await folders.own_folder(session, folder_id, user.id)
    share = await session.get(Share, share_id)
    return await _revoke(session, share, user, lambda s: s.folder_id == folder_id)
