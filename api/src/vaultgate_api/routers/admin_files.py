"""Administration of scanned files: list files by verdict, release a quarantined or
unscannable file for downloading or for sharing, and scan a file again (ADR 0005).

Restricted to members of VAULTGATE_ADMIN_GROUPS, like the rest of /admin. A release
names its purpose, needs a reason and records who gave it; it covers the current scan
only, so a rescan puts the file back in quarantine until the new verdict.
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import ColumnElement, and_, exists, func, select

from vaultgate_api import metrics, scans
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.models import File, ScanFinding, ScanRelease, User
from vaultgate_api.routers.admin import Limit, Offset, Page, require_admin
from vaultgate_api.routers.files import FileOut

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/files", tags=["admin"], dependencies=[Depends(require_admin)])


class AdminFileOut(FileOut):
    owner_id: uuid.UUID
    owner_username: str | None
    # The admins who gave the releases that stand, by purpose.
    released_by: dict[str, uuid.UUID | None]

    @classmethod
    def of_owned(cls, file: File, owner: User | None) -> "AdminFileOut":
        return cls(
            **FileOut.of(file).model_dump(),
            owner_id=file.owner_id,
            owner_username=owner.username if owner else None,
            released_by={
                r.purpose: r.released_by for r in file.releases if scans.released(file, r.purpose)
            },
        )


def _has_verdict(verdict: scans.Verdict) -> ColumnElement[bool]:
    """SQL for verdict(), with the quarantine kinds as configured now."""
    quarantining = exists().where(
        ScanFinding.file_id == File.id, ScanFinding.kind.in_(settings.quarantine_kinds)
    )
    match verdict:
        case "quarantined":
            return and_(File.scan_status == "scanned", quarantining)
        case "clean":
            return and_(File.scan_status == "scanned", ~quarantining)
        case _:
            return File.scan_status == verdict


@router.get("")
async def list_scanned_files(
    session: SessionDep,
    verdict: Annotated[scans.Verdict | None, Query()] = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[AdminFileOut]:
    """Every user's uploaded files, newest first, optionally only those with a verdict
    (for example the quarantined ones awaiting a decision)."""
    where = File.scan_status.is_not(None) if verdict is None else _has_verdict(verdict)
    total = await session.scalar(select(func.count()).select_from(File).where(where))
    rows = await session.execute(
        select(File, User)
        .outerjoin(User, User.id == File.owner_id)
        .where(where)
        .order_by(File.created_at.desc(), File.id)
        .limit(limit)
        .offset(offset)
    )
    items = [AdminFileOut.of_owned(f, u) for f, u in rows]
    return Page(items=items, total=total or 0, limit=limit, offset=offset)


async def _file(session, file_id: uuid.UUID, *, lock: bool = False) -> tuple[File, User | None]:
    query = select(File).where(File.id == file_id)
    file = await session.scalar(query.with_for_update() if lock else query)
    if file is None or file.scan_status is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="File not found")
    return file, await session.get(User, file.owner_id)


@router.get("/{file_id}")
async def get_scanned_file(file_id: uuid.UUID, session: SessionDep) -> AdminFileOut:
    return AdminFileOut.of_owned(*await _file(session, file_id))


class ReleaseRequest(BaseModel):
    # Why the file may be downloaded, or shared, despite its verdict; kept with it.
    reason: str = Field(min_length=1, max_length=500)
    purpose: scans.Purpose = "download"


@router.post("/{file_id}/release")
async def release_file(
    file_id: uuid.UUID,
    body: ReleaseRequest,
    admin: Annotated[User, Depends(require_admin)],
    session: SessionDep,
) -> AdminFileOut:
    """Let the owner download a quarantined or unscannable file (purpose "download"),
    or let it be shared ("share"). A clean file needs no release; a pending one must
    wait for its verdict."""
    file, owner = await _file(session, file_id, lock=True)
    verdict = scans.verdict(file)
    if verdict not in ("quarantined", "unscannable"):
        await session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"Only quarantined or unscannable files are released; this one is {verdict}",
        )
    if scans.released(file, body.purpose):
        await session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f"File is already released for {body.purpose}"
        )
    # A release left from an older scan is replaced.
    file.releases = [r for r in file.releases if r.purpose != body.purpose] + [
        ScanRelease(
            purpose=body.purpose,
            scan_id=file.scan_id,
            released_at=datetime.now(UTC),
            released_by=admin.id,
            reason=body.reason,
        )
    ]
    await session.commit()
    metrics.RELEASES.labels(body.purpose).inc()
    logger.info(
        "file released from quarantine",
        extra={
            "file_id": str(file.id),
            "verdict": verdict,
            "purpose": body.purpose,
            "admin_id": str(admin.id),
            "reason": body.reason,
        },
    )
    return AdminFileOut.of_owned(file, owner)


@router.post("/{file_id}/rescan", status_code=status.HTTP_202_ACCEPTED)
async def rescan_file(
    file_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: SessionDep,
    queue: scans.ScanQueueDep,
) -> AdminFileOut:
    """Scan the file again, for example after the scanner learned a format. Its findings
    and releases are dropped; it waits for the new verdict like a new upload."""
    file, owner = await _file(session, file_id, lock=True)
    if file.scan_status == "pending":
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="File is already waiting for a scan")
    previous = scans.verdict(file)
    await scans.rescan(session, file, queue)
    logger.info(
        "file sent for a new scan",
        extra={"file_id": str(file.id), "previous_verdict": previous, "admin_id": str(admin.id)},
    )
    return AdminFileOut.of_owned(file, owner)
