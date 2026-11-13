"""Files owned by the caller: create (with an upload intent), list, inspect, rename or
move, and get a download intent.

Files sit in one of the caller's folders or at the top level (M12.6, ADR 0020); names are
unique in a folder, across files and folders, case-insensitively (vaultgate_api.folders).

Another user's file is reported as not found, never as forbidden, so file IDs cannot
be probed for existence. Every route first needs its action allowed by the access
policies (vaultgate_api.access): read, upload or download.

An uploaded file shows its scan verdict and the kinds of personal data found, with
counts; the matches themselves are never stored (vaultgate_api.scans). Only a clean
file, or one an admin released, can be downloaded (quarantine, ADR 0005).
"""

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from vaultgate_api import audit, deletions, folders, intents, scans
from vaultgate_api.access import DownloaderDep, ReaderDep, UploaderDep
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.models import File
from vaultgate_api.uploads import live_upload

router = APIRouter(prefix="/files", tags=["files"])

# type/subtype per RFC 6838 token characters, optionally followed by parameters.
_CONTENT_TYPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$")


class FileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    size: int = Field(ge=0)
    content_type: str = Field(default="application/octet-stream", max_length=255)
    # The caller's folder to put it in; none for the top level.
    folder_id: uuid.UUID | None = None

    @field_validator("name")
    @classmethod
    def plain_file_name(cls, value: str) -> str:
        return folders.plain_name(value)

    @field_validator("content_type")
    @classmethod
    def media_type(cls, value: str) -> str:
        if not _CONTENT_TYPE.match(value):
            raise ValueError("must be a media type such as application/pdf")
        return value.lower()


class FindingOut(BaseModel):
    kind: str
    count: int


class ReleaseOut(BaseModel):
    purpose: scans.Purpose
    released_at: datetime
    reason: str


class ScanOut(BaseModel):
    verdict: scans.Verdict
    findings: list[FindingOut]
    # Why the file could not be scanned, when it could not.
    reason: str | None
    scanned_at: datetime | None
    # An admin's releases of a quarantined or unscannable verdict, by purpose.
    releases: list[ReleaseOut]


class FileOut(BaseModel):
    id: uuid.UUID
    name: str
    folder_id: uuid.UUID | None
    content_type: str
    declared_size: int
    status: str
    size: int | None
    sha256: str | None
    created_at: datetime
    uploaded_at: datetime | None
    # None until the upload completes.
    scan: ScanOut | None
    # Whether the scan allows downloading the file, and sharing it (access policies
    # still apply): a clean verdict, a release, or the quarantine scope (ADR 0005).
    downloadable: bool
    shareable: bool

    @classmethod
    def of(cls, file: File) -> "FileOut":
        verdict = scans.verdict(file)
        scan = None
        if verdict is not None:
            releases = [
                ReleaseOut(purpose=r.purpose, released_at=r.released_at, reason=r.reason)
                for r in file.releases
                if scans.released(file, r.purpose)
            ]
            scan = ScanOut(
                verdict=verdict,
                findings=[FindingOut(kind=f.kind, count=f.count) for f in file.findings],
                reason=file.scan_reason,
                scanned_at=file.scanned_at,
                releases=releases,
            )
        return cls(
            id=file.id,
            name=file.name,
            folder_id=file.folder_id,
            content_type=file.content_type,
            declared_size=file.declared_size,
            status=file.status,
            size=file.size,
            sha256=file.sha256,
            created_at=file.created_at,
            uploaded_at=file.uploaded_at,
            scan=scan,
            downloadable=file.status == "uploaded" and scans.blocked(file, "download") is None,
            shareable=file.status == "uploaded" and scans.blocked(file, "share") is None,
        )


class FileChange(BaseModel):
    """A rename, a move, or both. `folder_id` given as null moves to the top level;
    left out, the file stays where it is."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    folder_id: uuid.UUID | None = None

    @field_validator("name")
    @classmethod
    def plain_file_name(cls, value: str | None) -> str | None:
        return None if value is None else folders.plain_name(value)


class TransferOut(BaseModel):
    url: str
    token: str
    expires_at: datetime


class FileCreated(BaseModel):
    file: FileOut
    upload: TransferOut


async def _own_file(session, file_id: uuid.UUID, owner_id: uuid.UUID) -> File:
    file = await session.get(File, file_id)
    if file is None or file.owner_id != owner_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="File not found")
    return file


class FilePage(BaseModel):
    items: list[FileOut]
    total: int
    limit: int
    offset: int


async def _live_uploads(session, owner_id: uuid.UUID) -> int:
    """Uploads that can still finish; abandoned ones must not lock the user out."""
    count = await session.scalar(
        select(func.count())
        .select_from(File)
        .where(File.owner_id == owner_id, live_upload(datetime.now(UTC)))
    )
    return count or 0


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_file(body: FileCreate, user: UploaderDep, session: SessionDep) -> FileCreated:
    """Register a file and get a single-use upload intent for the gateway."""
    open_uploads = await _live_uploads(session, user.id)
    if open_uploads >= settings.max_open_uploads_per_user:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many uploads in progress; finish or wait for some before starting more",
        )
    if body.size > settings.max_upload_bytes:
        raise HTTPException(
            413,
            detail=f"Files are limited to {settings.max_upload_bytes} bytes",
        )
    if body.folder_id is not None:
        await folders.own_folder(session, body.folder_id, user.id)
    await folders.claim_name(session, user.id, body.folder_id, body.name)
    file_id = uuid.uuid4()
    file = File(
        id=file_id,
        owner_id=user.id,
        folder_id=body.folder_id,
        name=body.name,
        content_type=body.content_type,
        declared_size=body.size,
        storage_key=f"files/{file_id}",
    )
    session.add(file)
    await session.flush()
    token, expires_at = await intents.issue(
        session,
        file=file,
        kind="upload",
        user_id=user.id,
        ttl=timedelta(seconds=settings.upload_intent_ttl_seconds),
    )
    await audit.record(
        session,
        "file.registered",
        actor_id=user.id,
        target_kind="file",
        target_id=file.id,
        details={"name": file.name, "declared_size": file.declared_size}
        | ({"folder_id": str(file.folder_id)} if file.folder_id else {}),
    )
    await folders.commit(session, file.name)
    await session.refresh(file)
    url = f"{settings.gateway_public_url.rstrip('/')}/uploads/{file.id}"
    return FileCreated(
        file=FileOut.of(file), upload=TransferOut(url=url, token=token, expires_at=expires_at)
    )


@router.get("")
async def list_files(
    user: ReaderDep,
    session: SessionDep,
    folder_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FilePage:
    """The caller's files in one of their folders (none: the top level), newest first."""
    if folder_id is not None:
        await folders.own_folder(session, folder_id, user.id)
    where = (
        File.owner_id == user.id,
        File.folder_id.is_(None) if folder_id is None else File.folder_id == folder_id,
    )
    total = await session.scalar(select(func.count()).select_from(File).where(*where))
    files = await session.scalars(
        select(File)
        .where(*where)
        .order_by(File.created_at.desc(), File.id)
        .limit(limit)
        .offset(offset)
    )
    return FilePage(
        items=[FileOut.of(f) for f in files], total=total or 0, limit=limit, offset=offset
    )


@router.get("/{file_id}")
async def get_file(file_id: uuid.UUID, user: ReaderDep, session: SessionDep) -> FileOut:
    return FileOut.of(await _own_file(session, file_id, user.id))


@router.patch("/{file_id}")
async def change_file(
    file_id: uuid.UUID, body: FileChange, user: UploaderDep, session: SessionDep
) -> FileOut:
    """Rename a file, move it to another folder, or both. Only the metadata changes: the
    stored object, its key and its scan stay as they are."""
    file = await _own_file(session, file_id, user.id)
    moving = "folder_id" in body.model_fields_set and body.folder_id != file.folder_id
    renaming = body.name is not None and body.name != file.name
    if not moving and not renaming:
        return FileOut.of(file)
    folder_id = body.folder_id if moving else file.folder_id
    name = body.name if renaming else file.name
    if moving and folder_id is not None:
        await folders.own_folder(session, folder_id, user.id)
    await folders.claim_name(session, user.id, folder_id, name, keep=file.id)
    details = {}
    if moving:
        details |= {
            "from_folder_id": str(file.folder_id) if file.folder_id else None,
            "to_folder_id": str(folder_id) if folder_id else None,
        }
    if renaming:
        details |= {"from": file.name, "to": name}
    file.folder_id, file.name = folder_id, name
    await audit.record(
        session,
        "file.moved" if moving else "file.renamed",
        actor_id=user.id,
        target_kind="file",
        target_id=file.id,
        details=details,
    )
    await folders.commit(session, name)
    await session.refresh(file)
    return FileOut.of(file)


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_file(file_id: uuid.UUID, user: UploaderDep, session: SessionDep) -> None:
    """Delete a file at once: its row and wrapped key (so it can't be decrypted again),
    its shares and scan results; the gateway then deletes the stored object
    (vaultgate_api.deletions). Works whatever the file's state, quarantined included."""
    file = await _own_file(session, file_id, user.id)
    await deletions.delete_files(session, [file], actor_id=user.id)
    await session.commit()


@router.post("/{file_id}/download", status_code=status.HTTP_201_CREATED)
async def create_download(
    file_id: uuid.UUID, user: DownloaderDep, session: SessionDep
) -> TransferOut:
    """A single-use download intent for one of the caller's uploaded files."""
    file = await _own_file(session, file_id, user.id)
    if file.status != "uploaded":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="File is not available")
    if reason := scans.check(file, "download", checked_by="api"):
        await audit.record_refusal(
            session,
            "download.refused",
            actor_id=user.id,
            target_kind="file",
            target_id=file.id,
            details={"reason": reason},
        )
        raise HTTPException(status.HTTP_409_CONFLICT, detail=reason)
    token, expires_at = await intents.issue(
        session,
        file=file,
        kind="download",
        user_id=user.id,
        ttl=timedelta(seconds=settings.download_intent_ttl_seconds),
    )
    await audit.record(
        session, "download.issued", actor_id=user.id, target_kind="file", target_id=file.id
    )
    await session.commit()
    url = f"{settings.gateway_public_url.rstrip('/')}/downloads/{file.id}"
    return TransferOut(url=url, token=token, expires_at=expires_at)
