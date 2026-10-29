"""Files owned by the caller: create (with an upload intent), list, inspect.

Another user's file is reported as not found, never as forbidden, so file IDs cannot
be probed for existence.
"""

import re
import uuid
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from vaultgate_api import intents
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.models import File
from vaultgate_api.provisioning import CurrentUserDep

router = APIRouter(prefix="/files", tags=["files"])

# type/subtype per RFC 6838 token characters, optionally followed by parameters.
_CONTENT_TYPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$")


class FileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    size: int = Field(ge=0)
    content_type: str = Field(default="application/octet-stream", max_length=255)

    @field_validator("name")
    @classmethod
    def plain_file_name(cls, value: str) -> str:
        # A display name only (storage keys come from the file ID), but reject anything
        # that could be mistaken for a path or break headers when the file is served.
        if (
            value in {".", ".."}
            or any(c in value for c in "/\\")
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
        ):
            raise ValueError(
                "must be a plain file name without path separators or control characters"
            )
        return value

    @field_validator("content_type")
    @classmethod
    def media_type(cls, value: str) -> str:
        if not _CONTENT_TYPE.match(value):
            raise ValueError("must be a media type such as application/pdf")
        return value.lower()


class FileOut(BaseModel):
    id: uuid.UUID
    name: str
    content_type: str
    declared_size: int
    status: str
    size: int | None
    sha256: str | None
    created_at: datetime
    uploaded_at: datetime | None

    @classmethod
    def of(cls, file: File) -> "FileOut":
        return cls.model_validate(file, from_attributes=True)


class TransferOut(BaseModel):
    url: str
    token: str
    expires_at: datetime


class FileCreated(BaseModel):
    file: FileOut
    upload: TransferOut


class FilePage(BaseModel):
    items: list[FileOut]
    total: int
    limit: int
    offset: int


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_file(body: FileCreate, user: CurrentUserDep, session: SessionDep) -> FileCreated:
    """Register a file and get a single-use upload intent for the gateway."""
    if body.size > settings.max_upload_bytes:
        raise HTTPException(
            413,
            detail=f"Files are limited to {settings.max_upload_bytes} bytes",
        )
    file_id = uuid.uuid4()
    file = File(
        id=file_id,
        owner_id=user.id,
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
    await session.commit()
    await session.refresh(file)
    url = f"{settings.gateway_public_url.rstrip('/')}/uploads/{file.id}"
    return FileCreated(
        file=FileOut.of(file), upload=TransferOut(url=url, token=token, expires_at=expires_at)
    )


@router.get("")
async def list_files(
    user: CurrentUserDep,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FilePage:
    """The caller's files, newest first."""
    mine = File.owner_id == user.id
    total = await session.scalar(select(func.count()).select_from(File).where(mine))
    files = await session.scalars(
        select(File)
        .where(mine)
        .order_by(File.created_at.desc(), File.id)
        .limit(limit)
        .offset(offset)
    )
    return FilePage(
        items=[FileOut.of(f) for f in files], total=total or 0, limit=limit, offset=offset
    )


@router.get("/{file_id}")
async def get_file(file_id: uuid.UUID, user: CurrentUserDep, session: SessionDep) -> FileOut:
    file = await session.get(File, file_id)
    if file is None or file.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="File not found")
    return FileOut.of(file)
