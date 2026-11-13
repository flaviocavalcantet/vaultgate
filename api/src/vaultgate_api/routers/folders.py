"""The caller's folders (M12.6, ADR 0020): create, list, inspect with their path and
totals, rename, move, and delete with everything in them.

Folders follow files' rules: another user's folder is reported as not found, and every
route needs its action allowed by the access policies, `read` to look and `upload` to
change (vaultgate_api.access). Names are unique in a folder across files and folders,
case-insensitively (vaultgate_api.folders); a clash is a 409 that names it.
"""

import logging
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select

from vaultgate_api import audit, deletions, folders
from vaultgate_api.access import ReaderDep, UploaderDep
from vaultgate_api.db import SessionDep
from vaultgate_api.models import File, Folder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/folders", tags=["folders"])

Name = Annotated[str, Field(min_length=1, max_length=255)]


class FolderCreate(BaseModel):
    name: Name
    # The folder to create it in; none for the top level.
    parent_id: uuid.UUID | None = None

    @field_validator("name")
    @classmethod
    def plain(cls, value: str) -> str:
        return folders.plain_name(value)


class FolderChange(BaseModel):
    """A rename, a move, or both. `parent_id` given as null moves to the top level;
    left out, the folder stays where it is."""

    name: Name | None = None
    parent_id: uuid.UUID | None = None

    @field_validator("name")
    @classmethod
    def plain(cls, value: str | None) -> str | None:
        return None if value is None else folders.plain_name(value)


class FolderOut(BaseModel):
    id: uuid.UUID
    name: str
    parent_id: uuid.UUID | None
    created_at: datetime

    @classmethod
    def of(cls, folder: Folder) -> "FolderOut":
        return cls(
            id=folder.id, name=folder.name, parent_id=folder.parent_id, created_at=folder.created_at
        )


class PathEntry(BaseModel):
    id: uuid.UUID
    name: str


class FolderDetail(FolderOut):
    # From the top level down to this folder, for breadcrumbs.
    path: list[PathEntry]


class FolderTotals(BaseModel):
    """What the folder holds, at every level below it: what deleting it would delete."""

    folders: int
    files: int
    # The stored size of its uploaded files.
    bytes: int


class FolderPage(BaseModel):
    items: list[FolderOut]
    total: int
    limit: int
    offset: int


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_folder(body: FolderCreate, user: UploaderDep, session: SessionDep) -> FolderOut:
    await folders.check_placement(session, user.id, body.parent_id)
    await folders.claim_name(session, user.id, body.parent_id, body.name)
    folder = Folder(owner_id=user.id, parent_id=body.parent_id, name=body.name)
    session.add(folder)
    await session.flush()
    await audit.record(
        session,
        "folder.created",
        actor_id=user.id,
        target_kind="folder",
        target_id=folder.id,
        details={"name": folder.name, "parent_id": str(body.parent_id) if body.parent_id else None},
    )
    await folders.commit(session, folder.name)
    await session.refresh(folder)
    logger.info("folder created", extra={"folder_id": str(folder.id)})
    return FolderOut.of(folder)


@router.get("")
async def list_folders(
    user: ReaderDep,
    session: SessionDep,
    parent_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FolderPage:
    """The folders in a folder of the caller's (none: the top level), by name."""
    if parent_id is not None:
        await folders.own_folder(session, parent_id, user.id)
    where = (
        Folder.owner_id == user.id,
        Folder.parent_id.is_(None) if parent_id is None else Folder.parent_id == parent_id,
    )
    total = await session.scalar(select(func.count()).select_from(Folder).where(*where))
    rows = await session.scalars(
        select(Folder)
        .where(*where)
        .order_by(func.lower(Folder.name), Folder.id)
        .limit(limit)
        .offset(offset)
    )
    return FolderPage(
        items=[FolderOut.of(f) for f in rows], total=total or 0, limit=limit, offset=offset
    )


@router.get("/{folder_id}")
async def get_folder(folder_id: uuid.UUID, user: ReaderDep, session: SessionDep) -> FolderDetail:
    folder = await folders.own_folder(session, folder_id, user.id)
    chain = await folders.path(session, folder)
    return FolderDetail(
        **FolderOut.of(folder).model_dump(),
        path=[PathEntry(id=f.id, name=f.name) for f in chain],
    )


@router.patch("/{folder_id}")
async def change_folder(
    folder_id: uuid.UUID, body: FolderChange, user: UploaderDep, session: SessionDep
) -> FolderOut:
    """Rename a folder, move it (with all it holds) into another, or both."""
    folder = await folders.own_folder(session, folder_id, user.id)
    moving = "parent_id" in body.model_fields_set and body.parent_id != folder.parent_id
    renaming = body.name is not None and body.name != folder.name
    if not moving and not renaming:
        return FolderOut.of(folder)
    parent_id = body.parent_id if moving else folder.parent_id
    name = body.name if renaming else folder.name
    if moving:
        await folders.check_placement(session, user.id, parent_id, moving=folder)
    await folders.claim_name(session, user.id, parent_id, name, keep=folder.id)
    details = {}
    if moving:
        details |= {
            "from_parent_id": str(folder.parent_id) if folder.parent_id else None,
            "to_parent_id": str(parent_id) if parent_id else None,
        }
    if renaming:
        details |= {"from": folder.name, "to": name}
    folder.parent_id, folder.name = parent_id, name
    await audit.record(
        session,
        "folder.moved" if moving else "folder.renamed",
        actor_id=user.id,
        target_kind="folder",
        target_id=folder.id,
        details=details,
    )
    await folders.commit(session, name)
    await session.refresh(folder)
    return FolderOut.of(folder)


async def _totals(session, ids: list) -> FolderTotals:
    files, size = (
        await session.execute(
            select(func.count(), func.coalesce(func.sum(File.size), 0)).where(
                File.folder_id.in_(ids)
            )
        )
    ).one()
    return FolderTotals(folders=len(ids) - 1, files=files, bytes=size)


@router.get("/{folder_id}/totals")
async def folder_totals(folder_id: uuid.UUID, user: ReaderDep, session: SessionDep) -> FolderTotals:
    """How many folders and files the folder holds at every level, and their size: what
    a client shows before asking to delete it."""
    folder = await folders.own_folder(session, folder_id, user.id)
    return await _totals(session, [i for i, _ in await folders.subtree(session, folder.id)])


@router.delete("/{folder_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_folder(folder_id: uuid.UUID, user: UploaderDep, session: SessionDep) -> None:
    """Delete a folder with everything in it, at every level: each file as
    `DELETE /files/{id}` would (vaultgate_api.deletions), then the folders."""
    folder = await folders.own_folder(session, folder_id, user.id)
    # No folder can be created in, or moved into, the tree meanwhile (the tree lock),
    # nor a file added to it (the rows' locks, which adding a file waits on).
    await folders.lock_tree(session, user.id)
    below = await folders.subtree(session, folder.id)
    ids = [i for i, _ in below]
    await session.execute(select(Folder.id).where(Folder.id.in_(ids)).with_for_update())
    totals = await _totals(session, ids)
    files = await session.scalars(select(File).where(File.folder_id.in_(ids)))
    await deletions.delete_files(
        session, files, actor_id=user.id, reason=f"folder {folder.id} deleted"
    )
    name, parent_id = folder.name, folder.parent_id
    session.expunge(folder)
    # Deepest first: a folder can't be deleted while another sits in it.
    for depth in sorted({d for _, d in below}, reverse=True):
        level = [i for i, d in below if d == depth]
        await session.execute(delete(Folder).where(Folder.id.in_(level)))
    await audit.record(
        session,
        "folder.deleted",
        actor_id=user.id,
        target_kind="folder",
        target_id=folder_id,
        details={
            "name": name,
            "parent_id": str(parent_id) if parent_id else None,
            "folders": totals.folders,
            "files": totals.files,
            "bytes": totals.bytes,
        },
    )
    await session.commit()
