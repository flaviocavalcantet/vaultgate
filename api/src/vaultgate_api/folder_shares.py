"""What a folder share lets its recipient see and download (M12.6, ADR 0020).

A folder share shows the folder's live contents, at every level below it: files added
later appear, files moved out or deleted disappear. The recipient sees only the files
that may be shared now (uploaded, and a clean verdict or a release for sharing, ADR
0005); files being scanned or held are left out, so a listing never says a file exists
that can't be had. Subfolders are all listed, empty or not.

Everything is checked again where it counts: when a download intent is issued and at
the gateway's consume (vaultgate_api.internal), which also counts the download against
the share's one limit.
"""

import uuid

from fastapi import HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select

from vaultgate_api import folders, scans
from vaultgate_api.models import File, Folder, Share

# Most items of each kind a listing returns; a folder holding more says so.
MAX_ITEMS = 1000


class SharedItem(BaseModel):
    id: uuid.UUID
    name: str


class SharedFileItem(BaseModel):
    id: uuid.UUID
    name: str
    content_type: str
    size: int | None


class SharedContents(BaseModel):
    folder: SharedItem
    # From the shared folder down to this one, for breadcrumbs; never above it.
    path: list[SharedItem]
    folders: list[SharedItem]
    # The files that can be downloaded now.
    files: list[SharedFileItem]
    # More than MAX_ITEMS folders or files: the lists stop there.
    truncated: bool


async def within(session, folder_id: uuid.UUID | None, root_id: uuid.UUID) -> bool:
    """Whether the folder is the root or sits somewhere below it."""
    current = folder_id
    for _ in range(folders.MAX_DEPTH + 1):
        if current is None:
            return False
        if current == root_id:
            return True
        folder = await session.get(Folder, current)
        current = folder.parent_id if folder is not None else None
    return False


def downloadable(file: File) -> bool:
    return file.status == "uploaded" and scans.blocked(file, "share") is None


async def contents(session, share: Share, folder_id: uuid.UUID | None) -> SharedContents:
    """A folder of the share's (none: the shared folder itself), as its recipient sees
    it. A folder outside the share is not found."""
    root = share.folder_id
    target = folder_id or root
    if not await within(session, target, root):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Folder not found")
    folder = await session.get(Folder, target)
    chain = await folders.path(session, folder)
    chain = chain[[f.id for f in chain].index(root) :]
    subfolders = list(
        await session.scalars(
            select(Folder)
            .where(Folder.parent_id == target)
            .order_by(func.lower(Folder.name), Folder.id)
            .limit(MAX_ITEMS + 1)
        )
    )
    files = list(
        await session.scalars(
            select(File)
            .where(
                File.folder_id == target,
                File.owner_id == share.created_by,
                File.status == "uploaded",
            )
            .order_by(func.lower(File.name), File.id)
            .limit(MAX_ITEMS + 1)
        )
    )
    truncated = len(subfolders) > MAX_ITEMS or len(files) > MAX_ITEMS
    return SharedContents(
        folder=SharedItem(id=folder.id, name=folder.name),
        path=[SharedItem(id=f.id, name=f.name) for f in chain],
        folders=[SharedItem(id=f.id, name=f.name) for f in subfolders[:MAX_ITEMS]],
        files=[
            SharedFileItem(id=f.id, name=f.name, content_type=f.content_type, size=f.size)
            for f in files[:MAX_ITEMS]
            if downloadable(f)
        ],
        truncated=truncated,
    )


async def shared_file(session, share: Share, file_id: uuid.UUID | None) -> File:
    """The file a recipient asks for: the shared file itself, or one inside the shared
    folder at any level. Anything else is not found; whether it may be shared now is the
    caller's check (scans.check)."""
    if share.file_id is not None:
        if file_id is not None and file_id != share.file_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="File not found")
        file = await session.get(File, share.file_id)
    else:
        if file_id is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="A folder share needs the file_id of a file in it",
            )
        file = await session.get(File, file_id)
        if (
            file is None
            or file.owner_id != share.created_by
            or not await within(session, file.folder_id, share.folder_id)
        ):
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="File not found")
    if file is None or file.status != "uploaded":
        raise HTTPException(status.HTTP_410_GONE, detail="File is not available")
    return file
