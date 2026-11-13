"""Folders (M12.6, ADR 0020): where a user's files sit, as metadata only.

A folder belongs to one user and sits in another of theirs, or at the top level
(`parent_id` NULL). Files sit in a folder or at the top level (`folder_id` NULL).
Moving or renaming never touches a file's stored object, its key or its scan.

Names are unique within a folder, case-insensitively, across files and folders
together: "Report.pdf" can't sit beside "report.pdf", nor a folder beside a file of the
same name. Each table has its own unique index; the check across the two runs under a
lock on the folder (`claim_name`), so two requests can't both take the same name. A
failed upload holds no name.
"""

import uuid

from fastapi import HTTPException, status
from sqlalchemy import func, select, text

from vaultgate_api.models import File, Folder

# How deep folders may nest: deep enough for any filing scheme, shallow enough that
# walking a path is a handful of lookups.
MAX_DEPTH = 16


def plain_name(value: str) -> str:
    """A display name only (storage keys come from IDs): nothing that could be taken for
    a path, or break a header when a file is served."""
    if (
        value in {".", ".."}
        or value != value.strip()
        or any(c in value for c in "/\\")
        or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
    ):
        raise ValueError(
            "must be a plain name without path separators, control characters, "
            "or leading or trailing spaces"
        )
    return value


def _lock_key(owner_id: uuid.UUID, folder_id: uuid.UUID | None) -> str:
    return f"vaultgate-folder:{owner_id}:{folder_id or 'top'}"


async def claim_name(
    session,
    owner_id: uuid.UUID,
    folder_id: uuid.UUID | None,
    name: str,
    *,
    keep: uuid.UUID | None = None,
) -> None:
    """Refuse (409) if `name` is taken in the folder by another file or folder (`keep`:
    the item being renamed or moved, which may keep its own name). Holds the folder's
    lock until the transaction ends, so the name stays free until it commits."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": _lock_key(owner_id, folder_id)},
    )
    lowered = name.lower()
    file_taken = select(File.id).where(
        File.owner_id == owner_id,
        File.folder_id.is_(None) if folder_id is None else File.folder_id == folder_id,
        func.lower(File.name) == lowered,
        File.status != "failed",
    )
    folder_taken = select(Folder.id).where(
        Folder.owner_id == owner_id,
        Folder.parent_id.is_(None) if folder_id is None else Folder.parent_id == folder_id,
        func.lower(Folder.name) == lowered,
    )
    if keep is not None:
        file_taken = file_taken.where(File.id != keep)
        folder_taken = folder_taken.where(Folder.id != keep)
    if (await session.scalar(file_taken.limit(1))) or (await session.scalar(folder_taken.limit(1))):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"Something named “{name}” is already here; choose another name",
        )


async def own_folder(session, folder_id: uuid.UUID, owner_id: uuid.UUID) -> Folder:
    """The caller's folder, or 404: another user's folder is reported as not found, as
    files are, so IDs can't be probed."""
    folder = await session.get(Folder, folder_id)
    if folder is None or folder.owner_id != owner_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Folder not found")
    return folder


async def path(session, folder: Folder) -> list[Folder]:
    """The folder's ancestors and itself, from the top level down."""
    chain = [folder]
    while chain[0].parent_id is not None and len(chain) <= MAX_DEPTH:
        parent = await session.get(Folder, chain[0].parent_id)
        if parent is None:
            break
        chain.insert(0, parent)
    return chain


async def depth_below(session, folder_id: uuid.UUID) -> int:
    """How many levels of folders sit below this one (0 when it has none)."""
    depth = await session.scalar(
        text(
            """
            WITH RECURSIVE below(id, depth) AS (
                SELECT id, 1 FROM folders WHERE parent_id = :id
                UNION ALL
                SELECT f.id, b.depth + 1 FROM folders f JOIN below b ON f.parent_id = b.id
                WHERE b.depth < :limit
            )
            SELECT coalesce(max(depth), 0) FROM below
            """
        ),
        {"id": folder_id, "limit": MAX_DEPTH + 1},
    )
    return depth or 0


async def check_placement(
    session, owner_id: uuid.UUID, parent_id: uuid.UUID | None, *, moving: Folder | None = None
) -> None:
    """Refuse a folder (new, or `moving`) under `parent_id` when the parent isn't the
    caller's, when it would sit inside itself, or when the tree would get too deep.
    Takes the owner's tree lock first; callers take a folder's name lock after it, never
    before, so the two locks are always taken in the same order."""
    if parent_id is None:
        return
    # One lock for the owner's whole tree, before reading it: two moves that each pass
    # the checks alone (A into B and B into A) would otherwise make a cycle together,
    # or a tree too deep. Held until the transaction ends; placements are rare.
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"vaultgate-folder-tree:{owner_id}"},
    )
    parent = await own_folder(session, parent_id, owner_id)
    ancestors = await path(session, parent)
    if moving is not None and any(f.id == moving.id for f in ancestors):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A folder can't be moved into itself")
    below = await depth_below(session, moving.id) if moving is not None else 0
    if len(ancestors) + 1 + below > MAX_DEPTH:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"Folders nest at most {MAX_DEPTH} deep",
        )
