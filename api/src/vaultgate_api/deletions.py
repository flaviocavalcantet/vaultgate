"""Deleting files (M12.6, ADR 0020).

A file is deleted in one transaction: its row goes, and with it the wrapped data key,
its scan findings, releases, shares, share verifications and intents (all by cascade).
Without the wrapped key the stored object can't be decrypted, whatever copies of it
remain, so the content is unreadable from the moment the transaction commits.

The object itself is deleted by the gateway, the one service allowed to delete objects
(the API can't, by its IAM policy): the same transaction queues its key in
`object_deletions`, which the gateway claims, deletes and confirms through the internal
API. A claim lasts a while; one not confirmed by then (the gateway died, S3 refused) is
claimed again. The bucket is versioned, so a delete leaves a delete marker and the
object's versions, which the bucket's lifecycle rule expires.

An upload still streaming when its file is deleted is refused when it completes (its
row is gone), and the gateway deletes the object it wrote, as for any refused upload.
"""

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select, update

from vaultgate_api import audit
from vaultgate_api.models import File, ObjectDeletion


async def delete_files(
    session,
    files: Iterable[File],
    *,
    actor_id: uuid.UUID,
    reason: str | None = None,
) -> int:
    """Delete the files' rows, queue their objects for the gateway, and record each
    deletion. Commits nothing: the caller's transaction decides."""
    files = {f.id: f for f in files}
    if not files:
        return 0
    for file in files.values():
        session.expunge(file)
    # Only what this transaction removed: a file deleted meanwhile by another request
    # (its folder's deletion, say) is that request's to queue and record.
    gone = set(await session.scalars(delete(File).where(File.id.in_(files)).returning(File.id)))
    for file in (files[i] for i in files if i in gone):
        session.add(ObjectDeletion(storage_key=file.storage_key, file_id=file.id))
        await audit.record(
            session,
            "file.deleted",
            actor_id=actor_id,
            target_kind="file",
            target_id=file.id,
            details={
                "name": file.name,
                "folder_id": str(file.folder_id) if file.folder_id else None,
                "status": file.status,
                "size": file.size,
            }
            | ({"reason": reason} if reason else {}),
        )
    return len(gone)


async def claim(session, *, limit: int, lease: timedelta) -> list[ObjectDeletion]:
    """Up to `limit` deletions nobody holds, for the caller to hold until `lease` runs
    out. Gateways claiming at once get different rows (SKIP LOCKED)."""
    now = datetime.now(UTC)
    free = (
        select(ObjectDeletion.id)
        .where((ObjectDeletion.claimed_until.is_(None)) | (ObjectDeletion.claimed_until < now))
        .order_by(ObjectDeletion.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    claimed = await session.scalars(
        update(ObjectDeletion)
        .where(ObjectDeletion.id.in_(free.scalar_subquery()))
        .values(claimed_until=now + lease, attempts=ObjectDeletion.attempts + 1)
        .returning(ObjectDeletion)
        .execution_options(synchronize_session=False),
    )
    return list(claimed)


async def pending(session) -> int:
    return await session.scalar(select(func.count()).select_from(ObjectDeletion)) or 0


async def confirm(session, ids: list[int]) -> list[ObjectDeletion]:
    """Remove confirmed deletions from the queue and record each; unknown ids (already
    confirmed by another gateway) are ignored."""
    done = list(
        await session.scalars(
            delete(ObjectDeletion).where(ObjectDeletion.id.in_(ids)).returning(ObjectDeletion)
        )
    )
    for row in done:
        await audit.record(
            session,
            "file.object_deleted",
            actor_kind="gateway",
            target_kind="file",
            target_id=row.file_id,
            details={"storage_key": row.storage_key, "attempts": row.attempts},
        )
    return done
