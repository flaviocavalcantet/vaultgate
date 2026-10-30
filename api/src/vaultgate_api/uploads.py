"""Which uploads are still alive, and marking the abandoned ones failed.

An upload is live while it can still finish: pending with an unused, unexpired intent,
or uploading and started less than upload_stale_after_seconds ago. Everything else in
pending/uploading was abandoned (the client never came, the gateway crashed, the API
was down when the gateway reported the result). The per-user cap ignores those, and
the sweep marks them failed so they stop showing as in progress. The S3 bucket's
lifecycle rule removes any multipart parts they left behind.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import ColumnElement, and_, exists, not_, or_, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vaultgate_api import metrics
from vaultgate_api.config import settings
from vaultgate_api.models import File, TransferIntent

logger = logging.getLogger("vaultgate.uploads")


def live_upload(now: datetime) -> ColumnElement[bool]:
    intent = TransferIntent
    live_pending = and_(
        File.status == "pending",
        exists().where(
            intent.file_id == File.id,
            intent.kind == "upload",
            intent.consumed_at.is_(None),
            intent.expires_at > now,
        ),
    )
    recent_uploading = and_(
        File.status == "uploading",
        exists().where(
            intent.file_id == File.id,
            intent.kind == "upload",
            intent.consumed_at > now - timedelta(seconds=settings.upload_stale_after_seconds),
        ),
    )
    return or_(live_pending, recent_uploading)


async def fail_abandoned_uploads(session: AsyncSession, now: datetime | None = None) -> int:
    """Mark abandoned uploads failed; returns how many. Safe to run concurrently."""
    now = now or datetime.now(UTC)
    result = await session.execute(
        update(File)
        .where(File.status.in_(("pending", "uploading")), not_(live_upload(now)))
        .values(status="failed")
        .execution_options(synchronize_session=False)
    )
    await session.commit()
    count = result.rowcount or 0
    if count:
        metrics.UPLOADS_ABANDONED.inc(count)
        logger.info("marked abandoned uploads failed", extra={"count": count})
    return count


async def run_sweeper(sessionmaker: async_sessionmaker[AsyncSession], interval: float) -> None:
    """Run the sweep forever; a failed round is logged and retried next interval."""
    while True:
        try:
            async with sessionmaker() as session:
                await fail_abandoned_uploads(session)
        except Exception:
            logger.exception("upload sweep failed")
        await asyncio.sleep(interval)
