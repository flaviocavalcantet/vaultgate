"""Deleting the stored objects of deleted files (M12.6, ADR 0020).

When a user deletes a file, the API deletes its row and wrapped key at once and queues
the object, which it can't delete itself (least privilege). Every gateway runs this
worker: it claims a batch from the API, deletes each object from S3 and confirms the
ones it deleted. One it couldn't delete is claimed again once the claim runs out, by
this gateway or another.

Only keys of the form `files/<uuid>`, the only keys files have, are deleted: a queue
row naming anything else is refused and left for an operator, so the API can't use the
gateway to delete arbitrary objects.
"""

import asyncio
import logging
import re

from vaultgate_gateway import metrics
from vaultgate_gateway.api_client import ApiUnavailable, IntentRefused, InternalApi
from vaultgate_gateway.storage import StorageUnavailable, delete_object

logger = logging.getLogger(__name__)

FILE_KEY = re.compile(r"^files/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


async def delete_batch(api: InternalApi, s3, bucket: str, batch: int) -> int:
    """Claim up to `batch` objects, delete them, confirm the deleted; returns how many
    were claimed."""
    claimed = await api.claim_deletions(batch)
    metrics.OBJECT_DELETIONS_PENDING.set(claimed.pending)
    deleted = []
    for item in claimed.items:
        if not FILE_KEY.match(item.storage_key):
            metrics.OBJECT_DELETIONS.labels("refused").inc()
            logger.error("refused to delete a key that is not a file's", extra={"id": item.id})
            continue
        try:
            await delete_object(s3, bucket, item.storage_key)
        except StorageUnavailable as exc:
            metrics.OBJECT_DELETIONS.labels("failed").inc()
            logger.warning(
                "object deletion failed; it will be retried",
                extra={"key": item.storage_key, "error": str(exc)},
            )
            continue
        metrics.OBJECT_DELETIONS.labels("deleted").inc()
        deleted.append(item.id)
    if deleted:
        await api.confirm_deletions(deleted)
        logger.info("objects deleted", extra={"count": len(deleted)})
    return len(claimed.items)


async def run(api: InternalApi, s3, bucket: str, *, interval: float, batch: int) -> None:
    """Delete forever: at once again after a full batch, else after `interval`."""
    while True:
        claimed = 0
        try:
            claimed = await delete_batch(api, s3, bucket, batch)
        except (ApiUnavailable, IntentRefused) as exc:
            logger.warning("could not reach the API for deletions", extra={"error": str(exc)})
        except Exception:
            logger.exception("deletion round failed")
        if claimed < batch:
            await asyncio.sleep(interval)
