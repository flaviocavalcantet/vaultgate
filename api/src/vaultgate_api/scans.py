"""Scanning uploaded files for personal data.

When an upload completes, the file gets a scan request: scan_status pending and a
fresh scan_id. The request goes to an SQS queue; the scanner worker reads it, fetches
what it needs to decrypt the object from the internal API, and reports the result
there. The database is the record of what still needs scanning and the queue only
delivers it, so a request that never reached the queue, or a message that was lost,
is sent again by the resender. After scan_max_attempts sends with no result, the
file is marked unscannable.

Verdicts are worked out when they are read, from the findings and the configured
quarantine kinds, so changing VAULTGATE_QUARANTINE_KINDS applies to files already
scanned. A pending or unscannable file is never clean: downloads will need a clean
scan (fail closed).
"""

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Annotated, Literal, Protocol

import boto3
from botocore.config import Config
from fastapi import Depends
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vaultgate_api import metrics
from vaultgate_api.config import settings
from vaultgate_api.models import File

logger = logging.getLogger("vaultgate.scans")

Verdict = Literal["pending", "clean", "quarantined", "unscannable"]

# A round of the resender handles at most this many files.
RESEND_BATCH = 100


def verdict(file: File) -> Verdict | None:
    """The file's scan verdict, or None if it was never uploaded."""
    if file.scan_status is None:
        return None
    if file.scan_status != "scanned":
        return file.scan_status  # pending or unscannable
    quarantine = set(settings.quarantine_kinds)
    return "quarantined" if any(f.kind in quarantine for f in file.findings) else "clean"


def new_scan(now: datetime) -> dict:
    """Column values for a new scan request, counted as sent once."""
    return {
        "scan_status": "pending",
        "scan_id": uuid.uuid4(),
        "scan_requested_at": now,
        "scan_attempts": 1,
        "scanned_at": None,
        "scan_reason": None,
    }


class ScanQueue(Protocol):
    async def send(self, file_id: uuid.UUID, scan_id: uuid.UUID) -> None: ...


class SqsScanQueue:
    def __init__(self, url: str, client) -> None:
        self.url = url
        self.client = client

    @classmethod
    def from_settings(cls, url: str) -> "SqsScanQueue":
        client = boto3.client(
            "sqs",
            region_name=settings.aws_region,
            endpoint_url=settings.aws_endpoint_url,
            # Short: a slow queue must not hold up the request that triggered the send.
            config=Config(connect_timeout=2, read_timeout=5, retries={"max_attempts": 2}),
        )
        return cls(url, client)

    async def send(self, file_id: uuid.UUID, scan_id: uuid.UUID) -> None:
        body = json.dumps({"file_id": str(file_id), "scan_id": str(scan_id)})
        await asyncio.to_thread(self.client.send_message, QueueUrl=self.url, MessageBody=body)


class NoScanQueue:
    """No queue configured: requests stay pending, so nothing becomes downloadable."""

    async def send(self, file_id: uuid.UUID, scan_id: uuid.UUID) -> None:
        raise RuntimeError("VAULTGATE_SCAN_QUEUE_URL is not set")


@lru_cache
def get_scan_queue() -> ScanQueue:
    if settings.scan_queue_url:
        return SqsScanQueue.from_settings(settings.scan_queue_url)
    logger.warning("no scan queue configured; uploaded files will stay pending")
    return NoScanQueue()


ScanQueueDep = Annotated[ScanQueue, Depends(get_scan_queue)]


async def send_request(queue: ScanQueue, file_id: uuid.UUID, scan_id: uuid.UUID) -> bool:
    """Send one scan request; a failure is logged and left to the resender."""
    try:
        await queue.send(file_id, scan_id)
    except Exception as exc:  # noqa: BLE001 - any failure is retried by the resender
        metrics.SCAN_SEND_FAILURES.inc()
        logger.warning("scan request not sent", extra={"file_id": str(file_id), "error": repr(exc)})
        return False
    return True


async def resend_stuck_scans(
    session: AsyncSession, queue: ScanQueue, now: datetime | None = None
) -> int:
    """Send again the pending scans that were never sent or got no result in time, and
    give up on those already sent scan_max_attempts times. Returns how many files it
    handled. Rows are locked with SKIP LOCKED, so API replicas can run it concurrently.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(seconds=settings.scan_resend_after_seconds)
    files = (
        await session.scalars(
            select(File)
            .where(
                File.scan_status == "pending",
                or_(File.scan_attempts == 0, File.scan_requested_at < cutoff),
            )
            .order_by(File.scan_requested_at)
            .limit(RESEND_BATCH)
            .with_for_update(skip_locked=True, of=File)
        )
    ).all()
    handled = 0
    for file in files:
        if file.scan_attempts >= settings.scan_max_attempts:
            file.scan_status = "unscannable"
            file.scan_reason = f"No scan result after {file.scan_attempts} attempts"
            file.scanned_at = now
            metrics.SCANS_ABANDONED.inc()
            metrics.SCAN_RESULTS.labels("unscannable").inc()
            logger.warning("scan abandoned", extra={"file_id": str(file.id)})
        elif await send_request(queue, file.id, file.scan_id):
            metrics.SCAN_REQUESTS_SENT.labels(
                "first" if file.scan_attempts == 0 else "resend"
            ).inc()
            file.scan_attempts += 1
            file.scan_requested_at = now
        else:
            break  # the queue is failing: leave the rest for the next round
        handled += 1
    await session.commit()
    if handled:
        logger.info("stuck scans handled", extra={"count": handled})
    return handled


async def run_resender(
    sessionmaker: async_sessionmaker[AsyncSession], queue: ScanQueue, interval: float
) -> None:
    """Run the resender forever; a failed round is logged and retried next interval."""
    while True:
        try:
            async with sessionmaker() as session:
                await resend_stuck_scans(session, queue)
        except Exception:
            logger.exception("scan resend failed")
        await asyncio.sleep(interval)
