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
scanned.

Quarantine (ADR 0005) decides two things for a file: whether its owner may download
it, and whether it may be shared. Sharing needs a clean verdict, or an admin's release
for sharing after a quarantined or unscannable one. Downloads need the same with
VAULTGATE_QUARANTINE_BLOCKS=download (the default); with "share", owners download
their own files whatever the verdict. Pending and unscannable files are blocked like
quarantined ones (fail closed). The API checks when it issues an intent or creates a
share, and again when the gateway consumes an intent. A release covers the scan it
was given for: a rescan starts a new request, and releases no longer apply.
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

from vaultgate_api import audit, metrics
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


# Why a download is refused, by verdict.
BLOCKED = {
    "pending": "File is waiting for its PII scan",
    "quarantined": "File is quarantined: it contains personal data",
    "unscannable": "File could not be scanned for personal data",
}


Purpose = Literal["download", "share"]


def released(file: File, purpose: Purpose) -> bool:
    """An admin released the file's current quarantined or unscannable verdict for
    this purpose."""
    return verdict(file) in ("quarantined", "unscannable") and any(
        r.purpose == purpose and r.scan_id == file.scan_id for r in file.releases
    )


def blocked(file: File, purpose: Purpose = "download") -> str | None:
    """Why the file may not be downloaded by its owner, or shared; None if it may."""
    v = verdict(file)
    if v is None:
        return "File is not available"
    if v == "clean" or released(file, purpose):
        return None
    if purpose == "download" and settings.quarantine_blocks == "share":
        return None
    return BLOCKED[v]


def check(file: File, purpose: Purpose, checked_by: str) -> str | None:
    """blocked(), counted and logged when it refuses."""
    reason = blocked(file, purpose)
    if reason is not None:
        v = verdict(file) or "none"
        counter = metrics.DOWNLOADS_BLOCKED if purpose == "download" else metrics.SHARES_BLOCKED
        counter.labels(v, checked_by).inc()
        logger.info(
            f"{purpose} blocked by scan",
            extra={"file_id": str(file.id), "verdict": v, "checked_by": checked_by},
        )
    return reason


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


async def rescan(session: AsyncSession, file: File, queue: ScanQueue) -> None:
    """Start a new scan of an uploaded file: findings and any release are dropped, and
    the request is sent (or left to the resender if the queue fails)."""
    for column, value in new_scan(datetime.now(UTC)).items():
        setattr(file, column, value)
    file.findings = []
    file.releases = []  # they named the old scan; dropped so they don't linger
    await session.commit()
    metrics.RESCANS.inc()
    if await send_request(queue, file.id, file.scan_id):
        metrics.SCAN_REQUESTS_SENT.labels("first").inc()


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
            await audit.record(
                session,
                "scan.abandoned",
                outcome="unscannable",
                actor_kind="system",
                target_kind="file",
                target_id=file.id,
                details={"attempts": file.scan_attempts},
            )
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
