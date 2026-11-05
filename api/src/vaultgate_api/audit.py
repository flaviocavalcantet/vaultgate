"""The audit log (ADR 0007): an append-only, hash-chained record of security events.

`record` adds an event to the caller's transaction, so an action and its record commit
together, or neither does. A refusal rolls its transaction back first and then records
the refusal in a new one (`record_refusal`), so the attempt is kept even though the
action never happened.

Every event stores a SHA-256 over its own fields and the previous event's hash. Writers
take a transaction-level advisory lock, so events are chained one at a time, in commit
order. `verify` walks the chain and reports the first event that does not match: a row
changed or removed (around the trigger that refuses both) shows up there. The head of
the chain is also logged every few minutes (`run_anchor`), so the latest events can't
be rewritten either without the logs disagreeing.

What is recorded is security events, never file contents or PII found by the scanner.
Recipients' addresses are recorded with the shares they belong to: an audit log has to
answer who received a file. The log is read by admins only (/admin/audit).
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vaultgate_api import metrics
from vaultgate_api.clientip import client_ip_var
from vaultgate_api.logs import request_id_var
from vaultgate_api.models import AuditEvent

logger = logging.getLogger("vaultgate.audit")

ActorKind = Literal["user", "recipient", "gateway", "scanner", "system"]

# The hash the first event chains to.
GENESIS = "0" * 64

# Arbitrary, fixed: the advisory lock that serializes writers of the chain.
_CHAIN_LOCK = 0x5641554C54  # "VAULT"


def canonical_ip(value) -> str | None:
    """One text form for an address, whatever wrote or read it: Postgres INET and
    Python's ipaddress disagree on some forms (IPv4-mapped IPv6, a /32 suffix), and the
    hash must not depend on which side rendered it. IPv4-mapped IPv6 becomes IPv4."""
    if value is None:
        return None
    address = ipaddress.ip_interface(str(value)).ip
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def event_hash(event: AuditEvent) -> str:
    """SHA-256 over the event's fields and the previous hash, in a fixed form."""
    fields = {
        "occurred_at": event.occurred_at.astimezone(UTC).isoformat(),
        "actor_kind": event.actor_kind,
        "actor_id": str(event.actor_id) if event.actor_id else None,
        "action": event.action,
        "outcome": event.outcome,
        "target_kind": event.target_kind,
        "target_id": str(event.target_id) if event.target_id else None,
        "client_ip": canonical_ip(event.client_ip),
        "request_id": event.request_id,
        "details": event.details or {},
        "prev_hash": event.prev_hash,
    }
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


async def record(
    session: AsyncSession,
    action: str,
    *,
    outcome: str = "ok",
    actor_kind: ActorKind = "user",
    actor_id: uuid.UUID | None = None,
    target_kind: str | None = None,
    target_id: uuid.UUID | None = None,
    client_ip: str | None = None,
    details: dict | None = None,
) -> None:
    """Add an event to the session's transaction; it is stored when that commits."""
    await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _CHAIN_LOCK})
    prev = await session.scalar(select(AuditEvent.hash).order_by(AuditEvent.id.desc()).limit(1))
    event = AuditEvent(
        occurred_at=datetime.now(UTC),
        actor_kind=actor_kind,
        actor_id=actor_id,
        action=action,
        outcome=outcome,
        target_kind=target_kind,
        target_id=target_id,
        client_ip=canonical_ip(client_ip if client_ip is not None else client_ip_var.get()),
        request_id=request_id_var.get(),
        details=details or {},
        prev_hash=prev or GENESIS,
    )
    event.hash = event_hash(event)
    session.add(event)
    await session.flush()
    metrics.AUDIT_EVENTS.labels(outcome).inc()


async def record_refusal(session: AsyncSession, action: str, **fields) -> None:
    """Record a refused attempt in a transaction of its own and commit it. Call after
    rolling back whatever the attempt had started."""
    await record(session, action, outcome=fields.pop("outcome", "denied"), **fields)
    await session.commit()


@dataclass
class Verification:
    ok: bool
    events: int  # events checked
    head_id: int | None
    head_hash: str | None
    first_broken_id: int | None = None
    reason: str | None = None


async def _events(session: AsyncSession, batch: int = 1000) -> AsyncIterator[AuditEvent]:
    last = 0
    while True:
        rows = (
            await session.scalars(
                select(AuditEvent)
                .where(AuditEvent.id > last)
                .order_by(AuditEvent.id)
                .limit(batch)
                # What the database holds now, never a copy the session cached.
                .execution_options(populate_existing=True)
            )
        ).all()
        if not rows:
            return
        for row in rows:
            yield row
        last = rows[-1].id
        session.expunge_all()  # keep memory flat over a long chain


async def verify(session: AsyncSession) -> Verification:
    """Walk the whole chain, oldest first, and stop at the first event that does not
    match its predecessor or its own fields."""
    prev, count, head = GENESIS, 0, None
    async for event in _events(session):
        if event.prev_hash != prev:
            return Verification(
                False,
                count,
                head and head[0],
                head and head[1],
                event.id,
                "does not chain to the event before it (one was removed or changed)",
            )
        if event_hash(event) != event.hash:
            return Verification(
                False,
                count,
                head and head[0],
                head and head[1],
                event.id,
                "its fields do not match its hash (it was changed)",
            )
        prev, count, head = event.hash, count + 1, (event.id, event.hash)
    return Verification(True, count, head and head[0], head and head[1])


async def head(session: AsyncSession) -> tuple[int, str] | None:
    row = (
        await session.execute(
            select(AuditEvent.id, AuditEvent.hash).order_by(AuditEvent.id.desc()).limit(1)
        )
    ).first()
    return (row.id, row.hash) if row else None


async def run_anchor(sessionmaker: async_sessionmaker[AsyncSession], interval: float) -> None:
    """Log the head of the chain every interval: a copy outside the database, so the
    newest events can't be rewritten without disagreeing with the logs."""
    while True:
        try:
            async with sessionmaker() as session:
                if current := await head(session):
                    logger.info(
                        "audit head", extra={"audit_id": current[0], "audit_hash": current[1]}
                    )
        except Exception:
            logger.exception("audit anchor failed")
        await asyncio.sleep(interval)
