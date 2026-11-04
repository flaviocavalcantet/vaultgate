"""The audit log, for admins (ADR 0007): read it, and check that it is intact.

Members of VAULTGATE_ADMIN_GROUPS only, like the rest of /admin. Reading never
changes the log; verifying walks the whole hash chain and reports the first event
that does not match.
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from vaultgate_api import audit
from vaultgate_api.db import SessionDep
from vaultgate_api.models import AuditEvent
from vaultgate_api.routers.admin import Limit, Offset, Page, require_admin

router = APIRouter(prefix="/admin/audit", tags=["admin"], dependencies=[Depends(require_admin)])


class AuditEventOut(BaseModel):
    id: int
    occurred_at: datetime
    actor_kind: str
    actor_id: uuid.UUID | None
    action: str
    outcome: str
    target_kind: str | None
    target_id: uuid.UUID | None
    client_ip: str | None
    request_id: str | None
    details: dict
    hash: str

    @classmethod
    def of(cls, event: AuditEvent) -> "AuditEventOut":
        return cls(
            id=event.id,
            occurred_at=event.occurred_at,
            actor_kind=event.actor_kind,
            actor_id=event.actor_id,
            action=event.action,
            outcome=event.outcome,
            target_kind=event.target_kind,
            target_id=event.target_id,
            client_ip=str(event.client_ip) if event.client_ip else None,
            request_id=event.request_id,
            details=event.details,
            hash=event.hash,
        )


@router.get("")
async def list_events(
    session: SessionDep,
    action: Annotated[
        str | None, Query(max_length=64, description="exact, or a prefix ending in '.'")
    ] = None,
    actor_id: uuid.UUID | None = None,
    target_id: uuid.UUID | None = None,
    outcome: Annotated[str | None, Query(max_length=16)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[AuditEventOut]:
    """Events, newest first. `action=share.` matches every share event."""
    where = []
    if action:
        where.append(
            AuditEvent.action.startswith(action, autoescape=True)
            if action.endswith(".")
            else AuditEvent.action == action
        )
    if actor_id:
        where.append(AuditEvent.actor_id == actor_id)
    if target_id:
        where.append(AuditEvent.target_id == target_id)
    if outcome:
        where.append(AuditEvent.outcome == outcome)
    if since:
        where.append(AuditEvent.occurred_at >= since)
    if until:
        where.append(AuditEvent.occurred_at < until)
    total = await session.scalar(select(func.count()).select_from(AuditEvent).where(*where))
    rows = await session.scalars(
        select(AuditEvent).where(*where).order_by(AuditEvent.id.desc()).limit(limit).offset(offset)
    )
    return Page(
        items=[AuditEventOut.of(e) for e in rows], total=total or 0, limit=limit, offset=offset
    )


class VerificationOut(BaseModel):
    ok: bool
    events: int
    head_id: int | None
    head_hash: str | None
    first_broken_id: int | None
    reason: str | None


@router.post("/verify")
async def verify_chain(session: SessionDep) -> VerificationOut:
    """Walk the whole chain. `ok` is false at the first event that was changed, or
    whose predecessor was removed; `head_*` is the last event checked before it."""
    result = await audit.verify(session)
    return VerificationOut(**result.__dict__)
