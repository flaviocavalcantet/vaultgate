"""Node enrollment, the admin's side (M11, ADR 0014): the requests waiting, approval and
rejection, and the enrolled nodes, which an admin may revoke.

Approval is the first-trust check: the admin compares the key fingerprint the request
shows with the one the node shows its operator, out of band, and sends it back with the
approval. A different one is refused (and audited): the request's key isn't the node's.
The approval answers with a one-time code, shown once; the operator gives it to the
node, which completes its enrollment with it (vaultgate_api.routers.node_enrollment).
Approving again replaces the code.

Revoking a node revokes its current certificate in OpenBao (so OCSP and the lists show
it), then marks it revoked here, so it can't renew. Its name is free again.
"""

import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from vaultgate_api import audit, nodes
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.models import Node, NodeEnrollment
from vaultgate_api.provisioning import CurrentUserDep
from vaultgate_api.routers.admin import Limit, Offset, Page, require_admin
from vaultgate_api.routers.node_enrollment import (
    EnrollmentOut,
    SignerDep,
    active_node,
    enrollment_out,
    state,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/nodes", tags=["admin"], dependencies=[Depends(require_admin)])


class AdminEnrollmentOut(EnrollmentOut):
    client_ip: str | None
    created_at: datetime
    decided_at: datetime | None
    code_expires_at: datetime | None


def admin_enrollment_out(enrollment: NodeEnrollment, now: datetime) -> AdminEnrollmentOut:
    return AdminEnrollmentOut(
        **enrollment_out(enrollment, now).model_dump(),
        client_ip=str(enrollment.client_ip) if enrollment.client_ip is not None else None,
        created_at=enrollment.created_at,
        decided_at=enrollment.decided_at,
        code_expires_at=enrollment.code_expires_at,
    )


@router.get("/enrollments")
async def list_enrollments(
    session: SessionDep,
    status_: Annotated[Literal["waiting", "all"], Query(alias="status")] = "waiting",
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[AdminEnrollmentOut]:
    """Requests, newest first: by default those still waiting (pending or approved, not
    expired)."""
    now = datetime.now(UTC)
    query = select(NodeEnrollment)
    if status_ == "waiting":
        query = query.where(
            NodeEnrollment.status.in_(("pending", "approved")), NodeEnrollment.expires_at > now
        )
    total = await session.scalar(select(func.count()).select_from(query.subquery()))
    rows = await session.scalars(
        query.order_by(NodeEnrollment.created_at.desc()).limit(limit).offset(offset)
    )
    return Page(
        items=[admin_enrollment_out(e, now) for e in rows], total=total, limit=limit, offset=offset
    )


async def _waiting(session, enrollment_id: uuid.UUID) -> NodeEnrollment:
    enrollment = await session.get(NodeEnrollment, enrollment_id, with_for_update=True)
    if enrollment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such enrollment")
    if state(enrollment, datetime.now(UTC)) not in ("pending", "approved"):
        raise HTTPException(status.HTTP_409_CONFLICT, "The enrollment isn't waiting")
    return enrollment


class ApproveIn(BaseModel):
    # The fingerprint the node shows its operator: it must be the request's.
    key_fingerprint: str = Field(max_length=64)


class ApprovalOut(BaseModel):
    code: str
    code_expires_at: datetime


@router.post("/enrollments/{enrollment_id}/approve")
async def approve_enrollment(
    enrollment_id: uuid.UUID, body: ApproveIn, session: SessionDep, admin: CurrentUserDep
) -> ApprovalOut:
    """Approve the request once its key is confirmed: the answer is the one-time code,
    shown once, which the node completes its enrollment with."""
    enrollment = await _waiting(session, enrollment_id)
    fields = {"target_kind": "node_enrollment", "target_id": enrollment.id, "actor_id": admin.id}
    details = {"name": enrollment.name, "key_fingerprint": enrollment.key_fingerprint}
    if not secrets.compare_digest(body.key_fingerprint.strip(), enrollment.key_fingerprint):
        await session.rollback()
        await audit.record_refusal(
            session,
            "node.enrollment_approved",
            details=details | {"result": "fingerprint mismatch",
                               "confirmed": body.key_fingerprint[:64]},
            **fields,
        )  # fmt: skip
        raise HTTPException(
            status.HTTP_409_CONFLICT, "That isn't the request's key fingerprint: not approved"
        )
    if await active_node(session, enrollment.name) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "A node of that name is enrolled")
    now = datetime.now(UTC)
    code = nodes.new_code()
    enrollment.code_salt = secrets.token_hex(16)
    enrollment.code_hash = nodes.hash_code(code, enrollment.code_salt)
    enrollment.code_expires_at = min(
        now + timedelta(seconds=settings.node_code_ttl_seconds), enrollment.expires_at
    )
    enrollment.code_attempts = 0
    enrollment.status = "approved"
    enrollment.decided_by = admin.id
    enrollment.decided_at = now
    await audit.record(session, "node.enrollment_approved", details=details, **fields)
    await session.commit()
    logger.info("node enrollment approved", extra={"enrollment_id": str(enrollment.id)})
    return ApprovalOut(code=code, code_expires_at=enrollment.code_expires_at)


@router.post("/enrollments/{enrollment_id}/reject", status_code=status.HTTP_204_NO_CONTENT)
async def reject_enrollment(
    enrollment_id: uuid.UUID, session: SessionDep, admin: CurrentUserDep
) -> None:
    enrollment = await _waiting(session, enrollment_id)
    enrollment.status = "rejected"
    enrollment.code_hash = enrollment.code_salt = None
    enrollment.decided_by = admin.id
    enrollment.decided_at = datetime.now(UTC)
    await audit.record(
        session,
        "node.enrollment_rejected",
        actor_id=admin.id,
        target_kind="node_enrollment",
        target_id=enrollment.id,
        details={"name": enrollment.name, "key_fingerprint": enrollment.key_fingerprint},
    )
    await session.commit()


class NodeOut(BaseModel):
    id: uuid.UUID
    name: str
    identity: str
    status: str
    key_fingerprint: str
    cert_serial: str
    cert_expires_at: datetime
    enrolled_at: datetime
    renewed_at: datetime | None
    revoked_at: datetime | None


def node_out(node: Node) -> NodeOut:
    return NodeOut(
        id=node.id,
        name=node.name,
        identity=nodes.identity(node.name),
        status=node.status,
        key_fingerprint=node.key_fingerprint,
        cert_serial=node.cert_serial,
        cert_expires_at=node.cert_expires_at,
        enrolled_at=node.enrolled_at,
        renewed_at=node.renewed_at,
        revoked_at=node.revoked_at,
    )


@router.get("")
async def list_nodes(
    session: SessionDep,
    status_: Annotated[Literal["active", "all"], Query(alias="status")] = "active",
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[NodeOut]:
    query = select(Node)
    if status_ == "active":
        query = query.where(Node.status == "active")
    total = await session.scalar(select(func.count()).select_from(query.subquery()))
    rows = await session.scalars(query.order_by(Node.name).limit(limit).offset(offset))
    return Page(items=[node_out(n) for n in rows], total=total, limit=limit, offset=offset)


@router.post("/{node_id}/revoke")
async def revoke_node(
    node_id: uuid.UUID, session: SessionDep, admin: CurrentUserDep, signer: SignerDep
) -> NodeOut:
    """Revoke the node's certificate (OCSP and the lists show it) and the node: it can't
    renew, and its name may be enrolled again."""
    node = await session.get(Node, node_id, with_for_update=True)
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such node")
    if node.status != "active":
        raise HTTPException(status.HTTP_409_CONFLICT, "The node is already revoked")
    try:
        await signer.revoke(node.cert_serial)
    except nodes.SignerError:
        logger.exception("node certificate not revoked", extra={"node_id": str(node.id)})
        await session.rollback()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The CA is unavailable") from None
    node.status = "revoked"
    node.revoked_at = datetime.now(UTC)
    node.revoked_by = admin.id
    await audit.record(
        session,
        "node.revoked",
        actor_id=admin.id,
        target_kind="node",
        target_id=node.id,
        details={"name": node.name, "serial": node.cert_serial},
    )
    await session.commit()
    logger.info("node revoked", extra={"node_id": str(node.id)})
    return node_out(node)
