"""Node enrollment, the admin's side (M11, ADR 0014): the requests waiting, approval and
rejection, and the enrolled nodes, which an admin may revoke.

Approval is the first-trust check: the admin compares the key fingerprint the request
shows with the one the node shows its operator, out of band, and sends it back with the
approval. A different one is refused (and audited): the request's key isn't the node's.
The approval answers with a one-time code, shown once; the operator gives it to the
node, which completes its enrollment with it (vaultgate_api.routers.node_enrollment).
Approving again replaces the code.

Enrollment tokens are the other first-trust method admins hand out: a token for one node
name, single use, short lived, shown once (only its SHA-256 is kept). The node enrolls
with it (vaultgate_api.routers.node_enrollment); an unused one can be revoked.

TPM registrations are the third: an admin registers a TPM, by its endorsement key's
fingerprint, for one node name; the node then enrolls by TPM attestation, once.

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
from vaultgate_api.models import Node, NodeEnrollment, NodeEnrollmentToken, NodeTpm
from vaultgate_api.provisioning import CurrentUserDep
from vaultgate_api.routers.admin import Limit, Offset, Page, require_admin
from vaultgate_api.routers.node_enrollment import (
    EnrollmentOut,
    SignerDep,
    active_node,
    enrollment_out,
    state,
    usable_tpm,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/nodes", tags=["admin"], dependencies=[Depends(require_admin)])


class AdminEnrollmentOut(EnrollmentOut):
    method: str
    client_id: str | None
    client_ip: str | None
    created_at: datetime
    decided_at: datetime | None
    code_expires_at: datetime | None


def admin_enrollment_out(enrollment: NodeEnrollment, now: datetime) -> AdminEnrollmentOut:
    return AdminEnrollmentOut(
        **enrollment_out(enrollment, now).model_dump(),
        method=enrollment.method,
        client_id=enrollment.client_id,
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
    if enrollment.method != "admin_approval":  # a TPM's waits for its TPM, not an admin
        raise HTTPException(status.HTTP_409_CONFLICT, "The enrollment isn't waiting for approval")
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


class TokenIn(BaseModel):
    name: str = Field(pattern=nodes.NAME_PATTERN.pattern, max_length=63)
    # How long the token lasts; at most settings.node_token_max_ttl_seconds.
    ttl_seconds: int | None = Field(default=None, ge=60)


class TokenOut(BaseModel):
    id: uuid.UUID
    name: str
    identity: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None
    state: Literal["usable", "used", "revoked", "expired"]


class IssuedTokenOut(TokenOut):
    token: str  # shown once


def token_out(row: NodeEnrollmentToken, now: datetime) -> TokenOut:
    if row.used_at is not None:
        state = "used"
    elif row.revoked_at is not None:
        state = "revoked"
    elif row.expires_at <= now:
        state = "expired"
    else:
        state = "usable"
    return TokenOut(
        id=row.id,
        name=row.name,
        identity=nodes.identity(row.name),
        created_at=row.created_at,
        expires_at=row.expires_at,
        used_at=row.used_at,
        revoked_at=row.revoked_at,
        state=state,
    )


@router.post("/tokens", status_code=status.HTTP_201_CREATED)
async def issue_token(body: TokenIn, session: SessionDep, admin: CurrentUserDep) -> IssuedTokenOut:
    """An enrollment token for the node `name`: give it to the node, which enrolls with it
    once. The token is in this answer only."""
    if await active_node(session, body.name) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "A node of that name is enrolled")
    ttl = min(
        body.ttl_seconds or settings.node_token_ttl_seconds, settings.node_token_max_ttl_seconds
    )
    now = datetime.now(UTC)
    token = nodes.new_enrollment_token()
    row = NodeEnrollmentToken(
        id=uuid.uuid4(),
        name=body.name,
        token_hash=nodes.hash_token(token),
        created_by=admin.id,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    session.add(row)
    await audit.record(
        session,
        "node.enrollment_token_issued",
        actor_id=admin.id,
        target_kind="node_token",
        target_id=row.id,
        details={"name": row.name, "expires_at": row.expires_at.isoformat()},
    )
    await session.commit()
    logger.info("node enrollment token issued", extra={"token_id": str(row.id)})
    return IssuedTokenOut(**token_out(row, now).model_dump(), token=token)


@router.get("/tokens")
async def list_tokens(
    session: SessionDep,
    status_: Annotated[Literal["usable", "all"], Query(alias="status")] = "usable",
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[TokenOut]:
    now = datetime.now(UTC)
    query = select(NodeEnrollmentToken)
    if status_ == "usable":
        query = query.where(
            NodeEnrollmentToken.used_at.is_(None),
            NodeEnrollmentToken.revoked_at.is_(None),
            NodeEnrollmentToken.expires_at > now,
        )
    total = await session.scalar(select(func.count()).select_from(query.subquery()))
    rows = await session.scalars(
        query.order_by(NodeEnrollmentToken.created_at.desc()).limit(limit).offset(offset)
    )
    return Page(items=[token_out(t, now) for t in rows], total=total, limit=limit, offset=offset)


@router.post("/tokens/{token_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(token_id: uuid.UUID, session: SessionDep, admin: CurrentUserDep) -> None:
    """An unused token, no longer usable."""
    row = await session.get(NodeEnrollmentToken, token_id, with_for_update=True)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such token")
    if row.used_at is not None or row.revoked_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "The token is used or revoked already")
    row.revoked_at = datetime.now(UTC)
    await audit.record(
        session,
        "node.enrollment_token_revoked",
        actor_id=admin.id,
        target_kind="node_token",
        target_id=row.id,
        details={"name": row.name},
    )
    await session.commit()


class TpmIn(BaseModel):
    name: str = Field(pattern=nodes.NAME_PATTERN.pattern, max_length=63)
    # SHA-256 over the EK's SubjectPublicKeyInfo, as `vaultgate_node.py tpm-ek` shows it.
    ek_fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")


class TpmOut(BaseModel):
    id: uuid.UUID
    name: str
    identity: str
    ek_fingerprint: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None
    state: Literal["usable", "used", "revoked", "expired"]


def tpm_out(row: NodeTpm, now: datetime) -> TpmOut:
    if row.used_at is not None:
        state_ = "used"
    elif row.revoked_at is not None:
        state_ = "revoked"
    elif row.expires_at <= now:
        state_ = "expired"
    else:
        state_ = "usable"
    return TpmOut(
        id=row.id,
        name=row.name,
        identity=nodes.identity(row.name),
        ek_fingerprint=row.ek_fingerprint,
        created_at=row.created_at,
        expires_at=row.expires_at,
        used_at=row.used_at,
        revoked_at=row.revoked_at,
        state=state_,
    )


@router.post("/tpms", status_code=status.HTTP_201_CREATED)
async def register_tpm(body: TpmIn, session: SessionDep, admin: CurrentUserDep) -> TpmOut:
    """Register a TPM, by its EK's fingerprint, for the node `name`: that TPM may then
    enroll the node by attestation, once."""
    if await active_node(session, body.name) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "A node of that name is enrolled")
    taken = await session.scalar(
        select(NodeTpm).where(NodeTpm.ek_fingerprint == body.ek_fingerprint, *usable_tpm())
    )
    if taken is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "That TPM is registered already")
    now = datetime.now(UTC)
    row = NodeTpm(
        id=uuid.uuid4(),
        name=body.name,
        ek_fingerprint=body.ek_fingerprint,
        created_by=admin.id,
        created_at=now,
        expires_at=now + timedelta(seconds=settings.node_tpm_registration_ttl_seconds),
    )
    session.add(row)
    await audit.record(
        session,
        "node.tpm_registered",
        actor_id=admin.id,
        target_kind="node_tpm",
        target_id=row.id,
        details={"name": row.name, "ek_fingerprint": row.ek_fingerprint},
    )
    await session.commit()
    return tpm_out(row, now)


@router.get("/tpms")
async def list_tpms(
    session: SessionDep,
    status_: Annotated[Literal["usable", "all"], Query(alias="status")] = "usable",
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[TpmOut]:
    query = select(NodeTpm)
    if status_ == "usable":
        query = query.where(*usable_tpm())
    total = await session.scalar(select(func.count()).select_from(query.subquery()))
    rows = await session.scalars(
        query.order_by(NodeTpm.created_at.desc()).limit(limit).offset(offset)
    )
    now = datetime.now(UTC)
    return Page(items=[tpm_out(t, now) for t in rows], total=total, limit=limit, offset=offset)


@router.post("/tpms/{tpm_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_tpm(tpm_id: uuid.UUID, session: SessionDep, admin: CurrentUserDep) -> None:
    row = await session.get(NodeTpm, tpm_id, with_for_update=True)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such TPM registration")
    if row.used_at is not None or row.revoked_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "The registration is used or revoked already")
    row.revoked_at = datetime.now(UTC)
    await audit.record(
        session,
        "node.tpm_revoked",
        actor_id=admin.id,
        target_kind="node_tpm",
        target_id=row.id,
        details={"name": row.name, "ek_fingerprint": row.ek_fingerprint},
    )
    await session.commit()
