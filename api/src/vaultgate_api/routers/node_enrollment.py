"""Node enrollment, the node's side (M11, ADR 0014): ask for a certificate, wait, complete.

A node has no credential yet, so these routes take no token: they are limited per
client address, and each is under the access policies' `enroll` action, evaluated with
the node's address and the time (no groups: a node is no user). Policies deny by
default, so no node enrolls until an admin allows it, from the networks they choose.

1. POST /nodes/enrollments: the name the node asks for and a CSR for a key it
   generated. The answer has the request's ID and the key's fingerprint, which the node
   shows its operator.
2. An admin compares the fingerprint with the operator's and approves
   (vaultgate_api.routers.admin_nodes), which gives a one-time code; the operator
   passes it to the node.
3. POST /nodes/enrollments/{id}/complete with the code: the stored CSR is signed, so the
   code is good for that key only, and once.

Or, first trust by an admin's enrollment token: POST /nodes/enrollments/by-token, with
a token an admin issued for one node name (vaultgate_api.routers.admin_nodes): single
use, short lived. The token names the node, and the certificate comes back at once.

Or, first trust by a Keycloak client: POST /nodes/enrollments/by-client, with a token
of the node's own confidential client (node-<name>), which authenticates to Keycloak
with a JWT signed by the node's key (private_key_jwt). The token is for the audience
vaultgate-nodes, never the API's, so it opens no user route; it must carry the
enrollment role. No wait and no code: the certificate comes back at once. A client
enrolls one node, ever: its service account is recorded, and a second request with it
is refused, whatever Keycloak still allows (removing its role or the client afterwards
is the admin's tidying).

GET /nodes/enrollments/{id} tells a waiting node where its request is. Its ID is a
random UUID the node got back; the answer holds nothing a stranger could use.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vaultgate_api import audit, nodes, policies
from vaultgate_api.auth import Principal, TokenError, _unauthorized
from vaultgate_api.clientip import client_ip_var
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.models import Node, NodeEnrollment, NodeEnrollmentToken

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/nodes/enrollments", tags=["nodes"])

NOT_ALLOWED = "Node enrollment is not allowed from here"


def get_signer(request: Request) -> nodes.Signer:
    signer = getattr(request.app.state, "node_signer", None)
    if signer is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Node enrollment is off")
    return signer


SignerDep = Annotated[nodes.Signer, Depends(get_signer)]


async def enroll_allowed(session: AsyncSession) -> policies.Decision:
    """The access policies' `enroll` action, for the caller's address, now."""
    request = policies.AccessRequest.of("enroll", (), client_ip_var.get(), datetime.now(UTC))
    decision = await policies.check(session, request)
    if not decision.allowed:
        logger.info(
            "node enrollment refused by policy",
            extra={"reason": decision.reason, "deny_policies": list(decision.deny)},
        )
    return decision


def state(enrollment: NodeEnrollment, now: datetime) -> str:
    """pending, approved, completed or rejected; or expired, for a request still open
    after its time."""
    if enrollment.status in ("pending", "approved") and enrollment.expires_at <= now:
        return "expired"
    return enrollment.status


async def active_node(session: AsyncSession, name: str) -> Node | None:
    return await session.scalar(select(Node).where(Node.name == name, Node.status == "active"))


class EnrollmentIn(BaseModel):
    name: str = Field(pattern=nodes.NAME_PATTERN.pattern, max_length=63)
    csr: str = Field(max_length=nodes.MAX_CSR_BYTES)


class EnrollmentOut(BaseModel):
    id: uuid.UUID
    name: str
    identity: str
    key_fingerprint: str
    status: Literal["pending", "approved", "completed", "rejected", "expired"]
    expires_at: datetime


def enrollment_out(enrollment: NodeEnrollment, now: datetime) -> EnrollmentOut:
    return EnrollmentOut(
        id=enrollment.id,
        name=enrollment.name,
        identity=nodes.identity(enrollment.name),
        key_fingerprint=enrollment.key_fingerprint,
        status=state(enrollment, now),
        expires_at=enrollment.expires_at,
    )


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def request_enrollment(body: EnrollmentIn, session: SessionDep) -> EnrollmentOut:
    """Ask for a certificate for `name`, for the key in `csr`; it waits for an admin."""
    try:
        fingerprint = nodes.check_csr(body.csr)
    except nodes.InvalidCSR as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from None
    details = {"name": body.name, "key_fingerprint": fingerprint}
    if not (await enroll_allowed(session)).allowed:
        await audit.record_refusal(
            session, "node.enrollment_requested", actor_kind="node", details=details
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, NOT_ALLOWED)
    if await active_node(session, body.name) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "A node of that name is enrolled")
    now = datetime.now(UTC)
    waiting = (
        select(func.count())
        .select_from(NodeEnrollment)
        .where(NodeEnrollment.status.in_(("pending", "approved")), NodeEnrollment.expires_at > now)
    )
    # Per address first, so one client can't take every waiting place and keep real
    # nodes out for a day. Not per name: whoever knows a node's name could then keep its
    # real request out instead.
    address = client_ip_var.get()
    if address is not None and (
        await session.scalar(waiting.where(NodeEnrollment.client_ip == address))
        >= settings.node_max_pending_per_address
    ):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many enrollments from this address are waiting; try later",
        )
    if await session.scalar(waiting) >= settings.node_max_pending_enrollments:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Too many enrollments are waiting; try later"
        )
    enrollment = NodeEnrollment(
        id=uuid.uuid4(),
        name=body.name,
        method="admin_approval",
        csr=body.csr,
        key_fingerprint=fingerprint,
        status="pending",
        client_ip=client_ip_var.get(),
        expires_at=now + timedelta(seconds=settings.node_enrollment_ttl_seconds),
    )
    session.add(enrollment)
    await audit.record(
        session,
        "node.enrollment_requested",
        actor_kind="node",
        target_kind="node_enrollment",
        target_id=enrollment.id,
        details=details,
    )
    await session.commit()
    logger.info("node enrollment requested", extra={"enrollment_id": str(enrollment.id)})
    return enrollment_out(enrollment, now)


@router.get("/{enrollment_id}")
async def get_enrollment(enrollment_id: uuid.UUID, session: SessionDep) -> EnrollmentOut:
    enrollment = await session.get(NodeEnrollment, enrollment_id)
    if enrollment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such enrollment")
    return enrollment_out(enrollment, datetime.now(UTC))


class CompleteIn(BaseModel):
    code: str = Field(min_length=1, max_length=32)


class CertificateOut(BaseModel):
    node_id: uuid.UUID
    identity: str
    certificate: str
    chain: list[str]
    serial: str
    expires_at: datetime


@router.post("/{enrollment_id}/complete")
async def complete_enrollment(
    enrollment_id: uuid.UUID, body: CompleteIn, session: SessionDep, signer: SignerDep
) -> CertificateOut:
    """The approval's one-time code: the stored CSR is signed, and the node is enrolled."""
    enrollment = await session.get(NodeEnrollment, enrollment_id, with_for_update=True)
    if enrollment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such enrollment")
    now = datetime.now(UTC)
    target = {"target_kind": "node_enrollment", "target_id": enrollment.id}
    details = {"name": enrollment.name, "key_fingerprint": enrollment.key_fingerprint}

    async def refuse(result: str, code: int, detail: str) -> HTTPException:
        """Record the refusal, with whatever it changed, and commit."""
        await audit.record(
            session,
            "node.enrollment_completed",
            outcome="denied",
            actor_kind="node",
            details=details | {"result": result},
            **target,
        )
        await session.commit()
        logger.info("node enrollment refused", extra={"enrollment_id": str(enrollment_id),
                                                      "result": result})  # fmt: skip
        return HTTPException(code, detail)

    if not (await enroll_allowed(session)).allowed:
        raise await refuse("policy", status.HTTP_403_FORBIDDEN, NOT_ALLOWED)
    if state(enrollment, now) != "approved" or enrollment.code_hash is None:
        await session.rollback()  # nothing to try a code against: not audited, unbounded
        raise HTTPException(status.HTTP_409_CONFLICT, "The enrollment isn't waiting for a code")
    if enrollment.code_expires_at <= now:
        enrollment.code_hash = enrollment.code_salt = None
        raise await refuse("expired", status.HTTP_403_FORBIDDEN, "The code has expired")
    if not nodes.code_matches(body.code, enrollment.code_salt, enrollment.code_hash):
        enrollment.code_attempts += 1
        if enrollment.code_attempts >= settings.node_code_attempts:
            enrollment.code_hash = enrollment.code_salt = None
            enrollment.status = "rejected"  # a few tries for one code: ask again
            raise await refuse("exhausted", status.HTTP_403_FORBIDDEN, "Too many wrong codes")
        left = settings.node_code_attempts - enrollment.code_attempts
        raise await refuse("wrong", status.HTTP_403_FORBIDDEN, f"Wrong code; {left} tries left")
    if await active_node(session, enrollment.name) is not None:
        raise await refuse(
            "name taken", status.HTTP_409_CONFLICT, "A node of that name is enrolled"
        )

    identity = nodes.identity(enrollment.name)
    try:
        issued = await signer.sign(enrollment.csr, identity)
    except nodes.SignerError:
        logger.exception("node certificate not signed")
        await session.rollback()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The CA is unavailable") from None
    node = Node(
        id=uuid.uuid4(),
        name=enrollment.name,
        status="active",
        key_fingerprint=enrollment.key_fingerprint,
        cert_serial=issued.serial,
        cert_expires_at=issued.expires_at,
        enrolled_at=now,
        enrolled_by=enrollment.decided_by,
    )
    session.add(node)
    enrollment.code_hash = enrollment.code_salt = None  # single use
    enrollment.status = "completed"
    enrollment.completed_at = now
    enrollment.node_id = node.id
    await audit.record(
        session,
        "node.enrollment_completed",
        actor_kind="node",
        actor_id=node.id,
        details=details | {"node_id": str(node.id), "serial": issued.serial},
        **target,
    )
    try:
        await session.commit()
    except IntegrityError:  # another enrollment of the name won the race
        await session.rollback()
        await _revoke_quietly(signer, issued.serial)
        raise HTTPException(status.HTTP_409_CONFLICT, "A node of that name is enrolled") from None
    logger.info("node enrolled", extra={"node_id": str(node.id), "serial": issued.serial})
    return CertificateOut(
        node_id=node.id,
        identity=identity,
        certificate=issued.certificate,
        chain=issued.chain,
        serial=issued.serial,
        expires_at=issued.expires_at,
    )


_node_bearer = HTTPBearer(auto_error=False, description="A node client's access token")


async def node_client(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_node_bearer)],
) -> Principal:
    """The node client's token, for the node audience; else 401. Not counted towards the
    address's authentication failures, as the user routes' are: the route is limited per
    address already (limit_enroll), and a signed token can't be guessed."""
    if credentials is None:
        raise _unauthorized("missing_token")
    try:
        return await request.app.state.node_token_validator.validate(credentials.credentials)
    except TokenError as exc:
        logger.info("node client token rejected", extra={"reason": exc.reason})
        raise _unauthorized(exc.reason) from None


class ClientEnrollmentIn(BaseModel):
    csr: str = Field(max_length=nodes.MAX_CSR_BYTES)


@router.post("/by-client", status_code=status.HTTP_201_CREATED)
async def enroll_by_client(
    body: ClientEnrollmentIn,
    client: Annotated[Principal, Depends(node_client)],
    session: SessionDep,
    signer: SignerDep,
) -> CertificateOut:
    """First trust by the node's Keycloak client: its token, and a CSR. The node is named
    by its client (node-<name>); the client enrolls this one node, and never another."""
    prefix = settings.node_client_prefix
    client_id = client.client_id or ""
    name = client_id.removeprefix(prefix) if client_id.startswith(prefix) else ""
    details = {"client_id": client_id, "client_subject": client.subject, "name": name}

    async def refuse(result: str, code: int, detail: str) -> HTTPException:
        await session.rollback()
        await audit.record_refusal(
            session, "node.enrollment_completed", actor_kind="node",
            details=details | {"method": "keycloak_client", "result": result},
        )  # fmt: skip
        logger.info("node client enrollment refused", extra={"result": result})
        return HTTPException(code, detail)

    if not nodes.NAME_PATTERN.fullmatch(name):
        raise await refuse("not a node client", status.HTTP_403_FORBIDDEN, "Not a node's client")
    if settings.node_enroll_role not in client.roles:
        raise await refuse("no role", status.HTTP_403_FORBIDDEN, "The client may not enroll a node")
    try:
        fingerprint = nodes.check_csr(body.csr)
    except nodes.InvalidCSR as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from None
    details["key_fingerprint"] = fingerprint
    if not (await enroll_allowed(session)).allowed:
        raise await refuse("policy", status.HTTP_403_FORBIDDEN, NOT_ALLOWED)
    used = await session.scalar(
        select(NodeEnrollment).where(NodeEnrollment.client_subject == client.subject)
    )
    if used is not None:
        raise await refuse(
            "client used", status.HTTP_409_CONFLICT, "This client has enrolled a node already"
        )
    if await active_node(session, name) is not None:
        raise await refuse(
            "name taken", status.HTTP_409_CONFLICT, "A node of that name is enrolled"
        )

    identity = nodes.identity(name)
    try:
        issued = await signer.sign(body.csr, identity)
    except nodes.SignerError:
        logger.exception("node certificate not signed")
        await session.rollback()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The CA is unavailable") from None
    now = datetime.now(UTC)
    node = Node(
        id=uuid.uuid4(),
        name=name,
        status="active",
        key_fingerprint=fingerprint,
        cert_serial=issued.serial,
        cert_expires_at=issued.expires_at,
        enrolled_at=now,
    )
    enrollment = NodeEnrollment(
        id=uuid.uuid4(),
        name=name,
        method="keycloak_client",
        csr=body.csr,
        key_fingerprint=fingerprint,
        status="completed",
        client_ip=client_ip_var.get(),
        expires_at=now,
        completed_at=now,
        node_id=node.id,
        client_id=client_id,
        client_subject=client.subject,
    )
    session.add(node)
    await session.flush()  # the node first: the enrollment refers to it
    session.add(enrollment)
    await audit.record(
        session,
        "node.enrollment_completed",
        actor_kind="node",
        actor_id=node.id,
        target_kind="node_enrollment",
        target_id=enrollment.id,
        details=details | {"method": "keycloak_client", "node_id": str(node.id),
                           "serial": issued.serial},
    )  # fmt: skip
    try:
        await session.commit()
    except IntegrityError:  # the same client, or the name, in a concurrent request
        await session.rollback()
        await _revoke_quietly(signer, issued.serial)
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This client or name has enrolled a node already"
        ) from None
    logger.info("node enrolled by its client", extra={"node_id": str(node.id)})
    return CertificateOut(
        node_id=node.id,
        identity=identity,
        certificate=issued.certificate,
        chain=issued.chain,
        serial=issued.serial,
        expires_at=issued.expires_at,
    )


class TokenEnrollmentIn(BaseModel):
    token: str = Field(min_length=1, max_length=128)
    csr: str = Field(max_length=nodes.MAX_CSR_BYTES)


INVALID_TOKEN = "Not a valid enrollment token"


@router.post("/by-token", status_code=status.HTTP_201_CREATED)
async def enroll_by_token(
    body: TokenEnrollmentIn, session: SessionDep, signer: SignerDep
) -> CertificateOut:
    """First trust by an admin's enrollment token: the token (in the body, never a URL)
    and a CSR. The token names the node; it is used once."""
    row = await session.scalar(
        select(NodeEnrollmentToken)
        .where(NodeEnrollmentToken.token_hash == nodes.hash_token(body.token))
        .with_for_update()
    )
    if row is None:
        # Not audited: anyone can send any string, as often as the address limit lets
        # them. Known tokens' refusals are.
        await session.rollback()
        raise HTTPException(status.HTTP_403_FORBIDDEN, INVALID_TOKEN)
    now = datetime.now(UTC)
    details = {"method": "enrollment_token", "token_id": str(row.id), "name": row.name}

    async def refuse(result: str, code: int, detail: str) -> HTTPException:
        await session.rollback()
        await audit.record_refusal(
            session, "node.enrollment_completed", actor_kind="node",
            details=details | {"result": result},
        )  # fmt: skip
        logger.info("node token enrollment refused", extra={"result": result})
        return HTTPException(code, detail)

    if row.used_at is not None:
        raise await refuse("token used", status.HTTP_403_FORBIDDEN, INVALID_TOKEN)
    if row.revoked_at is not None:
        raise await refuse("token revoked", status.HTTP_403_FORBIDDEN, INVALID_TOKEN)
    if row.expires_at <= now:
        raise await refuse("token expired", status.HTTP_403_FORBIDDEN, INVALID_TOKEN)
    try:
        fingerprint = nodes.check_csr(body.csr)
    except nodes.InvalidCSR as e:
        await session.rollback()  # the token stays usable: the node may fix its CSR
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from None
    details["key_fingerprint"] = fingerprint
    if not (await enroll_allowed(session)).allowed:
        raise await refuse("policy", status.HTTP_403_FORBIDDEN, NOT_ALLOWED)
    if await active_node(session, row.name) is not None:
        raise await refuse(
            "name taken", status.HTTP_409_CONFLICT, "A node of that name is enrolled"
        )

    identity = nodes.identity(row.name)
    try:
        issued = await signer.sign(body.csr, identity)
    except nodes.SignerError:
        logger.exception("node certificate not signed")
        await session.rollback()  # nothing used up: the same token works once OpenBao does
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The CA is unavailable") from None
    node = Node(
        id=uuid.uuid4(),
        name=row.name,
        status="active",
        key_fingerprint=fingerprint,
        cert_serial=issued.serial,
        cert_expires_at=issued.expires_at,
        enrolled_at=now,
        enrolled_by=row.created_by,
    )
    session.add(node)
    await session.flush()
    enrollment = NodeEnrollment(
        id=uuid.uuid4(),
        name=row.name,
        method="enrollment_token",
        csr=body.csr,
        key_fingerprint=fingerprint,
        status="completed",
        client_ip=client_ip_var.get(),
        expires_at=row.expires_at,
        decided_by=row.created_by,
        decided_at=row.created_at,
        completed_at=now,
        node_id=node.id,
    )
    session.add(enrollment)
    await session.flush()
    row.used_at = now  # single use: with the node, or not at all
    row.enrollment_id = enrollment.id
    await audit.record(
        session,
        "node.enrollment_completed",
        actor_kind="node",
        actor_id=node.id,
        target_kind="node_enrollment",
        target_id=enrollment.id,
        details=details | {"node_id": str(node.id), "serial": issued.serial},
    )
    try:
        await session.commit()
    except IntegrityError:  # the name, enrolled by a concurrent request
        await session.rollback()
        await _revoke_quietly(signer, issued.serial)
        raise HTTPException(status.HTTP_409_CONFLICT, "A node of that name is enrolled") from None
    logger.info("node enrolled by token", extra={"node_id": str(node.id)})
    return CertificateOut(
        node_id=node.id,
        identity=identity,
        certificate=issued.certificate,
        chain=issued.chain,
        serial=issued.serial,
        expires_at=issued.expires_at,
    )


async def _revoke_quietly(signer: nodes.Signer, serial: str) -> None:
    """A certificate signed but never handed out: revoke it, or log that it stays valid
    until it expires (a day)."""
    try:
        await signer.revoke(serial)
    except nodes.SignerError:
        logger.exception("an unused node certificate was not revoked", extra={"serial": serial})
