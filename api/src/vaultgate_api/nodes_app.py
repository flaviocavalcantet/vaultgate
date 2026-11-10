"""The nodes' port (M11, ADR 0014): where enrolled nodes call the API, with their
certificates.

Mutual TLS: the server wants a client certificate from VaultGate's root
(settings.nodes_client_ca_file), and the routes want it to name a node,
spiffe://nodes.vaultgate/node/<name>, which only the nodes' CA may sign (its name
constraints; a service's certificate names no node). Then the node must be enrolled
and active, and the certificate its current one: an older certificate of the node, even
unexpired, is refused, as is any certificate of a revoked node. No token: the
certificate is the node's credential.

People never use this port: browsers and the frontend stay on the public port, with
their identity provider's tokens.

POST /renew: a CSR (the same key or a new one) for a new certificate; the presented one
is revoked once the new one is issued, so each certificate renews once. A node enrolled
by TPM attestation renews for the same key only: its TPM proved that key, and a new one
would come with no such proof.
GET /whoami: the node, as VaultGate sees it.
"""

import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from vaultgate_api import audit, nodes
from vaultgate_api.clientip import ClientAddressMiddleware
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.headers import SecurityHeadersMiddleware
from vaultgate_api.logs import RequestContextMiddleware
from vaultgate_api.models import Node, NodeEnrollment
from vaultgate_api.mtls import client_identities, client_serial
from vaultgate_api.routers.admin_nodes import NodeOut, node_out
from vaultgate_api.routers.node_enrollment import NOT_ALLOWED, SignerDep, enroll_allowed
from vaultgate_api.tracing import FASTAPI_TELEMETRY, TracingMiddleware

logger = logging.getLogger(__name__)

NOT_ENROLLED = "Not an enrolled node's current certificate"


async def current_node(request: Request, session: SessionDep) -> Node:
    """The active node whose current certificate the client presented, locked for this
    request's transaction."""
    name = nodes.name_of(client_identities(request.scope))
    serial = client_serial(request.scope)
    if name is None or serial is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not a node's certificate")
    node = await session.scalar(
        select(Node).where(Node.name == name, Node.status == "active").with_for_update()
    )
    if node is None or nodes.serial_int(node.cert_serial) != nodes.serial_int(serial):
        await audit.record_refusal(
            session,
            "node.authenticated",
            actor_kind="node",
            actor_id=node.id if node is not None else None,
            details={"name": name, "serial": serial,
                     "result": "unknown" if node is None else "not current"},
        )  # fmt: skip
        raise HTTPException(status.HTTP_403_FORBIDDEN, NOT_ENROLLED)
    return node


NodeDep = Annotated[Node, Depends(current_node)]


async def _tpm_bound(session, node: Node) -> bool:
    """Whether the node was enrolled by TPM attestation, so its key is the TPM's."""
    method = await session.scalar(
        select(NodeEnrollment.method).where(NodeEnrollment.node_id == node.id)
    )
    return method == "tpm"


router = APIRouter()


@router.get("/whoami")
async def whoami(node: NodeDep) -> NodeOut:
    return node_out(node)


class RenewIn(BaseModel):
    csr: str = Field(max_length=nodes.MAX_CSR_BYTES)


class RenewedOut(BaseModel):
    node_id: uuid.UUID
    identity: str
    certificate: str
    chain: list[str]
    serial: str
    expires_at: datetime


@router.post("/renew")
async def renew(body: RenewIn, node: NodeDep, session: SessionDep, signer: SignerDep) -> RenewedOut:
    """A new certificate for the node, for the CSR's key; the presented one is revoked."""
    try:
        fingerprint = nodes.check_csr(body.csr)
    except nodes.InvalidCSR as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from None
    if fingerprint != node.key_fingerprint and await _tpm_bound(session, node):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This node's key is attested to be in its TPM: renew for the same key",
        )
    fields = {
        "actor_kind": "node",
        "actor_id": node.id,
        "target_kind": "node",
        "target_id": node.id,
    }
    details = {
        "name": node.name,
        "key_fingerprint": fingerprint,
        "previous_serial": node.cert_serial,
    }
    if not (await enroll_allowed(session)).allowed:
        await session.rollback()
        await audit.record_refusal(session, "node.renewed", details=details, **fields)
        raise HTTPException(status.HTTP_403_FORBIDDEN, NOT_ALLOWED)
    identity = nodes.identity(node.name)
    try:
        issued = await signer.sign(body.csr, identity)
    except nodes.SignerError:
        logger.exception("node certificate not renewed", extra={"node_id": str(node.id)})
        await session.rollback()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The CA is unavailable") from None
    previous = node.cert_serial
    node.cert_serial = issued.serial
    node.cert_expires_at = issued.expires_at
    node.key_fingerprint = fingerprint
    node.renewed_at = datetime.now(UTC)
    await audit.record(
        session, "node.renewed", details=details | {"serial": issued.serial}, **fields
    )
    await session.commit()
    try:
        await signer.revoke(previous)
    except nodes.SignerError:
        # The new certificate is the node's current one either way, so the old one
        # renews nothing; it stays valid elsewhere until it expires (a day by default).
        logger.exception("the renewed certificate was not revoked", extra={"serial": previous})
    logger.info("node renewed", extra={"node_id": str(node.id), "serial": issued.serial})
    return RenewedOut(
        node_id=node.id,
        identity=identity,
        certificate=issued.certificate,
        chain=issued.chain,
        serial=issued.serial,
        expires_at=issued.expires_at,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        app.state.node_signer = nodes.openbao_signer(client)
        yield


nodes_app = FastAPI(
    lifespan=lifespan,
    title="VaultGate nodes API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    telemetry=FASTAPI_TELEMETRY,
)
nodes_app.add_middleware(RequestContextMiddleware)
# Nodes are outside: their own trace context is ignored, as the public port's clients'.
nodes_app.add_middleware(TracingMiddleware, trust_incoming=False)
nodes_app.add_middleware(ClientAddressMiddleware, trusted=settings.trusted_proxies)
nodes_app.add_middleware(SecurityHeadersMiddleware)
nodes_app.include_router(router)
