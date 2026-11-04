"""Internal API for the gateway, served on its own port (VAULTGATE_INTERNAL_PORT).

The gateway never decides who may do what (ADR 0001). Before accepting an upload it
calls `consume` with the client's intent token; when the bytes are stored it reports
the result with `complete` or `fail`. Before serving a download it calls `consume` with
a download intent, which returns the wrapped data key needed to decrypt the object.

`consume` also re-checks the access policies for the intent's user, with the client
address the gateway saw (ADR 0004), refuses intents of deactivated users, and, for
downloads, refuses files the scan does not allow (quarantine, ADR 0005). A refusal
leaves the intent unspent.

A completed upload gets a scan request (vaultgate_api.scans). The scanner worker uses
the `/internal/scans` routes: fetch what it needs to decrypt the object, then report
findings or that the file could not be read.

Gateway routes need `Authorization: Bearer <VAULTGATE_INTERNAL_TOKEN>` and scanner
routes `Bearer <VAULTGATE_SCANNER_TOKEN>`; neither secret opens the other's routes. A
secret that is not configured refuses every request: the internal API fails closed.
The port is never exposed through an ingress or published on the host.
"""

import base64
import hmac
import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, IPvAnyAddress, SecretStr, field_validator
from sqlalchemy import select, update

from vaultgate_api import audit, intents, metrics, scans
from vaultgate_api.access import DENIED, authorize
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.logs import RequestContextMiddleware
from vaultgate_api.models import File, ScanFinding, Share, User

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)


def _check(credentials: HTTPAuthorizationCredentials | None, secret: SecretStr | None) -> None:
    expected = secret.get_secret_value() if secret else ""
    presented = credentials.credentials if credentials else ""
    if not expected or not hmac.compare_digest(presented.encode(), expected.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]


async def require_gateway(credentials: Credentials) -> None:
    _check(credentials, settings.internal_token)


async def require_scanner(credentials: Credentials) -> None:
    _check(credentials, settings.scanner_token)


router = APIRouter(prefix="/internal", dependencies=[Depends(require_gateway)])
scanner_router = APIRouter(prefix="/internal/scans", dependencies=[Depends(require_scanner)])


class ConsumeRequest(BaseModel):
    token: str = Field(min_length=1, max_length=256)
    kind: Literal["upload", "download"]
    file_id: uuid.UUID
    # The client address as the gateway resolved it; None if it could not tell.
    client_ip: IPvAnyAddress | None = None


class ConsumeResponse(BaseModel):
    file_id: uuid.UUID
    owner_id: uuid.UUID
    storage_key: str
    declared_size: int
    content_type: str
    # Set for downloads only.
    name: str | None = None
    size: int | None = None
    sha256: str | None = None
    wrapped_key: str | None = Field(default=None, description="base64")
    kms_key_id: str | None = None


async def _refuse(
    session, code: int, detail: str, action: str, *, client_ip: str | None, **fields
) -> HTTPException:
    """Roll back (the intent stays unspent), record the refusal, and return the error
    to raise."""
    await session.rollback()
    await audit.record_refusal(session, action, client_ip=client_ip, **fields)
    return HTTPException(code, detail=detail)


@router.post("/intents/consume")
async def consume_intent(body: ConsumeRequest, session: SessionDep) -> ConsumeResponse:
    """Validate and spend a client's intent token. For uploads, mark the file uploading;
    for downloads, return what the gateway needs to decrypt and serve it."""
    client_ip = str(body.client_ip) if body.client_ip else None
    target = {"target_kind": "file", "target_id": body.file_id}
    try:
        intent = await intents.consume(
            session, token=body.token, kind=body.kind, file_id=body.file_id
        )
    except intents.IntentRejected:
        logger.info("intent rejected", extra={"file_id": str(body.file_id), "kind": body.kind})
        raise await _refuse(
            session,
            status.HTTP_403_FORBIDDEN,
            "Intent not valid",
            "intent.rejected",
            client_ip=client_ip,
            actor_kind="gateway",
            details={"kind": body.kind},
            **target,
        ) from None
    user = await session.get(User, intent.created_by)
    user_id, share_id = intent.created_by, intent.share_id
    if user is None or not user.is_active:
        logger.info("intent of an inactive user refused", extra={"file_id": str(body.file_id)})
        raise await _refuse(
            session,
            status.HTTP_403_FORBIDDEN,
            "User is deactivated",
            "intent.refused",
            client_ip=client_ip,
            actor_id=user_id,
            details={"kind": body.kind, "reason": "user deactivated"},
            **target,
        )
    if share_id is None:
        decision = await authorize(
            session, action=body.kind, user=user, client_ip=client_ip, checked_by="gateway"
        )
        if not decision.allowed:
            raise await _refuse(
                session,
                status.HTTP_403_FORBIDDEN,
                DENIED,
                "access.denied",
                client_ip=client_ip,
                actor_id=user_id,
                details={
                    "action": body.kind,
                    "reason": decision.reason,
                    "deny_policies": list(decision.deny),
                    "checked_by": "gateway",
                },
                **target,
            )
    file = await intents.file_for(session, intent)
    if share_id is not None:
        return await _consume_share_download(session, intent, file, client_ip)
    refused = None
    if body.kind == "upload":
        if file.status != "pending":
            refused = "File is not awaiting upload"
        else:
            file.status = "uploading"
    elif file.status != "uploaded":
        refused = "File is not available"
    elif reason := scans.check(file, "download", checked_by="gateway"):
        # The verdict changed since the intent was issued (a rescan, other quarantine
        # kinds); the intent stays unspent.
        refused = reason
    if refused:
        raise await _refuse(
            session,
            status.HTTP_409_CONFLICT,
            refused,
            f"{body.kind}.refused",
            client_ip=client_ip,
            actor_id=user_id,
            details={"reason": refused, "checked_by": "gateway"},
            **target,
        )
    await audit.record(
        session, f"{body.kind}.started", actor_id=user_id, client_ip=client_ip, **target
    )
    await session.commit()
    logger.info("intent consumed", extra={"file_id": str(file.id), "kind": body.kind})
    response = ConsumeResponse(
        file_id=file.id,
        owner_id=file.owner_id,
        storage_key=file.storage_key,
        declared_size=file.declared_size,
        content_type=file.content_type,
    )
    if body.kind == "download":
        response.name = file.name
        response.size = file.size
        response.sha256 = file.sha256
        response.wrapped_key = base64.b64encode(file.wrapped_key).decode()
        response.kms_key_id = file.kms_key_id
    return response


async def _consume_share_download(
    session, intent, file: File, client_ip: str | None
) -> ConsumeResponse:
    """A recipient's download through a share: the share must still be active and the
    file shareable (a revoke, an expiry or a rescan applies at once), and the download
    is counted against the share.

    An external recipient's intent is made out to the owner, whose access policies are
    not checked: they decided on sharing when the link was made. An internal
    recipient's intent is made out to the recipient, a VaultGate user like any other:
    their own policies apply to the download, the owner must still be active, and their
    verified email must still be the share's address.
    """
    share_id, file_id = intent.share_id, file.id  # a rollback expires both
    share = await session.get(Share, share_id)
    internal = share is not None and share.recipient_kind == "internal"
    # The audit names the recipient: a user when internal, the share's address otherwise.
    who = (
        {"actor_kind": "user", "actor_id": intent.created_by}
        if internal
        else {"actor_kind": "recipient", "actor_id": None}
    )
    target = {"target_kind": "file", "target_id": file_id}
    details = {"share_id": str(share_id)}
    if share is not None:
        details["recipient_email"] = share.recipient_email

    async def refuse(code: int, detail: str, event: str = "share.download_refused", **more):
        return await _refuse(
            session,
            code,
            detail,
            event,
            client_ip=client_ip,
            details=details | {"reason": detail, "checked_by": "gateway"} | more,
            **who,
            **target,
        )

    if internal:
        recipient = await session.get(User, intent.created_by)
        owner = await session.get(User, share.created_by)
        if (
            owner is None
            or not owner.is_active
            or not recipient.email_verified
            or (recipient.email or "").lower() != share.recipient_email
        ):
            raise await refuse(status.HTTP_403_FORBIDDEN, "Share is no longer active")
        decision = await authorize(
            session, action="download", user=recipient, client_ip=client_ip, checked_by="gateway"
        )
        if not decision.allowed:
            raise await refuse(
                status.HTTP_403_FORBIDDEN,
                DENIED,
                "access.denied",
                action="download",
                deny_policies=list(decision.deny),
            )
    if file.status != "uploaded":
        raise await refuse(status.HTTP_409_CONFLICT, "File is not available")
    if reason := scans.check(file, "share", checked_by="gateway"):
        raise await refuse(status.HTTP_409_CONFLICT, reason)
    now = datetime.now(UTC)
    counted = await session.scalar(
        update(Share)
        .where(
            Share.id == share_id,
            Share.revoked_at.is_(None),
            Share.expires_at > now,
            Share.downloads < Share.max_downloads,
        )
        .values(downloads=Share.downloads + 1)
        .returning(Share.id)
    )
    if counted is None:
        logger.info("share download refused", extra={"share_id": str(share_id)})
        raise await refuse(status.HTTP_403_FORBIDDEN, "Share is no longer active")
    await audit.record(
        session, "share.downloaded", client_ip=client_ip, details=details, **who, **target
    )
    await session.commit()
    metrics.SHARE_DOWNLOADS.inc()
    logger.info(
        "share download started",
        extra={"file_id": str(file_id), "share_id": str(share_id)},
    )
    return ConsumeResponse(
        file_id=file.id,
        owner_id=file.owner_id,
        storage_key=file.storage_key,
        declared_size=file.declared_size,
        content_type=file.content_type,
        name=file.name,
        size=file.size,
        sha256=file.sha256,
        wrapped_key=base64.b64encode(file.wrapped_key).decode(),
        kms_key_id=file.kms_key_id,
    )


class CompleteRequest(BaseModel):
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    wrapped_key: str = Field(min_length=1, max_length=4096, description="base64")
    kms_key_id: str = Field(min_length=1, max_length=2048)


async def _finish(
    session, file_id: uuid.UUID, values: dict, action: str, details: dict | None = None
) -> File:
    file = await session.scalar(
        update(File)
        .where(File.id == file_id, File.status == "uploading")
        .values(**values)
        .returning(File)
    )
    if file is None:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="File is not being uploaded")
    await audit.record(
        session,
        action,
        actor_kind="gateway",
        target_kind="file",
        target_id=file.id,
        details={"owner_id": str(file.owner_id)} | (details or {}),
    )
    await session.commit()
    return file


@router.post("/files/{file_id}/complete")
async def complete_upload(
    file_id: uuid.UUID,
    body: CompleteRequest,
    session: SessionDep,
    queue: scans.ScanQueueDep,
    background: BackgroundTasks,
) -> dict:
    try:
        wrapped = base64.b64decode(body.wrapped_key, validate=True)
    except ValueError:
        raise HTTPException(422, detail="wrapped_key is not base64") from None
    values = {
        "size": body.size,
        "sha256": body.sha256,
        "wrapped_key": wrapped,
        "kms_key_id": body.kms_key_id,
    }
    # Idempotent: the gateway retries when a response is lost, so repeating the call
    # that already completed this file succeeds; anything else is still a conflict.
    done = await session.get(File, file_id)
    if done is not None and done.status == "uploaded":
        if all(getattr(done, k) == v for k, v in values.items()):
            return {"status": done.status}
        raise HTTPException(status.HTTP_409_CONFLICT, detail="File is not being uploaded")
    now = datetime.now(UTC)
    file = await _finish(
        session,
        file_id,
        {**values, "status": "uploaded", "uploaded_at": now, **scans.new_scan(now)},
        "upload.completed",
        {"size": body.size, "sha256": body.sha256},
    )
    logger.info("upload completed", extra={"file_id": str(file.id), "bytes": body.size})
    # After the response, so a slow queue does not hold up the gateway; a request that
    # is not sent is picked up by the resender.
    background.add_task(_send_first_request, queue, file.id, file.scan_id)
    return {"status": file.status}


async def _send_first_request(
    queue: scans.ScanQueue, file_id: uuid.UUID, scan_id: uuid.UUID
) -> None:
    if await scans.send_request(queue, file_id, scan_id):
        metrics.SCAN_REQUESTS_SENT.labels("first").inc()


@router.post("/files/{file_id}/fail")
async def fail_upload(file_id: uuid.UUID, session: SessionDep) -> dict:
    file = await _finish(session, file_id, {"status": "failed"}, "upload.failed")
    logger.info("upload failed", extra={"file_id": str(file.id)})
    return {"status": file.status}


class ScanJob(BaseModel):
    file_id: uuid.UUID
    storage_key: str
    size: int
    content_type: str
    wrapped_key: str = Field(description="base64")
    kms_key_id: str


async def _scan_file(session, scan_id: uuid.UUID, *, lock: bool = False) -> File:
    query = select(File).where(File.scan_id == scan_id)
    file = await session.scalar(query.with_for_update() if lock else query)
    if file is None:
        # Unknown, or replaced by a newer request: the worker drops the message.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return file


@scanner_router.get("/{scan_id}")
async def get_scan_job(scan_id: uuid.UUID, session: SessionDep) -> ScanJob:
    """What the scanner needs to read the object: where it is and its wrapped data key.
    Only while the scan is pending."""
    file = await _scan_file(session, scan_id)
    if file.scan_status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Scan already has a result")
    return ScanJob(
        file_id=file.id,
        storage_key=file.storage_key,
        size=file.size,
        content_type=file.content_type,
        wrapped_key=base64.b64encode(file.wrapped_key).decode(),
        kms_key_id=file.kms_key_id,
    )


class FindingIn(BaseModel):
    # The scanner's detector names, e.g. payment_card, br_cpf, email.
    kind: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    count: int = Field(ge=1)


class ScanResult(BaseModel):
    outcome: Literal["scanned", "unscannable"]
    # Findings of an unscannable file are what was read before it failed.
    findings: list[FindingIn] = Field(default=[], max_length=64)
    # Why the file could not be read; never file content.
    reason: str | None = Field(default=None, max_length=500)

    @field_validator("findings")
    @classmethod
    def one_entry_per_kind(cls, value: list[FindingIn]) -> list[FindingIn]:
        if len({f.kind for f in value}) != len(value):
            raise ValueError("each kind may appear only once")
        return sorted(value, key=lambda f: f.kind)


def _recorded(file: File) -> ScanResult:
    return ScanResult(
        outcome=file.scan_status,
        findings=[FindingIn(kind=f.kind, count=f.count) for f in file.findings],
        reason=file.scan_reason,
    )


@scanner_router.post("/{scan_id}/result")
async def report_scan(scan_id: uuid.UUID, body: ScanResult, session: SessionDep) -> dict:
    """Record a scan result. Repeating the result already recorded succeeds (the worker
    retries when a response is lost); a different one for the same scan is a conflict."""
    file = await _scan_file(session, scan_id, lock=True)
    if file.scan_status != "pending":
        same, verdict = _recorded(file) == body, scans.verdict(file)
        await session.rollback()  # release the lock
        if same:
            return {"verdict": verdict}
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Scan already has a result")
    file.scan_status = body.outcome
    file.scan_reason = body.reason
    file.scanned_at = datetime.now(UTC)
    file.findings = [ScanFinding(kind=f.kind, count=f.count) for f in body.findings]
    verdict = scans.verdict(file)
    await audit.record(
        session,
        "scan.result",
        outcome=verdict,
        actor_kind="scanner",
        target_kind="file",
        target_id=file.id,
        details={
            "scan_id": str(scan_id),
            "findings": {f.kind: f.count for f in body.findings},
            "reason": body.reason,
        },
    )
    await session.commit()
    metrics.SCAN_RESULTS.labels(verdict).inc()
    logger.info(
        "scan result recorded",
        extra={
            "file_id": str(file.id),
            "verdict": verdict,
            "findings": {f.kind: f.count for f in body.findings},
        },
    )
    return {"verdict": verdict}


internal_app = FastAPI(
    title="VaultGate internal API", docs_url=None, redoc_url=None, openapi_url=None
)
internal_app.add_middleware(RequestContextMiddleware)
internal_app.include_router(router)
internal_app.include_router(scanner_router)
