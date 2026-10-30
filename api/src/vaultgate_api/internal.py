"""Internal API for the gateway, served on its own port (VAULTGATE_INTERNAL_PORT).

The gateway never decides who may do what (ADR 0001). Before accepting an upload it
calls `consume` with the client's intent token; when the bytes are stored it reports
the result with `complete` or `fail`. Before serving a download it calls `consume` with
a download intent, which returns the wrapped data key needed to decrypt the object.

Every request must carry `Authorization: Bearer <VAULTGATE_INTERNAL_TOKEN>`. If no
token is configured, every request is refused: the internal API fails closed. The port
is never exposed through an ingress or published on the host.
"""

import base64
import hmac
import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import update

from vaultgate_api import intents
from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.logs import RequestContextMiddleware
from vaultgate_api.models import File

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)


async def require_gateway(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    expected = settings.internal_token.get_secret_value() if settings.internal_token else ""
    presented = credentials.credentials if credentials else ""
    if not expected or not hmac.compare_digest(presented.encode(), expected.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


router = APIRouter(prefix="/internal", dependencies=[Depends(require_gateway)])


class ConsumeRequest(BaseModel):
    token: str = Field(min_length=1, max_length=256)
    kind: Literal["upload", "download"]
    file_id: uuid.UUID


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


@router.post("/intents/consume")
async def consume_intent(body: ConsumeRequest, session: SessionDep) -> ConsumeResponse:
    """Validate and spend a client's intent token. For uploads, mark the file uploading;
    for downloads, return what the gateway needs to decrypt and serve it."""
    try:
        intent = await intents.consume(
            session, token=body.token, kind=body.kind, file_id=body.file_id
        )
    except intents.IntentRejected:
        await session.rollback()
        logger.info("intent rejected", extra={"file_id": str(body.file_id), "kind": body.kind})
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Intent not valid") from None
    file = await intents.file_for(session, intent)
    if body.kind == "upload":
        if file.status != "pending":
            await session.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT, detail="File is not awaiting upload")
        file.status = "uploading"
    elif file.status != "uploaded":
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="File is not available")
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


class CompleteRequest(BaseModel):
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    wrapped_key: str = Field(min_length=1, max_length=4096, description="base64")
    kms_key_id: str = Field(min_length=1, max_length=2048)


async def _finish(session, file_id: uuid.UUID, values: dict) -> File:
    file = await session.scalar(
        update(File)
        .where(File.id == file_id, File.status == "uploading")
        .values(**values)
        .returning(File)
    )
    if file is None:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="File is not being uploaded")
    await session.commit()
    return file


@router.post("/files/{file_id}/complete")
async def complete_upload(file_id: uuid.UUID, body: CompleteRequest, session: SessionDep) -> dict:
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
    file = await _finish(
        session,
        file_id,
        {**values, "status": "uploaded", "uploaded_at": datetime.now(UTC)},
    )
    logger.info("upload completed", extra={"file_id": str(file.id), "bytes": body.size})
    return {"status": file.status}


@router.post("/files/{file_id}/fail")
async def fail_upload(file_id: uuid.UUID, session: SessionDep) -> dict:
    file = await _finish(session, file_id, {"status": "failed"})
    logger.info("upload failed", extra={"file_id": str(file.id)})
    return {"status": file.status}


internal_app = FastAPI(
    title="VaultGate internal API", docs_url=None, redoc_url=None, openapi_url=None
)
internal_app.add_middleware(RequestContextMiddleware)
internal_app.include_router(router)
