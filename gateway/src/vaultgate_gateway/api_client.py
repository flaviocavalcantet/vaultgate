"""Client for the API's internal endpoints (ADR 0001: the API decides, the gateway moves bytes)."""

import base64
import json
import uuid
from dataclasses import dataclass

from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest


class IntentRefused(Exception):
    """The API did not accept the intent token (unknown, used, expired, wrong file/kind)."""


class ApiUnavailable(Exception):
    """The API could not be reached or answered unexpectedly."""


@dataclass(frozen=True)
class UploadGrant:
    file_id: uuid.UUID
    storage_key: str
    declared_size: int


class InternalApi:
    def __init__(self, base_url: str, token: str | None, *, timeout: float = 10) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._http = AsyncHTTPClient()

    async def _post(self, path: str, body: dict) -> dict:
        if not self._token:
            raise ApiUnavailable("VAULTGATE_INTERNAL_TOKEN is not set")
        request = HTTPRequest(
            f"{self._base}{path}",
            method="POST",
            body=json.dumps(body),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
            connect_timeout=self._timeout,
            request_timeout=self._timeout,
        )
        try:
            response = await self._http.fetch(request)
        except HTTPClientError as exc:
            if exc.code == 403 and path.endswith("/consume"):
                raise IntentRefused from None
            if exc.code == 409:
                raise IntentRefused from None
            raise ApiUnavailable(f"internal API answered {exc.code}") from None
        except OSError as exc:
            raise ApiUnavailable(type(exc).__name__) from None
        return json.loads(response.body)

    async def consume_upload(self, token: str, file_id: uuid.UUID) -> UploadGrant:
        data = await self._post(
            "/internal/intents/consume",
            {"token": token, "kind": "upload", "file_id": str(file_id)},
        )
        return UploadGrant(
            file_id=uuid.UUID(data["file_id"]),
            storage_key=data["storage_key"],
            declared_size=data["declared_size"],
        )

    async def complete(
        self, file_id: uuid.UUID, *, size: int, sha256: str, wrapped_key: bytes, kms_key_id: str
    ) -> None:
        await self._post(
            f"/internal/files/{file_id}/complete",
            {
                "size": size,
                "sha256": sha256,
                "wrapped_key": base64.b64encode(wrapped_key).decode(),
                "kms_key_id": kms_key_id,
            },
        )

    async def fail(self, file_id: uuid.UUID) -> None:
        await self._post(f"/internal/files/{file_id}/fail", {})
