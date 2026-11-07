"""Client for the API's internal endpoints (ADR 0001: the API decides, the gateway moves bytes)."""

import base64
import json
import ssl
import uuid
from dataclasses import dataclass, field

from opentelemetry.trace import SpanKind, StatusCode
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest

from vaultgate_gateway import tracing


class IntentRefused(Exception):
    """The API did not accept the intent token (unknown, used, expired, wrong file/kind)."""


class ApiUnavailable(Exception):
    """The API could not be reached or answered unexpectedly."""


@dataclass(frozen=True)
class UploadGrant:
    file_id: uuid.UUID
    storage_key: str
    declared_size: int
    # Whose transfer it is, for the per-user limits (vaultgate_gateway.limits).
    limit_key: str = ""


@dataclass(frozen=True)
class DownloadGrant:
    file_id: uuid.UUID
    storage_key: str
    name: str
    content_type: str
    size: int
    sha256: str
    wrapped_key: bytes = field(repr=False)
    kms_key_id: str
    limit_key: str = ""


class InternalApi:
    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        timeout: float = 10,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        # With mutual TLS: the context holding the client certificate (and the trust
        # store the API's certificate is verified against).
        self._ssl_context = ssl_context
        self._http = AsyncHTTPClient()

    async def _post(self, operation: str, path: str, body: dict) -> dict:
        if not self._token:
            raise ApiUnavailable("VAULTGATE_INTERNAL_TOKEN is not set")
        # The API continues this trace on its internal port (vaultgate_api.tracing).
        with tracing.tracer.start_as_current_span(
            f"api {operation}",
            kind=SpanKind.CLIENT,
            attributes={"http.request.method": "POST", "url.path": path},
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            request = HTTPRequest(
                f"{self._base}{path}",
                method="POST",
                body=json.dumps(body),
                headers=tracing.inject(
                    {
                        "Authorization": f"Bearer {self._token}",
                        "Content-Type": "application/json",
                    }
                ),
                connect_timeout=self._timeout,
                request_timeout=self._timeout,
                ssl_options=self._ssl_context,
            )
            try:
                response = await self._http.fetch(request)
            except HTTPClientError as exc:
                span.set_attribute("http.response.status_code", exc.code)
                if exc.code == 403 and path.endswith("/consume"):
                    raise IntentRefused from None
                if exc.code == 409:
                    raise IntentRefused from None
                span.set_status(StatusCode.ERROR)
                raise ApiUnavailable(f"internal API answered {exc.code}") from None
            except OSError as exc:
                span.set_attribute("error.type", type(exc).__name__)
                span.set_status(StatusCode.ERROR)
                raise ApiUnavailable(type(exc).__name__) from None
            span.set_attribute("http.response.status_code", response.code)
            return json.loads(response.body)

    async def _consume(
        self, token: str, kind: str, file_id: uuid.UUID, client_ip: str | None
    ) -> dict:
        # The API re-checks the access policies with the client address seen here
        # (None when it could not be told), and refuses with 403 like a bad token.
        return await self._post(
            f"consume {kind}",
            "/internal/intents/consume",
            {"token": token, "kind": kind, "file_id": str(file_id), "client_ip": client_ip},
        )

    async def consume_upload(
        self, token: str, file_id: uuid.UUID, client_ip: str | None
    ) -> UploadGrant:
        data = await self._consume(token, "upload", file_id, client_ip)
        return UploadGrant(
            file_id=uuid.UUID(data["file_id"]),
            storage_key=data["storage_key"],
            declared_size=data["declared_size"],
            limit_key=data.get("limit_key", ""),
        )

    async def consume_download(
        self, token: str, file_id: uuid.UUID, client_ip: str | None
    ) -> DownloadGrant:
        data = await self._consume(token, "download", file_id, client_ip)
        try:
            return DownloadGrant(
                file_id=uuid.UUID(data["file_id"]),
                storage_key=data["storage_key"],
                name=data["name"],
                content_type=data["content_type"],
                size=data["size"],
                sha256=data["sha256"],
                wrapped_key=base64.b64decode(data["wrapped_key"]),
                kms_key_id=data["kms_key_id"],
                limit_key=data.get("limit_key", ""),
            )
        except (KeyError, TypeError, ValueError):
            raise ApiUnavailable("incomplete download grant") from None

    async def complete(
        self, file_id: uuid.UUID, *, size: int, sha256: str, wrapped_key: bytes, kms_key_id: str
    ) -> None:
        await self._post(
            "complete",
            f"/internal/files/{file_id}/complete",
            {
                "size": size,
                "sha256": sha256,
                "wrapped_key": base64.b64encode(wrapped_key).decode(),
                "kms_key_id": kms_key_id,
            },
        )

    async def fail(self, file_id: uuid.UUID) -> None:
        await self._post("fail", f"/internal/files/{file_id}/fail", {})
