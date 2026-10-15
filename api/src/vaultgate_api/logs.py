"""Structured logging for the API.

Every log line is one JSON object on stdout, so a collector (Loki, CloudWatch, ...)
can index fields without parsing free text. Each line carries the request ID of the
request that produced it, which ties API, gateway and scanner logs together.

Never log secrets or file contents: no tokens, no query strings, no PII.
"""

import json
import logging
import re
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime

from starlette.types import ASGIApp, Message, Receive, Scope, Send

SERVICE = "api"
REQUEST_ID_HEADER = "x-request-id"

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

# A client-supplied request ID is accepted only if it is short and plain, so it
# cannot be used to inject fake fields or line breaks into the logs.
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Attributes every LogRecord has; anything else was passed through `extra=`.
# color_message is uvicorn's ANSI-colored duplicate of msg.
_STANDARD_ATTRS = set(vars(logging.makeLogRecord({}))) | {
    "message",
    "asctime",
    "taskName",
    "color_message",
}

access_logger = logging.getLogger("vaultgate.access")


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "service": self.service,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if request_id := request_id_var.get():
            entry["request_id"] = request_id
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Send all logging (ours, uvicorn's, SQLAlchemy's) through one stdout handler."""
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter(SERVICE))
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    # The middleware below writes access logs with more context than uvicorn's.
    logging.getLogger("uvicorn.access").disabled = True


def resolve_request_id(incoming: str | None) -> str:
    if incoming and _VALID_REQUEST_ID.match(incoming):
        return incoming
    return uuid.uuid4().hex


class RequestContextMiddleware:
    """Assigns a request ID, echoes it in the response, and writes one access log line.

    Pure ASGI rather than BaseHTTPMiddleware, so streaming responses are not buffered.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope["headers"])
        incoming = headers.get(REQUEST_ID_HEADER.encode())
        request_id = resolve_request_id(incoming.decode("latin-1") if incoming else None)
        token = request_id_var.set(request_id)
        start = time.perf_counter()
        status_code = 500

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                message.setdefault("headers", [])
                message["headers"].append((REQUEST_ID_HEADER.encode(), request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            client = scope.get("client")
            access_logger.info(
                "request",
                extra={
                    "method": scope["method"],
                    # Path only: query strings may carry share tokens in later milestones.
                    "path": scope["path"],
                    "status": status_code,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                    "client_ip": client[0] if client else None,
                },
            )
            request_id_var.reset(token)
