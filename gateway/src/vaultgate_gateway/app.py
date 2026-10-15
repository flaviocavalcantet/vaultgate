"""VaultGate streaming gateway.

Tornado is used here for one specific reason: `@stream_request_body` lets us process
an upload chunk by chunk as it arrives, so a 5 GB file costs the same memory as a
5 KB one. Each chunk will be encrypted and forwarded to object storage without the
full body ever being buffered.
"""

import asyncio
import hashlib
import logging
import os

import tornado.web
from prometheus_client import start_http_server

from vaultgate_gateway import metrics
from vaultgate_gateway.logs import (
    REQUEST_ID_HEADER,
    configure_logging,
    request_id_var,
    resolve_request_id,
)

MAX_UPLOAD_BYTES = int(os.getenv("VAULTGATE_MAX_UPLOAD_BYTES", str(5 * 1024**3)))

access_logger = logging.getLogger("vaultgate.access")


class BaseHandler(tornado.web.RequestHandler):
    """Assigns every request an ID, echoed back in the X-Request-ID response header."""

    # Path template used as the metrics label; set by each concrete handler.
    route = metrics.UNMATCHED_ROUTE
    request_id: str

    def prepare(self) -> None:
        self.request_id = resolve_request_id(self.request.headers.get(REQUEST_ID_HEADER))
        request_id_var.set(self.request_id)
        self.set_header(REQUEST_ID_HEADER, self.request_id)


def on_request_finished(handler: tornado.web.RequestHandler) -> None:
    """Tornado's log_function hook: one JSON access line and metrics per request."""
    route = getattr(handler, "route", metrics.UNMATCHED_ROUTE)
    method = handler.request.method or ""
    metrics.HTTP_REQUESTS.labels(method, route, str(handler.get_status())).inc()
    metrics.HTTP_DURATION.labels(method, route).observe(handler.request.request_time())

    level = logging.INFO if handler.get_status() < 500 else logging.ERROR
    access_logger.log(
        level,
        "request",
        extra={
            "request_id": getattr(handler, "request_id", None),
            "method": handler.request.method,
            # Path only: query strings may carry share tokens in later milestones.
            "path": handler.request.path,
            "status": handler.get_status(),
            "duration_ms": round(handler.request.request_time() * 1000, 2),
            "bytes_in": getattr(handler, "_received", None),
            "client_ip": handler.request.remote_ip,
        },
    )


class HealthHandler(BaseHandler):
    route = "/healthz"

    def get(self) -> None:
        self.write({"status": "ok", "service": "gateway"})


@tornado.web.stream_request_body
class UploadHandler(BaseHandler):
    """Receives a file as a raw request body, one chunk at a time.

    Skeleton only: today it hashes and counts bytes. The roadmap replaces the
    hashing with envelope encryption and a multipart upload to S3, and adds
    upload-intent validation against the API before any byte is accepted.
    """

    route = "/uploads/{upload_id}"
    _in_progress = False

    def prepare(self) -> None:
        super().prepare()
        self.request.connection.set_max_body_size(MAX_UPLOAD_BYTES)
        self._digest = hashlib.sha256()
        self._received = 0
        metrics.UPLOADS_IN_PROGRESS.inc()
        self._in_progress = True

    def data_received(self, chunk: bytes) -> None:
        self._digest.update(chunk)
        self._received += len(chunk)
        metrics.UPLOAD_BYTES.inc(len(chunk))

    def put(self, upload_id: str) -> None:
        metrics.UPLOAD_SIZE.observe(self._received)
        self.write(
            {
                "upload_id": upload_id,
                "bytes": self._received,
                "sha256": self._digest.hexdigest(),
            }
        )

    def on_finish(self) -> None:
        self._end_upload()

    def on_connection_close(self) -> None:
        # Client went away mid-upload; on_finish is not called in that case.
        self._end_upload()
        super().on_connection_close()

    def _end_upload(self) -> None:
        if self._in_progress:
            self._in_progress = False
            metrics.UPLOADS_IN_PROGRESS.dec()


def make_app() -> tornado.web.Application:
    return tornado.web.Application(
        [
            (r"/healthz", HealthHandler),
            (r"/uploads/([A-Za-z0-9_-]+)", UploadHandler),
        ],
        log_function=on_request_finished,
    )


async def main() -> None:
    configure_logging(
        os.getenv("VAULTGATE_LOG_LEVEL", "INFO"), os.getenv("VAULTGATE_LOG_FORMAT", "json")
    )
    port = int(os.getenv("VAULTGATE_GATEWAY_PORT", "8888"))
    metrics_port = int(os.getenv("VAULTGATE_METRICS_PORT", "9100"))
    metrics.BUILD_INFO.info({"service": "gateway", "version": "0.1.0"})
    start_http_server(metrics_port)
    make_app().listen(port, max_body_size=MAX_UPLOAD_BYTES)
    logging.getLogger("vaultgate.gateway").info(
        "gateway listening", extra={"port": port, "metrics_port": metrics_port}
    )
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
