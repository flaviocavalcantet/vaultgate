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
import uuid
from dataclasses import dataclass

import tornado.web
from prometheus_client import start_http_server

from vaultgate_gateway import metrics
from vaultgate_gateway.api_client import ApiUnavailable, IntentRefused, InternalApi, UploadGrant
from vaultgate_gateway.crypto import Encryptor
from vaultgate_gateway.keys import KeyProvider, KeyUnavailable, KmsKeyProvider
from vaultgate_gateway.logs import (
    REQUEST_ID_HEADER,
    configure_logging,
    request_id_var,
    resolve_request_id,
)
from vaultgate_gateway.settings import settings
from vaultgate_gateway.storage import MultipartWriter, StorageUnavailable, s3_client

access_logger = logging.getLogger("vaultgate.access")
logger = logging.getLogger("vaultgate.gateway")

# Reporting a finished upload is retried: losing that call loses the upload.
COMPLETE_ATTEMPTS = 3
COMPLETE_RETRY_DELAY = 0.5  # seconds, grows linearly

# Cleanup started from synchronous callbacks; the event loop only keeps weak references
# to tasks, so they are held here until done.
_background_tasks: set[asyncio.Task] = set()


def _background(coro) -> None:
    task = asyncio.ensure_future(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


class BaseHandler(tornado.web.RequestHandler):
    """Assigns every request an ID, echoed back in the X-Request-ID response header."""

    # Path template used as the metrics label; set by each concrete handler.
    route = metrics.UNMATCHED_ROUTE
    request_id: str

    def prepare(self) -> None:
        self.request_id = resolve_request_id(self.request.headers.get(REQUEST_ID_HEADER))
        request_id_var.set(self.request_id)
        self.set_header(REQUEST_ID_HEADER, self.request_id)

    def clear(self) -> None:
        # send_error() clears headers; keep the request ID on error responses too.
        super().clear()
        if request_id := getattr(self, "request_id", None):
            self.set_header(REQUEST_ID_HEADER, request_id)


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


@dataclass
class Services:
    """Everything an upload talks to; tests pass fakes or moto-backed clients."""

    api: InternalApi
    keys: KeyProvider
    s3: object
    bucket: str
    part_size: int = 8 * 1024 * 1024
    max_upload_bytes: int = 5 * 1024**3


@tornado.web.stream_request_body
class UploadHandler(BaseHandler):
    """Receives one file as the raw request body and stores it encrypted.

    PUT /uploads/{file_id} with `Authorization: Bearer <upload intent token>`.

    1. Before reading the body, ask the API to consume the intent (single use; it
       fixes the declared size and the object key).
    2. Get a per-file data key from KMS and start an S3 multipart upload.
    3. As each piece arrives: hash the plaintext, encrypt (VGE1), buffer ciphertext into
       S3 parts. Tornado waits for each piece to be processed before reading the next,
       so memory stays at about one part per upload whatever the file size.
    4. At the end, require exactly the declared size, finish the object, and report
       size, SHA-256 and the wrapped key to the API.

    Any failure after step 1 aborts the multipart upload and reports `fail`, so no
    partial object survives and the file never shows as uploaded.
    """

    route = "/uploads/{upload_id}"
    _in_progress = False

    async def prepare(self) -> None:
        super().prepare()
        self.services: Services = self.application.settings["services"]
        self._received = 0
        self._grant: UploadGrant | None = None
        self._writer: MultipartWriter | None = None
        self._finished_ok = False
        self._cleaned_up = False
        self._error: tornado.web.HTTPError | None = None
        self.request.connection.set_max_body_size(self.services.max_upload_bytes)
        metrics.UPLOADS_IN_PROGRESS.inc()
        self._in_progress = True

        try:
            file_id = uuid.UUID(self.path_args[0])
        except ValueError:
            raise tornado.web.HTTPError(404) from None
        token = self._bearer_token()
        if token is None:
            raise tornado.web.HTTPError(401)

        try:
            self._grant = await self.services.api.consume_upload(token, file_id)
        except IntentRefused:
            self._count_failure("intent_refused")
            raise tornado.web.HTTPError(403) from None
        except ApiUnavailable:
            self._count_failure("api_unavailable")
            raise tornado.web.HTTPError(503) from None

        declared = self._grant.declared_size
        length = self.request.headers.get("Content-Length")
        if length is not None and int(length) != declared:
            await self._fail("size_mismatch")
            raise tornado.web.HTTPError(400, reason="Content-Length differs from declared size")

        try:
            self._key = await self.services.keys.generate(file_id)
            self._encryptor = Encryptor(self._key.plaintext, file_id)
            self._digest = hashlib.sha256()
            self._writer = MultipartWriter(
                self.services.s3,
                self.services.bucket,
                self._grant.storage_key,
                part_size=self.services.part_size,
            )
            await self._writer.start()
            await self._writer.write(self._encryptor.header())
        except (KeyUnavailable, StorageUnavailable) as exc:
            await self._fail(
                "kms_unavailable" if isinstance(exc, KeyUnavailable) else "storage_unavailable"
            )
            raise tornado.web.HTTPError(503) from None

    async def data_received(self, chunk: bytes) -> None:
        # Exceptions raised here never become a response (Tornado just drops the
        # connection), so errors are recorded and raised from put() instead; the rest
        # of the body is read and discarded, bounded by the declared size check.
        if self._grant is None or self._error is not None:
            return
        self._received += len(chunk)
        metrics.UPLOAD_BYTES.inc(len(chunk))
        if self._received > self._grant.declared_size:
            await self._fail("size_mismatch")
            self._error = tornado.web.HTTPError(413, reason="More bytes than the declared size")
            return
        self._digest.update(chunk)
        try:
            await self._writer.write(self._encryptor.update(chunk))
        except StorageUnavailable:
            await self._fail("storage_unavailable")
            self._error = tornado.web.HTTPError(503)

    async def put(self, upload_id: str) -> None:
        if self._error is not None:
            raise self._error
        if self._received != self._grant.declared_size:
            await self._fail("size_mismatch")
            raise tornado.web.HTTPError(400, reason="Fewer bytes than the declared size")
        try:
            await self._writer.write(self._encryptor.finalize())
            await self._writer.complete()
        except StorageUnavailable:
            await self._fail("storage_unavailable")
            raise tornado.web.HTTPError(503) from None
        sha256 = self._digest.hexdigest()
        try:
            await self._report_complete(sha256)
        except IntentRefused:
            # The API definitely did not record this upload (e.g. swept meanwhile):
            # remove the object so no unreferenced ciphertext remains.
            await self._delete_object()
            await self._fail("api_refused")
            raise tornado.web.HTTPError(409) from None
        except ApiUnavailable:
            # Outcome unknown: the API may have committed before the response was lost.
            # Keep the object (deleting it could orphan an uploaded file) and leave the
            # row to the API sweep if it was never recorded.
            self._cleaned_up = True
            self._count_failure("api_unavailable")
            logger.error(
                "could not confirm upload; object kept",
                extra={"file_id": str(self._grant.file_id), "key": self._writer.key},
            )
            raise tornado.web.HTTPError(503) from None
        self._finished_ok = True
        self._key = None  # drop the plaintext data key reference as soon as possible
        metrics.UPLOAD_SIZE.observe(self._received)
        self.set_status(201)
        self.write({"file_id": str(self._grant.file_id), "size": self._received, "sha256": sha256})

    def write_error(self, status_code: int, **kwargs) -> None:
        if status_code == 401:  # send_error clears headers set before the error
            self.set_header("WWW-Authenticate", 'Bearer realm="vaultgate-upload"')
        super().write_error(status_code, **kwargs)

    def on_finish(self) -> None:
        # Covers errors not handled above (bugs included): never leave parts behind.
        if self._grant is not None and not self._finished_ok and not self._cleaned_up:
            _background(self._fail("error"))
        self._end_upload()

    def on_connection_close(self) -> None:
        # Client went away mid-upload; on_finish is not called in that case.
        if self._grant is not None and not self._finished_ok and not self._cleaned_up:
            _background(self._fail("client_disconnected"))
        self._end_upload()
        super().on_connection_close()

    def _bearer_token(self) -> str | None:
        header = self.request.headers.get("Authorization", "")
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "bearer":
            return None
        return value.strip() or None

    async def _fail(self, reason: str) -> None:
        """Abort the S3 upload and tell the API; runs at most once per request."""
        if self._cleaned_up:
            return
        self._cleaned_up = True
        self._count_failure(reason)
        logger.warning(
            "upload failed", extra={"reason": reason, "file_id": str(self._grant.file_id)}
        )
        if self._writer is not None:
            try:
                await self._writer.abort()
            except StorageUnavailable:
                logger.error("multipart abort failed; bucket lifecycle rule will clean up")
        try:
            await self.services.api.fail(self._grant.file_id)
        except (ApiUnavailable, IntentRefused):
            logger.error("could not report failed upload; API sweep will mark it failed")

    async def _report_complete(self, sha256: str) -> None:
        """Report the result, retrying when the API cannot be reached; /complete is
        idempotent for the same result, so a retry after a lost response succeeds."""
        for attempt in range(COMPLETE_ATTEMPTS):
            try:
                await self.services.api.complete(
                    self._grant.file_id,
                    size=self._received,
                    sha256=sha256,
                    wrapped_key=self._key.wrapped,
                    kms_key_id=self._key.kms_key_id,
                )
                return
            except ApiUnavailable:
                if attempt == COMPLETE_ATTEMPTS - 1:
                    raise
                await asyncio.sleep(COMPLETE_RETRY_DELAY * (attempt + 1))

    async def _delete_object(self) -> None:
        try:
            await self._writer.delete()
        except StorageUnavailable:
            logger.error("could not delete unrecorded object", extra={"key": self._writer.key})

    def _count_failure(self, reason: str) -> None:
        metrics.UPLOAD_FAILURES.labels(reason).inc()

    def _end_upload(self) -> None:
        if self._in_progress:
            self._in_progress = False
            metrics.UPLOADS_IN_PROGRESS.dec()


def make_app(services: Services | None = None) -> tornado.web.Application:
    return tornado.web.Application(
        [
            (r"/healthz", HealthHandler),
            (r"/uploads/([A-Za-z0-9_-]+)", UploadHandler),
        ],
        log_function=on_request_finished,
        services=services,
    )


def services_from_settings() -> Services:
    return Services(
        api=InternalApi(settings.api_internal_url, settings.internal_token),
        keys=KmsKeyProvider.from_settings(
            kms_key_id=settings.kms_key_id,
            region=settings.aws_region,
            endpoint_url=settings.aws_endpoint_url,
        ),
        s3=s3_client(region=settings.aws_region, endpoint_url=settings.aws_endpoint_url),
        bucket=settings.bucket,
        part_size=settings.part_size,
        max_upload_bytes=settings.max_upload_bytes,
    )


async def main() -> None:
    configure_logging(
        os.getenv("VAULTGATE_LOG_LEVEL", "INFO"), os.getenv("VAULTGATE_LOG_FORMAT", "json")
    )
    if not settings.internal_token:
        raise SystemExit("VAULTGATE_INTERNAL_TOKEN is required")
    metrics.BUILD_INFO.info({"service": "gateway", "version": "0.1.0"})
    start_http_server(settings.metrics_port)
    make_app(services_from_settings()).listen(
        settings.port, max_body_size=settings.max_upload_bytes
    )
    logger.info(
        "gateway listening", extra={"port": settings.port, "metrics_port": settings.metrics_port}
    )
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
