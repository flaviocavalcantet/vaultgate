"""VaultGate streaming gateway.

Tornado is used here for one specific reason: `@stream_request_body` lets us process
an upload chunk by chunk as it arrives, so a 5 GB file costs the same memory as a
5 KB one. Each chunk will be encrypted and forwarded to object storage without the
full body ever being buffered.
"""

import asyncio
import hashlib
import os

import tornado.web

MAX_UPLOAD_BYTES = int(os.getenv("VAULTGATE_MAX_UPLOAD_BYTES", str(5 * 1024**3)))


class HealthHandler(tornado.web.RequestHandler):
    def get(self) -> None:
        self.write({"status": "ok", "service": "gateway"})


@tornado.web.stream_request_body
class UploadHandler(tornado.web.RequestHandler):
    """Receives a file as a raw request body, one chunk at a time.

    Skeleton only: today it hashes and counts bytes. The roadmap replaces the
    hashing with envelope encryption and a multipart upload to S3, and adds
    upload-intent validation against the API before any byte is accepted.
    """

    def prepare(self) -> None:
        self.request.connection.set_max_body_size(MAX_UPLOAD_BYTES)
        self._digest = hashlib.sha256()
        self._received = 0

    def data_received(self, chunk: bytes) -> None:
        self._digest.update(chunk)
        self._received += len(chunk)

    def put(self, upload_id: str) -> None:
        self.write(
            {
                "upload_id": upload_id,
                "bytes": self._received,
                "sha256": self._digest.hexdigest(),
            }
        )


def make_app() -> tornado.web.Application:
    return tornado.web.Application(
        [
            (r"/healthz", HealthHandler),
            (r"/uploads/([A-Za-z0-9_-]+)", UploadHandler),
        ]
    )


async def main() -> None:
    port = int(os.getenv("VAULTGATE_GATEWAY_PORT", "8888"))
    make_app().listen(port, max_body_size=MAX_UPLOAD_BYTES)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
