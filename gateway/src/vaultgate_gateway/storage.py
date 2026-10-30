"""Streaming reads and writes of vault objects in S3, with bounded memory.

Ciphertext is collected into parts of `part_size` bytes (S3 requires at least 5 MiB for
every part but the last); each full part is uploaded before more is accepted, so the
gateway holds at most one part per upload. boto3 is synchronous, so calls run in a
thread. An upload that is not completed must be aborted, or S3 keeps (and bills) the
parts; the bucket's lifecycle rule is the backstop for crashes.
"""

import asyncio

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

S3_CLIENT_CONFIG = Config(
    connect_timeout=5,
    read_timeout=60,
    retries={"total_max_attempts": 3, "mode": "standard"},
)


class StorageUnavailable(Exception):
    """S3 refused or could not be reached."""


def s3_client(*, region: str, endpoint_url: str | None):
    import boto3

    config = S3_CLIENT_CONFIG
    if endpoint_url:  # LocalStack/MinIO: bucket names do not resolve as hostnames
        config = config.merge(Config(s3={"addressing_style": "path"}))
    return boto3.client("s3", region_name=region, endpoint_url=endpoint_url, config=config)


async def _call(fn, **kwargs):
    try:
        return await asyncio.to_thread(fn, **kwargs)
    except (BotoCoreError, ClientError) as exc:
        raise StorageUnavailable(type(exc).__name__) from None


class MultipartWriter:
    def __init__(self, client, bucket: str, key: str, *, part_size: int) -> None:
        if part_size < 5 * 1024 * 1024:
            raise ValueError("S3 parts must be at least 5 MiB")
        self._client = client
        self._bucket = bucket
        self.key = key
        self._part_size = part_size
        self._buffer = bytearray()
        self._parts: list[dict] = []
        self._upload_id: str | None = None
        self.bytes_written = 0
        # Set by complete() when the bucket is versioned.
        self.version_id: str | None = None

    async def start(self) -> None:
        response = await _call(
            self._client.create_multipart_upload,
            Bucket=self._bucket,
            Key=self.key,
            ContentType="application/octet-stream",
            Metadata={"format": "VGE1"},
        )
        self._upload_id = response["UploadId"]

    async def write(self, data: bytes) -> None:
        self._buffer += data
        while len(self._buffer) >= self._part_size:
            part = bytes(self._buffer[: self._part_size])
            del self._buffer[: self._part_size]
            await self._upload_part(part)

    async def complete(self) -> None:
        if self._buffer or not self._parts:
            await self._upload_part(bytes(self._buffer))
            self._buffer.clear()
        response = await _call(
            self._client.complete_multipart_upload,
            Bucket=self._bucket,
            Key=self.key,
            UploadId=self._upload_id,
            MultipartUpload={"Parts": self._parts},
        )
        self._upload_id = None
        self.version_id = response.get("VersionId")

    async def delete(self) -> None:
        """Remove the completed object. In a versioned bucket a plain delete only adds
        a delete marker, so the version this writer created is deleted explicitly."""
        kwargs = {"VersionId": self.version_id} if self.version_id else {}
        await _call(self._client.delete_object, Bucket=self._bucket, Key=self.key, **kwargs)

    async def abort(self) -> None:
        """Discard the parts uploaded so far. Safe to call more than once."""
        upload_id, self._upload_id = self._upload_id, None
        self._buffer.clear()
        if upload_id:
            await _call(
                self._client.abort_multipart_upload,
                Bucket=self._bucket,
                Key=self.key,
                UploadId=upload_id,
            )

    async def _upload_part(self, data: bytes) -> None:
        number = len(self._parts) + 1
        response = await _call(
            self._client.upload_part,
            Bucket=self._bucket,
            Key=self.key,
            UploadId=self._upload_id,
            PartNumber=number,
            Body=data,
        )
        self._parts.append({"PartNumber": number, "ETag": response["ETag"]})
        self.bytes_written += len(data)

    @property
    def buffered(self) -> int:
        return len(self._buffer)


class ObjectReader:
    """Reads one object in pieces. boto3's body is a blocking stream, so each read runs
    in a thread; the caller decides the piece size and so the memory used."""

    def __init__(self, body, size: int) -> None:
        self._body = body
        self.size = size

    @classmethod
    async def open(cls, client, bucket: str, key: str) -> "ObjectReader":
        response = await _call(client.get_object, Bucket=bucket, Key=key)
        return cls(response["Body"], response["ContentLength"])

    async def read(self, size: int) -> bytes:
        try:
            return await asyncio.to_thread(self._body.read, size)
        except (BotoCoreError, ClientError, OSError) as exc:
            raise StorageUnavailable(type(exc).__name__) from None

    def close(self) -> None:
        self._body.close()
