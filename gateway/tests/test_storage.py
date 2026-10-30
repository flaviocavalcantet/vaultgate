import boto3
import pytest
from moto import mock_aws

from vaultgate_gateway.storage import MultipartWriter, StorageUnavailable, s3_client

MiB = 1024 * 1024


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="vault")
        yield client


async def test_writes_full_parts_and_keeps_at_most_one_buffered(s3) -> None:
    writer = MultipartWriter(s3, "vault", "k", part_size=5 * MiB)
    await writer.start()
    data = b""
    for i in range(12):
        piece = bytes([i]) * MiB
        data += piece
        await writer.write(piece)
        assert writer.buffered < 5 * MiB
    await writer.complete()
    assert writer.bytes_written == len(data)
    assert s3.get_object(Bucket="vault", Key="k")["Body"].read() == data


async def test_empty_object(s3) -> None:
    writer = MultipartWriter(s3, "vault", "k", part_size=5 * MiB)
    await writer.start()
    await writer.complete()
    assert s3.get_object(Bucket="vault", Key="k")["Body"].read() == b""


async def test_abort_discards_parts_and_is_idempotent(s3) -> None:
    writer = MultipartWriter(s3, "vault", "k", part_size=5 * MiB)
    await writer.start()
    await writer.write(b"x" * 6 * MiB)
    await writer.abort()
    await writer.abort()
    assert s3.list_multipart_uploads(Bucket="vault").get("Uploads", []) == []
    assert s3.list_objects_v2(Bucket="vault")["KeyCount"] == 0


async def test_s3_errors_become_storage_unavailable(s3) -> None:
    writer = MultipartWriter(s3, "missing-bucket", "k", part_size=5 * MiB)
    with pytest.raises(StorageUnavailable):
        await writer.start()


def test_parts_below_s3_minimum_are_rejected(s3) -> None:
    with pytest.raises(ValueError):
        MultipartWriter(s3, "vault", "k", part_size=MiB)


def test_custom_endpoint_uses_path_style() -> None:
    client = s3_client(region="us-east-1", endpoint_url="http://localstack:4566")
    assert client.meta.config.s3["addressing_style"] == "path"
    assert client.meta.config.retries["total_max_attempts"] == 3
