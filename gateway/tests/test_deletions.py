"""The worker that deletes the objects of deleted files (ADR 0020)."""

import asyncio
import uuid

import boto3
import pytest
from moto import mock_aws

from vaultgate_gateway import deletions, metrics
from vaultgate_gateway.api_client import ApiUnavailable, ClaimedDeletions, ObjectToDelete


class FakeApi:
    def __init__(self, keys: list[str], pending: int | None = None) -> None:
        self.queue = {n: key for n, key in enumerate(keys, start=1)}
        self.pending = pending
        self.confirmed: list[list[int]] = []
        self.limits: list[int] = []
        self.down = False

    async def claim_deletions(self, limit: int) -> ClaimedDeletions:
        if self.down:
            raise ApiUnavailable("down")
        self.limits.append(limit)
        items = [ObjectToDelete(n, key) for n, key in list(self.queue.items())[:limit]]
        pending = len(self.queue) if self.pending is None else self.pending
        return ClaimedDeletions(items=items, pending=pending)

    async def confirm_deletions(self, ids: list[int]) -> None:
        self.confirmed.append(ids)
        for n in ids:
            self.queue.pop(n, None)


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="vault")
        client.put_bucket_versioning(Bucket="vault", VersioningConfiguration={"Status": "Enabled"})
        yield client


def key() -> str:
    return f"files/{uuid.uuid4()}"


def count(outcome: str) -> float:
    return metrics.OBJECT_DELETIONS.labels(outcome)._value.get()


async def test_deletes_claimed_objects_and_confirms_them(s3) -> None:
    keys = [key(), key()]
    for k in keys:
        s3.put_object(Bucket="vault", Key=k, Body=b"ciphertext")
    api = FakeApi(keys)
    before = count("deleted")

    assert await deletions.delete_batch(api, s3, "vault", 10) == 2
    assert api.confirmed == [[1, 2]]
    assert count("deleted") == before + 2
    assert metrics.OBJECT_DELETIONS_PENDING._value.get() == 2
    for k in keys:
        with pytest.raises(s3.exceptions.ClientError):
            s3.get_object(Bucket="vault", Key=k)
        # Versioned: a delete marker over the version, which the lifecycle rule expires.
        versions = s3.list_object_versions(Bucket="vault", Prefix=k)
        assert len(versions["DeleteMarkers"]) == 1 and len(versions["Versions"]) == 1


async def test_an_object_already_gone_is_confirmed(s3) -> None:
    api = FakeApi([key()])
    assert await deletions.delete_batch(api, s3, "vault", 10) == 1
    assert api.confirmed == [[1]]


async def test_keys_that_are_not_a_files_are_refused(s3) -> None:
    s3.put_object(Bucket="vault", Key="audit/anchor", Body=b"keep me")
    good = key()
    api = FakeApi(["audit/anchor", "files/../audit/anchor", good, "files/not-a-uuid"])
    before = count("refused")

    await deletions.delete_batch(api, s3, "vault", 10)
    assert api.confirmed == [[3]]  # never confirmed: left for an operator
    assert count("refused") == before + 3
    assert s3.get_object(Bucket="vault", Key="audit/anchor")["Body"].read() == b"keep me"


async def test_an_object_that_fails_stays_claimed_for_a_retry(s3) -> None:
    ok, broken = key(), key()
    api = FakeApi([ok, broken])
    real = s3.delete_object
    before = count("failed")

    def flaky(**kwargs):
        if kwargs["Key"] == broken:
            raise s3.exceptions.ClientError(
                {"Error": {"Code": "SlowDown", "Message": "slow down"}}, "DeleteObject"
            )
        return real(**kwargs)

    s3.delete_object = flaky
    await deletions.delete_batch(api, s3, "vault", 10)
    assert api.confirmed == [[1]]
    assert count("failed") == before + 1


async def test_nothing_claimed_confirms_nothing(s3) -> None:
    api = FakeApi([])
    assert await deletions.delete_batch(api, s3, "vault", 10) == 0
    assert api.confirmed == []


async def test_the_loop_drains_full_batches_at_once_and_survives_the_api(s3) -> None:
    api = FakeApi([key() for _ in range(5)])
    task = asyncio.create_task(deletions.run(api, s3, "vault", interval=3600, batch=2))
    try:
        for _ in range(100):
            if not api.queue:
                break
            await asyncio.sleep(0.01)
        # 2, 2, then 1 (less than a batch: it would now wait the interval).
        assert [len(c) for c in api.confirmed] == [2, 2, 1]
    finally:
        task.cancel()

    api = FakeApi([key()])
    api.down = True
    task = asyncio.create_task(deletions.run(api, s3, "vault", interval=0.01, batch=2))
    try:
        await asyncio.sleep(0.05)
        api.down = False
        for _ in range(100):
            if api.confirmed:
                break
            await asyncio.sleep(0.01)
        assert api.confirmed == [[1]]
    finally:
        task.cancel()
