import hashlib
import json
import logging
import uuid

import boto3
import pytest
from moto import mock_aws
from prometheus_client import REGISTRY
from tornado.testing import AsyncHTTPTestCase

from vaultgate_gateway.api_client import ApiUnavailable, IntentRefused, UploadGrant
from vaultgate_gateway.app import Services, make_app
from vaultgate_gateway.crypto import Decryptor, ciphertext_size
from vaultgate_gateway.keys import KmsKeyProvider
from vaultgate_gateway.logs import JsonFormatter

BUCKET = "vault"
TOKEN = "good-token"
MiB = 1024 * 1024


class FakeApi:
    """Stands in for the API's internal endpoints."""

    def __init__(self) -> None:
        self.grants: dict[str, UploadGrant] = {}
        self.completed: dict[uuid.UUID, dict] = {}
        self.failed: list[uuid.UUID] = []
        self.down = False
        self.complete_down = False

    def grant(self, size: int) -> uuid.UUID:
        file_id = uuid.uuid4()
        self.grants[TOKEN] = UploadGrant(file_id, f"files/{file_id}", size)
        return file_id

    async def consume_upload(self, token: str, file_id: uuid.UUID) -> UploadGrant:
        if self.down:
            raise ApiUnavailable()
        grant = self.grants.pop(token, None)
        if grant is None or grant.file_id != file_id:
            raise IntentRefused()
        return grant

    async def complete(self, file_id, *, size, sha256, wrapped_key, kms_key_id) -> None:
        if self.complete_down:
            raise ApiUnavailable()
        self.completed[file_id] = {
            "size": size,
            "sha256": sha256,
            "wrapped_key": wrapped_key,
            "kms_key_id": kms_key_id,
        }

    async def fail(self, file_id: uuid.UUID) -> None:
        self.failed.append(file_id)


class UploadTest(AsyncHTTPTestCase):
    def setUp(self) -> None:
        self.aws = mock_aws()
        self.aws.start()
        self.s3 = boto3.client("s3", region_name="ap-northeast-1")
        self.s3.create_bucket(
            Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"}
        )
        kms = boto3.client("kms", region_name="ap-northeast-1")
        self.key_id = kms.create_key()["KeyMetadata"]["KeyId"]
        self.keys = KmsKeyProvider(kms, self.key_id)
        self.api = FakeApi()
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()
        self.aws.stop()

    def get_app(self):
        services = Services(
            api=self.api, keys=self.keys, s3=self.s3, bucket=BUCKET, part_size=5 * MiB
        )
        return make_app(services)

    def put(self, file_id, body: bytes, token: str | None = TOKEN, **kwargs):
        headers = kwargs.pop("headers", {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self.fetch(f"/uploads/{file_id}", method="PUT", body=body, headers=headers, **kwargs)

    def stored(self, file_id) -> bytes:
        return self.s3.get_object(Bucket=BUCKET, Key=f"files/{file_id}")["Body"].read()

    def open_uploads(self) -> list:
        return self.s3.list_multipart_uploads(Bucket=BUCKET).get("Uploads", [])

    def assert_nothing_stored(self, file_id) -> None:
        assert self.s3.list_objects_v2(Bucket=BUCKET).get("KeyCount") == 0
        assert self.open_uploads() == []
        assert self.api.failed == [file_id]

    def test_health(self) -> None:
        response = self.fetch("/healthz")
        assert response.code == 200
        assert json.loads(response.body) == {"status": "ok", "service": "gateway"}

    def test_upload_is_stored_encrypted_and_reported(self) -> None:
        payload = bytes(range(256)) * (48 * 1024)  # 12 MiB: three S3 parts
        file_id = self.api.grant(len(payload))
        response = self.put(file_id, payload)
        assert response.code == 201, response.body
        sha256 = hashlib.sha256(payload).hexdigest()
        assert json.loads(response.body) == {
            "file_id": str(file_id),
            "size": len(payload),
            "sha256": sha256,
        }

        record = self.api.completed[file_id]
        assert record["size"] == len(payload)
        assert record["sha256"] == sha256
        assert self.key_id in record["kms_key_id"]

        stored = self.stored(file_id)
        assert len(stored) == ciphertext_size(len(payload))
        assert payload[:1024] not in stored
        key = self.io_loop.run_sync(lambda: self.keys.unwrap(file_id, record["wrapped_key"]))
        decryptor = Decryptor(key, file_id)
        assert decryptor.update(stored) + decryptor.finalize() == payload
        assert self.open_uploads() == []

    def test_empty_file(self) -> None:
        file_id = self.api.grant(0)
        response = self.put(file_id, b"")
        assert response.code == 201, response.body
        assert self.api.completed[file_id]["sha256"] == hashlib.sha256(b"").hexdigest()

    def test_missing_token_is_401(self) -> None:
        file_id = self.api.grant(3)
        response = self.put(file_id, b"abc", token=None)
        assert response.code == 401
        assert response.headers["WWW-Authenticate"].startswith("Bearer")
        assert TOKEN in self.api.grants  # not consumed

    def test_refused_token_is_403(self) -> None:
        file_id = self.api.grant(3)
        assert self.put(file_id, b"abc", token="wrong").code == 403
        assert self.put(uuid.uuid4(), b"abc").code == 403  # token for another file

    def test_token_is_single_use(self) -> None:
        file_id = self.api.grant(3)
        assert self.put(file_id, b"abc").code == 201
        assert self.put(file_id, b"abc").code == 403

    def test_error_responses_keep_request_id(self) -> None:
        response = self.put(uuid.uuid4(), b"abc", token="nope", headers={"X-Request-ID": "r-1"})
        assert response.code == 403
        assert response.headers["X-Request-ID"] == "r-1"

    def test_not_a_uuid_is_404(self) -> None:
        assert self.put("abc123", b"abc").code == 404

    def test_api_down_is_503(self) -> None:
        file_id = self.api.grant(3)
        self.api.down = True
        assert self.put(file_id, b"abc").code == 503

    def test_content_length_must_match_declared_size(self) -> None:
        file_id = self.api.grant(10)
        assert self.put(file_id, b"abc").code == 400
        assert self.api.failed == [file_id]
        assert self.open_uploads() == []

    def test_chunked_body_shorter_than_declared(self) -> None:
        file_id = self.api.grant(10)
        response = self.put(file_id, body_producer=_chunks(b"abc"), body=None)
        assert response.code == 400
        self.assert_nothing_stored(file_id)

    def test_chunked_body_longer_than_declared(self) -> None:
        file_id = self.api.grant(3)
        response = self.put(file_id, body_producer=_chunks(b"abc", b"def"), body=None)
        assert response.code == 413
        self.assert_nothing_stored(file_id)

    def test_storage_failure_aborts_and_reports(self) -> None:
        file_id = self.api.grant(6 * MiB)
        self.s3.delete_bucket(Bucket=BUCKET)
        assert self.put(file_id, b"x" * (6 * MiB)).code == 503
        assert self.api.failed == [file_id]

    def test_kms_failure_reports(self) -> None:
        file_id = self.api.grant(3)
        self.keys._kms_key_id = "alias/missing"
        assert self.put(file_id, b"abc").code == 503
        self.assert_nothing_stored(file_id)

    def test_unrecorded_object_is_deleted(self) -> None:
        file_id = self.api.grant(3)
        self.api.complete_down = True
        assert self.put(file_id, b"abc").code == 503
        self.assert_nothing_stored(file_id)

    def test_unrecorded_object_leaves_no_version_in_versioned_bucket(self) -> None:
        self.s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
        file_id = self.api.grant(3)
        self.api.complete_down = True
        assert self.put(file_id, b"abc").code == 503
        versions = self.s3.list_object_versions(Bucket=BUCKET)
        assert versions.get("Versions", []) == []
        assert versions.get("DeleteMarkers", []) == []

    @pytest.fixture(autouse=True)
    def _caplog(self, caplog: pytest.LogCaptureFixture) -> None:
        self.caplog = caplog

    def test_upload_is_logged_with_request_id_and_size(self) -> None:
        file_id = self.api.grant(1024)
        with self.caplog.at_level(logging.INFO, logger="vaultgate.access"):
            response = self.fetch(
                f"/uploads/{file_id}?sig=secret",
                method="PUT",
                body=b"x" * 1024,
                headers={"X-Request-ID": "req-42", "Authorization": f"Bearer {TOKEN}"},
            )
        assert response.headers["X-Request-ID"] == "req-42"
        [record] = [r for r in self.caplog.records if r.name == "vaultgate.access"]
        assert record.request_id == "req-42"
        assert record.path == f"/uploads/{file_id}"
        assert record.status == 201
        assert record.bytes_in == 1024
        line = json.dumps(json.loads(JsonFormatter("gateway").format(record)))
        assert "secret" not in line
        assert TOKEN not in line

    def test_upload_metrics(self) -> None:
        bytes_before = _sample("vaultgate_gateway_upload_bytes_total")
        sizes_before = _sample("vaultgate_gateway_upload_size_bytes_count")
        route = {"method": "PUT", "route": "/uploads/{upload_id}", "status": "201"}
        requests_before = _sample("vaultgate_http_requests_total", route)

        payload = b"x" * (2 * MiB)
        assert self.put(self.api.grant(len(payload)), payload).code == 201

        assert _sample("vaultgate_gateway_upload_bytes_total") == bytes_before + len(payload)
        assert _sample("vaultgate_gateway_upload_size_bytes_count") == sizes_before + 1
        assert _sample("vaultgate_http_requests_total", route) == requests_before + 1
        assert _sample("vaultgate_gateway_uploads_in_progress") == 0

    def test_failures_are_counted(self) -> None:
        before = _failures("intent_refused")
        self.put(uuid.uuid4(), b"abc", token="nope")
        assert _failures("intent_refused") == before + 1


def _chunks(*parts: bytes):
    async def produce(write):
        for part in parts:
            await write(part)

    return produce


def _sample(name: str, labels: dict[str, str] | None = None) -> float:
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


def _failures(reason: str) -> float:
    return _sample("vaultgate_gateway_upload_failures_total", {"reason": reason})
