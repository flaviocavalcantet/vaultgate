import base64
import hashlib
import json
import logging
import os
import uuid

import boto3
import pytest
from moto import mock_aws
from prometheus_client import REGISTRY
from tornado.simple_httpclient import HTTPStreamClosedError
from tornado.testing import AsyncHTTPTestCase

from vaultgate_gateway.api_client import (
    ApiUnavailable,
    DownloadGrant,
    IntentRefused,
    UploadGrant,
)
from vaultgate_gateway.app import Services, content_disposition, make_app
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
        self.download_grants: dict[str, DownloadGrant] = {}
        self.down = False
        self.complete_down = False
        self.complete_failures = 0  # fail this many complete calls, then succeed
        self.complete_refused = False
        self.complete_calls = 0

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
        self.complete_calls += 1
        if self.complete_refused:
            raise IntentRefused()
        if self.complete_down or self.complete_calls <= self.complete_failures:
            raise ApiUnavailable()
        self.completed[file_id] = {
            "size": size,
            "sha256": sha256,
            "wrapped_key": wrapped_key,
            "kms_key_id": kms_key_id,
        }

    async def fail(self, file_id: uuid.UUID) -> None:
        self.failed.append(file_id)

    def grant_download(self, file_id: uuid.UUID, name: str = "report.pdf", **overrides) -> str:
        done = self.completed[file_id]
        token = f"download-{uuid.uuid4()}"
        self.download_grants[token] = DownloadGrant(
            file_id=file_id,
            storage_key=f"files/{file_id}",
            name=name,
            content_type="application/pdf",
            size=done["size"],
            sha256=done["sha256"],
            wrapped_key=done["wrapped_key"],
            kms_key_id=done["kms_key_id"],
        )
        if overrides:
            grant = self.download_grants[token]
            self.download_grants[token] = DownloadGrant(**{**grant.__dict__, **overrides})
        return token

    async def consume_download(self, token: str, file_id: uuid.UUID) -> DownloadGrant:
        if self.down:
            raise ApiUnavailable()
        grant = self.download_grants.pop(token, None)
        if grant is None or grant.file_id != file_id:
            raise IntentRefused()
        return grant


class GatewayCase(AsyncHTTPTestCase):
    """moto-backed S3 and KMS plus a fake internal API; no tests of its own."""

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


class UploadTest(GatewayCase):
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
        # The upload fails before the body is read, so keep the body small: a client
        # still sending a large body when the server answers and closes gets a
        # connection reset instead of the response on Windows.
        file_id = self.api.grant(3)
        self.s3.delete_bucket(Bucket=BUCKET)
        assert self.put(file_id, b"abc").code == 503
        assert self.api.failed == [file_id]

    def test_kms_failure_reports(self) -> None:
        file_id = self.api.grant(3)
        self.keys._kms_key_id = "alias/missing"
        assert self.put(file_id, b"abc").code == 503
        self.assert_nothing_stored(file_id)

    def test_refused_completion_deletes_the_object(self) -> None:
        file_id = self.api.grant(3)
        self.api.complete_refused = True
        assert self.put(file_id, b"abc").code == 409
        self.assert_nothing_stored(file_id)

    def test_refused_completion_leaves_no_version_in_versioned_bucket(self) -> None:
        self.s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
        file_id = self.api.grant(3)
        self.api.complete_refused = True
        assert self.put(file_id, b"abc").code == 409
        versions = self.s3.list_object_versions(Bucket=BUCKET)
        assert versions.get("Versions", []) == []
        assert versions.get("DeleteMarkers", []) == []

    def test_completion_is_retried(self) -> None:
        file_id = self.api.grant(3)
        self.api.complete_failures = 2
        assert self.put(file_id, b"abc").code == 201
        assert file_id in self.api.completed
        assert self.api.complete_calls == 3

    def test_unconfirmed_completion_keeps_the_object(self) -> None:
        # The API may have recorded the upload before its answer was lost, so the
        # object must survive; the API sweep handles the row if it was not recorded.
        file_id = self.api.grant(3)
        self.api.complete_down = True
        assert self.put(file_id, b"abc").code == 503
        assert self.stored(file_id)
        assert self.api.failed == []

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


class DownloadTest(GatewayCase):
    """Downloads of files stored through the upload handler."""

    def upload(self, payload: bytes) -> uuid.UUID:
        file_id = self.api.grant(len(payload))
        assert self.put(file_id, payload).code == 201
        return file_id

    def get(self, file_id, token: str | None, **kwargs):
        headers = kwargs.pop("headers", {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self.fetch(f"/downloads/{file_id}", headers=headers, **kwargs)

    def assert_cut_short(self, file_id, token: str) -> None:
        """The client must never receive what looks like a complete file."""
        with pytest.raises(HTTPStreamClosedError):
            self.get(file_id, token)

    def test_download_returns_the_original_bytes(self) -> None:
        payload = os.urandom(3 * MiB + 12345)  # several S3 reads and VGE1 chunks
        file_id = self.upload(payload)
        response = self.get(file_id, self.api.grant_download(file_id))
        assert response.code == 200
        assert response.body == payload
        assert response.headers["Content-Length"] == str(len(payload))
        assert response.headers["Content-Type"] == "application/pdf"
        assert response.headers["Content-Disposition"].startswith("attachment;")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Cache-Control"] == "no-store"
        digest = base64.b64encode(hashlib.sha256(payload).digest()).decode()
        assert response.headers["Repr-Digest"] == f"sha-256=:{digest}:"

    def test_empty_file(self) -> None:
        file_id = self.upload(b"")
        response = self.get(file_id, self.api.grant_download(file_id))
        assert response.code == 200
        assert response.body == b""

    def test_token_is_single_use(self) -> None:
        file_id = self.upload(b"abc")
        token = self.api.grant_download(file_id)
        assert self.get(file_id, token).code == 200
        assert self.get(file_id, token).code == 403

    def test_missing_or_wrong_token(self) -> None:
        file_id = self.upload(b"abc")
        assert self.get(file_id, None).code == 401
        assert self.get(file_id, "nope").code == 403
        other = self.upload(b"def")
        assert self.get(other, self.api.grant_download(file_id)).code == 403

    def test_api_down_is_503(self) -> None:
        file_id = self.upload(b"abc")
        token = self.api.grant_download(file_id)
        self.api.down = True
        assert self.get(file_id, token).code == 503

    def test_missing_object_is_503(self) -> None:
        file_id = self.upload(b"abc")
        self.s3.delete_object(Bucket=BUCKET, Key=f"files/{file_id}")
        assert self.get(file_id, self.api.grant_download(file_id)).code == 503

    def test_key_bound_to_another_file_is_refused(self) -> None:
        a, b = self.upload(b"abc"), self.upload(b"def")
        token = self.api.grant_download(a, wrapped_key=self.api.completed[b]["wrapped_key"])
        assert self.get(a, token).code == 503  # KMS refuses: encryption context mismatch

    def test_tampered_object_is_cut_short(self) -> None:
        payload = os.urandom(MiB)
        file_id = self.upload(payload)
        stored = bytearray(self.stored(file_id))
        stored[len(stored) // 2] ^= 1
        self.s3.put_object(Bucket=BUCKET, Key=f"files/{file_id}", Body=bytes(stored))
        before = _sample("vaultgate_gateway_download_failures_total", {"reason": "integrity"})
        self.assert_cut_short(file_id, self.api.grant_download(file_id))
        after = _sample("vaultgate_gateway_download_failures_total", {"reason": "integrity"})
        assert after == before + 1

    def test_truncated_object_is_cut_short(self) -> None:
        payload = os.urandom(MiB)
        file_id = self.upload(payload)
        stored = self.stored(file_id)
        cut = stored[: len(stored) - 100]
        self.s3.put_object(Bucket=BUCKET, Key=f"files/{file_id}", Body=cut)
        self.assert_cut_short(file_id, self.api.grant_download(file_id))

    def test_object_with_wrong_recorded_size_is_cut_short(self) -> None:
        file_id = self.upload(b"abcdef")
        token = self.api.grant_download(file_id, size=10)
        self.assert_cut_short(file_id, token)

    def test_download_metrics(self) -> None:
        file_id = self.upload(b"x" * 4096)
        before = _sample("vaultgate_gateway_download_bytes_total")
        assert self.get(file_id, self.api.grant_download(file_id)).code == 200
        assert _sample("vaultgate_gateway_download_bytes_total") == before + 4096
        assert _sample("vaultgate_gateway_downloads_in_progress") == 0


def test_content_disposition_keeps_unicode_and_neutralises_quotes() -> None:
    header = content_disposition('relatório "final".pdf')
    assert header == (
        'attachment; filename="relat_rio _final_.pdf"; '
        "filename*=UTF-8''relat%C3%B3rio%20%22final%22.pdf"
    )
