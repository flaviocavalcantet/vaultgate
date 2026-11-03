import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import boto3
import httpx
import pytest
from moto import mock_aws
from pydantic import SecretStr
from sqlalchemy import select, update

from tests.conftest import requires_db
from tests.test_files import as_user, uploaded
from vaultgate_api import scans
from vaultgate_api.config import settings
from vaultgate_api.internal import internal_app
from vaultgate_api.models import File

SCANNER_TOKEN = "scanner-secret-for-tests"


class FakeQueue:
    def __init__(self) -> None:
        self.sent: list[tuple[uuid.UUID, uuid.UUID]] = []
        self.failing = False

    async def send(self, file_id: uuid.UUID, scan_id: uuid.UUID) -> None:
        if self.failing:
            raise ConnectionError("queue unavailable")
        self.sent.append((file_id, scan_id))


@pytest.fixture
def queue() -> FakeQueue:
    return FakeQueue()


@pytest.fixture
async def scanner(clients, queue, monkeypatch):
    """Public, gateway and scanner clients; scan requests go to `queue`."""
    monkeypatch.setattr(settings, "scanner_token", SecretStr(SCANNER_TOKEN))
    internal_app.dependency_overrides[scans.get_scan_queue] = lambda: queue
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=internal_app),
        base_url="http://internal",
        headers={"Authorization": f"Bearer {SCANNER_TOKEN}"},
    )
    async with client:
        yield (*clients, client)


async def scanned_upload(public, internal, provider, queue) -> tuple[str, str]:
    """Upload a file; returns its id and the scan id sent to the queue."""
    created = await uploaded(public, internal, provider)
    file_id = created["file"]["id"]
    [(_, scan_id)] = [s for s in queue.sent if str(s[0]) == file_id]
    return file_id, str(scan_id)


async def file_of(public, provider, file_id: str) -> dict:
    response = await public.get(f"/files/{file_id}", headers=as_user(provider))
    assert response.status_code == 200
    return response.json()


def report(scanner_client, scan_id: str, outcome: str = "scanned", **body):
    return scanner_client.post(
        f"/internal/scans/{scan_id}/result", json={"outcome": outcome} | body
    )


@requires_db
async def test_completed_upload_gets_a_pending_scan_request(scanner, provider, queue) -> None:
    public, internal, _ = scanner
    file_id, scan_id = await scanned_upload(public, internal, provider, queue)
    scan = (await file_of(public, provider, file_id))["scan"]
    assert scan == {"verdict": "pending", "findings": [], "reason": None, "scanned_at": None}
    assert uuid.UUID(scan_id)


@requires_db
async def test_a_file_not_yet_uploaded_has_no_scan(scanner, provider, queue) -> None:
    public, _, _ = scanner
    created = await public.post(
        "/files", json={"name": "a.txt", "size": 1}, headers=as_user(provider)
    )
    assert created.json()["file"]["scan"] is None
    assert queue.sent == []


@requires_db
async def test_a_queue_failure_does_not_fail_the_upload(scanner, provider, queue) -> None:
    public, internal, _ = scanner
    queue.failing = True
    created = await uploaded(public, internal, provider)
    file = await file_of(public, provider, created["file"]["id"])
    assert file["status"] == "uploaded"
    assert file["scan"]["verdict"] == "pending"


@requires_db
async def test_scanner_gets_what_it_needs_to_read_the_object(scanner, provider, queue) -> None:
    public, internal, scanner_client = scanner
    file_id, scan_id = await scanned_upload(public, internal, provider, queue)
    response = await scanner_client.get(f"/internal/scans/{scan_id}")
    assert response.status_code == 200
    job = response.json()
    assert job["file_id"] == file_id
    assert job["storage_key"] == f"files/{file_id}"
    assert base64.b64decode(job["wrapped_key"])
    assert job["kms_key_id"]


@pytest.mark.parametrize(
    ("outcome", "findings", "verdict"),
    [
        ("scanned", [], "clean"),
        ("scanned", [{"kind": "email", "count": 3}], "clean"),  # recorded, not quarantined
        ("scanned", [{"kind": "payment_card", "count": 1}], "quarantined"),
        ("scanned", [{"kind": "email", "count": 1}, {"kind": "br_cpf", "count": 2}], "quarantined"),
        ("unscannable", [], "unscannable"),
    ],
)
@requires_db
async def test_results_give_a_verdict(scanner, provider, queue, outcome, findings, verdict) -> None:
    public, internal, scanner_client = scanner
    file_id, scan_id = await scanned_upload(public, internal, provider, queue)
    response = await report(scanner_client, scan_id, outcome, findings=findings)
    assert response.status_code == 200, response.text
    assert response.json() == {"verdict": verdict}
    scan = (await file_of(public, provider, file_id))["scan"]
    assert scan["verdict"] == verdict
    assert scan["findings"] == sorted(findings, key=lambda f: f["kind"])
    assert scan["scanned_at"] is not None


@requires_db
async def test_unscannable_files_say_why(scanner, provider, queue) -> None:
    public, internal, scanner_client = scanner
    file_id, scan_id = await scanned_upload(public, internal, provider, queue)
    await report(scanner_client, scan_id, "unscannable", reason="PDF is encrypted")
    scan = (await file_of(public, provider, file_id))["scan"]
    assert scan["verdict"] == "unscannable"
    assert scan["reason"] == "PDF is encrypted"


@requires_db
async def test_quarantine_kinds_apply_to_files_already_scanned(
    scanner,
    provider,
    queue,
    monkeypatch,
) -> None:
    public, internal, scanner_client = scanner
    file_id, scan_id = await scanned_upload(public, internal, provider, queue)
    await report(scanner_client, scan_id, findings=[{"kind": "email", "count": 1}])
    assert (await file_of(public, provider, file_id))["scan"]["verdict"] == "clean"
    monkeypatch.setattr(settings, "quarantine_kinds", ["email"])
    assert (await file_of(public, provider, file_id))["scan"]["verdict"] == "quarantined"


@requires_db
async def test_repeating_the_same_result_succeeds(scanner, provider, queue) -> None:
    public, internal, scanner_client = scanner
    _, scan_id = await scanned_upload(public, internal, provider, queue)
    findings = [{"kind": "payment_card", "count": 2}, {"kind": "email", "count": 1}]
    assert (await report(scanner_client, scan_id, findings=findings)).status_code == 200
    again = await report(scanner_client, scan_id, findings=list(reversed(findings)))
    assert again.status_code == 200
    assert again.json() == {"verdict": "quarantined"}


@pytest.mark.parametrize(
    "second",
    [
        {"outcome": "scanned"},
        {"outcome": "scanned", "findings": [{"kind": "payment_card", "count": 3}]},
        {"outcome": "unscannable", "reason": "PDF is encrypted"},
    ],
)
@requires_db
async def test_a_different_second_result_is_a_conflict(scanner, provider, queue, second) -> None:
    public, internal, scanner_client = scanner
    file_id, scan_id = await scanned_upload(public, internal, provider, queue)
    findings = [{"kind": "payment_card", "count": 2}]
    await report(scanner_client, scan_id, findings=findings)
    response = await scanner_client.post(f"/internal/scans/{scan_id}/result", json=second)
    assert response.status_code == 409
    scan = (await file_of(public, provider, file_id))["scan"]
    assert scan["findings"] == findings


@requires_db
async def test_no_job_once_the_scan_has_a_result(scanner, provider, queue) -> None:
    public, internal, scanner_client = scanner
    _, scan_id = await scanned_upload(public, internal, provider, queue)
    await report(scanner_client, scan_id)
    assert (await scanner_client.get(f"/internal/scans/{scan_id}")).status_code == 409


@requires_db
async def test_unknown_scans_are_not_found(scanner) -> None:
    _, _, scanner_client = scanner
    unknown = uuid.uuid4()
    assert (await scanner_client.get(f"/internal/scans/{unknown}")).status_code == 404
    assert (await report(scanner_client, str(unknown))).status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {"outcome": "clean"},
        {"outcome": "scanned", "findings": [{"kind": "Card", "count": 1}]},
        {"outcome": "scanned", "findings": [{"kind": "email", "count": 0}]},
        {"outcome": "scanned", "findings": [{"kind": "email", "count": 1}] * 2},
        {"outcome": "unscannable", "reason": "x" * 501},
    ],
)
@requires_db
async def test_malformed_results_are_rejected(scanner, provider, queue, body) -> None:
    public, internal, scanner_client = scanner
    _, scan_id = await scanned_upload(public, internal, provider, queue)
    response = await scanner_client.post(f"/internal/scans/{scan_id}/result", json=body)
    assert response.status_code == 422


@requires_db
async def test_gateway_and_scanner_secrets_do_not_open_each_others_routes(
    scanner,
    provider,
    queue,
) -> None:
    public, internal, scanner_client = scanner
    file_id, scan_id = await scanned_upload(public, internal, provider, queue)
    assert (await internal.get(f"/internal/scans/{scan_id}")).status_code == 401
    assert (await report(internal, scan_id)).status_code == 401
    response = await scanner_client.post(f"/internal/files/{file_id}/fail")
    assert response.status_code == 401


@requires_db
async def test_scanner_routes_fail_closed_without_a_configured_secret(
    scanner,
    provider,
    queue,
    monkeypatch,
) -> None:
    public, internal, scanner_client = scanner
    _, scan_id = await scanned_upload(public, internal, provider, queue)
    monkeypatch.setattr(settings, "scanner_token", None)
    assert (await scanner_client.get(f"/internal/scans/{scan_id}")).status_code == 401
    bare = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=internal_app), base_url="http://internal"
    )
    async with bare:
        assert (await bare.get(f"/internal/scans/{scan_id}")).status_code == 401


# --- Resending stuck scans ---------------------------------------------------------


async def _set_scan(session, file_id: str, **values) -> None:
    await session.execute(update(File).where(File.id == uuid.UUID(file_id)).values(**values))
    await session.flush()


@requires_db
async def test_resender_sends_requests_never_sent_and_stuck_ones(
    scanner,
    provider,
    queue,
    session,
) -> None:
    public, internal, _ = scanner
    now = datetime.now(UTC)
    old = now - timedelta(seconds=settings.scan_resend_after_seconds + 1)
    recent, _ = await scanned_upload(public, internal, provider, queue)
    stuck, stuck_scan = await scanned_upload(public, internal, provider, queue)
    never_sent, never_scan = await scanned_upload(public, internal, provider, queue)
    await _set_scan(session, stuck, scan_requested_at=old)
    await _set_scan(session, never_sent, scan_attempts=0, scan_requested_at=now)
    queue.sent.clear()

    assert await scans.resend_stuck_scans(session, queue, now) == 2
    assert {(str(f), str(s)) for f, s in queue.sent} == {
        (stuck, stuck_scan),
        (never_sent, never_scan),
    }
    rows = {str(f.id): f for f in (await session.scalars(_files())).all()}
    assert rows[stuck].scan_attempts == 2
    assert rows[never_sent].scan_attempts == 1
    assert rows[recent].scan_attempts == 1
    # Just sent: not sent again on the next round.
    queue.sent.clear()
    assert await scans.resend_stuck_scans(session, queue, now) == 0


def _files():
    return select(File).execution_options(populate_existing=True)


@requires_db
async def test_resender_gives_up_after_the_last_attempt(
    scanner,
    provider,
    queue,
    session,
) -> None:
    public, internal, scanner_client = scanner
    now = datetime.now(UTC)
    old = now - timedelta(seconds=settings.scan_resend_after_seconds + 1)
    file_id, scan_id = await scanned_upload(public, internal, provider, queue)
    await _set_scan(
        session, file_id, scan_attempts=settings.scan_max_attempts, scan_requested_at=old
    )
    queue.sent.clear()
    assert await scans.resend_stuck_scans(session, queue, now) == 1
    assert queue.sent == []
    scan = (await file_of(public, provider, file_id))["scan"]
    assert scan["verdict"] == "unscannable"
    assert scan["reason"] == f"No scan result after {settings.scan_max_attempts} attempts"
    # A result arriving afterwards does not make the file clean.
    assert (await report(scanner_client, scan_id)).status_code == 409


@requires_db
async def test_resender_stops_while_the_queue_fails(scanner, provider, queue, session) -> None:
    public, internal, _ = scanner
    now = datetime.now(UTC)
    old = now - timedelta(seconds=settings.scan_resend_after_seconds + 1)
    file_id, _ = await scanned_upload(public, internal, provider, queue)
    await _set_scan(session, file_id, scan_requested_at=old)
    queue.failing = True
    assert await scans.resend_stuck_scans(session, queue, now) == 0
    [file] = [f for f in (await session.scalars(_files())).all() if str(f.id) == file_id]
    assert file.scan_attempts == 1
    assert file.scan_status == "pending"


@requires_db
async def test_results_are_not_resent(scanner, provider, queue, session) -> None:
    public, internal, scanner_client = scanner
    now = datetime.now(UTC)
    file_id, scan_id = await scanned_upload(public, internal, provider, queue)
    await report(scanner_client, scan_id)
    await _set_scan(session, file_id, scan_requested_at=now - timedelta(days=1))
    queue.sent.clear()
    assert await scans.resend_stuck_scans(session, queue, now) == 0


# --- SQS -------------------------------------------------------------------------


async def test_sqs_queue_sends_the_file_and_scan_ids() -> None:
    with mock_aws():
        client = boto3.client("sqs", region_name="ap-northeast-1")
        url = client.create_queue(QueueName="scans")["QueueUrl"]
        file_id, scan_id = uuid.uuid4(), uuid.uuid4()
        await scans.SqsScanQueue(url, client).send(file_id, scan_id)
        [message] = client.receive_message(QueueUrl=url)["Messages"]
        assert json.loads(message["Body"]) == {"file_id": str(file_id), "scan_id": str(scan_id)}


def test_without_a_queue_url_requests_are_not_sent(monkeypatch) -> None:
    monkeypatch.setattr(settings, "scan_queue_url", None)
    scans.get_scan_queue.cache_clear()
    try:
        assert isinstance(scans.get_scan_queue(), scans.NoScanQueue)
    finally:
        scans.get_scan_queue.cache_clear()
