import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from prometheus_client import REGISTRY
from pydantic import SecretStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import requires_db
from tests.fake_oidc import FakeProvider, make_validator
from vaultgate_api.config import settings
from vaultgate_api.db import get_session
from vaultgate_api.internal import internal_app
from vaultgate_api.main import app
from vaultgate_api.models import File, TransferIntent
from vaultgate_api.uploads import fail_abandoned_uploads

pytestmark = requires_db

INTERNAL_TOKEN = "gateway-secret-for-tests"


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
async def clients(provider: FakeProvider, session: AsyncSession, monkeypatch):
    """Public API and internal API clients sharing the test's database session."""

    async def test_session():
        yield session

    monkeypatch.setattr(settings, "internal_token", SecretStr(INTERNAL_TOKEN))
    app.state.token_validator = make_validator(provider)
    for a in (app, internal_app):
        a.dependency_overrides[get_session] = test_session
    public = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api")
    internal = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=internal_app),
        base_url="http://internal",
        headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"},
    )
    async with public, internal:
        yield public, internal
    for a in (app, internal_app):
        a.dependency_overrides.clear()
    del app.state.token_validator


def as_user(provider: FakeProvider, sub: str = "alice") -> dict[str, str]:
    return {"Authorization": f"Bearer {provider.token(sub=sub, preferred_username=sub)}"}


async def create(public, provider, sub="alice", **body) -> dict:
    payload = {"name": "report.pdf", "size": 1234, "content_type": "application/pdf"} | body
    response = await public.post("/files", json=payload, headers=as_user(provider, sub))
    assert response.status_code == 201, response.text
    return response.json()


def consume(internal, created: dict, kind: str = "upload", token: str | None = None):
    return internal.post(
        "/internal/intents/consume",
        json={
            "token": token or created["upload"]["token"],
            "kind": kind,
            "file_id": created["file"]["id"],
        },
    )


# --- public API ---------------------------------------------------------------


async def test_create_returns_file_and_upload_intent(clients, provider, session) -> None:
    public, _ = clients
    created = await create(public, provider)
    file = created["file"]
    assert file["status"] == "pending"
    assert file["declared_size"] == 1234
    assert created["upload"]["url"] == f"http://localhost:8888/uploads/{file['id']}"

    # Only the token's hash is stored.
    token = created["upload"]["token"]
    stored = (await session.scalars(select(TransferIntent))).one()
    assert stored.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert token not in stored.token_hash
    # The object key comes from the ID, never from the user's file name.
    row = await session.get(File, uuid.UUID(file["id"]))
    assert row.storage_key == f"files/{file['id']}"


@pytest.mark.parametrize(
    "body",
    [
        {"name": "../etc/passwd"},
        {"name": "a\\b"},
        {"name": ".."},
        {"name": "bad\nname"},
        {"name": ""},
        {"size": -1},
        {"content_type": "not a type"},
        {"content_type": "text/html\r\nX-Injected: 1"},
    ],
)
async def test_invalid_file_metadata_is_rejected(clients, provider, body) -> None:
    public, _ = clients
    payload = {"name": "ok.txt", "size": 1, "content_type": "text/plain"} | body
    response = await public.post("/files", json=payload, headers=as_user(provider))
    assert response.status_code == 422


async def test_size_above_limit_is_413(clients, provider) -> None:
    public, _ = clients
    payload = {"name": "huge.bin", "size": settings.max_upload_bytes + 1}
    response = await public.post("/files", json=payload, headers=as_user(provider))
    assert response.status_code == 413


async def test_open_uploads_per_user_are_capped(clients, provider, monkeypatch) -> None:
    public, _ = clients
    monkeypatch.setattr(settings, "max_open_uploads_per_user", 2)
    await create(public, provider)
    await create(public, provider)
    payload = {"name": "third.pdf", "size": 1}
    response = await public.post("/files", json=payload, headers=as_user(provider))
    assert response.status_code == 429
    # The cap is per user.
    await create(public, provider, sub="bob")


async def test_abandoned_uploads_do_not_count_towards_the_cap(
    clients, provider, session, monkeypatch
) -> None:
    public, internal = clients
    monkeypatch.setattr(settings, "max_open_uploads_per_user", 2)
    expired = await create(public, provider)
    stalled = await create(public, provider, name="stalled.pdf")
    await consume(internal, stalled)
    blocked = await public.post("/files", json={"name": "x", "size": 1}, headers=as_user(provider))
    assert blocked.status_code == 429

    long_ago = datetime.now(UTC) - timedelta(seconds=settings.upload_stale_after_seconds + 1)
    await session.execute(
        update(TransferIntent)
        .where(TransferIntent.file_id == uuid.UUID(expired["file"]["id"]))
        .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    await session.execute(
        update(TransferIntent)
        .where(TransferIntent.file_id == uuid.UUID(stalled["file"]["id"]))
        .values(consumed_at=long_ago)
    )
    # An expired pending upload and a long-stalled one no longer hold the user back.
    await create(public, provider, name="fresh-1.pdf")
    await create(public, provider, name="fresh-2.pdf")


async def test_sweep_marks_only_abandoned_uploads_failed(clients, provider, session) -> None:
    public, internal = clients
    expired = await create(public, provider, name="expired.pdf")
    stalled = await create(public, provider, name="stalled.pdf")
    await consume(internal, stalled)
    waiting = await create(public, provider, name="waiting.pdf")
    receiving = await create(public, provider, name="receiving.pdf")
    await consume(internal, receiving)

    now = datetime.now(UTC)
    await _set_intent(session, expired, expires_at=now - timedelta(seconds=1))
    await _set_intent(
        session,
        stalled,
        consumed_at=now - timedelta(seconds=settings.upload_stale_after_seconds + 1),
    )

    before = REGISTRY.get_sample_value("vaultgate_api_uploads_abandoned_total") or 0
    assert await fail_abandoned_uploads(session) == 2
    assert await fail_abandoned_uploads(session) == 0  # idempotent
    after = REGISTRY.get_sample_value("vaultgate_api_uploads_abandoned_total")
    assert after == before + 2

    statuses = {
        name: await session.scalar(
            select(File.status).where(File.id == uuid.UUID(created["file"]["id"]))
        )
        for name, created in [
            ("expired", expired),
            ("stalled", stalled),
            ("waiting", waiting),
            ("receiving", receiving),
        ]
    }
    assert statuses == {
        "expired": "failed",
        "stalled": "failed",
        "waiting": "pending",
        "receiving": "uploading",
    }
    # A swept upload cannot be completed afterwards.
    response = await internal.post(
        f"/internal/files/{stalled['file']['id']}/complete",
        json={
            "size": 1234,
            "sha256": "ab" * 32,
            "wrapped_key": base64.b64encode(b"wrapped-data-key").decode(),
            "kms_key_id": "arn:aws:kms:local:000000000000:key/test",
        },
    )
    assert response.status_code == 409


async def _set_intent(session, created: dict, **values) -> None:
    await session.execute(
        update(TransferIntent)
        .where(TransferIntent.file_id == uuid.UUID(created["file"]["id"]))
        .values(**values)
    )


async def test_users_only_see_their_own_files(clients, provider) -> None:
    public, _ = clients
    mine = await create(public, provider, sub="alice")
    await create(public, provider, sub="bob", name="bobs.txt")

    listing = (await public.get("/files", headers=as_user(provider, "alice"))).json()
    assert [f["id"] for f in listing["items"]] == [mine["file"]["id"]]
    assert (
        await public.get(f"/files/{mine['file']['id']}", headers=as_user(provider))
    ).status_code == 200
    # Another user's file looks exactly like a missing one.
    other = await public.get(f"/files/{mine['file']['id']}", headers=as_user(provider, "bob"))
    missing = await public.get(f"/files/{uuid.uuid4()}", headers=as_user(provider, "bob"))
    assert other.status_code == missing.status_code == 404
    assert other.json() == missing.json()


# --- internal API ---------------------------------------------------------------


@pytest.mark.parametrize("header", [None, "Bearer wrong", "Basic Z2F0ZXdheQ=="])
async def test_internal_api_requires_the_gateway_secret(clients, provider, header) -> None:
    public, internal = clients
    created = await create(public, provider)
    headers = {"Authorization": header} if header else {}
    internal.headers.pop("Authorization")
    response = await internal.post(
        "/internal/intents/consume",
        json={
            "token": created["upload"]["token"],
            "kind": "upload",
            "file_id": created["file"]["id"],
        },
        headers=headers,
    )
    assert response.status_code == 401


async def test_internal_api_fails_closed_without_configured_secret(
    clients, provider, monkeypatch
) -> None:
    public, internal = clients
    created = await create(public, provider)
    monkeypatch.setattr(settings, "internal_token", None)
    internal.headers["Authorization"] = "Bearer "
    assert (await consume(internal, created)).status_code == 401


async def test_upload_lifecycle(clients, provider) -> None:
    public, internal = clients
    created = await create(public, provider)
    file_id = created["file"]["id"]

    consumed = await consume(internal, created)
    assert consumed.status_code == 200
    assert consumed.json()["storage_key"] == f"files/{file_id}"
    assert consumed.json()["declared_size"] == 1234
    status = (await public.get(f"/files/{file_id}", headers=as_user(provider))).json()["status"]
    assert status == "uploading"

    done = await internal.post(
        f"/internal/files/{file_id}/complete",
        json={
            "size": 1234,
            "sha256": "ab" * 32,
            "wrapped_key": base64.b64encode(b"wrapped-data-key").decode(),
            "kms_key_id": "arn:aws:kms:local:000000000000:key/test",
        },
    )
    assert done.status_code == 200
    file = (await public.get(f"/files/{file_id}", headers=as_user(provider))).json()
    assert file["status"] == "uploaded"
    assert file["size"] == 1234 and file["sha256"] == "ab" * 32
    assert file["uploaded_at"] is not None
    assert "wrapped_key" not in file  # key material never goes to clients

    again = await internal.post(f"/internal/files/{file_id}/fail")
    assert again.status_code == 409  # already finished


async def test_failed_upload(clients, provider) -> None:
    public, internal = clients
    created = await create(public, provider)
    await consume(internal, created)
    response = await internal.post(f"/internal/files/{created['file']['id']}/fail")
    assert response.status_code == 200
    file = (await public.get(f"/files/{created['file']['id']}", headers=as_user(provider))).json()
    assert file["status"] == "failed"


async def test_intent_is_single_use(clients, provider) -> None:
    public, internal = clients
    created = await create(public, provider)
    assert (await consume(internal, created)).status_code == 200
    assert (await consume(internal, created)).status_code == 403


async def test_intent_is_bound_to_file_and_kind(clients, provider) -> None:
    public, internal = clients
    first = await create(public, provider)
    second = await create(public, provider, name="other.pdf")
    wrong_file = await internal.post(
        "/internal/intents/consume",
        json={"token": first["upload"]["token"], "kind": "upload", "file_id": second["file"]["id"]},
    )
    assert wrong_file.status_code == 403
    assert (await consume(internal, first, kind="download")).status_code == 403
    assert (await consume(internal, first, token="made-up")).status_code == 403
    assert (await consume(internal, first)).status_code == 200  # still usable afterwards


async def test_expired_intent_is_rejected(clients, provider, session) -> None:
    public, internal = clients
    created = await create(public, provider)
    await session.execute(
        update(TransferIntent).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    assert (await consume(internal, created)).status_code == 403


async def test_complete_needs_an_upload_in_progress(clients, provider) -> None:
    public, internal = clients
    created = await create(public, provider)
    body = {"size": 1, "sha256": "00" * 32, "wrapped_key": "AA==", "kms_key_id": "k"}
    response = await internal.post(f"/internal/files/{created['file']['id']}/complete", json=body)
    assert response.status_code == 409  # intent never consumed, file still pending
    assert (await internal.post(f"/internal/files/{uuid.uuid4()}/fail")).status_code == 409


async def test_internal_routes_all_require_the_secret(clients) -> None:
    _, internal = clients
    internal.headers.pop("Authorization")
    for route in internal_app.routes:
        for method in getattr(route, "methods", ()) or ():
            path = route.path.replace("{file_id}", str(uuid.uuid4()))
            response = await internal.request(method, path, json={})
            assert response.status_code == 401, f"{method} {route.path}"


def test_internal_api_has_no_docs() -> None:
    assert internal_app.openapi_url is None and internal_app.docs_url is None
