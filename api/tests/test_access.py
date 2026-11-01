"""Access policies enforced on the file routes and on the gateway's intent consume."""

import logging
import uuid

import httpx
import pytest
from prometheus_client import REGISTRY
from pydantic import SecretStr
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import requires_db
from tests.fake_oidc import FakeProvider, make_validator
from vaultgate_api.config import settings
from vaultgate_api.db import get_session
from vaultgate_api.internal import internal_app
from vaultgate_api.main import app
from vaultgate_api.models import File, Policy, User

pytestmark = requires_db

INTERNAL_TOKEN = "gateway-secret-for-tests"
ALL = ["read", "upload", "download"]
OFFICE_IP = "10.1.2.3"
HOME_IP = "203.0.113.9"


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
async def stack(provider: FakeProvider, session: AsyncSession, monkeypatch):
    """A function that opens a public API client connecting from a given address, and
    the internal API client. No policies exist unless a test adds them."""

    async def test_session():
        yield session

    monkeypatch.setattr(settings, "internal_token", SecretStr(INTERNAL_TOKEN))
    app.state.token_validator = make_validator(provider)
    for a in (app, internal_app):
        a.dependency_overrides[get_session] = test_session
    opened = []

    def public(client_ip: str = OFFICE_IP) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=app, client=(client_ip, 40000))
        client = httpx.AsyncClient(transport=transport, base_url="http://api")
        opened.append(client)
        return client

    internal = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=internal_app),
        base_url="http://internal",
        headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"},
    )
    async with internal:
        yield public, internal
    for client in opened:
        await client.aclose()
    for a in (app, internal_app):
        a.dependency_overrides.clear()
    del app.state.token_validator


async def add_policy(session: AsyncSession, name: str, effect: str = "allow", **fields) -> None:
    fields.setdefault("actions", ALL)
    session.add(Policy(name=name, effect=effect, **fields))
    await session.flush()


async def remove_policy(session: AsyncSession, name: str) -> None:
    await session.execute(delete(Policy).where(Policy.name == name))
    await session.flush()


def as_user(provider: FakeProvider, sub: str = "alice", groups=("/finance",)) -> dict:
    token = provider.token(sub=sub, preferred_username=sub, groups=list(groups))
    return {"Authorization": f"Bearer {token}"}


async def create(api: httpx.AsyncClient, headers: dict) -> dict:
    body = {"name": "report.pdf", "size": 3, "content_type": "application/pdf"}
    response = await api.post("/files", json=body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def consume(internal, created: dict, client_ip: str | None, kind="upload", token=None):
    return internal.post(
        "/internal/intents/consume",
        json={
            "token": token or created["upload"]["token"],
            "kind": kind,
            "file_id": created["file"]["id"],
            "client_ip": client_ip,
        },
    )


async def mark_uploaded(session: AsyncSession, file_id: str) -> None:
    await session.execute(
        update(File)
        .where(File.id == uuid.UUID(file_id))
        .values(status="uploaded", size=3, sha256="0" * 64, wrapped_key=b"k", kms_key_id="k")
    )
    await session.flush()


def decisions(action: str, result: str, checked_by: str) -> float:
    labels = {"action": action, "result": result, "checked_by": checked_by}
    return REGISTRY.get_sample_value("vaultgate_policy_decisions_total", labels) or 0.0


# --- deny by default ---------------------------------------------------------------


async def test_without_policies_every_file_route_is_refused(stack, provider) -> None:
    public, _ = stack
    api, alice = public(), as_user(provider)
    some_id = uuid.uuid4()
    for method, path, body in [
        ("GET", "/files", None),
        ("GET", f"/files/{some_id}", None),  # refused before it can be probed: 403, not 404
        ("POST", "/files", {"name": "a.txt", "size": 1}),
        ("POST", f"/files/{some_id}/download", None),
    ]:
        response = await api.request(method, path, json=body, headers=alice)
        assert response.status_code == 403, (method, path)
        assert response.json() == {"detail": "Access denied by policy"}


async def test_me_and_admin_are_never_subject_to_policies(stack, provider, session) -> None:
    public, _ = stack
    await add_policy(session, "block everything", effect="deny")
    api = public()
    assert (await api.get("/me", headers=as_user(provider))).status_code == 200
    carol = as_user(provider, "carol", ("/vaultgate-admins",))
    assert (await api.get("/admin/policies", headers=carol)).status_code == 200
    assert (await api.get("/admin/users", headers=carol)).status_code == 200


# --- what the public routes check --------------------------------------------------


async def test_each_route_checks_its_own_action(stack, provider, session) -> None:
    public, _ = stack
    api, alice = public(), as_user(provider)
    await add_policy(session, "read only", actions=["read"])
    assert (await api.get("/files", headers=alice)).status_code == 200
    assert (await api.get(f"/files/{uuid.uuid4()}", headers=alice)).status_code == 404
    response = await api.post("/files", json={"name": "a.txt", "size": 1}, headers=alice)
    assert response.status_code == 403

    await add_policy(session, "upload", actions=["upload"])
    created = await create(api, alice)
    await mark_uploaded(session, created["file"]["id"])
    path = f"/files/{created['file']['id']}/download"
    assert (await api.post(path, headers=alice)).status_code == 403
    await add_policy(session, "download", actions=["download"])
    assert (await api.post(path, headers=alice)).status_code == 201


async def test_groups_decide(stack, provider, session) -> None:
    public, _ = stack
    api = public()
    await add_policy(session, "finance", groups=["/finance"])
    assert (await api.get("/files", headers=as_user(provider))).status_code == 200
    payroll = as_user(provider, "paula", ("/finance/payroll",))
    assert (await api.get("/files", headers=payroll)).status_code == 200
    bob = as_user(provider, "bob", ("/legal",))
    assert (await api.get("/files", headers=bob)).status_code == 403


async def test_the_resolved_client_address_decides(stack, provider, session) -> None:
    public, _ = stack
    alice = as_user(provider)
    await add_policy(session, "office", networks=["10.0.0.0/8"])
    assert (await public(OFFICE_IP).get("/files", headers=alice)).status_code == 200
    assert (await public(HOME_IP).get("/files", headers=alice)).status_code == 403
    # Without trusted proxies, a forwarded address is the client's own claim.
    forged = alice | {"X-Forwarded-For": OFFICE_IP}
    assert (await public(HOME_IP).get("/files", headers=forged)).status_code == 403


async def test_deny_wins_and_is_logged(stack, provider, session, caplog) -> None:
    public, _ = stack
    api, alice = public(), as_user(provider)
    await add_policy(session, "everyone")
    await add_policy(
        session, "no finance downloads", effect="deny", groups=["/finance"], actions=["download"]
    )
    created = await create(api, alice)
    await mark_uploaded(session, created["file"]["id"])
    before = decisions("download", "denied", "api")
    with caplog.at_level(logging.INFO, logger="vaultgate_api.access"):
        response = await api.post(f"/files/{created['file']['id']}/download", headers=alice)
    assert response.status_code == 403
    assert decisions("download", "denied", "api") == before + 1
    [record] = [r for r in caplog.records if r.getMessage() == "access denied by policy"]
    assert record.deny_policies == ["no finance downloads"]
    assert (record.action, record.client_ip, record.checked_by) == ("download", OFFICE_IP, "api")
    assert (await api.get("/files", headers=alice)).status_code == 200  # read still allowed


# --- the gateway's consume re-checks -----------------------------------------------


async def test_consume_rechecks_and_a_refusal_leaves_the_intent_unspent(
    stack, provider, session
) -> None:
    public, internal = stack
    await add_policy(session, "everyone")
    created = await create(public(), as_user(provider))

    await add_policy(session, "uploads paused", effect="deny", actions=["upload"])
    before = decisions("upload", "denied", "gateway")
    response = await consume(internal, created, OFFICE_IP)
    assert response.status_code == 403
    assert decisions("upload", "denied", "gateway") == before + 1

    await remove_policy(session, "uploads paused")
    assert (await consume(internal, created, OFFICE_IP)).status_code == 200
    assert (await consume(internal, created, OFFICE_IP)).status_code == 403  # now it is spent


async def test_consume_uses_the_address_the_gateway_saw(stack, provider, session) -> None:
    public, internal = stack
    await add_policy(session, "office", networks=["10.0.0.0/8"])
    alice = as_user(provider)
    api = public(OFFICE_IP)

    # An intent obtained in the office is useless from home, or from nowhere known.
    created = await create(api, alice)
    assert (await consume(internal, created, HOME_IP)).status_code == 403
    assert (await consume(internal, created, None)).status_code == 403
    assert (await consume(internal, created, "::ffff:10.9.9.9")).status_code == 200

    # Downloads too.
    await mark_uploaded(session, created["file"]["id"])
    intent = (await api.post(f"/files/{created['file']['id']}/download", headers=alice)).json()
    download = {"kind": "download", "token": intent["token"]}
    assert (await consume(internal, created, HOME_IP, **download)).status_code == 403
    assert (await consume(internal, created, OFFICE_IP, **download)).status_code == 200


async def test_consume_without_an_address_from_an_older_gateway(stack, provider, session) -> None:
    public, internal = stack
    await add_policy(session, "everyone")
    created = await create(public(), as_user(provider))
    body = {"token": created["upload"]["token"], "kind": "upload", "file_id": created["file"]["id"]}
    assert (await internal.post("/internal/intents/consume", json=body)).status_code == 200


async def test_consume_refuses_intents_of_deactivated_users(stack, provider, session) -> None:
    public, internal = stack
    await add_policy(session, "everyone")
    created = await create(public(), as_user(provider))
    await session.execute(update(User).where(User.subject == "alice").values(is_active=False))
    await session.flush()
    response = await consume(internal, created, OFFICE_IP)
    assert response.status_code == 403
    assert response.json() == {"detail": "User is deactivated"}


async def test_consume_rejects_a_malformed_address(stack, provider, session) -> None:
    public, internal = stack
    await add_policy(session, "everyone")
    created = await create(public(), as_user(provider))
    assert (await consume(internal, created, "10.0.0.0/8")).status_code == 422
