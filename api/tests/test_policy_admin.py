import logging
import uuid

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import requires_db
from tests.fake_oidc import FakeProvider, make_validator
from vaultgate_api.db import get_session
from vaultgate_api.main import app

pytestmark = requires_db

OFFICE = {
    "name": "finance office hours",
    "description": "Finance, from the office, on weekdays",
    "effect": "allow",
    "actions": ["read", "upload", "download"],
    "groups": ["/finance"],
    "networks": ["10.0.0.0/8"],
    "days": [1, 2, 3, 4, 5],
    "start_time": "08:00",
    "end_time": "18:00",
    "timezone": "America/Sao_Paulo",
}


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
async def api(provider: FakeProvider, session: AsyncSession):
    async def test_session():
        yield session

    app.state.token_validator = make_validator(provider)
    app.dependency_overrides[get_session] = test_session
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()
    del app.state.token_validator


@pytest.fixture
def admin(provider: FakeProvider) -> dict[str, str]:
    token = provider.token(sub="carol", preferred_username="carol", groups=["/vaultgate-admins"])
    return {"Authorization": f"Bearer {token}"}


def user(provider: FakeProvider, sub: str = "alice", groups=("/finance",)) -> dict[str, str]:
    return {"Authorization": f"Bearer {provider.token(sub=sub, groups=list(groups))}"}


async def create(api, admin, **overrides) -> dict:
    response = await api.post("/admin/policies", json=OFFICE | overrides, headers=admin)
    assert response.status_code == 201, response.text
    return response.json()


async def test_only_admins_manage_policies(api, provider) -> None:
    alice = user(provider)
    some_id = uuid.uuid4()
    for method, path in [
        ("GET", "/admin/policies"),
        ("POST", "/admin/policies"),
        ("POST", "/admin/policies/evaluate"),
        ("GET", f"/admin/policies/{some_id}"),
        ("PUT", f"/admin/policies/{some_id}"),
        ("DELETE", f"/admin/policies/{some_id}"),
    ]:
        response = await api.request(method, path, json=OFFICE, headers=alice)
        assert response.status_code == 403, (method, path)
        assert (await api.request(method, path, json=OFFICE)).status_code == 401


async def test_create_and_read_back(api, admin, caplog) -> None:
    with caplog.at_level(logging.INFO, logger="vaultgate_api.routers.policies"):
        created = await create(api, admin)
    assert created["name"] == "finance office hours"
    assert created["networks"] == ["10.0.0.0/8"]
    assert created["excluded_networks"] == []
    assert created["start_time"] == "08:00:00"
    assert created["enabled"] is True
    assert created["created_at"] and created["updated_at"]
    [record] = [r for r in caplog.records if r.getMessage() == "policy changed"]
    assert (record.change, record.policy_id) == ("created", created["id"])

    fetched = await api.get(f"/admin/policies/{created['id']}", headers=admin)
    assert fetched.json() == created
    listed = (await api.get("/admin/policies", headers=admin)).json()
    assert listed["total"] == 1 and listed["items"] == [created]


async def test_input_is_normalized(api, admin) -> None:
    created = await create(
        api,
        admin,
        name="  padded  ",
        actions=["download", "read", "download"],
        groups=["/finance/", "/finance", "/legal"],
        days=[5, 1, 1],
    )
    assert created["name"] == "padded"
    assert created["actions"] == ["read", "download"]
    assert created["groups"] == ["/finance", "/legal"]
    assert created["days"] == [1, 5]


@pytest.mark.parametrize(
    "change",
    [
        {"name": "   "},
        {"name": "tab\there"},
        {"effect": "maybe"},
        {"actions": []},
        {"actions": ["delete"]},
        {"groups": ["finance"]},
        {"groups": ["/"]},
        {"groups": ["/finance//payroll"]},
        {"networks": ["10.0.0.1/8"]},
        {"networks": ["not-a-network"]},
        {"excluded_networks": ["300.0.0.0/8"]},
        {"days": [0]},
        {"days": [8]},
        {"start_time": "08:00", "end_time": None},
        {"start_time": None, "end_time": "18:00"},
        {"start_time": "08:00", "end_time": "08:00"},
        {"start_time": "08:00+02:00"},
        {"timezone": "Mars/Olympus_Mons"},
        {"timezone": "localtime"},
        {"timezone": "../../etc/passwd"},
        {"networks": [f"10.{i}.0.0/16" for i in range(101)]},
    ],
)
async def test_invalid_policies_are_rejected(api, admin, change) -> None:
    response = await api.post("/admin/policies", json=OFFICE | change, headers=admin)
    assert response.status_code == 422, response.text


async def test_minimal_policy(api, admin) -> None:
    body = {"name": "everyone reads", "effect": "allow", "actions": ["read"]}
    created = (await api.post("/admin/policies", json=body, headers=admin)).json()
    assert created["groups"] == [] and created["networks"] == [] and created["days"] == []
    assert created["start_time"] is None and created["timezone"] == "UTC"


async def test_names_are_unique(api, admin) -> None:
    await create(api, admin)
    response = await api.post("/admin/policies", json=OFFICE, headers=admin)
    assert response.status_code == 409
    other = await create(api, admin, name="other")
    response = await api.put(f"/admin/policies/{other['id']}", json=OFFICE, headers=admin)
    assert response.status_code == 409


async def test_replace_and_delete(api, admin) -> None:
    created = await create(api, admin)
    replaced = await api.put(
        f"/admin/policies/{created['id']}",
        json=OFFICE | {"effect": "deny", "start_time": None, "end_time": None, "enabled": False},
        headers=admin,
    )
    assert replaced.status_code == 200
    body = replaced.json()
    assert (body["id"], body["effect"], body["enabled"]) == (created["id"], "deny", False)
    assert body["start_time"] is None

    path = f"/admin/policies/{created['id']}"
    assert (await api.delete(path, headers=admin)).status_code == 204
    assert (await api.get(path, headers=admin)).status_code == 404
    assert (await api.delete(path, headers=admin)).status_code == 404
    assert (await api.put(path, json=OFFICE, headers=admin)).status_code == 404


async def evaluate(api, admin, **body) -> dict:
    response = await api.post("/admin/policies/evaluate", json=body, headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


async def test_dry_run_explains_the_decision(api, admin) -> None:
    await create(api, admin)
    await create(
        api,
        admin,
        name="block lab network",
        effect="deny",
        groups=[],
        networks=["10.66.0.0/16"],
        days=[],
        start_time=None,
        end_time=None,
    )
    wednesday_3pm = "2026-11-04T15:00:00-03:00"
    common = {"action": "download", "groups": ["/finance/payroll"], "at": wednesday_3pm}

    allowed = await evaluate(api, admin, client_ip="10.1.2.3", **common)
    assert (allowed["allowed"], allowed["reason"]) == (True, "allowed")
    assert allowed["allow"] == ["finance office hours"]

    denied = await evaluate(api, admin, client_ip="10.66.0.9", **common)
    assert (denied["allowed"], denied["reason"]) == (False, "denied")
    assert denied["deny"] == ["block lab network"]
    assert denied["allow"] == ["finance office hours"]

    evening = await evaluate(
        api, admin, client_ip="10.1.2.3", **(common | {"at": "2026-11-04T20:00:00-03:00"})
    )
    assert evening["reason"] == "no_matching_policy"

    mapped = await evaluate(api, admin, client_ip="::ffff:10.1.2.3", **common)
    assert (mapped["allowed"], mapped["client_ip"]) == (True, "10.1.2.3")


async def test_dry_run_with_a_users_groups(api, admin, provider) -> None:
    await create(api, admin, days=[], start_time=None, end_time=None)
    alice = user(provider, groups=("/finance",))
    alice_id = (await api.get("/me", headers=alice)).json()["id"]
    bob = user(provider, sub="bob", groups=("/legal",))
    bob_id = (await api.get("/me", headers=bob)).json()["id"]

    result = await evaluate(api, admin, action="read", user_id=alice_id, client_ip="10.0.0.1")
    assert (result["allowed"], result["groups"]) == (True, ["/finance"])
    result = await evaluate(api, admin, action="read", user_id=bob_id, client_ip="10.0.0.1")
    assert (result["allowed"], result["groups"]) == (False, ["/legal"])
    assert result["at"]  # defaults to now

    response = await api.post(
        "/admin/policies/evaluate",
        json={"action": "read", "user_id": str(uuid.uuid4()), "client_ip": "10.0.0.1"},
        headers=admin,
    )
    assert response.status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {"action": "read", "client_ip": "10.0.0.1"},  # nobody to evaluate
        {"action": "read", "client_ip": "10.0.0.1", "groups": [], "user_id": str(uuid.uuid4())},
        {"action": "read", "client_ip": "10.0.0.0/8", "groups": []},
        {"action": "share", "client_ip": "10.0.0.1", "groups": []},
        {"action": "read", "client_ip": "10.0.0.1", "groups": [], "at": "2026-11-04T15:00:00"},
    ],
)
async def test_dry_run_rejects_incomplete_requests(api, admin, body) -> None:
    response = await api.post("/admin/policies/evaluate", json=body, headers=admin)
    assert response.status_code == 422, response.text


async def test_disabled_policies_do_not_count_in_the_dry_run(api, admin) -> None:
    await create(api, admin, days=[], start_time=None, end_time=None, enabled=False)
    result = await evaluate(api, admin, action="read", groups=["/finance"], client_ip="10.0.0.1")
    assert result["reason"] == "no_matching_policy"
