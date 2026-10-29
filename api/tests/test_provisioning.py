import uuid
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import requires_db
from tests.fake_oidc import ISSUER, FakeProvider, make_validator
from vaultgate_api.auth import Principal
from vaultgate_api.db import get_session
from vaultgate_api.main import app
from vaultgate_api.models import Group, User
from vaultgate_api.provisioning import LAST_SEEN_RESOLUTION, provision

pytestmark = requires_db


def principal(**overrides) -> Principal:
    values = {
        "issuer": ISSUER,
        "subject": "sub-alice",
        "username": "alice",
        "email": "alice@example.com",
        "name": "Alice Finance",
        "groups": ("/finance",),
    }
    values.update(overrides)
    return Principal(**values)


async def count(session: AsyncSession, model) -> int:
    return await session.scalar(select(func.count()).select_from(model))


# --- provision() ----------------------------------------------------------------


async def test_first_request_creates_user_and_groups(session) -> None:
    user = await provision(session, principal(groups=("/finance", "/legal")))
    assert user.username == "alice"
    assert user.email == "alice@example.com"
    assert user.display_name == "Alice Finance"
    assert user.last_login_at is not None
    assert sorted(g.name for g in user.groups) == ["/finance", "/legal"]
    assert await count(session, User) == 1
    assert await count(session, Group) == 2


async def test_repeat_requests_reuse_the_record(session) -> None:
    first = await provision(session, principal())
    second = await provision(session, principal())
    assert first.id == second.id
    assert await count(session, User) == 1


async def test_same_subject_from_another_issuer_is_another_user(session) -> None:
    a = await provision(session, principal())
    b = await provision(session, principal(issuer="https://other-idp.example"))
    assert a.id != b.id


async def test_profile_follows_the_token(session) -> None:
    await provision(session, principal())
    user = await provision(session, principal(email="alice@new.example", name="Alice F."))
    assert user.email == "alice@new.example"
    assert user.display_name == "Alice F."


async def test_groups_follow_the_token(session) -> None:
    await provision(session, principal(groups=("/finance", "/legal")))
    user = await provision(session, principal(groups=("/legal", "/engineering")))
    assert sorted(g.name for g in user.groups) == ["/engineering", "/legal"]

    user = await provision(session, principal(groups=()))
    assert user.groups == []
    # Groups themselves are kept: other users may still be in them.
    assert await count(session, Group) == 3


async def test_shared_groups_are_not_duplicated(session) -> None:
    await provision(session, principal(subject="a"))
    await provision(session, principal(subject="b"))
    assert await count(session, Group) == 1


async def test_last_seen_is_refreshed_at_most_every_resolution(session) -> None:
    user = await provision(session, principal())
    first_seen = user.last_login_at

    user = await provision(session, principal(), now=first_seen + timedelta(minutes=1))
    assert user.last_login_at == first_seen

    later = first_seen + LAST_SEEN_RESOLUTION + timedelta(seconds=1)
    user = await provision(session, principal(), now=later)
    assert user.last_login_at == later


# --- HTTP -------------------------------------------------------------------------


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
async def api(provider: FakeProvider, session: AsyncSession):
    """An HTTP client on the test's event loop, so the app can share its DB session."""

    async def test_session():
        yield session

    app.state.token_validator = make_validator(provider)
    app.dependency_overrides[get_session] = test_session
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()
    del app.state.token_validator


def bearer(provider: FakeProvider, **claims) -> dict[str, str]:
    return {"Authorization": f"Bearer {provider.token(**claims)}"}


async def test_me_returns_the_provisioned_user(provider, api) -> None:
    response = await api.get("/me", headers=bearer(provider, groups=["/legal", "/finance"]))
    assert response.status_code == 200
    body = response.json()
    uuid.UUID(body["id"])
    assert body["issuer"] == ISSUER
    assert body["subject"] == "user-123"
    assert body["username"] == "alice"
    assert body["groups"] == ["/finance", "/legal"]
    assert body["is_active"] is True

    again = (await api.get("/me", headers=bearer(provider))).json()
    assert again["id"] == body["id"]


async def test_deactivated_user_is_refused(provider, api, session) -> None:
    await api.get("/me", headers=bearer(provider))
    await session.execute(update(User).values(is_active=False))
    response = await api.get("/me", headers=bearer(provider))
    assert response.status_code == 403


async def test_admin_endpoints_need_the_admin_group(provider, api) -> None:
    alice = bearer(provider, sub="alice", groups=["/finance"])
    for path in ("/admin/users", "/admin/groups", f"/admin/users/{uuid.uuid4()}"):
        assert (await api.get(path, headers=alice)).status_code == 403


async def test_admin_lists_users_and_groups(provider, api) -> None:
    await api.get("/me", headers=bearer(provider, sub="alice", groups=["/finance"]))
    carol = bearer(provider, sub="carol", preferred_username="carol", groups=["/vaultgate-admins"])

    users = await api.get("/admin/users", headers=carol)
    assert users.status_code == 200
    page = users.json()
    assert page["total"] == 2
    # Both rows share created_at here (one test transaction), so compare as a set.
    assert sorted(u["subject"] for u in page["items"]) == ["alice", "carol"]

    groups = (await api.get("/admin/groups", headers=carol)).json()
    assert {g["name"]: g["members"] for g in groups["items"]} == {
        "/finance": 1,
        "/vaultgate-admins": 1,
    }

    alice_id = next(u["id"] for u in page["items"] if u["subject"] == "alice")
    assert (await api.get(f"/admin/users/{alice_id}", headers=carol)).json()["subject"] == "alice"
    assert (await api.get(f"/admin/users/{uuid.uuid4()}", headers=carol)).status_code == 404


async def test_admin_pagination_is_bounded(provider, api) -> None:
    carol = bearer(provider, sub="carol", groups=["/vaultgate-admins"])
    assert (await api.get("/admin/users?limit=101", headers=carol)).status_code == 422
    assert (await api.get("/admin/users?limit=1&offset=0", headers=carol)).json()["limit"] == 1
