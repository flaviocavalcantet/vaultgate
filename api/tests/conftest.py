"""Shared fixtures.

Database tests run against a real PostgreSQL, because the schema relies on Postgres
behaviour (UUIDs, timestamptz, server defaults). Point VAULTGATE_TEST_DATABASE_URL at
a disposable database to run them; CI does this with a Postgres service container.
Without it they are skipped, so the rest of the suite still runs anywhere.
"""

import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

from tests.fake_oidc import FakeProvider, make_validator
from vaultgate_api import ratelimit, scans
from vaultgate_api.config import settings
from vaultgate_api.db import get_session
from vaultgate_api.internal import internal_app
from vaultgate_api.main import app
from vaultgate_api.models import Policy


@pytest.fixture(autouse=True)
def fresh_rate_limits():
    """Each test starts with empty rate-limit counters (vaultgate_api.ratelimit)."""
    ratelimit.reset()


TEST_DATABASE_URL = os.getenv("VAULTGATE_TEST_DATABASE_URL")
API_ROOT = Path(__file__).resolve().parent.parent

requires_db = pytest.mark.skipif(
    not TEST_DATABASE_URL, reason="VAULTGATE_TEST_DATABASE_URL is not set"
)


def alembic_config() -> Config:
    cfg = Config(str(API_ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", TEST_DATABASE_URL or "")
    return cfg


@pytest.fixture(scope="session")
def migrated_database() -> str:
    """Rebuild the test schema from migrations once per run."""
    cfg = alembic_config()
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    return TEST_DATABASE_URL


@pytest.fixture(scope="session")
async def engine(migrated_database: str) -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(migrated_database)
    yield engine
    await engine.dispose()


@pytest.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """A session inside a transaction that is rolled back, so tests never leak rows."""
    async with engine.connect() as connection:
        transaction = await connection.begin()
        async with AsyncSession(
            bind=connection,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ) as session:
            yield session
        await transaction.rollback()


INTERNAL_TOKEN = "gateway-secret-for-tests"


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
async def clients(provider: FakeProvider, session: AsyncSession, monkeypatch):
    """Public API and internal API clients sharing the test's database session, with a
    policy that allows every action to everyone (access policies have their own tests in
    test_access.py)."""
    session.add(Policy(name="everyone", effect="allow", actions=["read", "upload", "download"]))
    await session.flush()

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
    for a in (app, internal_app):
        a.dependency_overrides[scans.get_scan_queue] = lambda: queue
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=internal_app),
        base_url="http://internal",
        headers={"Authorization": f"Bearer {SCANNER_TOKEN}"},
    )
    async with client:
        yield (*clients, client)
