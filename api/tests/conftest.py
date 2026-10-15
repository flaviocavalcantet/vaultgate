"""Shared fixtures.

Database tests run against a real PostgreSQL, because the schema relies on Postgres
behaviour (UUIDs, timestamptz, server defaults). Point VAULTGATE_TEST_DATABASE_URL at
a disposable database to run them; CI does this with a Postgres service container.
Without it they are skipped, so the rest of the suite still runs anywhere.
"""

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

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
