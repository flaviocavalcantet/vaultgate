"""Each new connection logs in with the credentials in OpenBao's file right then
(vaultgate_api.db.use_current_credentials): a rotation needs no restart."""

import asyncio

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from tests.conftest import TEST_DATABASE_URL, requires_db
from vaultgate_api.db import use_current_credentials

pytestmark = requires_db


@pytest.fixture
async def rotated_login():
    """A second login, as OpenBao would create one."""
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    async with admin.begin() as conn:
        await conn.execute(text("DROP ROLE IF EXISTS vaultgate_rotated_test"))
        await conn.execute(text("CREATE ROLE vaultgate_rotated_test LOGIN PASSWORD 'rotated-pw'"))
    yield "vaultgate_rotated_test", "rotated-pw"
    async with admin.begin() as conn:
        await conn.execute(text("DROP ROLE IF EXISTS vaultgate_rotated_test"))
    await admin.dispose()


def url_with(user: str, password: str) -> str:
    url = make_url(TEST_DATABASE_URL).set(username=user, password=password)
    return url.render_as_string(hide_password=False)


async def current_user(engine) -> str:
    async with engine.connect() as conn:
        return (await conn.execute(text("select current_user"))).scalar_one()


async def test_new_connections_use_the_file_as_it_is_now(tmp_path, rotated_login):
    original = make_url(TEST_DATABASE_URL)
    url_file = tmp_path / "vaultgate_database_url"
    url_file.write_text(TEST_DATABASE_URL)
    # The engine's own URL never logs in: its wrong password proves it.
    engine = create_async_engine(url_with(original.username, "wrong"), poolclass=NullPool)
    use_current_credentials(engine, url_file)
    try:
        assert await current_user(engine) == original.username

        url_file.write_text(url_with(*rotated_login) + "\n")  # the agent renewed it
        assert await current_user(engine) == rotated_login[0]

        url_file.write_text(url_with(rotated_login[0], "revoked"))
        with pytest.raises(Exception, match="password authentication failed"):
            await current_user(engine)
    finally:
        await engine.dispose()


async def test_migrations_run_in_process(monkeypatch):
    """`python -m vaultgate_api` runs `alembic upgrade head` itself when asked (the image
    has no shell): here against the test database, already at head."""
    from pathlib import Path

    from vaultgate_api import __main__ as entry
    from vaultgate_api.config import settings

    monkeypatch.setattr(settings, "database_url", TEST_DATABASE_URL)
    ini = Path(__file__).resolve().parent.parent / "alembic.ini"
    await asyncio.to_thread(entry.migrate, str(ini))  # it runs its own event loop
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            head = (await conn.execute(text("select version_num from alembic_version"))).scalar()
    finally:
        await engine.dispose()
    assert head
