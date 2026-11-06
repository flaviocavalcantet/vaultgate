"""Each new connection logs in with the credentials in OpenBao's file right then
(vaultgate_api.db.use_current_credentials): a rotation needs no restart."""

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
