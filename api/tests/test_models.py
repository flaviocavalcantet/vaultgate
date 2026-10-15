import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from tests.conftest import requires_db
from vaultgate_api.models import Base, Group, User

pytestmark = requires_db

ISSUER = "http://localhost:8080/realms/vaultgate"


async def test_migrations_match_models(engine: AsyncEngine) -> None:
    """The schema built by Alembic is exactly what the ORM models describe."""

    def diff(connection):
        return compare_metadata(MigrationContext.configure(connection), Base.metadata)

    async with engine.connect() as connection:
        assert await connection.run_sync(diff) == []


async def test_user_defaults(session: AsyncSession) -> None:
    user = User(issuer=ISSUER, subject="sub-1", email="ana@example.com")
    session.add(user)
    await session.flush()
    await session.refresh(user)

    assert user.id is not None
    assert user.is_active is True
    assert user.created_at is not None
    assert user.last_login_at is None


async def test_subject_is_unique_per_issuer(session: AsyncSession) -> None:
    session.add(User(issuer=ISSUER, subject="sub-1"))
    session.add(User(issuer="https://other-idp.example", subject="sub-1"))
    await session.flush()  # same subject from a different issuer is a different person

    session.add(User(issuer=ISSUER, subject="sub-1"))
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_group_membership(session: AsyncSession) -> None:
    finance = Group(name="/finance")
    user = User(issuer=ISSUER, subject="sub-2", groups=[finance])
    session.add(user)
    await session.flush()
    session.expunge_all()

    loaded = (await session.execute(select(Group).where(Group.name == "/finance"))).scalar_one()
    assert [m.subject for m in loaded.members] == ["sub-2"]


async def test_deleting_user_removes_memberships(session: AsyncSession) -> None:
    group = Group(name="/legal")
    user = User(issuer=ISSUER, subject="sub-3", groups=[group])
    session.add(user)
    await session.flush()

    await session.delete(user)
    await session.flush()
    session.expunge_all()

    loaded = (await session.execute(select(Group).where(Group.name == "/legal"))).scalar_one()
    assert loaded.members == []
