"""Alembic environment: runs migrations over the API's async engine."""

import asyncio
import logging

from alembic import context
from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from vaultgate_api.config import settings
from vaultgate_api.logs import configure_logging
from vaultgate_api.models import Base

config = context.config
# Same log format as the API, so migration output on container start is collected too.
configure_logging(settings.log_level, settings.log_format)
logging.getLogger("alembic").setLevel(logging.INFO)

target_metadata = Base.metadata

# Arbitrary constant shared by every replica; serializes concurrent `alembic upgrade`.
MIGRATION_LOCK_ID = 0x7661756C74


def database_url() -> str:
    # An explicit URL (set by tests via Config.set_main_option) wins over the environment.
    return config.get_main_option("sqlalchemy.url") or settings.database_url


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running it (`alembic upgrade head --sql`)."""
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        # Released automatically when the migration transaction ends.
        connection.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": MIGRATION_LOCK_ID})
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(database_url(), poolclass=pool.NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
