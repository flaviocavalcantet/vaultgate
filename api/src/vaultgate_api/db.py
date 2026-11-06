"""Database engine and per-request sessions.

The engine is created lazily so importing the app (tests, OpenAPI generation) never
opens a connection. Each request gets its own session; handlers commit explicitly.

On the cluster the database URL is a file that OpenBao's agent rewrites when it renews
the API's credentials, short-lived and the pod's own (M9, ADR 0012): every new
connection logs in with the credentials in the file at that moment, and pooled
connections are recycled every 15 minutes, well within a credential's life.
"""

import os
from collections.abc import AsyncIterator
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends
from sqlalchemy import event
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from vaultgate_api.config import settings

RECYCLE_SECONDS = 900


def database_url_file() -> Path | None:
    """The URL file from OpenBao, unless a variable sets the URL (it wins, as in config)."""
    directory = os.getenv("VAULTGATE_SECRETS_DIR")
    if not directory or os.getenv("VAULTGATE_DATABASE_URL"):
        return None
    path = Path(directory) / "vaultgate_database_url"
    return path if path.is_file() else None


def use_current_credentials(engine: AsyncEngine, path: Path) -> None:
    """Each new connection logs in with the user and password in `path` right now."""

    @event.listens_for(engine.sync_engine, "do_connect")
    def current_credentials(dialect, connection_record, cargs, cparams) -> None:
        url = make_url(path.read_text().strip())
        cparams["user"], cparams["password"] = url.username, url.password


@lru_cache
def get_engine() -> AsyncEngine:
    path = database_url_file()
    engine = create_async_engine(
        settings.database_url,
        echo=settings.database_echo,
        pool_pre_ping=True,
        pool_recycle=RECYCLE_SECONDS if path else -1,
    )
    if path:
        use_current_credentials(engine, path)
    return engine


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one session per request, rolled back if not committed."""
    async with get_sessionmaker()() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]
