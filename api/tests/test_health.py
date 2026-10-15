from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from tests.conftest import requires_db
from vaultgate_api.db import get_session
from vaultgate_api.main import app


def test_liveness() -> None:
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "api"}


class _BrokenSession:
    async def execute(self, *args, **kwargs):
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))


def test_readiness_reports_database_down() -> None:
    async def broken_session():
        yield _BrokenSession()

    app.dependency_overrides[get_session] = broken_session
    try:
        response = TestClient(app).get("/readyz")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 503
    assert response.json()["database"] == "down"


@requires_db
def test_readiness_with_database(migrated_database: str, monkeypatch) -> None:
    from vaultgate_api import db
    from vaultgate_api.config import settings

    monkeypatch.setattr(settings, "database_url", migrated_database)
    db.get_engine.cache_clear()
    db.get_sessionmaker.cache_clear()
    try:
        response = TestClient(app).get("/readyz")
    finally:
        db.get_engine.cache_clear()
        db.get_sessionmaker.cache_clear()
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "api", "database": "up"}
