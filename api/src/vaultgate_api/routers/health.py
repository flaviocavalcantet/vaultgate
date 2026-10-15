from fastapi import APIRouter, Response, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from vaultgate_api.db import SessionDep

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def liveness() -> dict[str, str]:
    """Liveness probe: the process is up and serving requests."""
    return {"status": "ok", "service": "api"}


@router.get("/readyz")
async def readiness(response: Response, session: SessionDep) -> dict[str, str]:
    """Readiness probe: the database is reachable, so requests can be served."""
    try:
        await session.execute(text("SELECT 1"))
    except (SQLAlchemyError, OSError):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unavailable", "service": "api", "database": "down"}
    return {"status": "ok", "service": "api", "database": "up"}
