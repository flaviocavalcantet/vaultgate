from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def liveness() -> dict[str, str]:
    """Liveness probe: the process is up and serving requests."""
    return {"status": "ok", "service": "api"}
