"""VaultGate control plane.

Owns everything that is request/response shaped: who the user is, what they may do,
which files exist, and who they were shared with. Large byte streams never pass
through this service; the Tornado gateway handles those.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import APIRouter, Depends, FastAPI

from vaultgate_api.auth import build_validator, get_principal
from vaultgate_api.logs import RequestContextMiddleware
from vaultgate_api.metrics import BUILD_INFO, MetricsMiddleware
from vaultgate_api.routers import admin, files, health, me

# Routes that answer without a token. Everything else is mounted on `protected`,
# so a new router is authenticated unless it is deliberately added here.
PUBLIC_PATHS = frozenset(
    {"/healthz", "/readyz", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with httpx.AsyncClient(timeout=5.0) as client:
        app.state.token_validator = build_validator(client)
        yield


app = FastAPI(
    title="VaultGate API",
    version="0.1.0",
    description="Identity, access policies, file metadata, share links and audit log.",
    lifespan=lifespan,
)

BUILD_INFO.info({"service": "api", "version": app.version})

# Starlette runs the last-added middleware first, so the request ID is assigned
# before metrics and handlers run.
app.add_middleware(MetricsMiddleware)
app.add_middleware(RequestContextMiddleware)
app.include_router(health.router)

# Deny by default: every router below requires a valid bearer token.
protected = APIRouter(dependencies=[Depends(get_principal)])
protected.include_router(me.router)
protected.include_router(admin.router)
protected.include_router(files.router)
app.include_router(protected)

# Public: /healthz (liveness), /readyz (database reachable).
# Protected: /me (caller's user record, provisioned from the access token),
#            /admin/users, /admin/groups (members of VAULTGATE_ADMIN_GROUPS only),
#            /files (the caller's files; POST returns a single-use upload intent).
# Internal (separate app and port, gateway only): see vaultgate_api.internal.
# Planned routers (see README roadmap):
#   policies - CRUD for access rules (IP range, time window, group, device posture)
#   files    - file metadata, upload intents, scan status
#   shares   - signed, expiring share links with download limits
#   audit    - read-only, append-only audit trail
