"""VaultGate control plane.

Owns everything that is request/response shaped: who the user is, what they may do,
which files exist, and who they were shared with. Large byte streams never pass
through this service; the Tornado gateway handles those.
"""

import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import APIRouter, Depends, FastAPI

from vaultgate_api.auth import build_validator, get_principal
from vaultgate_api.clientip import ClientAddressMiddleware
from vaultgate_api.config import settings
from vaultgate_api.headers import SecurityHeadersMiddleware
from vaultgate_api.logs import RequestContextMiddleware
from vaultgate_api.metrics import BUILD_INFO, MetricsMiddleware
from vaultgate_api.ratelimit import limit_pki, limit_share_access, limit_user
from vaultgate_api.routers import (
    admin,
    admin_files,
    audit,
    files,
    health,
    me,
    pki,
    policies,
    share_access,
    shared_with_me,
    shares,
)
from vaultgate_api.tracing import FASTAPI_TELEMETRY, TracingMiddleware

# Routes that answer without a token. Everything else is mounted on `protected`,
# so a new router is authenticated unless it is deliberately added here.
PUBLIC_PATHS = frozenset(
    {"/healthz", "/readyz", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}
    | {f"/pki/nodes/{p}" for p in ("ca", "ca/pem", "crl", "crl/delta", "ocsp")}
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # OpenBao, for the nodes' CA (vaultgate_api.routers.pki): verified with the trust
    # store OpenSSL's defaults name (SSL_CERT_FILE on the cluster).
    openbao_tls = ssl.create_default_context()
    async with (
        httpx.AsyncClient(timeout=5.0) as client,
        httpx.AsyncClient(timeout=5.0, verify=openbao_tls) as openbao,
    ):
        app.state.token_validator = build_validator(client)
        app.state.openbao = openbao
        yield


class _API(FastAPI):
    """FastAPI, with the security headers (vaultgate_api.headers) outside every layer:
    Starlette's ServerErrorMiddleware, which answers an unhandled exception's 500 itself,
    is outside every middleware add_middleware adds, so the headers go around it here."""

    def build_middleware_stack(self):
        return SecurityHeadersMiddleware(super().build_middleware_stack())


def docs_urls() -> dict:
    """Where FastAPI serves the documentation, or None for each when it is off."""
    on = settings.docs_enabled
    return {
        "docs_url": "/docs" if on else None,
        "redoc_url": "/redoc" if on else None,
        "openapi_url": "/openapi.json" if on else None,
    }


app = _API(
    **docs_urls(),
    title="VaultGate API",
    version="0.1.0",
    description="Identity, access policies, file metadata, share links and audit log.",
    lifespan=lifespan,
    telemetry=FASTAPI_TELEMETRY,
)

BUILD_INFO.info({"service": "api", "version": app.version})

# Starlette runs the last-added middleware first: the client address is resolved
# before anything reads it, the request's span is open before the access log line is
# written (so the line carries its trace ID), and the request ID is assigned before
# metrics and handlers.
app.add_middleware(MetricsMiddleware)
app.add_middleware(RequestContextMiddleware)
# Public: a client's own trace context is ignored (vaultgate_api.tracing).
app.add_middleware(TracingMiddleware, trust_incoming=False)
app.add_middleware(ClientAddressMiddleware, trusted=settings.trusted_proxies)
app.include_router(health.router)
# Share recipients have no token: the link's own token and an emailed code authorize
# them (vaultgate_api.routers.share_access).
app.include_router(share_access.router, dependencies=[Depends(limit_share_access)])
# The nodes' CA's certificate, revocation lists and OCSP: public by nature (signed), so
# limited per client address (vaultgate_api.routers.pki).
app.include_router(pki.router, dependencies=[Depends(limit_pki)])

# Deny by default: every router below requires a valid bearer token.
# Authenticated, then within the caller's rate limits (vaultgate_api.ratelimit).
protected = APIRouter(dependencies=[Depends(get_principal), Depends(limit_user)])
protected.include_router(me.router)
protected.include_router(admin.router)
protected.include_router(admin_files.router)
protected.include_router(audit.router)
protected.include_router(policies.router)
protected.include_router(files.router)
protected.include_router(shares.router)
protected.include_router(shared_with_me.router)
app.include_router(protected)

# Public: /healthz (liveness), /readyz (database reachable), /shares/access (share
#         recipients, authorized by the link's token and an emailed code), /pki/nodes
#         (the nodes' CA's certificate, revocation lists and OCSP).
# Protected: /me (caller's user record, provisioned from the access token),
#            /admin/users, /admin/groups, /admin/policies, /admin/files, /admin/audit (members
#            of VAULTGATE_ADMIN_GROUPS only; never subject to access policies),
#            /files (the caller's files; POST returns a single-use upload intent),
#            /files/{id}/shares (share links for one of the caller's files),
#            /shared-with-me (internal shares addressed to the caller's verified email).
# Internal (separate app and port, gateway only): see vaultgate_api.internal.
# Planned routers (see README roadmap):
#   files    - file metadata, upload intents, scan status
#   shares   - signed, expiring share links with download limits
#   audit    - read-only, append-only audit trail
