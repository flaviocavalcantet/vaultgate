"""VaultGate control plane.

Owns everything that is request/response shaped: who the user is, what they may do,
which files exist, and who they were shared with. Large byte streams never pass
through this service; the Tornado gateway handles those.
"""

from fastapi import FastAPI

from vaultgate_api.logs import RequestContextMiddleware
from vaultgate_api.metrics import BUILD_INFO, MetricsMiddleware
from vaultgate_api.routers import health

app = FastAPI(
    title="VaultGate API",
    version="0.1.0",
    description="Identity, access policies, file metadata, share links and audit log.",
)

BUILD_INFO.info({"service": "api", "version": app.version})

# Starlette runs the last-added middleware first, so the request ID is assigned
# before metrics and handlers run.
app.add_middleware(MetricsMiddleware)
app.add_middleware(RequestContextMiddleware)
app.include_router(health.router)

# Health: /healthz (liveness) and /readyz (database reachable).
# Planned routers (see README roadmap):
#   auth     - OIDC login callback, token validation, session introspection
#   policies - CRUD for access rules (IP range, time window, group, device posture)
#   files    - file metadata, upload intents, scan status
#   shares   - signed, expiring share links with download limits
#   audit    - read-only, append-only audit trail
