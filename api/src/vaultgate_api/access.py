"""Enforcing access policies (ADR 0004).

Every file route needs its action allowed for the caller, from the client address
resolved by vaultgate_api.clientip, at the time of the request: listing and viewing
files is `read`, registering one is `upload`, asking for a download is `download`.
The gateway's intent consume repeats the upload or download check with the address
the gateway sees, so an intent obtained from an allowed network or inside a time window
is useless from elsewhere or later.

A refusal is a plain 403 for the caller. The log line names the matching deny policies
(or that nothing allowed the request); the admin dry run shows the same detail. /me
and /admin are not checked here, so admins can always fix a bad policy.
"""

import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from prometheus_client import Counter
from sqlalchemy.ext.asyncio import AsyncSession

from vaultgate_api import policies
from vaultgate_api.db import SessionDep
from vaultgate_api.models import User
from vaultgate_api.provisioning import CurrentUserDep

logger = logging.getLogger(__name__)

POLICY_DECISIONS = Counter(
    "vaultgate_policy_decisions_total",
    "Access policy decisions on real requests (not dry runs), by action and result",
    ["action", "result", "checked_by"],
)

DENIED = "Access denied by policy"


async def authorize(
    session: AsyncSession,
    *,
    action: policies.Action,
    user: User,
    client_ip: str | None,
    checked_by: str,
) -> policies.Decision:
    """Decide `action` for `user` now; count it, and log a refusal."""
    request = policies.AccessRequest.of(
        action, [g.name for g in user.groups], client_ip, datetime.now(UTC)
    )
    decision = await policies.check(session, request)
    POLICY_DECISIONS.labels(action, decision.reason, checked_by).inc()
    if not decision.allowed:
        logger.info(
            "access denied by policy",
            extra={
                "user_id": str(user.id),
                "action": action,
                "reason": decision.reason,
                "deny_policies": list(decision.deny),
                "client_ip": client_ip,
                "checked_by": checked_by,
            },
        )
    return decision


def _require(action: policies.Action):
    async def dependency(request: Request, user: CurrentUserDep, session: SessionDep) -> User:
        client_ip = request.client.host if request.client else None
        decision = await authorize(
            session, action=action, user=user, client_ip=client_ip, checked_by="api"
        )
        if not decision.allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=DENIED)
        return user

    return Depends(dependency)


# The caller's user record, once the action is allowed for them.
ReaderDep = Annotated[User, _require("read")]
UploaderDep = Annotated[User, _require("upload")]
DownloaderDep = Annotated[User, _require("download")]
SharerDep = Annotated[User, _require("share")]
