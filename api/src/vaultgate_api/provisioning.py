"""Just-in-time user provisioning from validated access tokens.

The identity provider is the source of truth for who a user is and which groups they
belong to. On every authenticated request the caller's local record is looked up by
(issuer, subject) and, if needed, created or brought in line with the token:
profile fields, group memberships and the last-seen time.

Steady state costs one read: nothing is written unless the token differs from the
stored record, and `last_login_at` is refreshed at most every LAST_SEEN_RESOLUTION.
Concurrent first requests for the same user are safe: inserts use ON CONFLICT DO
NOTHING and then re-read.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, status
from prometheus_client import Counter
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from vaultgate_api.auth import Principal, PrincipalDep
from vaultgate_api.db import SessionDep
from vaultgate_api.models import Group, User, user_groups

logger = logging.getLogger(__name__)

LAST_SEEN_RESOLUTION = timedelta(minutes=5)

USERS_PROVISIONED = Counter(
    "vaultgate_users_provisioned_total", "Users created on their first authenticated request"
)
GROUP_SYNCS = Counter(
    "vaultgate_group_syncs_total", "Times a user's group memberships changed to match the token"
)


async def provision(
    session: AsyncSession, principal: Principal, now: datetime | None = None
) -> User:
    """Return the caller's user record, created or updated to match the token."""
    now = now or datetime.now(UTC)
    user = await _find(session, principal)
    if user is None:
        result = await session.execute(
            insert(User)
            .values(issuer=principal.issuer, subject=principal.subject)
            .on_conflict_do_nothing(constraint="uq_users_issuer_subject")
            .returning(User.id)
        )
        if result.scalar_one_or_none() is not None:
            USERS_PROVISIONED.inc()
        user = await _find(session, principal)
        if user is None:  # inserted or found by a concurrent request; must exist now
            raise RuntimeError("user row missing after insert")
        logger.info("user provisioned", extra={"user_id": str(user.id)})

    changed = _update_profile(user, principal, now)
    if {g.name for g in user.groups} != set(principal.groups):
        await _sync_groups(session, user, principal.groups)
        GROUP_SYNCS.inc()
        changed = True
    if changed:
        await session.commit()
        await session.refresh(user, ["groups"])
    return user


async def _find(session: AsyncSession, principal: Principal) -> User | None:
    return await session.scalar(
        select(User).where(User.issuer == principal.issuer, User.subject == principal.subject)
    )


def _update_profile(user: User, principal: Principal, now: datetime) -> bool:
    changed = False
    for attr, value in (
        ("username", principal.username),
        ("email", principal.email),
        ("display_name", principal.name),
    ):
        if getattr(user, attr) != value:
            setattr(user, attr, value)
            changed = True
    if user.last_login_at is None or now - user.last_login_at >= LAST_SEEN_RESOLUTION:
        user.last_login_at = now
        changed = True
    return changed


async def _sync_groups(session: AsyncSession, user: User, names: tuple[str, ...]) -> None:
    """Make the user's memberships exactly `names`, creating groups as needed.

    Rows are inserted in sorted order: concurrent first logins that name the same new
    groups in a different order would otherwise lock them in opposite orders and
    deadlock.
    """
    group_ids = []
    if names:
        await session.execute(
            insert(Group).values([{"name": n} for n in sorted(set(names))]).on_conflict_do_nothing()
        )
        group_ids = sorted(await session.scalars(select(Group.id).where(Group.name.in_(names))))
        await session.execute(
            insert(user_groups)
            .values([{"user_id": user.id, "group_id": gid} for gid in group_ids])
            .on_conflict_do_nothing()
        )
    await session.execute(
        delete(user_groups).where(
            user_groups.c.user_id == user.id, user_groups.c.group_id.not_in(group_ids)
        )
    )


async def get_current_user(principal: PrincipalDep, session: SessionDep) -> User:
    """FastAPI dependency: the caller's local user record; 403 if it is deactivated."""
    user = await provision(session, principal)
    if not user.is_active:
        logger.info("inactive user refused", extra={"user_id": str(user.id)})
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="User is deactivated")
    return user


CurrentUserDep = Annotated[User, Depends(get_current_user)]
