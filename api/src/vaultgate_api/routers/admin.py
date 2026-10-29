"""Read-only administration views of users and groups.

Restricted to members of the configured admin groups (VAULTGATE_ADMIN_GROUPS). Group
membership comes from the identity provider's token, synced on every request, so
granting or revoking admin rights is done in the identity provider.
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select

from vaultgate_api.config import settings
from vaultgate_api.db import SessionDep
from vaultgate_api.models import Group, User, user_groups
from vaultgate_api.provisioning import CurrentUserDep
from vaultgate_api.routers.me import UserOut


async def require_admin(user: CurrentUserDep) -> User:
    if not {g.name for g in user.groups} & set(settings.admin_groups):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Administrator access required")
    return user


router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


class GroupOut(BaseModel):
    id: uuid.UUID
    name: str
    members: int
    created_at: datetime


@router.get("/users")
async def list_users(session: SessionDep, limit: Limit = 50, offset: Offset = 0) -> Page[UserOut]:
    """All users seen so far, oldest first."""
    total = await session.scalar(select(func.count()).select_from(User))
    users = await session.scalars(
        select(User).order_by(User.created_at, User.id).limit(limit).offset(offset)
    )
    return Page(items=[UserOut.of(u) for u in users], total=total or 0, limit=limit, offset=offset)


@router.get("/users/{user_id}")
async def get_user(user_id: uuid.UUID, session: SessionDep) -> UserOut:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserOut.of(user)


@router.get("/groups")
async def list_groups(session: SessionDep, limit: Limit = 50, offset: Offset = 0) -> Page[GroupOut]:
    """All groups seen in tokens so far, by name, with member counts."""
    total = await session.scalar(select(func.count()).select_from(Group))
    members = func.count(user_groups.c.user_id)
    rows = await session.execute(
        select(Group, members)
        .outerjoin(user_groups, user_groups.c.group_id == Group.id)
        .group_by(Group.id)
        .order_by(Group.name)
        .limit(limit)
        .offset(offset)
    )
    items = [
        GroupOut(id=g.id, name=g.name, members=count, created_at=g.created_at) for g, count in rows
    ]
    return Page(items=items, total=total or 0, limit=limit, offset=offset)
