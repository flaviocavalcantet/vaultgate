import uuid
from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel

from vaultgate_api.models import User
from vaultgate_api.provisioning import CurrentUserDep

router = APIRouter(tags=["identity"])


class UserOut(BaseModel):
    id: uuid.UUID
    issuer: str
    subject: str
    username: str | None
    email: str | None
    name: str | None
    groups: list[str]
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None

    @classmethod
    def of(cls, user: User) -> "UserOut":
        return cls(
            id=user.id,
            issuer=user.issuer,
            subject=user.subject,
            username=user.username,
            email=user.email,
            name=user.display_name,
            groups=sorted(g.name for g in user.groups),
            is_active=user.is_active,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )


@router.get("/me")
async def me(user: CurrentUserDep) -> UserOut:
    """The caller's user record, created or refreshed from the access token."""
    return UserOut.of(user)
