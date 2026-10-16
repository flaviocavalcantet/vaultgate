from fastapi import APIRouter
from pydantic import BaseModel

from vaultgate_api.auth import PrincipalDep

router = APIRouter(tags=["identity"])


class Identity(BaseModel):
    issuer: str
    subject: str
    username: str | None
    email: str | None
    name: str | None
    groups: list[str]


@router.get("/me")
async def me(principal: PrincipalDep) -> Identity:
    """The caller's identity, as asserted by the identity provider's access token."""
    return Identity(
        issuer=principal.issuer,
        subject=principal.subject,
        username=principal.username,
        email=principal.email,
        name=principal.name,
        groups=list(principal.groups),
    )
