"""Access policy administration (ADR 0004).

Admins (VAULTGATE_ADMIN_GROUPS) create, replace and delete policies, and can ask how
a request would be decided. These routes are never subject to policies themselves,
so a bad policy cannot lock admins out. Changes apply to the next request: policies
are read fresh on every evaluation.

A policy is always written whole (PUT replaces it), so there are no partial-update
rules to get wrong. Every change is logged with the admin's user ID until the audit
log arrives (M6).
"""

import functools
import logging
import uuid
from datetime import UTC, datetime, time
from importlib.resources import files
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import (
    AwareDatetime,
    BaseModel,
    Field,
    IPvAnyAddress,
    IPvAnyNetwork,
    field_validator,
    model_validator,
)
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from vaultgate_api import policies
from vaultgate_api.db import SessionDep
from vaultgate_api.models import POLICY_ACTIONS, Policy, User
from vaultgate_api.routers.admin import Limit, Offset, Page, require_admin

logger = logging.getLogger(__name__)

AdminDep = Annotated[User, Depends(require_admin)]
router = APIRouter(
    prefix="/admin/policies", tags=["policies"], dependencies=[Depends(require_admin)]
)

Action = policies.Action
GroupPath = Annotated[str, Field(min_length=2, max_length=255, pattern=r"^/[^/\x00-\x1f\x7f]")]
MAX_ITEMS = 100


@functools.cache
def _timezones() -> frozenset[str]:
    # The IANA list shipped with tzdata. zoneinfo.available_timezones() also reports
    # other files in the system zone directory, such as "localtime".
    return frozenset(files("tzdata").joinpath("zones").read_text().split())


def _no_control_characters(value: str) -> str:
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError("must not contain control characters")
    return value


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=2000)
    effect: Literal["allow", "deny"]
    actions: list[Action] = Field(min_length=1)
    groups: list[GroupPath] = Field(default=[], max_length=MAX_ITEMS)
    networks: list[IPvAnyNetwork] = Field(default=[], max_length=MAX_ITEMS)
    excluded_networks: list[IPvAnyNetwork] = Field(default=[], max_length=MAX_ITEMS)
    days: list[Annotated[int, Field(ge=1, le=7)]] = Field(default=[], max_length=7)
    start_time: time | None = None
    end_time: time | None = None
    timezone: str = Field(default="UTC", max_length=64)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = _no_control_characters(value.strip())
        if not value:
            raise ValueError("must not be blank")
        return value

    @field_validator("actions")
    @classmethod
    def unique_actions(cls, value: list[str]) -> list[str]:
        return [a for a in POLICY_ACTIONS if a in value]

    @field_validator("groups")
    @classmethod
    def clean_groups(cls, value: list[str]) -> list[str]:
        cleaned = []
        for group in value:
            group = _no_control_characters(group).rstrip("/")
            if "//" in group:
                raise ValueError(f"{group!r} is not a group path such as /finance/payroll")
            if group not in cleaned:
                cleaned.append(group)
        return cleaned

    @field_validator("days")
    @classmethod
    def unique_days(cls, value: list[int]) -> list[int]:
        return sorted(set(value))

    @field_validator("start_time", "end_time")
    @classmethod
    def local_time(cls, value: time | None) -> time | None:
        if value is not None and value.tzinfo is not None:
            raise ValueError("must be a local time without an offset; set timezone instead")
        return value

    @field_validator("timezone")
    @classmethod
    def known_timezone(cls, value: str) -> str:
        if value not in _timezones():
            raise ValueError(
                f"unknown timezone {value!r}; use an IANA name such as America/Sao_Paulo"
            )
        return value

    @model_validator(mode="after")
    def whole_window(self) -> "PolicyIn":
        if (self.start_time is None) != (self.end_time is None):
            raise ValueError("start_time and end_time go together")
        if self.start_time is not None and self.start_time == self.end_time:
            raise ValueError("start_time and end_time must differ (omit both for all day)")
        return self


class PolicyOut(PolicyIn):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    @classmethod
    def of(cls, policy: Policy) -> "PolicyOut":
        return cls.model_validate(policy, from_attributes=True)


class EvaluateIn(BaseModel):
    """A hypothetical request: whose groups (a user's, or a list), from where, when."""

    action: Action
    user_id: uuid.UUID | None = None
    groups: list[GroupPath] | None = Field(default=None, max_length=MAX_ITEMS)
    client_ip: IPvAnyAddress
    at: AwareDatetime | None = None

    @model_validator(mode="after")
    def one_subject(self) -> "EvaluateIn":
        if (self.user_id is None) == (self.groups is None):
            raise ValueError("give either user_id or groups")
        return self


class EvaluateOut(BaseModel):
    allowed: bool
    reason: Literal["allowed", "denied", "no_matching_policy"]
    deny: list[str]
    allow: list[str]
    groups: list[str]
    client_ip: str
    at: datetime


def _apply(policy: Policy, body: PolicyIn) -> None:
    for field, value in body.model_dump().items():
        setattr(policy, field, value)


async def _get(session, policy_id: uuid.UUID) -> Policy:
    policy = await session.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Policy not found")
    return policy


async def _save(session, policy: Policy) -> None:
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="A policy with this name already exists"
        ) from None
    await session.refresh(policy)


def _log(change: str, policy: Policy, admin: User) -> None:
    logger.info(
        "policy changed",
        extra={
            "change": change,
            "policy_id": str(policy.id),
            "policy": policy.name,
            "admin_id": str(admin.id),
        },
    )


@router.get("")
async def list_policies(
    session: SessionDep, limit: Limit = 50, offset: Offset = 0
) -> Page[PolicyOut]:
    """All policies, enabled or not, by name."""
    total = await session.scalar(select(func.count()).select_from(Policy))
    rows = await session.scalars(select(Policy).order_by(Policy.name).limit(limit).offset(offset))
    return Page(items=[PolicyOut.of(p) for p in rows], total=total or 0, limit=limit, offset=offset)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_policy(body: PolicyIn, admin: AdminDep, session: SessionDep) -> PolicyOut:
    policy = Policy()
    _apply(policy, body)
    session.add(policy)
    await _save(session, policy)
    _log("created", policy, admin)
    return PolicyOut.of(policy)


@router.post("/evaluate")
async def evaluate_policies(body: EvaluateIn, session: SessionDep) -> EvaluateOut:
    """How a request would be decided now (or at `at`), with the matching policies."""
    if body.user_id is not None:
        user = await session.get(User, body.user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found")
        groups = sorted(g.name for g in user.groups)
    else:
        groups = body.groups or []
    at = body.at or datetime.now(UTC)
    request = policies.AccessRequest.of(body.action, groups, str(body.client_ip), at)
    decision = await policies.check(session, request)
    return EvaluateOut(
        allowed=decision.allowed,
        reason=decision.reason,
        deny=list(decision.deny),
        allow=list(decision.allow),
        groups=groups,
        client_ip=str(request.client_ip),
        at=at,
    )


@router.get("/{policy_id}")
async def get_policy(policy_id: uuid.UUID, session: SessionDep) -> PolicyOut:
    return PolicyOut.of(await _get(session, policy_id))


@router.put("/{policy_id}")
async def replace_policy(
    policy_id: uuid.UUID, body: PolicyIn, admin: AdminDep, session: SessionDep
) -> PolicyOut:
    policy = await _get(session, policy_id)
    _apply(policy, body)
    await _save(session, policy)
    _log("replaced", policy, admin)
    return PolicyOut.of(policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(policy_id: uuid.UUID, admin: AdminDep, session: SessionDep) -> Response:
    policy = await _get(session, policy_id)
    await session.delete(policy)
    await session.commit()
    _log("deleted", policy, admin)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
