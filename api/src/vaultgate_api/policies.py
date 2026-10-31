"""Access policy evaluation (ADR 0004).

Deny by default: a request is allowed only when at least one enabled allow policy
matches it and no enabled deny policy does. Policies are read from the database on
every evaluation, never cached, so a change applies to the next request.

A policy matches when the action is one of its `actions` and every condition it sets
holds (an empty list or no time window means "any"):

- groups: the user is in one of them, or in a subgroup ("/finance" covers
  "/finance/payroll"); the identity provider's groups, synced on every request;
- networks: the client address is in one of them; excluded_networks: in none of them;
- days and start_time/end_time: the request time, in the policy's timezone, falls in
  the window. A window that ends before it starts runs overnight and belongs to the
  day it starts: Friday 22:00-06:00 covers Saturday 03:00.

`evaluate` is pure (no I/O, no clock): callers pass the time and the client address.
A policy that cannot be evaluated (an unknown timezone, say) fails closed: a deny
policy then counts as matching and an allow policy as not matching.
"""

import ipaddress
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultgate_api.clientip import IPAddress, parse_ip
from vaultgate_api.models import Policy

logger = logging.getLogger(__name__)

Action = Literal["read", "upload", "download"]


@dataclass(frozen=True)
class AccessRequest:
    action: Action
    groups: tuple[str, ...]
    client_ip: IPAddress
    at: datetime  # timezone-aware

    @classmethod
    def of(cls, action: Action, groups: Iterable[str], client_ip: str, at: datetime):
        if at.tzinfo is None:
            raise ValueError("the request time must be timezone-aware")
        return cls(action, tuple(groups), parse_ip(client_ip), at)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: Literal["allowed", "denied", "no_matching_policy"]
    # Names of the matching policies, so a refusal can be explained in logs and in the
    # admin dry run (never to the caller).
    deny: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()


def evaluate(policies: Iterable[Policy], request: AccessRequest) -> Decision:
    deny, allow = [], []
    for policy in policies:
        if not policy.enabled or request.action not in policy.actions:
            continue
        try:
            matched = _matches(policy, request)
        except Exception:
            logger.exception("policy could not be evaluated", extra={"policy": policy.name})
            matched = policy.effect == "deny"
        if matched:
            (deny if policy.effect == "deny" else allow).append(policy.name)
    deny.sort()
    allow.sort()
    if deny:
        return Decision(False, "denied", tuple(deny), tuple(allow))
    if allow:
        return Decision(True, "allowed", (), tuple(allow))
    return Decision(False, "no_matching_policy")


async def check(session: AsyncSession, request: AccessRequest) -> Decision:
    """Evaluate the enabled policies for the request's action, read fresh."""
    policies = await session.scalars(
        select(Policy).where(Policy.enabled, Policy.actions.contains([request.action]))
    )
    return evaluate(policies, request)


def _matches(policy: Policy, request: AccessRequest) -> bool:
    return (
        _in_groups(policy.groups or (), request.groups)
        and _in_networks(policy.networks or (), policy.excluded_networks or (), request.client_ip)
        and _in_window(policy, request.at)
    )


def _in_groups(policy_groups: Iterable[str], user_groups: tuple[str, ...]) -> bool:
    policy_groups = [g.rstrip("/") for g in policy_groups]
    if not policy_groups:
        return True
    return any(
        group == wanted or group.startswith(wanted + "/")
        for group in user_groups
        for wanted in policy_groups
    )


def _in_networks(networks: Iterable, excluded: Iterable, ip: IPAddress) -> bool:
    # Rows hold ip_network objects (asyncpg returns CIDR that way); str() also accepts
    # policies built in memory with strings. An address never matches a network of the
    # other IP version.
    networks = [ipaddress.ip_network(str(n)) for n in networks]
    if networks and not any(ip in n for n in networks):
        return False
    return not any(ip in ipaddress.ip_network(str(n)) for n in excluded)


def _in_window(policy: Policy, at: datetime) -> bool:
    days = set(policy.days or ())
    start, end = policy.start_time, policy.end_time
    if not days and start is None:
        return True
    local = at.astimezone(ZoneInfo(policy.timezone or "UTC"))
    today = local.date()

    def on(day) -> bool:
        return not days or day.isoweekday() in days

    if start is None or end is None:
        return on(today)
    now = local.time()
    if start < end:
        return on(today) and start <= now < end
    # Overnight: the evening part belongs to today, the morning part to yesterday.
    return (now >= start and on(today)) or (now < end and on(today - timedelta(days=1)))
