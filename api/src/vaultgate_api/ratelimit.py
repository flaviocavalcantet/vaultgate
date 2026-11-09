"""Rate limits on the public API (M10, TM-3 in docs/threat-model.md).

- **Per user**, once authenticated:
  - starting a transfer (`POST /files`, `POST /files/{id}/download`,
    `POST /shared-with-me/{id}/download`): 60 a minute, bursts of 20;
  - everything else: 300 a minute, bursts of 100.
- **Per client address**, for what has no user:
  - the share recipients' routes (`/shares/access`): 30 a minute;
  - failed authentication: an address whose requests fail authentication more than 20
    times a minute gets 429 for its failing requests for the next 5 minutes. A valid
    token from it still works, so the people behind a misbehaving client's address
    aren't locked out with it.

Over a limit the API answers 429 with Retry-After. The counters are in this process's
memory, so with N replicas a client gets up to N times a limit; health checks are never
limited. The users in `rate_limit_exempt_users` (usernames, empty by default) skip the
per-user limits: a security scanner, which would otherwise scan the limiter.
"""

import math
import time
from collections import OrderedDict
from collections.abc import Callable

from fastapi import HTTPException, Request, status
from prometheus_client import Counter

from vaultgate_api.auth import PrincipalDep
from vaultgate_api.clientip import client_ip_var
from vaultgate_api.config import settings

RATE_LIMITED = Counter(
    "vaultgate_api_rate_limited_total",
    "Requests refused with 429, by limit",
    ["limit"],
)

INTENT_ROUTES = {
    ("POST", "/files"),
    ("POST", "/files/{file_id}/download"),
    ("POST", "/shared-with-me/{share_id}/download"),
}
MAX_KEYS = 100_000  # the oldest are forgotten beyond this: memory stays bounded


class TokenBuckets:
    """One token bucket per key: `per_minute` tokens a minute, at most `burst` saved."""

    def __init__(
        self, per_minute: int, burst: int, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.rate = per_minute / 60
        self.burst = burst
        self.clock = clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def take(self, key: str) -> float:
        """Spends a token for `key`: 0 when there was one, else the seconds until one."""
        if self.rate <= 0:
            return 0  # no limit
        now = self.clock()
        tokens, last = self._buckets.pop(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens >= 1:
            self._store(key, tokens - 1, now)
            return 0
        self._store(key, tokens, now)
        return (1 - tokens) / self.rate

    def _store(self, key: str, tokens: float, now: float) -> None:
        self._buckets[key] = (tokens, now)
        if len(self._buckets) > MAX_KEYS:
            self._buckets.popitem(last=False)


class FailureBlock:
    """Blocks a key for `block_seconds` once its failures exceed `per_minute`."""

    def __init__(
        self, per_minute: int, block_seconds: int, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.failures = TokenBuckets(per_minute, per_minute, clock)
        self.block_seconds = block_seconds
        self.clock = clock
        self._until: OrderedDict[str, float] = OrderedDict()

    def blocked(self, key: str) -> float:
        """Seconds the block on `key` has left, 0 if it has none."""
        until = self._until.get(key)
        if until is None:
            return 0
        left = until - self.clock()
        if left <= 0:
            del self._until[key]
            return 0
        return left

    def failed(self, key: str) -> None:
        if self.failures.take(key) and self.block_seconds > 0:
            self._until[key] = self.clock() + self.block_seconds
            if len(self._until) > MAX_KEYS:
                self._until.popitem(last=False)


class Limits:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        s = settings
        self.requests = TokenBuckets(s.rate_limit_per_minute, s.rate_limit_burst, clock)
        self.intents = TokenBuckets(
            s.rate_limit_intents_per_minute, s.rate_limit_intents_burst, clock
        )
        self.share_access = TokenBuckets(
            s.rate_limit_share_access_per_minute, s.rate_limit_share_access_per_minute, clock
        )
        self.pki = TokenBuckets(s.rate_limit_pki_per_minute, s.rate_limit_pki_per_minute, clock)
        self.auth = FailureBlock(
            s.rate_limit_auth_failures_per_minute, s.rate_limit_auth_block_seconds, clock
        )


limits = Limits()


def reset(clock: Callable[[], float] = time.monotonic) -> None:
    """New, empty counters with the current settings (tests)."""
    global limits
    limits = Limits(clock)


def too_many(limit: str, wait: float) -> HTTPException:
    RATE_LIMITED.labels(limit).inc()
    return HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many requests",
        headers={"Retry-After": str(max(1, math.ceil(wait)))},
    )


async def limit_user(request: Request, principal: PrincipalDep) -> None:
    """Per-user limits, after authentication (a dependency of every protected route)."""
    if principal.username and principal.username in settings.rate_limit_exempt_users:
        return
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    key = f"{principal.issuer} {principal.subject}"
    if (request.method, path) in INTENT_ROUTES:
        limit, wait = "intents", limits.intents.take(key)
    else:
        limit, wait = "requests", limits.requests.take(key)
    if wait:
        raise too_many(limit, wait)


async def limit_share_access(request: Request) -> None:
    """Per-address limit on the share recipients' routes, which have no user."""
    if wait := limits.share_access.take(client_key(request)):
        raise too_many("share_access", wait)


async def limit_pki(request: Request) -> None:
    """Per-address limit on the nodes' CA's public routes, which have no user."""
    if wait := limits.pki.take(client_key(request)):
        raise too_many("pki", wait)


def client_key(request: Request) -> str:
    return client_ip_var.get() or (request.client.host if request.client else "unknown")
