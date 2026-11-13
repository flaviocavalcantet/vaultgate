"""Rate limits on the public API (vaultgate_api.ratelimit)."""

import pytest

from tests.conftest import requires_db
from tests.fake_oidc import FakeProvider
from vaultgate_api import ratelimit
from vaultgate_api.config import settings
from vaultgate_api.ratelimit import FailureBlock, TokenBuckets


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_a_bucket_allows_its_burst_then_refills_at_its_rate() -> None:
    clock = Clock()
    buckets = TokenBuckets(per_minute=60, burst=3, clock=clock)
    assert [buckets.take("a") for _ in range(3)] == [0, 0, 0]
    assert buckets.take("a") == pytest.approx(1.0)  # one token a second
    assert buckets.take("b") == 0  # another key has its own
    clock.now += 1
    assert buckets.take("a") == 0
    assert buckets.take("a") > 0


def test_zero_means_no_limit() -> None:
    buckets = TokenBuckets(per_minute=0, burst=0)
    assert all(buckets.take("a") == 0 for _ in range(1000))


def test_failures_block_for_a_while_then_not() -> None:
    clock = Clock()
    block = FailureBlock(per_minute=3, block_seconds=300, clock=clock)
    for _ in range(3):
        block.failed("ip")
    assert block.blocked("ip") == 0  # three failures are allowed
    block.failed("ip")
    assert block.blocked("ip") == pytest.approx(300)
    assert block.blocked("other") == 0
    clock.now += 301
    assert block.blocked("ip") == 0


def as_user(provider: FakeProvider, name: str = "alice") -> dict:
    return {"Authorization": f"Bearer {provider.token(sub=name, preferred_username=name)}"}


@pytest.fixture
def small_limits(monkeypatch):
    for name, value in {
        "rate_limit_per_minute": 60,
        "rate_limit_burst": 3,
        "rate_limit_intents_per_minute": 60,
        "rate_limit_intents_burst": 2,
        "rate_limit_share_access_per_minute": 2,
        "rate_limit_auth_failures_per_minute": 2,
    }.items():
        monkeypatch.setattr(settings, name, value)
    ratelimit.reset()


@requires_db
async def test_each_user_has_their_own_request_limit(clients, provider, small_limits) -> None:
    public, _ = clients
    for _ in range(3):
        assert (await public.get("/me", headers=as_user(provider))).status_code == 200
    refused = await public.get("/me", headers=as_user(provider))
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) >= 1
    assert (await public.get("/me", headers=as_user(provider, "bob"))).status_code == 200


@requires_db
async def test_starting_transfers_has_a_limit_of_its_own(clients, provider, small_limits) -> None:
    public, _ = clients
    for n in range(2):
        body = {"name": f"{n}.txt", "size": 1}
        response = await public.post("/files", json=body, headers=as_user(provider))
        assert response.status_code == 201
    body = {"name": "2.txt", "size": 1}
    assert (await public.post("/files", json=body, headers=as_user(provider))).status_code == 429
    # Other requests still have their own allowance.
    assert (await public.get("/me", headers=as_user(provider))).status_code == 200


@requires_db
async def test_exempt_users_skip_the_per_user_limits(
    clients, provider, small_limits, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "rate_limit_exempt_users", ["zap-scanner"])
    public, _ = clients
    for _ in range(10):
        response = await public.get("/me", headers=as_user(provider, "zap-scanner"))
        assert response.status_code == 200


@requires_db
async def test_failing_authentication_too_often_gets_429_but_valid_tokens_work(
    clients, provider, small_limits
) -> None:
    public, _ = clients
    bad = {"Authorization": "Bearer not-a-jwt"}
    assert [(await public.get("/files", headers=bad)).status_code for _ in range(3)] == [
        401,
        401,
        401,
    ]
    refused = await public.get("/files", headers=bad)
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) > 200  # the 5-minute block
    assert (await public.get("/files")).status_code == 429  # no token at all, likewise
    # The same address with a valid token is not blocked.
    assert (await public.get("/me", headers=as_user(provider))).status_code == 200


@requires_db
async def test_share_recipients_routes_are_limited_per_address(clients, small_limits) -> None:
    public, _ = clients
    statuses = [(await public.get("/shares/access?token=x")).status_code for _ in range(3)]
    assert 429 not in statuses[:2] and statuses[2] == 429


async def test_health_checks_are_never_limited(small_limits) -> None:
    from fastapi.testclient import TestClient

    from vaultgate_api.main import app

    client = TestClient(app)
    assert all(client.get("/healthz").status_code == 200 for _ in range(20))
