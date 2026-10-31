import ipaddress
from datetime import UTC, datetime, time
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import requires_db
from vaultgate_api.models import Policy
from vaultgate_api.policies import AccessRequest, check, evaluate, parse_ip

SAO_PAULO = ZoneInfo("America/Sao_Paulo")
BERLIN = ZoneInfo("Europe/Berlin")
# A Wednesday, mid-afternoon in Sao Paulo (UTC-3).
WEDNESDAY_3PM = datetime(2026, 11, 4, 15, 0, tzinfo=SAO_PAULO)


def policy(name="p", effect="allow", actions=("read", "upload", "download"), **conditions):
    conditions.setdefault("enabled", True)
    return Policy(name=name, effect=effect, actions=list(actions), **conditions)


def request(action="download", groups=("/finance",), ip="10.1.2.3", at=WEDNESDAY_3PM):
    return AccessRequest.of(action, groups, ip, at)


# --- deny by default, deny wins ----------------------------------------------------


def test_no_policies_denies() -> None:
    decision = evaluate([], request())
    assert not decision.allowed
    assert decision.reason == "no_matching_policy"


def test_matching_allow_allows() -> None:
    decision = evaluate([policy("finance", groups=["/finance"])], request())
    assert decision.allowed
    assert decision.allow == ("finance",)


def test_deny_wins_over_allow() -> None:
    decision = evaluate(
        [policy("everyone"), policy("no-downloads", effect="deny", actions=["download"])],
        request(),
    )
    assert not decision.allowed
    assert decision.reason == "denied"
    assert decision.deny == ("no-downloads",)
    assert decision.allow == ("everyone",)


def test_deny_alone_is_still_a_denial() -> None:
    decision = evaluate([policy("block", effect="deny")], request())
    assert (decision.allowed, decision.reason) == (False, "denied")


def test_policy_for_another_action_does_not_apply() -> None:
    assert not evaluate([policy(actions=["upload"])], request(action="download")).allowed
    deny_uploads = policy("no-uploads", effect="deny", actions=["upload"])
    assert evaluate([policy("all"), deny_uploads], request(action="download")).allowed


def test_disabled_policies_are_ignored() -> None:
    assert not evaluate([policy(enabled=False)], request()).allowed
    blocked = [policy("all"), policy("off", effect="deny", enabled=False)]
    assert evaluate(blocked, request()).allowed


def test_names_are_reported_sorted() -> None:
    decision = evaluate([policy("b"), policy("a")], request())
    assert decision.allow == ("a", "b")


# --- groups ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("policy_groups", "user_groups", "allowed"),
    [
        ([], (), True),  # no group condition: any signed-in user
        (["/finance"], ("/finance",), True),
        (["/finance"], ("/legal",), False),
        (["/finance"], (), False),
        (["/finance", "/legal"], ("/legal",), True),
        (["/finance"], ("/finance/payroll",), True),  # subgroups are covered
        (["/finance/"], ("/finance/payroll",), True),
        (["/finance"], ("/finance-external",), False),  # a prefix is not a parent
        (["/finance/payroll"], ("/finance",), False),  # a parent is not a subgroup
    ],
)
def test_groups(policy_groups, user_groups, allowed) -> None:
    assert evaluate([policy(groups=policy_groups)], request(groups=user_groups)).allowed is allowed


# --- networks ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("networks", "excluded", "ip", "allowed"),
    [
        ([], [], "203.0.113.9", True),
        (["10.0.0.0/8"], [], "10.1.2.3", True),
        (["10.0.0.0/8"], [], "192.168.1.1", False),
        (["10.0.0.0/8", "192.168.0.0/16"], [], "192.168.1.1", True),
        (["10.0.0.0/8"], ["10.66.0.0/16"], "10.66.0.1", False),
        ([], ["10.66.0.0/16"], "10.1.2.3", True),
        (["2001:db8::/32"], [], "2001:db8::1", True),
        (["2001:db8::/32"], [], "10.1.2.3", False),  # other IP version never matches
        (["10.0.0.0/8"], [], "::ffff:10.1.2.3", True),  # IPv4-mapped IPv6
        (["10.1.2.3/32"], [], "10.1.2.3", True),
    ],
)
def test_networks(networks, excluded, ip, allowed) -> None:
    rule = policy(networks=networks, excluded_networks=excluded)
    assert evaluate([rule], request(ip=ip)).allowed is allowed


def test_networks_as_stored_by_postgres() -> None:
    rule = policy(networks=[ipaddress.ip_network("10.0.0.0/8")])
    assert evaluate([rule], request(ip="10.9.9.9")).allowed


def test_deny_from_outside_the_office() -> None:
    """The typical global restriction: deny everything not from the office network."""
    rules = [
        policy("finance", groups=["/finance"]),
        policy("office-only", effect="deny", excluded_networks=["10.0.0.0/8"]),
    ]
    assert evaluate(rules, request(ip="10.1.2.3")).allowed
    outside = evaluate(rules, request(ip="198.51.100.7"))
    assert (outside.allowed, outside.deny) == (False, ("office-only",))


def test_parse_ip() -> None:
    assert parse_ip("::ffff:192.0.2.1") == ipaddress.IPv4Address("192.0.2.1")
    assert parse_ip(" 2001:db8::1 ") == ipaddress.IPv6Address("2001:db8::1")
    with pytest.raises(ValueError):
        parse_ip("10.0.0.0/8")


# --- time windows ------------------------------------------------------------------

WEEKDAYS = [1, 2, 3, 4, 5]
OFFICE_HOURS = {"start_time": time(8), "end_time": time(18), "timezone": "America/Sao_Paulo"}


@pytest.mark.parametrize(
    ("at", "allowed"),
    [
        (datetime(2026, 11, 4, 8, 0, tzinfo=SAO_PAULO), True),  # start is inclusive
        (datetime(2026, 11, 4, 17, 59, 59, tzinfo=SAO_PAULO), True),
        (datetime(2026, 11, 4, 18, 0, tzinfo=SAO_PAULO), False),  # end is exclusive
        (datetime(2026, 11, 4, 7, 59, tzinfo=SAO_PAULO), False),
        (datetime(2026, 11, 7, 10, 0, tzinfo=SAO_PAULO), False),  # Saturday
        # 12:00 UTC is 09:00 in Sao Paulo: the policy's timezone decides, not UTC.
        (datetime(2026, 11, 4, 12, 0, tzinfo=UTC), True),
        # 22:30 UTC on Friday is 19:30 Friday in Sao Paulo: after hours.
        (datetime(2026, 11, 6, 22, 30, tzinfo=UTC), False),
        # 01:00 UTC on Saturday is still 22:00 Friday in Sao Paulo, and 02:00 UTC
        # Monday is 23:00 Sunday: the local day decides.
        (datetime(2026, 11, 9, 2, 0, tzinfo=UTC), False),
    ],
)
def test_office_hours(at, allowed) -> None:
    rule = policy(days=WEEKDAYS, **OFFICE_HOURS)
    assert evaluate([rule], request(at=at)).allowed is allowed


def test_days_without_hours() -> None:
    rule = policy(days=[6, 7], timezone="America/Sao_Paulo")
    assert evaluate([rule], request(at=datetime(2026, 11, 7, 23, 59, tzinfo=SAO_PAULO))).allowed
    assert not evaluate([rule], request(at=WEDNESDAY_3PM)).allowed


def test_hours_without_days_apply_every_day() -> None:
    rule = policy(**OFFICE_HOURS)
    assert evaluate([rule], request(at=datetime(2026, 11, 8, 9, 0, tzinfo=SAO_PAULO))).allowed


@pytest.mark.parametrize(
    ("at", "allowed"),
    [
        (datetime(2026, 11, 6, 22, 0, tzinfo=SAO_PAULO), True),  # Friday evening
        (datetime(2026, 11, 7, 3, 0, tzinfo=SAO_PAULO), True),  # Friday's night, on Saturday
        (datetime(2026, 11, 7, 6, 0, tzinfo=SAO_PAULO), False),  # end is exclusive
        (datetime(2026, 11, 7, 22, 0, tzinfo=SAO_PAULO), False),  # Saturday evening
        (datetime(2026, 11, 2, 3, 0, tzinfo=SAO_PAULO), False),  # Sunday's night, on Monday
        (datetime(2026, 11, 3, 3, 0, tzinfo=SAO_PAULO), True),  # Monday's night, on Tuesday
        (datetime(2026, 11, 6, 12, 0, tzinfo=SAO_PAULO), False),
    ],
)
def test_overnight_window_belongs_to_the_day_it_starts(at, allowed) -> None:
    rule = policy(
        days=WEEKDAYS, start_time=time(22), end_time=time(6), timezone="America/Sao_Paulo"
    )
    assert evaluate([rule], request(at=at)).allowed is allowed


@pytest.mark.parametrize(
    ("at", "allowed"),
    [
        # Berlin moves to summer time on 2026-03-29 at 02:00 -> 03:00. 08:30 local is
        # 07:30 UTC before the change and 06:30 UTC after it.
        (datetime(2026, 3, 27, 7, 30, tzinfo=UTC), True),
        (datetime(2026, 3, 30, 6, 30, tzinfo=UTC), True),
        (datetime(2026, 3, 30, 5, 30, tzinfo=UTC), False),  # 07:30 local
    ],
)
def test_windows_follow_daylight_saving_time(at, allowed) -> None:
    rule = policy(start_time=time(8), end_time=time(18), timezone="Europe/Berlin")
    assert evaluate([rule], request(at=at)).allowed is allowed


def test_request_time_must_be_aware() -> None:
    with pytest.raises(ValueError):
        AccessRequest.of("read", (), "10.0.0.1", datetime(2026, 11, 4, 15, 0))


# --- conditions combine; broken policies fail closed -------------------------------


def test_all_conditions_must_hold() -> None:
    rule = policy(groups=["/finance"], networks=["10.0.0.0/8"], days=WEEKDAYS, **OFFICE_HOURS)
    assert evaluate([rule], request()).allowed
    assert not evaluate([rule], request(groups=("/legal",))).allowed
    assert not evaluate([rule], request(ip="192.168.0.1")).allowed
    assert not evaluate([rule], request(at=datetime(2026, 11, 4, 20, tzinfo=SAO_PAULO))).allowed


def test_unknown_timezone_fails_closed() -> None:
    broken = {"start_time": time(8), "end_time": time(18), "timezone": "Mars/Olympus_Mons"}
    assert not evaluate([policy("allow", **broken)], request()).allowed
    decision = evaluate([policy("all"), policy("deny", effect="deny", **broken)], request())
    assert (decision.allowed, decision.deny) == (False, ("deny",))


# --- stored policies ---------------------------------------------------------------


@requires_db
async def test_check_reads_enabled_policies_for_the_action(session: AsyncSession) -> None:
    session.add_all(
        [
            Policy(
                name="finance",
                effect="allow",
                actions=["read", "download"],
                groups=["/finance"],
                networks=["10.0.0.0/8"],
            ),
            Policy(name="uploads", effect="allow", actions=["upload"]),
            Policy(name="off", effect="deny", actions=["download"], enabled=False),
        ]
    )
    await session.flush()

    decision = await check(session, request(action="download"))
    assert (decision.allowed, decision.allow) == (True, ("finance",))
    assert not (await check(session, request(action="download", ip="192.0.2.1"))).allowed
    assert (await check(session, request(action="upload", groups=()))).allow == ("uploads",)


@requires_db
async def test_policy_defaults(session: AsyncSession) -> None:
    rule = Policy(name="minimal", effect="allow", actions=["read"])
    session.add(rule)
    await session.flush()
    await session.refresh(rule)
    assert (rule.groups, rule.networks, rule.excluded_networks, rule.days) == ([], [], [], [])
    assert (rule.timezone, rule.enabled, rule.description) == ("UTC", True, "")
    assert rule.start_time is None and rule.end_time is None


@requires_db
@pytest.mark.parametrize(
    "fields",
    [
        {"effect": "maybe"},
        {"actions": []},
        {"actions": ["read", "delete"]},
        {"days": [0]},
        {"days": [8]},
        {"start_time": time(8)},  # a window needs both ends
        {"end_time": time(8)},
        {"start_time": time(8), "end_time": time(8)},  # and must not be empty
        {"networks": ["10.0.0.1/8"]},  # host bits set: not a network
    ],
)
async def test_invalid_policies_are_rejected(session: AsyncSession, fields) -> None:
    values = {"name": "bad", "effect": "allow", "actions": ["read"]} | fields
    session.add(Policy(**values))
    # Check constraints raise IntegrityError; a malformed CIDR is a DataError.
    with pytest.raises(DBAPIError):
        await session.flush()


@requires_db
async def test_policy_names_are_unique(session: AsyncSession) -> None:
    session.add(Policy(name="same", effect="allow", actions=["read"]))
    await session.flush()
    session.add(Policy(name="same", effect="deny", actions=["read"]))
    with pytest.raises(IntegrityError):
        await session.flush()
