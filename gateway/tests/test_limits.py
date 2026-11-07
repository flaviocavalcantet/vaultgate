"""The gateway's transfer limits' counting (vaultgate_gateway.limits)."""

from vaultgate_gateway.limits import TransferLimits


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_refusals_count_within_a_minute_only() -> None:
    clock = Clock()
    limits = TransferLimits(refused_per_minute=2, block_seconds=300, clock=clock)
    limits.refused("a")
    limits.refused("a")
    clock.now += 61  # those two are more than a minute old
    limits.refused("a")
    limits.refused("a")
    assert limits.blocked("a") == 0
    limits.refused("a")  # the third within a minute
    assert limits.blocked("a") == 300
    assert limits.blocked("b") == 0
    clock.now += 300
    assert limits.blocked("a") == 0


def test_a_slot_is_released_once() -> None:
    limits = TransferLimits(transfers_per_client=1, uploads_per_user=1)
    slot = limits.client_slot("a")
    assert limits.client_slot("a") is None
    assert limits.user_slot("upload", "user:1", slot)
    assert not limits.user_slot("upload", "user:1", limits.client_slot("b"))
    slot.release()
    slot.release()  # again: nothing more is given back
    assert limits.client_slot("a") is not None
    assert not limits._users["upload"]


def test_zero_means_no_limit() -> None:
    limits = TransferLimits(transfers_per_client=0, uploads_per_user=0, refused_per_minute=0)
    slots = [limits.client_slot("a") for _ in range(100)]
    assert all(limits.user_slot("upload", "u", slot) for slot in slots)
    for _ in range(100):
        limits.refused("a")
    assert limits.blocked("a") == 0
