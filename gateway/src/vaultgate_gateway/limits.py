"""Limits on transfers at the gateway (M10, TM-3 in docs/threat-model.md).

A transfer is one long request, so what is limited is how many run at once, not how
many start in a minute (the API limits that, at its intents):

- per user, as the API names them (`limit_key`: the user, or the share a recipient
  downloads through): 4 uploads and 8 downloads at once;
- per client address: 16 transfers at once;
- per client address, intents the API refused: after 10 in a minute, its transfers get
  429 for 5 minutes. A token is 256 random bits, so this is about noise and load, not
  guessing.

The address limits are checked before the intent is spent. Whose transfer it is is known
only once the API has consumed the intent, so a transfer over its user's limit has spent
its intent: a download needs a new one, an upload is reported failed. Counters are in
this process's memory; 0 turns a limit off.
"""

import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from vaultgate_gateway import metrics


@dataclass
class Slot:
    """One place taken in one or more counters; released once, whatever happens."""

    _counters: list[tuple[Counter, str]] = field(default_factory=list)

    def release(self) -> None:
        for counter, key in self._counters:
            counter[key] -= 1
            if counter[key] <= 0:
                del counter[key]
        self._counters.clear()


class TransferLimits:
    def __init__(
        self,
        *,
        uploads_per_user: int = 4,
        downloads_per_user: int = 8,
        transfers_per_client: int = 16,
        refused_per_minute: int = 10,
        block_seconds: int = 300,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.per_user = {"upload": uploads_per_user, "download": downloads_per_user}
        self.per_client = transfers_per_client
        self.refused_per_minute = refused_per_minute
        self.block_seconds = block_seconds
        self.clock = clock
        self._users: dict[str, Counter] = {"upload": Counter(), "download": Counter()}
        self._clients: Counter = Counter()
        self._refused: dict[str, deque] = {}
        self._blocked: dict[str, float] = {}

    def blocked(self, client: str) -> float:
        """Seconds the client's block has left, 0 if it has none."""
        until = self._blocked.get(client)
        if until is None:
            return 0
        left = until - self.clock()
        if left <= 0:
            del self._blocked[client]
            return 0
        return left

    def refused(self, client: str) -> None:
        """An intent from `client` the API refused."""
        if self.refused_per_minute <= 0:
            return
        now = self.clock()
        times = self._refused.setdefault(client, deque())
        times.append(now)
        while times and times[0] <= now - 60:
            times.popleft()
        if len(times) > self.refused_per_minute and self.block_seconds > 0:
            self._blocked[client] = now + self.block_seconds
            del self._refused[client]

    def client_slot(self, client: str) -> Slot | None:
        """A transfer from `client`, or None if it has as many as it may."""
        if self.per_client > 0 and self._clients[client] >= self.per_client:
            metrics.TRANSFERS_LIMITED.labels("client").inc()
            return None
        self._clients[client] += 1
        return Slot([(self._clients, client)])

    def user_slot(self, kind: str, key: str, slot: Slot) -> bool:
        """Adds a `kind` transfer for `key` to `slot`; False if it has as many as it may."""
        limit, counter = self.per_user[kind], self._users[kind]
        if limit > 0 and counter[key] >= limit:
            metrics.TRANSFERS_LIMITED.labels(f"user_{kind}").inc()
            return False
        counter[key] += 1
        slot._counters.append((counter, key))
        return True
