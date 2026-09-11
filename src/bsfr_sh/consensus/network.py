"""`P2PCS` — the in-process peer-to-peer cloud-server message bus.

What it is
----------
A discrete-event scheduler that stands in for the network between the pBFT replicas of one chain.
Nodes register a handler; `send()` schedules a delivery at a *simulated* time; `run()` pops events
in time order and calls the handlers. Timers (view-change timeouts) live on the same clock.

Latency — the decision recorded in the M2b brief and in DEV-21
---------------------------------------------------------------
Every message is delivered `message_delay_s` after it was sent (plus any per-node fault delay),
on the simulated clock. The default is `0.0` (`configs/chain.yaml` `consensus.message_delay_s`),
and nothing here or in `pbft` hardcodes either choice.

**Nothing sleeps.** A non-zero delay moves `now` forward; it does not move wall-clock. So:

* at delay 0, wall-clock spent inside `run()` is exactly the protocol's compute cost;
* at delay `d`, wall-clock is the same, and the modelled network cost is `now` — about `3d` per
  committed block (pre-prepare, prepare, commit), since one height is in flight at a time.

M6 reports the two separately; the second is modelled, not measured. See `configs/bench.yaml`.

Faults — what the byzantine fixtures need
-----------------------------------------
`LinkFaults` attaches to a *sending* node and applies to everything it sends: drop (at a rate,
or always to named recipients), extra delay, duplicate copies, and jitter — a random extra delay
per copy, which is how messages come to overtake each other, i.e. reorder. All randomness comes
from one `random.Random(seed)` owned by the bus, so a faulty run replays exactly from its seed.

What the bus does not do
------------------------
It does not authenticate. The `sender` a handler receives is the transport-level source and is
as spoofable as a source IP; any caller may `send()` under any name, registered or not, which is
how tests inject messages from outside the membership. Authentication is the pBFT layer's job and
is done with signatures, never with this argument. The bus also does not serialise: payloads are
passed as Python objects (immutable dataclasses), so wire encoding cost is not part of the
modelled consensus cost. Recorded for M6 in the M2b session log.
"""

from __future__ import annotations

import heapq
import random
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Final

__all__ = [
    "NO_FAULTS",
    "Handler",
    "LinkFaults",
    "NetworkError",
    "NetworkStats",
    "P2PCSNetwork",
    "Timer",
]

#: A node's inbound handler: `(transport_sender, payload)`.
Handler = Callable[[str, object], None]

#: Guard against a run that never drains — a stalled cluster keeps re-arming view-change timers,
#: so "run until idle" is not guaranteed to end. Exceeding it is an error, not a silent stop.
DEFAULT_MAX_EVENTS: Final = 5_000_000


class NetworkError(RuntimeError):
    """Raised on bus misuse: a duplicate registration, a negative delay, a runaway run."""


@dataclass(frozen=True)
class LinkFaults:
    """Faults applied to every message a node *sends*.

    `drop_rate` and `jitter_s` draw from the bus's seeded RNG, so they are reproducible. The rest
    are deterministic.
    """

    #: Probability each outgoing message is lost. 1.0 makes the node mute on the wire.
    drop_rate: float = 0.0
    #: Recipients this node's messages never reach — a directional partition.
    drop_to: frozenset[str] = frozenset()
    #: Added to every outgoing message's delivery time.
    extra_delay_s: float = 0.0
    #: Each copy gets an extra uniform delay in `[0, jitter_s)`. Non-zero jitter reorders.
    jitter_s: float = 0.0
    #: Extra copies of every message. Each copy is jittered independently.
    duplicates: int = 0

    def __post_init__(self) -> None:
        if not 0.0 <= self.drop_rate <= 1.0:
            raise NetworkError(f"drop_rate must be in [0, 1], got {self.drop_rate}")
        if self.extra_delay_s < 0 or self.jitter_s < 0:
            raise NetworkError("delays must be non-negative; messages do not arrive before sending")
        if self.duplicates < 0:
            raise NetworkError("duplicates must be non-negative")


#: The fault set of a well-behaved link.
NO_FAULTS: Final = LinkFaults()


@dataclass
class NetworkStats:
    """Counters, for tests and for M6's messages-per-commit figure."""

    sent: int = 0
    delivered: int = 0
    dropped: int = 0
    duplicated: int = 0
    #: Delivered to an id with no registered handler.
    undeliverable: int = 0


class Timer:
    """A cancellable scheduled callback. Cancelling after it fired is a no-op."""

    __slots__ = ("at", "cancelled", "fired")

    def __init__(self, at: float) -> None:
        self.at = at
        self.cancelled = False
        self.fired = False

    def cancel(self) -> None:
        self.cancelled = True

    @property
    def active(self) -> bool:
        return not (self.cancelled or self.fired)


@dataclass(order=True)
class _Event:
    at: float
    order: int
    action: Callable[[], None] = field(compare=False)
    #: Set for timer events, so a cancelled one can be discarded without touching the clock.
    timer: Timer | None = field(default=None, compare=False)


class P2PCSNetwork:
    """`P2PCS` for one chain. `BC_DTBU` and `BC_SigRW` each get their own instance.

    Everything mutable is per-instance (CLAUDE.md §4 — the two chains share no state).
    """

    __slots__ = (
        "_faults",
        "_handlers",
        "_now",
        "_order",
        "_queue",
        "_rng",
        "message_delay_s",
        "stats",
    )

    def __init__(self, *, message_delay_s: float = 0.0, seed: int, start_time: float = 0.0) -> None:
        if message_delay_s < 0:
            raise NetworkError("message_delay_s must be non-negative")
        self.message_delay_s = float(message_delay_s)
        self._rng = random.Random(seed)
        self._now = float(start_time)
        self._order = 0
        self._queue: list[_Event] = []
        self._handlers: dict[str, Handler] = {}
        self._faults: dict[str, LinkFaults] = {}
        self.stats = NetworkStats()

    # -- membership on the wire ------------------------------------------------------------------
    def register(self, node_id: str, handler: Handler) -> None:
        if node_id in self._handlers:
            raise NetworkError(f"{node_id!r} is already registered on this bus")
        self._handlers[node_id] = handler

    @property
    def nodes(self) -> tuple[str, ...]:
        return tuple(self._handlers)

    # -- faults ------------------------------------------------------------------------------------
    def set_faults(self, node_id: str, faults: LinkFaults) -> None:
        """Apply `faults` to everything `node_id` sends from now on."""
        self._faults[node_id] = faults

    def clear_faults(self, node_id: str) -> None:
        self._faults.pop(node_id, None)

    def faults_of(self, node_id: str) -> LinkFaults:
        return self._faults.get(node_id, NO_FAULTS)

    # -- clock -------------------------------------------------------------------------------------
    @property
    def now(self) -> float:
        """Simulated time. Advances only as events are processed — see the module docstring."""
        return self._now

    @property
    def pending(self) -> int:
        return len(self._queue)

    def schedule(self, delay_s: float, callback: Callable[[], None]) -> Timer:
        """Run `callback` at `now + delay_s` unless the returned timer is cancelled first."""
        if delay_s < 0:
            raise NetworkError("cannot schedule in the past")
        timer = Timer(self._now + delay_s)

        def fire() -> None:
            timer.fired = True
            callback()

        self._push(timer.at, fire, timer)
        return timer

    # -- sending -----------------------------------------------------------------------------------
    def send(self, sender: str, recipient: str, payload: object) -> None:
        """Schedule `payload` for delivery to `recipient`, subject to `sender`'s link faults."""
        self.stats.sent += 1
        faults = self.faults_of(sender)
        if recipient in faults.drop_to or (
            faults.drop_rate > 0.0 and self._rng.random() < faults.drop_rate
        ):
            self.stats.dropped += 1
            return
        base = self._now + self.message_delay_s + faults.extra_delay_s
        for copy in range(1 + faults.duplicates):
            jitter = self._rng.uniform(0.0, faults.jitter_s) if faults.jitter_s > 0.0 else 0.0
            if copy:
                self.stats.duplicated += 1
            self._push(base + jitter, self._delivery(sender, recipient, payload))

    def broadcast(self, sender: str, payload: object, recipients: Iterable[str]) -> None:
        """`send()` to each recipient other than `sender`, in the order given."""
        for recipient in recipients:
            if recipient != sender:
                self.send(sender, recipient, payload)

    def _delivery(self, sender: str, recipient: str, payload: object) -> Callable[[], None]:
        def deliver() -> None:
            handler = self._handlers.get(recipient)
            if handler is None:
                self.stats.undeliverable += 1
                return
            self.stats.delivered += 1
            handler(sender, payload)

        return deliver

    def _push(self, at: float, action: Callable[[], None], timer: Timer | None = None) -> None:
        # `order` breaks ties FIFO, so with zero delay messages arrive in the order they were sent
        # and a run is a pure function of the seed.
        self._order += 1
        heapq.heappush(self._queue, _Event(at, self._order, action, timer))

    # -- running -----------------------------------------------------------------------------------
    def run(self, *, until: float | None = None, max_events: int = DEFAULT_MAX_EVENTS) -> int:
        """Process events in time order. Returns how many were processed.

        With `until=None`, runs until the queue drains. With `until=t`, stops before any event
        later than `t` and then advances the clock to `t`, so a stalled cluster can be observed for
        a bounded stretch of simulated time.
        """
        processed = 0
        while self._queue and (until is None or self._queue[0].at <= until):
            if processed >= max_events:
                raise NetworkError(
                    f"run exceeded {max_events} events at t={self._now:.3f}; the cluster is not "
                    f"converging — pass `until=` to observe a stall for bounded time"
                )
            event = heapq.heappop(self._queue)
            if event.timer is not None and event.timer.cancelled:
                # Discarded without advancing the clock. A cancelled view-change timeout that
                # moved `now` would add seconds of phantom "network time" to every commit — the
                # number DEV-21 says M6 reads as modelled latency.
                continue
            self._now = event.at
            event.action()
            processed += 1
        if until is not None and until > self._now:
            self._now = until
        return processed

    def __repr__(self) -> str:
        return (
            f"P2PCSNetwork(nodes={len(self._handlers)}, now={self._now:.3f}, "
            f"pending={len(self._queue)}, delay={self.message_delay_s})"
        )
