"""`consensus.network` — the P2PCS bus: simulated clock, delay, drop, duplicate, reorder, timers."""

from __future__ import annotations

import pytest

from bsfr_sh.consensus.network import LinkFaults, NetworkError, P2PCSNetwork


def _bus(**kwargs: float) -> tuple[P2PCSNetwork, list[tuple[float, str, str, object]]]:
    net = P2PCSNetwork(seed=1, **kwargs)
    log: list[tuple[float, str, str, object]] = []
    for node in ("A", "B", "C"):
        net.register(
            node, lambda sender, payload, node=node: log.append((net.now, node, sender, payload))
        )
    return net, log


def test_zero_delay_is_the_default_and_delivers_in_send_order_without_moving_the_clock() -> None:
    net, log = _bus()
    assert net.message_delay_s == 0.0
    for i in range(5):
        net.send("A", "B", i)
    net.run()
    assert [entry[3] for entry in log] == [0, 1, 2, 3, 4]
    assert net.now == 0.0


def test_configured_delay_moves_the_simulated_clock_not_the_wall_clock() -> None:
    net, log = _bus(message_delay_s=0.25)
    net.send("A", "B", "x")
    net.run()
    assert log == [(0.25, "B", "A", "x")]
    assert net.now == 0.25


def test_negative_delay_is_rejected() -> None:
    with pytest.raises(NetworkError):
        P2PCSNetwork(seed=1, message_delay_s=-0.1)
    with pytest.raises(NetworkError):
        LinkFaults(extra_delay_s=-1.0)


def test_drop_rate_one_mutes_a_node_and_only_that_node() -> None:
    net, log = _bus()
    net.set_faults("A", LinkFaults(drop_rate=1.0))
    net.send("A", "B", "lost")
    net.send("C", "B", "kept")
    net.run()
    assert [entry[3] for entry in log] == ["kept"]
    assert net.stats.dropped == 1


def test_drop_to_partitions_one_direction() -> None:
    net, log = _bus()
    net.set_faults("A", LinkFaults(drop_to=frozenset({"B"})))
    net.broadcast("A", "hello", ["A", "B", "C"])
    net.run()
    assert [(entry[1], entry[3]) for entry in log] == [("C", "hello")]


def test_partial_drop_rate_is_reproducible_from_the_seed() -> None:
    def delivered(seed: int) -> list[object]:
        net = P2PCSNetwork(seed=seed)
        got: list[object] = []
        net.register("B", lambda _s, p: got.append(p))
        net.set_faults("A", LinkFaults(drop_rate=0.5))
        for i in range(200):
            net.send("A", "B", i)
        net.run()
        return got

    assert delivered(3) == delivered(3)
    assert delivered(3) != delivered(4)
    assert 50 < len(delivered(3)) < 150


def test_duplicates_deliver_extra_copies() -> None:
    net, log = _bus()
    net.set_faults("A", LinkFaults(duplicates=2))
    net.send("A", "B", "x")
    net.run()
    assert [entry[3] for entry in log] == ["x", "x", "x"]
    assert net.stats.duplicated == 2


def test_jitter_reorders_deterministically() -> None:
    def order(seed: int) -> list[object]:
        net = P2PCSNetwork(seed=seed)
        got: list[object] = []
        net.register("B", lambda _s, p: got.append(p))
        net.set_faults("A", LinkFaults(jitter_s=1.0))
        for i in range(20):
            net.send("A", "B", i)
        net.run()
        return got

    assert order(5) != list(range(20)), "jitter should let later messages overtake earlier ones"
    assert sorted(order(5)) == list(range(20)), "reordering must not lose anything"
    assert order(5) == order(5)


def test_extra_delay_applies_per_sending_node() -> None:
    net, log = _bus()
    net.set_faults("A", LinkFaults(extra_delay_s=1.0))
    net.send("A", "B", "slow")
    net.send("C", "B", "fast")
    net.run()
    assert [(entry[0], entry[3]) for entry in log] == [(0.0, "fast"), (1.0, "slow")]


def test_clear_faults_restores_the_link() -> None:
    net, log = _bus()
    net.set_faults("A", LinkFaults(drop_rate=1.0))
    net.clear_faults("A")
    net.send("A", "B", "x")
    net.run()
    assert len(log) == 1


def test_timers_fire_on_the_simulated_clock_and_can_be_cancelled() -> None:
    net, _ = _bus()
    fired: list[float] = []
    net.schedule(2.0, lambda: fired.append(net.now))
    cancelled = net.schedule(1.0, lambda: fired.append(-1.0))
    cancelled.cancel()
    net.run()
    assert fired == [2.0]


def test_a_cancelled_timer_does_not_advance_the_clock() -> None:
    """Regression: a popped, cancelled view-change timer used to move `now` to its expiry.

    Every commit cancels a timer, so this added `view_change_timeout_s` of phantom modelled
    network time per block — the exact quantity DEV-21 says M6 reads off the bus clock.
    """
    net, _ = _bus()
    net.schedule(2.0, lambda: None).cancel()
    net.run()
    assert net.now == 0.0


def test_run_until_stops_and_advances_the_clock_to_the_bound() -> None:
    net, _ = _bus()
    fired: list[float] = []
    net.schedule(5.0, lambda: fired.append(net.now))
    net.run(until=3.0)
    assert fired == []
    assert net.now == 3.0
    net.run()
    assert fired == [5.0]


def test_a_run_that_never_drains_raises_rather_than_spinning() -> None:
    net, _ = _bus()

    def rearm() -> None:
        net.schedule(1.0, rearm)

    rearm()
    with pytest.raises(NetworkError, match="not converging"):
        net.run(max_events=100)


def test_messages_to_unregistered_ids_are_counted_not_raised() -> None:
    net, _ = _bus()
    net.send("A", "nobody", "x")
    net.run()
    assert net.stats.undeliverable == 1


def test_any_name_may_send_the_bus_does_not_authenticate() -> None:
    """The transport sender is spoofable by design; authentication is pBFT's job (signatures)."""
    net, log = _bus()
    net.send("not-registered", "B", "x")
    net.run()
    assert log == [(0.0, "B", "not-registered", "x")]


def test_double_registration_is_rejected() -> None:
    net, _ = _bus()
    with pytest.raises(NetworkError):
        net.register("A", lambda _s, _p: None)


def test_two_buses_share_no_state() -> None:
    a, log_a = _bus()
    b, log_b = _bus()
    a.set_faults("A", LinkFaults(drop_rate=1.0))
    a.send("C", "B", "x")
    a.run()
    assert b.faults_of("A").drop_rate == 0.0
    assert log_b == [] and len(log_a) == 1
    assert a.stats is not b.stats
