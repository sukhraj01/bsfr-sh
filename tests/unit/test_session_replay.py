"""§V-1 replay resistance — DEV-02's nonce cache.

The paper claims replay resistance for session establishment. A timestamp window alone does not
provide it: inside the window a captured message replays perfectly, so all a window buys is a
bound on *how long* the replay works. These tests cover the seen-nonce cache that actually makes
a captured message single-use, and the cross-identity replay that the original
docs/ARCHITECTURE.md sketch admitted.

Named to match the test file docs/EXPERIMENTS.md Target 5 maps §V-1 to.
"""

from __future__ import annotations

import pytest
from tests.unit.conftest import FakeClock

from bsfr_sh.crypto.ecdsa import KeyPair
from bsfr_sh.crypto.session import (
    Initiator,
    NonceCache,
    Responder,
    SessionError,
    SessionPolicy,
)


# --------------------------------------------------------------------------------------------
# Replay of message 1
# --------------------------------------------------------------------------------------------
def test_replayed_session_opening_is_rejected(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    """The core §V-1 claim: the same captured message must not open a second session."""
    initiator = Initiator("SYS_1", sys_keys.private)
    responder = Responder("CS_1", cs1_keys.private)
    open_msg = initiator.open_session("CS_1")

    responder.accept(open_msg, sys_keys.public)
    with pytest.raises(SessionError, match="replayed nonce"):
        responder.accept(open_msg, sys_keys.public)


def test_replay_is_rejected_even_inside_the_timestamp_window(
    sys_keys: KeyPair, cs1_keys: KeyPair
) -> None:
    """The window is still open, and the replay still fails. This is the point of the cache."""
    clock = FakeClock()
    policy = SessionPolicy(timestamp_window_s=30.0, clock=clock)
    initiator = Initiator("SYS_1", sys_keys.private, policy)
    responder = Responder("CS_1", cs1_keys.private, policy)
    open_msg = initiator.open_session("CS_1")

    responder.accept(open_msg, sys_keys.public)
    clock.advance(29.0)  # still inside the window
    with pytest.raises(SessionError, match="replayed nonce"):
        responder.accept(open_msg, sys_keys.public)


def test_a_replay_after_the_window_fails_on_the_timestamp(
    sys_keys: KeyPair, cs1_keys: KeyPair
) -> None:
    """Belt and braces: once the window closes, the timestamp check rejects it first."""
    clock = FakeClock()
    policy = SessionPolicy(timestamp_window_s=30.0, clock=clock)
    initiator = Initiator("SYS_1", sys_keys.private, policy)
    responder = Responder("CS_1", cs1_keys.private, policy)
    open_msg = initiator.open_session("CS_1")
    responder.accept(open_msg, sys_keys.public)
    clock.advance(120.0)
    with pytest.raises(SessionError, match="outside the"):
        responder.accept(open_msg, sys_keys.public)


def test_distinct_openings_from_the_same_peer_are_all_accepted(
    sys_keys: KeyPair, cs1_keys: KeyPair
) -> None:
    """Replay rejection must not become a denial of service against an honest system."""
    responder = Responder("CS_1", cs1_keys.private)
    for _ in range(10):
        responder.accept(Initiator("SYS_1", sys_keys.private).open_session("CS_1"), sys_keys.public)


# --------------------------------------------------------------------------------------------
# Cross-identity replay — the flaw in the original sketch
# --------------------------------------------------------------------------------------------
def test_opening_addressed_to_one_server_is_refused_by_another(
    sys_keys: KeyPair, cs1_keys: KeyPair, cs2_keys: KeyPair
) -> None:
    """The DEV-02 amendment, stated as an attack.

    Under the original sketch, A's signature covered only `ID_A || N_A || TS_A || g^a` — nothing
    naming the intended peer. An attacker capturing A's opening to `CS_1` could replay it to
    `CS_2`, whose signature check would pass, and `CS_2` would complete a session it believed A
    had requested. That is impersonation of A with no key material, against a claim §V-1 makes
    explicitly. Binding `ID_B` into A's signed message closes it, and `CS_2` now refuses.
    """
    initiator = Initiator("SYS_1", sys_keys.private)
    open_msg = initiator.open_session("CS_1")

    cs2 = Responder("CS_2", cs2_keys.private)
    with pytest.raises(SessionError, match="addressed to 'CS_1', not 'CS_2'"):
        cs2.accept(open_msg, sys_keys.public)

    # The legitimate recipient still accepts it, so the check is addressing and not breakage.
    Responder("CS_1", cs1_keys.private).accept(open_msg, sys_keys.public)


def test_rewriting_the_responder_id_breaks_the_signature(
    sys_keys: KeyPair, cs2_keys: KeyPair
) -> None:
    """The attacker's obvious next move: relabel the message. `ID_B` is signed, so it fails."""
    from dataclasses import replace

    initiator = Initiator("SYS_1", sys_keys.private)
    open_msg = initiator.open_session("CS_1")
    relabelled = replace(open_msg, responder_id="CS_2")

    cs2 = Responder("CS_2", cs2_keys.private)
    with pytest.raises(SessionError, match="signature does not verify"):
        cs2.accept(relabelled, sys_keys.public)


def test_each_server_keeps_its_own_nonce_cache(
    sys_keys: KeyPair, cs1_keys: KeyPair, cs2_keys: KeyPair
) -> None:
    """Two servers must not be able to lock each other out of an honest peer's nonces."""
    cs1 = Responder("CS_1", cs1_keys.private)
    cs2 = Responder("CS_2", cs2_keys.private)
    cs1.accept(Initiator("SYS_1", sys_keys.private).open_session("CS_1"), sys_keys.public)
    cs2.accept(Initiator("SYS_1", sys_keys.private).open_session("CS_2"), sys_keys.public)
    assert len(cs1.nonce_cache) == 1
    assert len(cs2.nonce_cache) == 1


# --------------------------------------------------------------------------------------------
# Replay of message 2
# --------------------------------------------------------------------------------------------
def test_response_to_one_opening_is_rejected_for_another(
    sys_keys: KeyPair, cs1_keys: KeyPair
) -> None:
    """B's signature covers `N_A` and `g^a`, so a response cannot be moved between sessions."""
    responder = Responder("CS_1", cs1_keys.private)
    first = Initiator("SYS_1", sys_keys.private)
    second = Initiator("SYS_1", sys_keys.private)
    response_for_first, _ = responder.accept(first.open_session("CS_1"), sys_keys.public)
    second.open_session("CS_1")

    with pytest.raises(SessionError, match="signature does not verify"):
        second.complete(response_for_first, cs1_keys.public)


def test_initiator_can_reject_a_replayed_response_with_a_cache(
    sys_keys: KeyPair, cs1_keys: KeyPair
) -> None:
    initiator = Initiator("SYS_1", sys_keys.private)
    responder = Responder("CS_1", cs1_keys.private)
    response, _ = responder.accept(initiator.open_session("CS_1"), sys_keys.public)
    cache = NonceCache(initiator.policy.nonce_cache_horizon_s)

    initiator.complete(response, cs1_keys.public, nonce_cache=cache)
    with pytest.raises(SessionError, match="replayed nonce"):
        initiator.complete(response, cs1_keys.public, nonce_cache=cache)


# --------------------------------------------------------------------------------------------
# The cache itself
# --------------------------------------------------------------------------------------------
def test_nonce_cache_rejects_a_repeat_and_evicts_after_the_horizon() -> None:
    cache = NonceCache(horizon_s=60.0)
    cache.remember("SYS_1", b"n1", now=1000.0)
    assert cache.seen("SYS_1", b"n1")
    with pytest.raises(SessionError, match="replayed nonce"):
        cache.remember("SYS_1", b"n1", now=1030.0)

    # Past the horizon the entry is swept, which is safe: a message that old fails the timestamp
    # check before the cache is ever consulted.
    cache.remember("SYS_2", b"other", now=1061.0)
    assert not cache.seen("SYS_1", b"n1")


def test_nonce_cache_separates_peers() -> None:
    cache = NonceCache(horizon_s=60.0)
    cache.remember("SYS_1", b"n1", now=1000.0)
    cache.remember("SYS_2", b"n1", now=1000.0)
    assert len(cache) == 2


def test_nonce_cache_rejects_a_non_positive_horizon() -> None:
    with pytest.raises(SessionError, match="must be positive"):
        NonceCache(horizon_s=0.0)
