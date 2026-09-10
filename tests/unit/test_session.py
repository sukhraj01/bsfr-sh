"""`crypto.session` — DEV-02 happy path, key agreement, timestamp window, config.

§V mapping: §V-1, the "illegal session key computation" and "distinct per-session key" halves.
Replay is `test_session_replay.py`; MITM and impersonation are `test_session_mitm.py`. The split
follows the file names in docs/EXPERIMENTS.md Target 5.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.unit.conftest import FakeClock

from bsfr_sh.crypto.ecdsa import KeyPair
from bsfr_sh.crypto.session import (
    DEFAULT_NONCE_BYTES,
    DEFAULT_TIMESTAMP_WINDOW_S,
    SESSION_KEY_BYTES,
    Initiator,
    Responder,
    SessionError,
    SessionPolicy,
)
from bsfr_sh.util.config import load_config

REPO_ROOT = Path(__file__).resolve().parents[2]


def make_pair(
    sys_keys: KeyPair, cs1_keys: KeyPair, policy: SessionPolicy | None = None
) -> tuple[Initiator, Responder]:
    policy = policy or SessionPolicy()
    return (
        Initiator("SYS_1", sys_keys.private, policy),
        Responder("CS_1", cs1_keys.private, policy),
    )


# --------------------------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------------------------
def test_both_sides_derive_the_same_session_key(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    initiator, responder = make_pair(sys_keys, cs1_keys)
    open_msg = initiator.open_session("CS_1")
    response, responder_key = responder.accept(open_msg, sys_keys.public)
    initiator_key = initiator.complete(response, cs1_keys.public)

    assert initiator_key.key == responder_key.key
    assert len(initiator_key.key) == SESSION_KEY_BYTES
    assert initiator_key.session_id == responder_key.session_id
    assert (initiator_key.local_id, initiator_key.peer_id) == ("SYS_1", "CS_1")
    assert (responder_key.local_id, responder_key.peer_id) == ("CS_1", "SYS_1")


def test_each_session_produces_a_distinct_key(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    """§V-1: per-session keys are distinct, so compromising one reveals nothing about another."""
    responder = Responder("CS_1", cs1_keys.private)
    keys = set()
    for _ in range(5):
        initiator = Initiator("SYS_1", sys_keys.private)
        open_msg = initiator.open_session("CS_1")
        response, responder_key = responder.accept(open_msg, sys_keys.public)
        initiator.complete(response, cs1_keys.public)
        keys.add(responder_key.key)
    assert len(keys) == 5


def test_the_session_key_never_travels_on_the_wire(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    """§V-1 illegal session-key computation: an observer sees `g^a` and `g^b`, never `g^ab`."""
    initiator, responder = make_pair(sys_keys, cs1_keys)
    open_msg = initiator.open_session("CS_1")
    response, session_key = responder.accept(open_msg, sys_keys.public)
    on_the_wire = b"".join(
        [
            open_msg.nonce,
            open_msg.ephemeral_public,
            open_msg.signature,
            response.nonce,
            response.ephemeral_public,
            response.signature,
        ]
    )
    assert session_key.key not in on_the_wire


def test_session_key_repr_does_not_leak_material(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    initiator, responder = make_pair(sys_keys, cs1_keys)
    _, session_key = responder.accept(initiator.open_session("CS_1"), sys_keys.public)
    assert session_key.key.hex() not in repr(session_key)


# --------------------------------------------------------------------------------------------
# Timestamp window
# --------------------------------------------------------------------------------------------
def test_expired_timestamp_is_rejected(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    clock = FakeClock()
    policy = SessionPolicy(timestamp_window_s=30.0, clock=clock)
    initiator, responder = make_pair(sys_keys, cs1_keys, policy)
    open_msg = initiator.open_session("CS_1")
    clock.advance(31.0)
    with pytest.raises(SessionError, match="outside the 30s window"):
        responder.accept(open_msg, sys_keys.public)


def test_message_inside_the_window_is_accepted(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    clock = FakeClock()
    policy = SessionPolicy(timestamp_window_s=30.0, clock=clock)
    initiator, responder = make_pair(sys_keys, cs1_keys, policy)
    open_msg = initiator.open_session("CS_1")
    clock.advance(29.0)
    responder.accept(open_msg, sys_keys.public)


def test_a_future_dated_message_is_rejected(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    """The window is two-sided: a far-future timestamp would otherwise stay valid indefinitely."""
    clock = FakeClock()
    policy = SessionPolicy(timestamp_window_s=30.0, clock=clock)
    initiator, responder = make_pair(sys_keys, cs1_keys, policy)
    clock.advance(3600.0)
    open_msg = initiator.open_session("CS_1")
    clock.advance(-3600.0)
    with pytest.raises(SessionError, match="outside the"):
        responder.accept(open_msg, sys_keys.public)


def test_stale_response_is_rejected_by_the_initiator(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    clock = FakeClock()
    policy = SessionPolicy(timestamp_window_s=30.0, clock=clock)
    initiator, responder = make_pair(sys_keys, cs1_keys, policy)
    response, _ = responder.accept(initiator.open_session("CS_1"), sys_keys.public)
    clock.advance(31.0)
    with pytest.raises(SessionError, match="outside the"):
        initiator.complete(response, cs1_keys.public)


# --------------------------------------------------------------------------------------------
# Policy and config
# --------------------------------------------------------------------------------------------
def test_policy_defaults_match_the_documented_values() -> None:
    policy = SessionPolicy()
    assert policy.timestamp_window_s == DEFAULT_TIMESTAMP_WINDOW_S == 30.0
    assert policy.nonce_bytes == DEFAULT_NONCE_BYTES == 16


def test_policy_reads_the_skew_window_from_chain_yaml() -> None:
    """DEV-02: the window is configurable, and `configs/chain.yaml` is where it is declared."""
    config = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
    policy = SessionPolicy.from_config(config)
    assert policy.timestamp_window_s == 30.0
    assert policy.nonce_bytes == 16


def test_nonce_cache_horizon_is_at_least_the_skew_window() -> None:
    """A nonce must outlive the interval in which its message is still acceptable."""
    policy = SessionPolicy(timestamp_window_s=30.0)
    assert policy.nonce_cache_horizon_s >= policy.timestamp_window_s
    assert policy.nonce_cache_horizon_s == 60.0


def test_a_non_positive_window_is_rejected() -> None:
    with pytest.raises(SessionError, match="must be positive"):
        SessionPolicy(timestamp_window_s=0.0)


def test_a_short_nonce_is_rejected() -> None:
    with pytest.raises(SessionError, match="at least 16"):
        SessionPolicy(nonce_bytes=8)


# --------------------------------------------------------------------------------------------
# Misuse
# --------------------------------------------------------------------------------------------
def test_an_initiator_refuses_to_open_twice(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    """Reusing an instance would reuse `g^a`, which collapses forward secrecy across sessions."""
    initiator, _ = make_pair(sys_keys, cs1_keys)
    initiator.open_session("CS_1")
    with pytest.raises(SessionError, match="already opened"):
        initiator.open_session("CS_1")


def test_complete_before_open_is_rejected(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    initiator, responder = make_pair(sys_keys, cs1_keys)
    other = Initiator("SYS_2", sys_keys.private)
    response, _ = responder.accept(other.open_session("CS_1"), sys_keys.public)
    with pytest.raises(SessionError, match="before open_session"):
        initiator.complete(response, cs1_keys.public)


def test_an_unaddressed_opening_is_refused(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    initiator, _ = make_pair(sys_keys, cs1_keys)
    with pytest.raises(SessionError, match="responder_id is required"):
        initiator.open_session("")


def test_a_server_refuses_an_opening_that_claims_to_be_itself(cs1_keys: KeyPair) -> None:
    initiator = Initiator("CS_1", cs1_keys.private)
    responder = Responder("CS_1", cs1_keys.private)
    with pytest.raises(SessionError, match="from ourselves"):
        responder.accept(initiator.open_session("CS_1"), cs1_keys.public)
