"""`crypto.channel`: what "over `SK_{A,B}`" means once a session exists. §V-1 inside a session.

M1's tests showed that session *establishment* resists replay, MITM and impersonation. These
tests show that the messages sent under the resulting key do too: they are bound to the session,
the direction, the protocol step and a counter.
"""

from __future__ import annotations

import dataclasses

import pytest

from bsfr_sh.crypto.channel import Channel, ChannelError
from bsfr_sh.crypto.ecdsa import KeyPair
from bsfr_sh.crypto.session import Initiator, Responder


def _pair(
    a_keys: KeyPair, b_keys: KeyPair, a: str = "SYS_1", b: str = "CS_1"
) -> tuple[Channel, Channel]:
    initiator = Initiator(identity=a, private_key=a_keys.private)
    responder = Responder(identity=b, private_key=b_keys.private)
    response, b_session = responder.accept(initiator.open_session(b), a_keys.public)
    return Channel(initiator.complete(response, b_keys.public)), Channel(b_session)


@pytest.fixture
def pair(sys_keys, cs1_keys):
    return _pair(sys_keys, cs1_keys)


def test_round_trip_in_both_directions(pair) -> None:
    a, b = pair
    assert b.open(a.seal("p", b"hello"), "p") == b"hello"
    assert a.open(b.seal("p", b"back"), "p") == b"back"


def test_a_message_reflected_to_its_sender_does_not_open(pair) -> None:
    a, _ = pair
    with pytest.raises(ChannelError, match="reflected"):
        a.open(a.seal("p", b"x"), "p")


def test_rewriting_the_direction_fields_breaks_the_tag(pair) -> None:
    """Both ends hold one key; only the AAD distinguishes A->B from B->A."""
    a, _ = pair
    env = a.seal("p", b"x")
    swapped = dataclasses.replace(env, sender=env.recipient, recipient=env.sender)
    with pytest.raises(ChannelError, match="authenticate"):
        a.open(swapped, "p")


def test_a_replayed_envelope_is_rejected(pair) -> None:
    a, b = pair
    env = a.seal("p", b"once")
    b.open(env, "p")
    with pytest.raises(ChannelError, match="replayed"):
        b.open(env, "p")


def test_a_forged_envelope_does_not_burn_the_counter(pair) -> None:
    a, b = pair
    genuine = a.seal("p", b"real")
    forged = dataclasses.replace(genuine, counter=5, ciphertext=bytes(len(genuine.ciphertext)))
    with pytest.raises(ChannelError):
        b.open(forged, "p")
    assert b.open(genuine, "p") == b"real"


def test_an_envelope_from_another_session_does_not_open(sys_keys, cs1_keys) -> None:
    a1, _ = _pair(sys_keys, cs1_keys)
    _, b2 = _pair(sys_keys, cs1_keys)
    env = a1.seal("p", b"x")
    with pytest.raises(ChannelError, match="different session"):
        b2.open(env, "p")
    relabelled = dataclasses.replace(env, session_id=b2.session_id)
    with pytest.raises(ChannelError, match="authenticate"):
        b2.open(relabelled, "p")


def test_a_message_for_one_step_cannot_be_opened_as_another(pair) -> None:
    a, b = pair
    env = a.seal("alg1.backup", b"x")
    with pytest.raises(ChannelError, match="expected"):
        b.open(env, "alg5.delivery")
    relabelled = dataclasses.replace(env, purpose="alg5.delivery")
    with pytest.raises(ChannelError, match="authenticate"):
        b.open(relabelled, "alg5.delivery")


def test_tampered_ciphertext_is_rejected(pair) -> None:
    a, b = pair
    env = a.seal("p", b"payload")
    flipped = bytes([env.ciphertext[0] ^ 1]) + env.ciphertext[1:]
    with pytest.raises(ChannelError, match="authenticate"):
        b.open(dataclasses.replace(env, ciphertext=flipped), "p")


def test_a_third_party_holding_its_own_session_cannot_open_it(sys_keys, cs1_keys, cs2_keys) -> None:
    a, _ = _pair(sys_keys, cs1_keys)
    _, eve = _pair(sys_keys, cs2_keys, b="CS_2")
    with pytest.raises(ChannelError):
        eve.open(a.seal("p", b"x"), "p")


def test_an_unlabelled_message_is_refused(pair) -> None:
    with pytest.raises(ChannelError, match="purpose"):
        pair[0].seal("", b"x")
