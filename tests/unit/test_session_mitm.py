"""§V-1 MITM and impersonation resistance — DEV-02's signed transcript.

An attacker sitting between `SYS_i` and `CS_l` can read, drop, reorder and rewrite every message.
What it cannot do is produce a signature under either party's long-term ECDSA key. These tests
walk the things it *can* try — substituting an ephemeral public key, forging an identity,
splicing two sessions together — and check each one fails.

Named to match the test file docs/EXPERIMENTS.md Target 5 maps §V-1 to.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from bsfr_sh.crypto.ecdsa import KeyPair, PublicKey, generate_keypair
from bsfr_sh.crypto.session import Initiator, Responder, SessionError


def attacker_ephemeral() -> bytes:
    """A public key the attacker knows the private half of — the classic MITM substitution."""
    return PublicKey(ec.generate_private_key(ec.SECP256R1()).public_key()).to_bytes()


# --------------------------------------------------------------------------------------------
# Substituting the ephemeral key
# --------------------------------------------------------------------------------------------
def test_substituted_initiator_ephemeral_key_is_rejected(
    sys_keys: KeyPair, cs1_keys: KeyPair
) -> None:
    """The textbook MITM: swap `g^a` for `g^m` so the attacker shares a key with `CS_l`.

    `g^a` is inside A's signature, so the substitution invalidates it.
    """
    initiator = Initiator("SYS_1", sys_keys.private)
    open_msg = initiator.open_session("CS_1")
    tampered = replace(open_msg, ephemeral_public=attacker_ephemeral())

    with pytest.raises(SessionError, match="signature does not verify"):
        Responder("CS_1", cs1_keys.private).accept(tampered, sys_keys.public)


def test_substituted_responder_ephemeral_key_is_rejected(
    sys_keys: KeyPair, cs1_keys: KeyPair
) -> None:
    """The other direction: swap `g^b` on the way back to A."""
    initiator = Initiator("SYS_1", sys_keys.private)
    responder = Responder("CS_1", cs1_keys.private)
    response, _ = responder.accept(initiator.open_session("CS_1"), sys_keys.public)
    tampered = replace(response, ephemeral_public=attacker_ephemeral())

    with pytest.raises(SessionError, match="signature does not verify"):
        initiator.complete(tampered, cs1_keys.public)


def test_tampered_nonce_or_timestamp_is_rejected(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    initiator = Initiator("SYS_1", sys_keys.private)
    open_msg = initiator.open_session("CS_1")
    responder = Responder("CS_1", cs1_keys.private)

    with pytest.raises(SessionError, match="signature does not verify"):
        responder.accept(replace(open_msg, nonce=b"\x00" * 16), sys_keys.public)
    with pytest.raises(SessionError, match="signature does not verify"):
        responder.accept(replace(open_msg, timestamp=open_msg.timestamp + 0.001), sys_keys.public)


def test_tampered_signature_is_rejected(sys_keys: KeyPair, cs1_keys: KeyPair) -> None:
    initiator = Initiator("SYS_1", sys_keys.private)
    open_msg = initiator.open_session("CS_1")
    mangled = bytearray(open_msg.signature)
    mangled[-1] ^= 0x01

    with pytest.raises(SessionError, match="signature does not verify"):
        Responder("CS_1", cs1_keys.private).accept(
            replace(open_msg, signature=bytes(mangled)), sys_keys.public
        )


# --------------------------------------------------------------------------------------------
# Impersonation
# --------------------------------------------------------------------------------------------
def test_an_attacker_cannot_impersonate_the_initiator(
    cs1_keys: KeyPair, sys_keys: KeyPair, attacker_keys: KeyPair
) -> None:
    """§V-1: the attacker signs a well-formed opening claiming to be `SYS_1`.

    The message is structurally perfect. `CS_1` checks it against `SYS_1`'s registered public key,
    which is not the key that signed it, and refuses.
    """
    forger = Initiator("SYS_1", attacker_keys.private)
    open_msg = forger.open_session("CS_1")

    with pytest.raises(SessionError, match="signature does not verify"):
        Responder("CS_1", cs1_keys.private).accept(open_msg, sys_keys.public)


def test_an_attacker_cannot_impersonate_the_responder(
    sys_keys: KeyPair, cs1_keys: KeyPair, attacker_keys: KeyPair
) -> None:
    """The mirror case: a fake `CS_1` answers the opening."""
    initiator = Initiator("SYS_1", sys_keys.private)
    open_msg = initiator.open_session("CS_1")
    fake_server = Responder("CS_1", attacker_keys.private)
    response, _ = fake_server.accept(open_msg, sys_keys.public)

    with pytest.raises(SessionError, match="signature does not verify"):
        initiator.complete(response, cs1_keys.public)


def test_a_response_addressed_to_someone_else_is_rejected(
    sys_keys: KeyPair, cs1_keys: KeyPair
) -> None:
    initiator = Initiator("SYS_1", sys_keys.private)
    responder = Responder("CS_1", cs1_keys.private)
    response, _ = responder.accept(initiator.open_session("CS_1"), sys_keys.public)

    with pytest.raises(SessionError, match="addressed to"):
        initiator.complete(replace(response, initiator_id="SYS_9"), cs1_keys.public)


def test_a_response_claiming_a_different_server_is_rejected(
    sys_keys: KeyPair, cs1_keys: KeyPair, cs2_keys: KeyPair
) -> None:
    """A opened a session with `CS_1`; an answer claiming to be `CS_2` is not an answer to it."""
    initiator = Initiator("SYS_1", sys_keys.private)
    open_msg = initiator.open_session("CS_1")
    genuine, _ = Responder("CS_1", cs1_keys.private).accept(open_msg, sys_keys.public)

    with pytest.raises(SessionError, match="expected 'SYS_1' from 'CS_1'"):
        initiator.complete(replace(genuine, responder_id="CS_2"), cs2_keys.public)


# --------------------------------------------------------------------------------------------
# Splicing
# --------------------------------------------------------------------------------------------
def test_a_message_1_signature_cannot_be_replayed_as_a_message_2_signature(
    sys_keys: KeyPair, cs1_keys: KeyPair
) -> None:
    """The two messages are signed under different domain tags, so neither fits the other slot."""
    initiator = Initiator("SYS_1", sys_keys.private)
    responder = Responder("CS_1", cs1_keys.private)
    open_msg = initiator.open_session("CS_1")
    response, _ = responder.accept(open_msg, sys_keys.public)

    spliced = replace(response, signature=open_msg.signature)
    with pytest.raises(SessionError, match="signature does not verify"):
        initiator.complete(spliced, cs1_keys.public)


def test_an_unknown_key_share_does_not_yield_a_shared_key(
    sys_keys: KeyPair, cs1_keys: KeyPair
) -> None:
    """An attacker with its own registered key cannot make A and B derive the same `SK` with it."""
    stranger = generate_keypair()
    initiator = Initiator("SYS_1", sys_keys.private)
    responder = Responder("CS_1", cs1_keys.private)
    open_msg = initiator.open_session("CS_1")
    response, responder_key = responder.accept(open_msg, sys_keys.public)

    with pytest.raises(SessionError, match="signature does not verify"):
        initiator.complete(response, stranger.public)
    assert responder_key.peer_id == "SYS_1"
