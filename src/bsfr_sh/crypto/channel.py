"""Messages under a session key: the "over `SK_{A,B}`" of Alg. 1 line 1 and Alg. 5 lines 4-5.

`crypto.session` establishes `SK` (DEV-02), and until M3a nothing used it. This module is how a
session key carries data. It uses AES-256-GCM under `SK`, with associated data binding every
message to:

* **the session** (`session_id`), so an envelope from one session never opens in another;
* **the direction** (`sender`, `recipient`). Both ends derive the same key, so without this a
  message could be reflected back to the endpoint that sent it and would still open;
* **the purpose** (`"alg1.backup"`, `"alg5.delivery"`, ...), so a message sealed for one protocol
  step cannot be replayed into another;
* **a counter**, which the receiver requires to increase strictly. §V-1 claims replay resistance,
  and a session key alone does not provide it inside a session.

The counter only advances after the tag verifies, so a forged envelope cannot burn a counter value
and lock out the genuine one. Nonces are random (`crypto.aead` refuses to accept one from a caller).
Both directions seal under one key, each endpoint with its own `AeadKey` instance. At 96 bits the
collision bound is irrelevant at this project's message counts.

Channel is its own module rather than part of `crypto.session` because `recovery/` implements
the two hops of Alg. 5 and may not import `framework/`. The thing that seals a hop therefore has
to sit below both.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from bsfr_sh.crypto.aead import AeadError, AeadKey, Sealed
from bsfr_sh.crypto.session import SessionKey
from bsfr_sh.util.serialization import encode

__all__ = ["Channel", "ChannelError", "Envelope"]

_AAD_LABEL: Final = "bsfr_sh.channel.v1"


class ChannelError(ValueError):
    """Raised for an envelope from another session, direction or step, a replay, or tampering."""


@dataclass(frozen=True)
class Envelope:
    """One message under `SK_{sender, recipient}`. All fields but `ciphertext` are bound as AAD."""

    session_id: bytes
    sender: str
    recipient: str
    purpose: str
    counter: int
    nonce: bytes
    ciphertext: bytes


def _aad(session_id: bytes, sender: str, recipient: str, purpose: str, counter: int) -> bytes:
    return encode([_AAD_LABEL, session_id, sender, recipient, purpose, counter])


class Channel:
    """One endpoint's side of an established session. Build one per `SessionKey`."""

    __slots__ = ("_key", "_received", "_sent", "_session")

    def __init__(self, session: SessionKey) -> None:
        self._session = session
        self._key = AeadKey(session.key)
        self._sent = 0
        self._received = 0

    @property
    def local_id(self) -> str:
        return self._session.local_id

    @property
    def peer_id(self) -> str:
        return self._session.peer_id

    @property
    def session_id(self) -> bytes:
        return self._session.session_id

    def seal(self, purpose: str, payload: bytes) -> Envelope:
        """Encrypt `payload` to the peer for one protocol step."""
        if not purpose:
            raise ChannelError(
                "purpose is required; an unlabelled message can be replayed anywhere"
            )
        self._sent += 1
        aad = _aad(self.session_id, self.local_id, self.peer_id, purpose, self._sent)
        sealed = self._key.seal(payload, aad)
        return Envelope(
            session_id=self.session_id,
            sender=self.local_id,
            recipient=self.peer_id,
            purpose=purpose,
            counter=self._sent,
            nonce=sealed.nonce,
            ciphertext=sealed.ciphertext,
        )

    def open(self, envelope: Envelope, purpose: str) -> bytes:
        """Decrypt an envelope from the peer. Raises `ChannelError` on any mismatch."""
        if envelope.session_id != self.session_id:
            raise ChannelError("envelope belongs to a different session")
        if envelope.sender != self.peer_id or envelope.recipient != self.local_id:
            raise ChannelError(
                f"envelope is {envelope.sender!r} -> {envelope.recipient!r}; this channel "
                f"receives {self.peer_id!r} -> {self.local_id!r} (misdirected or reflected)"
            )
        if envelope.purpose != purpose:
            raise ChannelError(f"envelope is for {envelope.purpose!r}, expected {purpose!r}")
        if envelope.counter <= self._received:
            raise ChannelError(
                f"counter {envelope.counter} is not above {self._received}: replayed or reordered"
            )
        aad = _aad(
            envelope.session_id, envelope.sender, envelope.recipient, purpose, envelope.counter
        )
        try:
            payload = self._key.unseal(
                Sealed(nonce=envelope.nonce, ciphertext=envelope.ciphertext), aad
            )
        except AeadError as exc:
            raise ChannelError(f"envelope does not authenticate under this session: {exc}") from exc
        self._received = envelope.counter
        return payload

    def __repr__(self) -> str:
        return f"Channel({self.local_id!r} <-> {self.peer_id!r}, sent={self._sent})"
