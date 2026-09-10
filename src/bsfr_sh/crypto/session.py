"""Session establishment — DEV-02, filling GAP-7.

The paper (§IV-A, §V-1) defers key establishment to "any standard mutual authentication and key
establishment mechanism" while §V-1 nevertheless *claims* resistance to replay, MITM,
impersonation and illegal session-key computation. Something concrete has to exist for those
claims to be checkable, so DEV-02 supplies one: ephemeral ECDH over secp256r1 with an
ECDSA-signed transcript, nonces and timestamps, reusing the primitives the paper already
mandates.

Two corrections to the sketch in docs/ARCHITECTURE.md §crypto
--------------------------------------------------------------
The sketch as originally written was::

    A -> B : ID_A, N_A, TS_A, g^a, Sig_A(ID_A || N_A || TS_A || g^a)
    B -> A : ID_B, N_B, TS_B, g^b, Sig_B(ID_B || N_B || TS_B || g^b || N_A)

**(1) A's signature does not name B.** Nothing in the first message says who it is for, so it is
a valid session opening addressed to *every* cloud server. An attacker who captures A's message
to `CS_1` replays it verbatim to `CS_2`, which checks A's signature, finds it good, and completes
a session it believes A asked for. That is an impersonation of A against `CS_2` requiring no key
material at all, and §V-1 claims impersonation resistance. Fixed here: `ID_B` is inside A's
signed message.

**(2) A timestamp window is not replay protection.** It bounds *how long* a replay stays
acceptable; inside the window a captured message replays perfectly. Because §V-1 claims replay
resistance outright, this module keeps a seen-nonce cache and rejects any nonce it has seen from
a peer. The eviction horizon is twice the accepted skew: a message stamped `TS` is acceptable
until `TS + window`, and the responder's clock may itself be `window` behind, so a nonce must be
remembered for `2 * window` after it is first accepted or a replay could arrive after eviction.

Both are amendments to DEV-02 in docs/DEVIATIONS.md.

Resulting protocol
------------------
::

    A -> B : ID_A, ID_B, N_A, TS_A, g^a,
             Sig_A(tag_msg1 || ID_A || ID_B || N_A || TS_A || g^a)
    B -> A : ID_B, ID_A, N_B, TS_B, g^b,
             Sig_B(tag_msg2 || ID_B || ID_A || N_B || TS_B || g^b || N_A || g^a)
    both   : SK = HKDF(g^ab, info = tag_sk || ID_A || ID_B || N_A || N_B || g^a || g^b)

B's signature covers `N_A` and `g^a`, so the second message cannot be detached from the first
one it answers, and neither signature can be lifted into the other position because the two are
computed over different domain tags (`crypto.hashing`).

Both keys are ephemeral, so `SK` is unique per session and past sessions stay secure if a
long-term ECDSA key later leaks. `illegal session key computation` reduces to computational
Diffie-Hellman on secp256r1: an observer sees `g^a` and `g^b` and never `g^ab`.

Clock and randomness are injected (`SessionPolicy.clock`, `nonce_source`) so the replay and
expiry paths are testable without sleeping.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from bsfr_sh.crypto.ecdsa import (
    PrivateKey,
    PublicKey,
    load_public_key,
    sign,
    verify,
)
from bsfr_sh.crypto.hashing import DOMAIN_SESSION_TRANSCRIPT, tagged_h
from bsfr_sh.util.config import Config
from bsfr_sh.util.serialization import encode

try:  # pragma: no cover - import-shape only
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as exc:  # pragma: no cover - dependency is declared in pyproject
    raise ImportError("crypto.session requires the 'cryptography' package") from exc

__all__ = [
    "DEFAULT_NONCE_BYTES",
    "DEFAULT_TIMESTAMP_WINDOW_S",
    "SESSION_KEY_BYTES",
    "Initiator",
    "NonceCache",
    "Responder",
    "SessionError",
    "SessionKey",
    "SessionOpen",
    "SessionPolicy",
    "SessionResponse",
]

#: `configs/chain.yaml` → `crypto.session.timestamp_window_s`. DECLARED, per DEV-02.
DEFAULT_TIMESTAMP_WINDOW_S: Final = 30.0
#: `configs/chain.yaml` → `crypto.session.nonce_bytes`.
DEFAULT_NONCE_BYTES: Final = 16
SESSION_KEY_BYTES: Final = 32

_TAG_MSG1: Final = DOMAIN_SESSION_TRANSCRIPT + ".msg1"
_TAG_MSG2: Final = DOMAIN_SESSION_TRANSCRIPT + ".msg2"
_TAG_SESSION_KEY: Final = DOMAIN_SESSION_TRANSCRIPT + ".sk"
_KDF_INFO_LABEL: Final = b"bsfr-sh/session/hkdf-sha256/v1"


class SessionError(ValueError):
    """Raised when a session message is stale, replayed, misaddressed, or badly signed."""


# --------------------------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class SessionPolicy:
    """Tunables for session establishment, sourced from `configs/chain.yaml`.

    `clock` and `nonce_source` are injectable so that expiry and replay have deterministic tests;
    production callers take the defaults.
    """

    timestamp_window_s: float = DEFAULT_TIMESTAMP_WINDOW_S
    nonce_bytes: int = DEFAULT_NONCE_BYTES
    clock: Callable[[], float] = time.time
    nonce_source: Callable[[int], bytes] = os.urandom

    def __post_init__(self) -> None:
        if self.timestamp_window_s <= 0:
            raise SessionError("timestamp_window_s must be positive")
        if self.nonce_bytes < 16:
            raise SessionError(
                "nonce_bytes must be at least 16; a shorter nonce makes collision, not freshness"
            )

    @property
    def nonce_cache_horizon_s(self) -> float:
        """How long a seen nonce must be remembered — see the module docstring's point (2)."""
        return 2 * self.timestamp_window_s

    @classmethod
    def from_config(
        cls,
        config: Config,
        *,
        clock: Callable[[], float] = time.time,
        nonce_source: Callable[[int], bytes] = os.urandom,
    ) -> SessionPolicy:
        """Build a policy from a loaded `chain` config.

        Read with `get(..., default)` rather than through `util.config`'s required-key schema:
        these keys are DECLARED (DEV-02), so a config written before they existed still loads
        with the documented 30 s default instead of failing at load time.
        """
        return cls(
            timestamp_window_s=float(
                config.get("crypto.session.timestamp_window_s", DEFAULT_TIMESTAMP_WINDOW_S)
            ),
            nonce_bytes=int(config.get("crypto.session.nonce_bytes", DEFAULT_NONCE_BYTES)),
            clock=clock,
            nonce_source=nonce_source,
        )


# --------------------------------------------------------------------------------------------
# Replay protection
# --------------------------------------------------------------------------------------------
class NonceCache:
    """Nonces already accepted from each peer, with time-bounded eviction.

    The timestamp window alone only bounds the replay *interval*; this is what actually makes a
    captured message single-use. Keyed by `(peer_id, nonce)` so two peers choosing the same nonce
    do not lock each other out.

    Eviction is lazy — swept on insert — because a session layer that needs a background thread
    to stay correct is a session layer that is wrong whenever the thread is not running.
    """

    __slots__ = ("_horizon_s", "_seen")

    def __init__(self, horizon_s: float) -> None:
        if horizon_s <= 0:
            raise SessionError("nonce cache horizon must be positive")
        self._horizon_s = horizon_s
        self._seen: dict[tuple[str, bytes], float] = {}

    def __len__(self) -> int:
        return len(self._seen)

    def seen(self, peer_id: str, nonce: bytes) -> bool:
        return (peer_id, nonce) in self._seen

    def remember(self, peer_id: str, nonce: bytes, now: float) -> None:
        """Record a nonce, or raise if it has already been used inside the horizon."""
        self._evict(now)
        key = (peer_id, nonce)
        if key in self._seen:
            raise SessionError(
                f"replayed nonce from {peer_id!r}: this message has already been accepted"
            )
        self._seen[key] = now + self._horizon_s

    def _evict(self, now: float) -> None:
        expired = [key for key, expiry in self._seen.items() if expiry <= now]
        for key in expired:
            del self._seen[key]


# --------------------------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class SessionOpen:
    """Message 1, `A -> B`. `responder_id` is the DEV-02 amendment: A names its intended peer."""

    initiator_id: str
    responder_id: str
    nonce: bytes
    timestamp: float
    ephemeral_public: bytes
    signature: bytes


@dataclass(frozen=True)
class SessionResponse:
    """Message 2, `B -> A`. Its signature covers `N_A` and `g^a`, binding it to message 1."""

    responder_id: str
    initiator_id: str
    nonce: bytes
    timestamp: float
    ephemeral_public: bytes
    signature: bytes


@dataclass(frozen=True)
class SessionKey:
    """`SK_{E_A, E_B}` (docs/NOTATION.md) plus the context it was derived in."""

    key: bytes
    session_id: bytes
    local_id: str
    peer_id: str
    established_at: float

    def __repr__(self) -> str:
        # Never render key material.
        return (
            f"SessionKey(local={self.local_id!r}, peer={self.peer_id!r}, "
            f"session_id={self.session_id[:8].hex()}...)"
        )


# --------------------------------------------------------------------------------------------
# Transcript
# --------------------------------------------------------------------------------------------
def _msg1_preimage(
    initiator_id: str,
    responder_id: str,
    nonce: bytes,
    timestamp: float,
    ephemeral_public: bytes,
) -> bytes:
    return tagged_h(
        _TAG_MSG1,
        encode(initiator_id),
        encode(responder_id),
        nonce,
        encode(timestamp),
        ephemeral_public,
    )


def _msg2_preimage(
    responder_id: str,
    initiator_id: str,
    nonce: bytes,
    timestamp: float,
    ephemeral_public: bytes,
    initiator_nonce: bytes,
    initiator_ephemeral: bytes,
) -> bytes:
    return tagged_h(
        _TAG_MSG2,
        encode(responder_id),
        encode(initiator_id),
        nonce,
        encode(timestamp),
        ephemeral_public,
        initiator_nonce,
        initiator_ephemeral,
    )


def _session_transcript(open_msg: SessionOpen, response: SessionResponse) -> bytes:
    return tagged_h(
        _TAG_SESSION_KEY,
        encode(open_msg.initiator_id),
        encode(open_msg.responder_id),
        open_msg.nonce,
        response.nonce,
        open_msg.ephemeral_public,
        response.ephemeral_public,
    )


def _derive_session_key(shared_secret: bytes, transcript: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_BYTES,
        salt=None,
        info=_KDF_INFO_LABEL + transcript,
    ).derive(shared_secret)


def _check_timestamp(timestamp: float, policy: SessionPolicy, what: str) -> float:
    now = policy.clock()
    skew = abs(now - timestamp)
    if skew > policy.timestamp_window_s:
        raise SessionError(
            f"{what} timestamp is {skew:.1f}s from local time, outside the "
            f"{policy.timestamp_window_s:.0f}s window"
        )
    return now


# --------------------------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------------------------
@dataclass
class Initiator:
    """Entity A — a `SYS_i`, a honeypot, or a cloud server opening a session.

    One instance drives one session: `open_session()` then `complete()`. Reusing an instance for a
    second session would reuse `g^a`, so it is refused.
    """

    identity: str
    private_key: PrivateKey
    policy: SessionPolicy = field(default_factory=SessionPolicy)
    _ephemeral: ec.EllipticCurvePrivateKey | None = field(default=None, init=False, repr=False)
    _open: SessionOpen | None = field(default=None, init=False, repr=False)

    def open_session(self, responder_id: str) -> SessionOpen:
        """Build message 1, addressed to `responder_id`."""
        if self._open is not None:
            raise SessionError(
                "this Initiator has already opened a session; build a new one rather than "
                "reusing the ephemeral key"
            )
        if not responder_id:
            raise SessionError("responder_id is required: an unaddressed opening is replayable")
        self._ephemeral = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public = PublicKey(self._ephemeral.public_key()).to_bytes()
        nonce = self.policy.nonce_source(self.policy.nonce_bytes)
        timestamp = self.policy.clock()
        signature = sign(
            self.private_key,
            _msg1_preimage(self.identity, responder_id, nonce, timestamp, ephemeral_public),
        )
        self._open = SessionOpen(
            initiator_id=self.identity,
            responder_id=responder_id,
            nonce=nonce,
            timestamp=timestamp,
            ephemeral_public=ephemeral_public,
            signature=signature,
        )
        return self._open

    def complete(
        self,
        response: SessionResponse,
        responder_public: PublicKey,
        nonce_cache: NonceCache | None = None,
    ) -> SessionKey:
        """Verify message 2 and derive `SK`."""
        if self._open is None or self._ephemeral is None:
            raise SessionError("complete() called before open_session()")
        sent = self._open
        if response.initiator_id != self.identity or response.responder_id != sent.responder_id:
            raise SessionError(
                f"response is addressed to {response.initiator_id!r} from "
                f"{response.responder_id!r}; expected {self.identity!r} from "
                f"{sent.responder_id!r}"
            )
        now = _check_timestamp(response.timestamp, self.policy, "response")
        preimage = _msg2_preimage(
            response.responder_id,
            response.initiator_id,
            response.nonce,
            response.timestamp,
            response.ephemeral_public,
            sent.nonce,
            sent.ephemeral_public,
        )
        if not verify(responder_public, response.signature, preimage):
            raise SessionError(
                "response signature does not verify: wrong key, altered message, or a response "
                "to a different opening"
            )
        if nonce_cache is not None:
            nonce_cache.remember(response.responder_id, response.nonce, now)
        peer_ephemeral = load_public_key(response.ephemeral_public)
        shared = self._ephemeral.exchange(ec.ECDH(), peer_ephemeral._key)
        transcript = _session_transcript(sent, response)
        return SessionKey(
            key=_derive_session_key(shared, transcript),
            session_id=transcript,
            local_id=self.identity,
            peer_id=response.responder_id,
            established_at=now,
        )


@dataclass
class Responder:
    """Entity B — typically `CS_l`. One instance serves many sessions and owns the nonce cache."""

    identity: str
    private_key: PrivateKey
    policy: SessionPolicy = field(default_factory=SessionPolicy)
    nonce_cache: NonceCache = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.nonce_cache = NonceCache(self.policy.nonce_cache_horizon_s)

    def accept(
        self, open_msg: SessionOpen, initiator_public: PublicKey
    ) -> tuple[SessionResponse, SessionKey]:
        """Verify message 1, build message 2, and derive `SK`.

        Checks, in order: the message is addressed to us (the DEV-02 amendment — this is what
        stops a replay to a different cloud server); the timestamp is inside the window; the
        signature verifies; the nonce has not been seen. Signature before nonce so that a garbage
        message cannot fill the cache.
        """
        if open_msg.responder_id != self.identity:
            raise SessionError(
                f"session opening is addressed to {open_msg.responder_id!r}, not "
                f"{self.identity!r}; refusing a message intended for another server"
            )
        if open_msg.initiator_id == self.identity:
            raise SessionError("refusing a session opening that claims to come from ourselves")
        now = _check_timestamp(open_msg.timestamp, self.policy, "session opening")
        preimage = _msg1_preimage(
            open_msg.initiator_id,
            open_msg.responder_id,
            open_msg.nonce,
            open_msg.timestamp,
            open_msg.ephemeral_public,
        )
        if not verify(initiator_public, open_msg.signature, preimage):
            raise SessionError(
                "session opening signature does not verify: wrong key or altered message"
            )
        self.nonce_cache.remember(open_msg.initiator_id, open_msg.nonce, now)

        ephemeral = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public = PublicKey(ephemeral.public_key()).to_bytes()
        nonce = self.policy.nonce_source(self.policy.nonce_bytes)
        timestamp = self.policy.clock()
        signature = sign(
            self.private_key,
            _msg2_preimage(
                self.identity,
                open_msg.initiator_id,
                nonce,
                timestamp,
                ephemeral_public,
                open_msg.nonce,
                open_msg.ephemeral_public,
            ),
        )
        response = SessionResponse(
            responder_id=self.identity,
            initiator_id=open_msg.initiator_id,
            nonce=nonce,
            timestamp=timestamp,
            ephemeral_public=ephemeral_public,
            signature=signature,
        )
        peer_ephemeral = load_public_key(open_msg.ephemeral_public)
        shared = ephemeral.exchange(ec.ECDH(), peer_ephemeral._key)
        transcript = _session_transcript(open_msg, response)
        session_key = SessionKey(
            key=_derive_session_key(shared, transcript),
            session_id=transcript,
            local_id=self.identity,
            peer_id=open_msg.initiator_id,
            established_at=now,
        )
        return response, session_key
