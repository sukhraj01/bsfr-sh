"""`SYS_i` and `CS_l`, the participants of Phases 1 and 5 (docs/NOTATION.md).

Thin by design. An entity holds an identity, an ECDSA keypair, and the sessions it has established,
and it performs the steps the algorithms assign to *it*. It does not decide what happens next;
`phase1_backup` and `phase5_recovery` do.

Sessions
--------
`establish_session` runs DEV-02's two-message protocol from `crypto.session` between two
entities, and installs a `crypto.channel.Channel` on each side. Everything that travels "over
`SK_{A,B}`" in Alg. 1 and Alg. 5 goes through that channel. Registration is out of scope: §V-2
assumes a phase that provisions long-term keys, and we start after it. So `establish_session` reads
each side's public key straight off the other entity, standing in for the registry a deployment
would consult.

What a wipe leaves
------------------
`System.wipe()` removes `DT_BU` and every session key. It keeps the identity keypair: the system
needs that to open a recovery session at all, and DEV-23's attestation check needs its public key.
Re-provisioning a device whose identity was also destroyed is a registration question (§V-2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from bsfr_sh.blockchain.backup import BackupError, BackupManifest, attest, pack, unpack
from bsfr_sh.blockchain.transaction import Transaction, decrypt
from bsfr_sh.crypto.channel import Channel, Envelope
from bsfr_sh.crypto.ecdsa import KeyPair, PublicKey
from bsfr_sh.crypto.session import (
    Initiator,
    Responder,
    SessionKey,
    SessionOpen,
    SessionPolicy,
    SessionResponse,
)
from bsfr_sh.recovery import restore as alg5

__all__ = [
    "PURPOSE_BACKUP",
    "CloudServer",
    "EntityError",
    "Participant",
    "System",
    "establish_session",
]

PURPOSE_BACKUP: Final = "alg1.backup"


class EntityError(ValueError):
    """Raised when an entity is asked to act without a session, or refuses what it was sent."""


@dataclass(eq=False)
class Participant:
    """What `SYS_i` and `CS_l` share: an identity, a keypair, and established sessions."""

    identity: str
    keypair: KeyPair = field(repr=False)
    policy: SessionPolicy = field(default_factory=SessionPolicy, repr=False)
    _channels: dict[str, Channel] = field(default_factory=dict, init=False, repr=False)
    _peer_keys: dict[str, PublicKey] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.identity:
            raise EntityError("an entity must have an identity")

    @property
    def public_key(self) -> PublicKey:
        """`KU_CSl` or `KU_SYSi` (docs/NOTATION.md)."""
        return self.keypair.public

    def has_session(self, peer_id: str) -> bool:
        return peer_id in self._channels

    def channel(self, peer_id: str) -> Channel:
        """This entity's side of `SK_{self, peer}`."""
        try:
            return self._channels[peer_id]
        except KeyError as exc:
            raise EntityError(f"{self.identity!r} has no session with {peer_id!r}") from exc

    def peer_key(self, peer_id: str) -> PublicKey:
        """The public key a peer authenticated with when its session was established."""
        try:
            return self._peer_keys[peer_id]
        except KeyError as exc:
            raise EntityError(f"{self.identity!r} has no session with {peer_id!r}") from exc

    def forget_sessions(self) -> None:
        self._channels.clear()
        self._peer_keys.clear()

    def _install(self, session: SessionKey, peer_public: PublicKey) -> None:
        self._channels[session.peer_id] = Channel(session)
        self._peer_keys[session.peer_id] = peer_public


@dataclass(eq=False)
class System(Participant):
    """`SYS_i`, a protected smart-healthcare system. `data` is its `DT_BU`, or `None` once wiped."""

    data: bytes | None = field(default=None, repr=False)

    def ship_backup(self, collector_id: str, *, captured_at: int) -> Envelope:
        """Implements Alg. 1, line 1 (the `SYS_i` side): ship `DT_BU` over `SK_{CS_l,SYS_i}`.

        The data is attested before it leaves (DEV-23). That signature is what `SYS_i` checks on
        restore, after a wipe, against its own public key.
        """
        if self.data is None:
            raise EntityError(f"{self.identity!r} has no data to back up")
        manifest = attest(
            self.keypair.private, system_id=self.identity, captured_at=captured_at, data=self.data
        )
        return self.channel(collector_id).seal(PURPOSE_BACKUP, pack(manifest, self.data))

    def wipe(self) -> None:
        """A simulated full wipe: `DT_BU` and every session key are gone. The identity key stays."""
        self.data = None
        self.forget_sessions()

    def request_recovery(self, front_id: str) -> Envelope:
        """Ask the front server `CS_l` for this system's own backup (Alg. 5, line 1)."""
        return alg5.request(self.channel(front_id), self.identity)

    def restore(self, delivery: Envelope) -> BackupManifest:
        """Implements Alg. 5, line 6: store `DT_BU`, only after DEV-23's end-to-end check."""
        manifest, data = alg5.open_delivery(
            delivery, self.channel(delivery.sender), system_public=self.public_key
        )
        self.data = data
        return manifest


@dataclass(eq=False)
class CloudServer(Participant):
    """`CS_l`. Phase 1 collector; in Phase 5, key holder `CS'_l` or front server `CS_l`."""

    _responder: Responder = field(init=False, repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        self._responder = Responder(
            identity=self.identity, private_key=self.keypair.private, policy=self.policy
        )

    def accept_session(self, open_msg: SessionOpen, initiator_public: PublicKey) -> SessionResponse:
        """Responder side of DEV-02. Installs `SK_{self, initiator}` and returns message 2."""
        response, session = self._responder.accept(open_msg, initiator_public)
        self._install(session, initiator_public)
        return response

    def receive_backup(self, envelope: Envelope) -> tuple[BackupManifest, bytes]:
        """Implements Alg. 1, line 1 (the `CS_l` side): open `DT_BU` and authenticate its origin.

        The backup must be attested by the system at the other end of the session it arrived on.
        A system shipping a backup in another system's name is refused here, before anything
        reaches the chain.
        """
        raw = self.channel(envelope.sender).open(envelope, PURPOSE_BACKUP)
        try:
            manifest, data = unpack(raw)
        except BackupError as exc:
            raise EntityError(f"malformed backup from {envelope.sender!r}: {exc}") from exc
        if manifest.system_id != envelope.sender:
            raise EntityError(
                f"{envelope.sender!r} shipped a backup claiming to be {manifest.system_id!r}"
            )
        if not manifest.matches(data) or not manifest.verify(self.peer_key(envelope.sender)):
            raise EntityError(f"backup from {envelope.sender!r} is not attested by its sender")
        return manifest, data

    def decrypt(self, transaction: Transaction) -> bytes:
        """Open `E_KU_CSl(Tx)`, which only works if it was encrypted to this server."""
        return decrypt(self.keypair.private, transaction)

    def accept_recovery_request(self, envelope: Envelope) -> str:
        """Front-server side of Alg. 5, line 1. Returns the system to recover: the requester."""
        return alg5.accept_request(envelope, self.channel(envelope.sender))


def establish_session(initiator: Participant, responder: CloudServer) -> None:
    """Run DEV-02 between two entities and install `SK_{initiator, responder}` on both. §V-1."""
    opener = Initiator(
        identity=initiator.identity,
        private_key=initiator.keypair.private,
        policy=initiator.policy,
    )
    response = responder.accept_session(
        opener.open_session(responder.identity), initiator.public_key
    )
    initiator._install(opener.complete(response, responder.public_key), responder.public_key)
