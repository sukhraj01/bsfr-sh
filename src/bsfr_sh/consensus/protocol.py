"""pBFT wire messages, membership, and certificate verification.

Shared by `consensus.pbft` (normal case) and `consensus.view_change`, which is why it is its own
module: each of those needs the other's message types, and a cycle between them would be the
architectural bug docs/ARCHITECTURE.md warns about.

What every signature covers — DEV-19
------------------------------------
Every signed message is an ECDSA signature (`crypto.ecdsa`) over a canonical struct
(`util.serialization.encode_struct`) whose **domain names the message type**. For the three
normal-case messages the signed fields are:

    chain, view, seq, digest, replica_id

* `view` inside the signature: otherwise a prepare from view 0 is a valid prepare in view 1.
* `seq` inside the signature: otherwise a vote for height `n` counts at height `n+1`.
* `digest` inside the signature: otherwise a vote can be moved onto a different block.
* `chain` inside the signature: `BC_DTBU` and `BC_SigRW` are independent clusters, but if one
  cloud server's key serves both, a prepare for one chain would otherwise verify on the other.
* the **type-specific domain**: a prepare's signature is never a valid commit signature for the
  same `(chain, view, seq, digest)`, so a replica that only prepared cannot be counted as
  having committed.

This is deliberately *not* the block-signing pre-image (`BlockPart.SIGN`). A pre-prepare signs
only the block digest (Q7): the `Block` travels next to it in a `Proposal`, outside the signature,
and a receiver rejects the pair unless `block.current_hash == pre_prepare.digest`.

Certificates — DEV-10
---------------------
* **prepared** — an accepted pre-prepare plus `2f` prepares matching its `(view, seq, digest)`
  from *distinct, non-primary* members. The primary's pre-prepare is its vote; a prepare from the
  primary would count it twice, so it is not counted.
* **committed** — `commit_threshold` (= `2f+1`) matching commits from distinct members.
* **new-view** — `2f+1` view-changes from distinct members.

"Distinct" means distinct *signed* `replica_id`, never distinct arrivals: counting is always
over a set keyed by the identity that verified the signature.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, ClassVar, Final, TypeVar, cast

from bsfr_sh.blockchain.block import Block
from bsfr_sh.blockchain.transaction import Transaction
from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey, sign, verify
from bsfr_sh.crypto.hashing import h
from bsfr_sh.crypto.merkle import merkle_root
from bsfr_sh.util.serialization import CanonicalEncodingError, Value, decode, encode, encode_struct

__all__ = [
    "VOTE_FIELDS",
    "ClientRequest",
    "Commit",
    "CommitCertificate",
    "Membership",
    "MembershipError",
    "Message",
    "MessageKind",
    "NewView",
    "PrePrepare",
    "Prepare",
    "PreparedCertificate",
    "Proposal",
    "RejectReason",
    "ViewChange",
    "check_request_identity",
    "check_vote_identity",
    "decode_message",
    "encode_message",
    "resign",
    "unwire_block",
    "unwire_transaction",
    "verify_commit_certificate",
    "verify_prepared_certificate",
    "wire_block",
    "wire_transaction",
]


class MembershipError(ValueError):
    """Raised when a membership or quorum configuration is not a valid pBFT configuration."""


class MessageKind(Enum):
    """One signing domain per message type. Versioned, like `crypto.hashing`'s domains."""

    PRE_PREPARE = "bsfr_sh.pbft.pre_prepare.v1"
    PREPARE = "bsfr_sh.pbft.prepare.v1"
    COMMIT = "bsfr_sh.pbft.commit.v1"
    VIEW_CHANGE = "bsfr_sh.pbft.view_change.v1"
    NEW_VIEW = "bsfr_sh.pbft.new_view.v1"
    CLIENT_REQUEST = "bsfr_sh.pbft.client_request.v1"


#: The signed body of every normal-case message, in encoding order.
VOTE_FIELDS: Final = ("chain", "view", "seq", "digest", "replica_id")
_CLIENT_REQUEST_FIELDS: Final = ("chain", "request_id", "timestamp", "submitter_id")
_VIEW_CHANGE_FIELDS: Final = (
    "chain",
    "new_view",
    "last_seq",
    "commit_proof",
    "prepared",
    "replica_id",
)
_NEW_VIEW_FIELDS: Final = ("chain", "view", "view_changes", "proposals", "replica_id")


class RejectReason(Enum):
    """Why a replica refused a message. Recorded on the replica so tests can assert the *reason*."""

    MALFORMED = "malformed"
    WRONG_CHAIN = "wrong_chain"
    NON_MEMBER = "non_member"
    BAD_SIGNATURE = "bad_signature"
    WRONG_VIEW = "wrong_view"
    ALREADY_COMMITTED = "already_committed"
    OUT_OF_WINDOW = "out_of_window"
    NOT_PRIMARY = "not_primary"
    PRIMARY_PREPARE = "primary_prepare"
    DIGEST_MISMATCH = "digest_mismatch"
    CONFLICTING_PRE_PREPARE = "conflicting_pre_prepare"
    CONFLICTING_VOTE = "conflicting_vote"
    DUPLICATE = "duplicate"
    INVALID_BLOCK = "invalid_block"
    BAD_VIEW_CHANGE = "bad_view_change"
    BAD_NEW_VIEW = "bad_new_view"


# --------------------------------------------------------------------------------------------
# Membership
# --------------------------------------------------------------------------------------------
class Membership:
    """The permissioned replica set of one chain, and the quorum sizes it implies.

    This is the property §V-3 leans on for Sybil resistance: a message counts only if its signed
    `replica_id` is in this set and its signature verifies under the key registered here. Minting
    identities buys an attacker nothing; there is no way to join except being configured.

    Leader election is round-robin over the ids in sorted order (`configs/chain.yaml`
    `consensus.leader_election`, DECLARED): `primary(v) = ids[v mod n]`.
    """

    __slots__ = ("_keys", "commit_threshold", "f", "ids")

    def __init__(self, keys: Mapping[str, PublicKey], *, f: int, commit_threshold: int) -> None:
        n = len(keys)
        if f < 0:
            raise MembershipError("f must be non-negative")
        if n < 3 * f + 1:
            raise MembershipError(f"n={n} replicas cannot tolerate f={f}; pBFT needs n >= 3f+1")
        # Below 2f+1, two quorums need not share an honest replica, and two blocks can commit at
        # one height. Above n-f, the f faulty replicas can withhold a quorum forever.
        if not 2 * f + 1 <= commit_threshold <= n - f:
            raise MembershipError(
                f"commit_threshold={commit_threshold} must lie in [2f+1, n-f] = "
                f"[{2 * f + 1}, {n - f}] (DEV-10)"
            )
        self._keys = dict(keys)
        self.ids: tuple[str, ...] = tuple(sorted(keys))
        self.f = f
        self.commit_threshold = commit_threshold

    @property
    def n(self) -> int:
        return len(self.ids)

    @property
    def prepare_quorum(self) -> int:
        """Matching prepares from distinct non-primary replicas needed to be prepared: `2f`."""
        return 2 * self.f

    @property
    def view_change_quorum(self) -> int:
        """View-changes from distinct replicas a new primary needs: `2f+1`."""
        return 2 * self.f + 1

    @property
    def join_quorum(self) -> int:
        """View-changes for higher views that make a replica join without its own timeout: `f+1`.

        `f+1` guarantees at least one of them is honest, so a lone byzantine replica cannot drag
        the cluster into view changes.
        """
        return self.f + 1

    def primary(self, view: int) -> str:
        return self.ids[view % self.n]

    def key(self, replica_id: str) -> PublicKey | None:
        return self._keys.get(replica_id)

    def __contains__(self, replica_id: object) -> bool:
        return replica_id in self._keys

    def __repr__(self) -> str:
        return f"Membership(n={self.n}, f={self.f}, ids={list(self.ids)})"


# --------------------------------------------------------------------------------------------
# Signed messages
# --------------------------------------------------------------------------------------------
S = TypeVar("S", bound="PrePrepare | Prepare | Commit | ViewChange | NewView")


def resign(message: S, key: PrivateKey, **changes: object) -> S:
    """Return `message` with `changes` applied and a fresh signature by `key`.

    The one way to produce a signed message variant. Used by the protocol to sign, and by the
    byzantine test fixtures to forge — a forged message built here is exactly as well-formed as an
    honest one, so what makes it fail is the check that is supposed to catch it.
    """
    unsigned = replace(message, **changes, signature=b"")  # type: ignore[arg-type]
    return replace(unsigned, signature=sign(key, unsigned.signed_body()))


@dataclass(frozen=True)
class _Vote:
    """The shared shape of pre-prepare, prepare and commit: `(chain, view, seq, digest)`."""

    KIND: ClassVar[MessageKind]

    chain: str
    view: int
    seq: int
    digest: bytes
    replica_id: str
    signature: bytes = b""

    def signed_body(self) -> bytes:
        fields: dict[str, Value] = {
            "chain": self.chain,
            "view": self.view,
            "seq": self.seq,
            "digest": self.digest,
            "replica_id": self.replica_id,
        }
        return encode_struct(self.KIND.value, VOTE_FIELDS, fields)

    def verify(self, key: PublicKey) -> bool:
        return verify(key, self.signature, self.signed_body())

    @property
    def slot(self) -> tuple[int, int]:
        return (self.view, self.seq)


@dataclass(frozen=True)
class PrePrepare(_Vote):
    """The primary's proposal of `digest` at `(view, seq)`. Signed over the digest only (Q7)."""

    KIND: ClassVar[MessageKind] = MessageKind.PRE_PREPARE

    @classmethod
    def create(
        cls, *, chain: str, view: int, seq: int, digest: bytes, replica_id: str, key: PrivateKey
    ) -> PrePrepare:
        return resign(cls(chain, view, seq, digest, replica_id), key)


@dataclass(frozen=True)
class Prepare(_Vote):
    KIND: ClassVar[MessageKind] = MessageKind.PREPARE

    @classmethod
    def create(
        cls, *, chain: str, view: int, seq: int, digest: bytes, replica_id: str, key: PrivateKey
    ) -> Prepare:
        return resign(cls(chain, view, seq, digest, replica_id), key)


@dataclass(frozen=True)
class Commit(_Vote):
    KIND: ClassVar[MessageKind] = MessageKind.COMMIT

    @classmethod
    def create(
        cls, *, chain: str, view: int, seq: int, digest: bytes, replica_id: str, key: PrivateKey
    ) -> Commit:
        return resign(cls(chain, view, seq, digest, replica_id), key)


@dataclass(frozen=True)
class Proposal:
    """A signed pre-prepare with the block travelling alongside it, outside the signature (Q7).

    Nothing binds the two except the receiver's check that `block.current_hash` equals the signed
    digest — which is enough, because `current_hash` is derived from the block's contents and
    cannot be set independently of them (`blockchain.block`).
    """

    pre_prepare: PrePrepare
    block: Block

    @property
    def digest_matches(self) -> bool:
        return self.block.current_hash == self.pre_prepare.digest


@dataclass(frozen=True)
class ClientRequest:
    """A batch of transactions some submitter wants in the next block.

    Identified by the Merkle root of its transaction digests, which is exactly the `MTR` of the
    block built from it — so a replica can tell, on commit, which pending request a block answered.

    Signed by the submitting `CS_l` over `(chain, request_id, timestamp, submitter_id)` (DEV-20
    item 5, closed): a replica checks the signer against the cluster's configured submitters the
    same way `check_vote_identity` checks a vote's signer against `membership` — see
    `check_request_identity`. The submitter need not be one of the chain's pBFT replicas (DEV-22
    leaves that unspecified); `Cluster` is constructed with its own, separate submitter set.
    """

    chain: str
    transactions: tuple[Transaction, ...]
    timestamp: float
    submitter_id: str
    signature: bytes = b""

    @property
    def request_id(self) -> bytes:
        return merkle_root([tx.digest for tx in self.transactions])

    def signed_body(self) -> bytes:
        fields: dict[str, Value] = {
            "chain": self.chain,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "submitter_id": self.submitter_id,
        }
        return encode_struct(MessageKind.CLIENT_REQUEST.value, _CLIENT_REQUEST_FIELDS, fields)

    def verify(self, key: PublicKey) -> bool:
        return verify(key, self.signature, self.signed_body())

    @classmethod
    def create(
        cls,
        *,
        chain: str,
        transactions: tuple[Transaction, ...],
        timestamp: float,
        submitter_id: str,
        key: PrivateKey,
    ) -> ClientRequest:
        unsigned = cls(chain, transactions, timestamp, submitter_id)
        return replace(unsigned, signature=sign(key, unsigned.signed_body()))


# --------------------------------------------------------------------------------------------
# Certificates
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class PreparedCertificate:
    """Proof that `(view, seq, digest)` was prepared: a pre-prepare and `2f` matching prepares.

    Carries the block so a new primary can re-propose it after a view change (DEV-20).
    """

    pre_prepare: PrePrepare
    prepares: tuple[Prepare, ...]
    block: Block

    @property
    def view(self) -> int:
        return self.pre_prepare.view

    @property
    def seq(self) -> int:
        return self.pre_prepare.seq

    @property
    def digest(self) -> bytes:
        return self.pre_prepare.digest


@dataclass(frozen=True)
class CommitCertificate:
    """Proof that `(view, seq, digest)` committed: `commit_threshold` matching commits.

    Used as a one-block checkpoint in view-changes: it is what makes a replica's claimed committed
    height checkable rather than taken on trust (DEV-20 item 1).
    """

    commits: tuple[Commit, ...]

    @property
    def view(self) -> int:
        return self.commits[0].view

    @property
    def seq(self) -> int:
        return self.commits[0].seq

    @property
    def digest(self) -> bytes:
        return self.commits[0].digest


def check_vote_identity(vote: _Vote, membership: Membership, chain: str) -> RejectReason | None:
    """Chain, membership, and signature — the checks that say *who* sent a vote.

    Returns `None` if the vote is authentic. Says nothing about whether it is timely or relevant;
    that is the replica's business.
    """
    if vote.chain != chain:
        return RejectReason.WRONG_CHAIN
    key = membership.key(vote.replica_id)
    if key is None:
        return RejectReason.NON_MEMBER
    if not vote.verify(key):
        return RejectReason.BAD_SIGNATURE
    return None


def check_request_identity(
    request: ClientRequest, submitters: Mapping[str, PublicKey], chain: str
) -> RejectReason | None:
    """Chain, submitter authorization, and signature — `check_vote_identity`'s shape, for requests.

    `submitters` is deliberately not a `Membership`: an authorized submitter (a collecting `CS_l`)
    need not be one of the chain's pBFT replicas (DEV-22 leaves that open), so there is no quorum
    to enforce — only who may post a `ClientRequest` at all. Closes DEV-20 item 5 / debt D4: a
    non-member submission is rejected here before it ever occupies a pending slot.
    """
    if request.chain != chain:
        return RejectReason.WRONG_CHAIN
    key = submitters.get(request.submitter_id)
    if key is None:
        return RejectReason.NON_MEMBER
    if not request.verify(key):
        return RejectReason.BAD_SIGNATURE
    return None


def verify_prepared_certificate(
    cert: PreparedCertificate, membership: Membership, chain: str
) -> str | None:
    """Return why `cert` is not a valid prepared certificate, or `None` if it is."""
    pre_prepare = cert.pre_prepare
    if (reason := check_vote_identity(pre_prepare, membership, chain)) is not None:
        return f"pre-prepare: {reason.value}"
    primary = membership.primary(pre_prepare.view)
    if pre_prepare.replica_id != primary:
        return (
            f"pre-prepare is from {pre_prepare.replica_id!r}, not view {pre_prepare.view}'s primary"
        )
    if cert.block.current_hash != pre_prepare.digest:
        return "block does not match the pre-prepare digest"
    senders: set[str] = set()
    for prepare in cert.prepares:
        if (reason := check_vote_identity(prepare, membership, chain)) is not None:
            return f"prepare from {prepare.replica_id!r}: {reason.value}"
        if (prepare.view, prepare.seq, prepare.digest) != (
            pre_prepare.view,
            pre_prepare.seq,
            pre_prepare.digest,
        ):
            return f"prepare from {prepare.replica_id!r} does not match the pre-prepare"
        if prepare.replica_id == primary:
            return "a prepare from the primary does not count toward a prepared certificate"
        senders.add(prepare.replica_id)
    if len(senders) < membership.prepare_quorum:
        return (
            f"{len(senders)} distinct prepares, need {membership.prepare_quorum} (2f); "
            f"{len(cert.prepares)} messages were supplied"
        )
    return None


def verify_commit_certificate(
    cert: CommitCertificate, membership: Membership, chain: str
) -> str | None:
    """Return why `cert` is not a valid commit certificate, or `None` if it is."""
    if not cert.commits:
        return "empty commit certificate"
    first = cert.commits[0]
    senders: set[str] = set()
    for commit in cert.commits:
        if (reason := check_vote_identity(commit, membership, chain)) is not None:
            return f"commit from {commit.replica_id!r}: {reason.value}"
        if (commit.view, commit.seq, commit.digest) != (first.view, first.seq, first.digest):
            return "commits in one certificate disagree"
        senders.add(commit.replica_id)
    if len(senders) < membership.commit_threshold:
        return f"{len(senders)} distinct commits, need {membership.commit_threshold} (2f+1)"
    return None


# --------------------------------------------------------------------------------------------
# View change messages — built and checked in `consensus.view_change`
# --------------------------------------------------------------------------------------------
def _triple(view: int, seq: int, digest: bytes) -> list[Value]:
    return [view, seq, digest]


@dataclass(frozen=True)
class ViewChange:
    """`VIEW-CHANGE` — "I am leaving for `new_view`; here is what I committed and prepared."

    The signature binds the `(view, seq, digest)` summary of every certificate it carries; each
    certificate's own messages carry their own signatures and are verified individually.
    """

    chain: str
    new_view: int
    last_seq: int
    commit_proof: CommitCertificate | None
    prepared: tuple[PreparedCertificate, ...]
    replica_id: str
    signature: bytes = b""

    def signed_body(self) -> bytes:
        proof = self.commit_proof
        fields: dict[str, Value] = {
            "chain": self.chain,
            "new_view": self.new_view,
            "last_seq": self.last_seq,
            "commit_proof": None if proof is None else _triple(proof.view, proof.seq, proof.digest),
            "prepared": [_triple(c.view, c.seq, c.digest) for c in self.prepared],
            "replica_id": self.replica_id,
        }
        return encode_struct(MessageKind.VIEW_CHANGE.value, _VIEW_CHANGE_FIELDS, fields)

    def verify(self, key: PublicKey) -> bool:
        return verify(key, self.signature, self.signed_body())


@dataclass(frozen=True)
class NewView:
    """`NEW-VIEW` — the new primary's justification: `2f+1` view-changes and what they force.

    Signed over the digest of each carried view-change's signed body and the `(view, seq, digest)`
    of each re-proposal. Receivers do not trust the re-proposals; they recompute them from the
    carried view-changes and reject a mismatch (`consensus.view_change.verify_new_view`).
    """

    chain: str
    view: int
    view_changes: tuple[ViewChange, ...]
    proposals: tuple[Proposal, ...]
    replica_id: str
    signature: bytes = b""

    def signed_body(self) -> bytes:
        fields: dict[str, Value] = {
            "chain": self.chain,
            "view": self.view,
            "view_changes": [h(vc.signed_body()) for vc in self.view_changes],
            "proposals": [
                _triple(p.pre_prepare.view, p.pre_prepare.seq, p.pre_prepare.digest)
                for p in self.proposals
            ],
            "replica_id": self.replica_id,
        }
        return encode_struct(MessageKind.NEW_VIEW.value, _NEW_VIEW_FIELDS, fields)

    def verify(self, key: PublicKey) -> bool:
        return verify(key, self.signature, self.signed_body())


#: Everything a replica can receive.
Message = ClientRequest | Proposal | Prepare | Commit | ViewChange | NewView


# --------------------------------------------------------------------------------------------
# Wire encoding — D3, `consensus.network.P2PCSNetwork`'s optional serialize mode
# --------------------------------------------------------------------------------------------
# Plain mappings and lists via `util.serialization.encode`/`decode`, not a declared `Struct`
# domain: nothing here is ever hashed or signed (that stays `signed_body()`'s job, above), so a
# bespoke field-order-and-domain declaration for six message shapes would buy nothing over field
# lookup by name. This exists only so the bus's serialize mode can pay a real, measured
# encode-then-decode cost per hop instead of an estimate (DEV-30's magnitude, quantified further).
#
# Every `_unwire_*` trusts the shape `_wire_*` produced and reads it with `cast` rather than
# reconstructing it generically: the fields on each side are typed exactly (`Transaction`,
# `Block`, ...), and a generic `Mapping[Any, Value]` has no way to state that without losing the
# static types `mypy --strict` checks everywhere else in this module. `decode()` raising on
# malformed bytes is still what actually protects this at runtime.
def wire_transaction(tx: Transaction) -> dict[str, Value]:
    return dict(tx.to_fields())


def _map(value: Value, what: str) -> Mapping[Any, Value]:
    if not isinstance(value, Mapping):
        raise CanonicalEncodingError(f"{what} envelope must be a mapping")
    return value


def _list(value: Value, what: str) -> list[Value]:
    if not isinstance(value, list):
        raise CanonicalEncodingError(f"{what} envelope must be a list")
    return value


def unwire_transaction(value: Value) -> Transaction:
    v = _map(value, "transaction")
    return Transaction(
        tx_id=cast(str, v["tx_id"]),
        payload_type=cast(str, v["payload_type"]),
        ciphertext=cast(bytes, v["ciphertext"]),
        wrapped_key=cast(bytes, v["wrapped_key"]),
        nonce=cast(bytes, v["nonce"]),
        digest=cast(bytes, v["digest"]),
        created_at=cast(int, v["created_at"]),
    )


def wire_block(block: Block) -> dict[str, Value]:
    return {
        "owner_id": block.owner_id,
        "owner_pubkey": block.owner_pubkey,
        "transactions": [wire_transaction(t) for t in block.transactions],
        "prev_hash": block.prev_hash,
        "timestamp": block.timestamp,
        "version": block.version,
        "nonce": block.nonce,
        "signature": block.signature,
    }


def unwire_block(value: Value) -> Block:
    v = _map(value, "block")
    txs = _list(v["transactions"], "block.transactions")
    return Block(
        owner_id=cast(str, v["owner_id"]),
        owner_pubkey=cast(bytes, v["owner_pubkey"]),
        transactions=tuple(unwire_transaction(t) for t in txs),
        prev_hash=cast(bytes, v["prev_hash"]),
        timestamp=cast(float, v["timestamp"]),
        version=cast(int, v["version"]),
        nonce=cast(bytes, v["nonce"]),
        signature=cast(bytes, v["signature"]),
    )


def _wire_client_request(request: ClientRequest) -> dict[str, Value]:
    return {
        "chain": request.chain,
        "transactions": [wire_transaction(t) for t in request.transactions],
        "timestamp": request.timestamp,
        "submitter_id": request.submitter_id,
        "signature": request.signature,
    }


def _unwire_client_request(value: Value) -> ClientRequest:
    v = _map(value, "client-request")
    txs = _list(v["transactions"], "client-request.transactions")
    return ClientRequest(
        chain=cast(str, v["chain"]),
        transactions=tuple(unwire_transaction(t) for t in txs),
        timestamp=cast(float, v["timestamp"]),
        submitter_id=cast(str, v["submitter_id"]),
        signature=cast(bytes, v["signature"]),
    )


def _wire_vote(vote: PrePrepare | Prepare | Commit) -> dict[str, Value]:
    return {
        "chain": vote.chain,
        "view": vote.view,
        "seq": vote.seq,
        "digest": vote.digest,
        "replica_id": vote.replica_id,
        "signature": vote.signature,
    }


def _unwire_pre_prepare(value: Value) -> PrePrepare:
    v = _map(value, "pre-prepare")
    return PrePrepare(
        chain=cast(str, v["chain"]),
        view=cast(int, v["view"]),
        seq=cast(int, v["seq"]),
        digest=cast(bytes, v["digest"]),
        replica_id=cast(str, v["replica_id"]),
        signature=cast(bytes, v["signature"]),
    )


def _unwire_prepare(value: Value) -> Prepare:
    v = _map(value, "prepare")
    return Prepare(
        chain=cast(str, v["chain"]),
        view=cast(int, v["view"]),
        seq=cast(int, v["seq"]),
        digest=cast(bytes, v["digest"]),
        replica_id=cast(str, v["replica_id"]),
        signature=cast(bytes, v["signature"]),
    )


def _unwire_commit(value: Value) -> Commit:
    v = _map(value, "commit")
    return Commit(
        chain=cast(str, v["chain"]),
        view=cast(int, v["view"]),
        seq=cast(int, v["seq"]),
        digest=cast(bytes, v["digest"]),
        replica_id=cast(str, v["replica_id"]),
        signature=cast(bytes, v["signature"]),
    )


def _wire_proposal(proposal: Proposal) -> dict[str, Value]:
    return {
        "pre_prepare": _wire_vote(proposal.pre_prepare),
        "block": wire_block(proposal.block),
    }


def _unwire_proposal(value: Value) -> Proposal:
    v = _map(value, "proposal")
    return Proposal(_unwire_pre_prepare(v["pre_prepare"]), unwire_block(v["block"]))


def _wire_view_change(vc: ViewChange) -> dict[str, Value]:
    return {
        "chain": vc.chain,
        "new_view": vc.new_view,
        "last_seq": vc.last_seq,
        "commit_proof": None
        if vc.commit_proof is None
        else _wire_commit_certificate(vc.commit_proof),
        "prepared": [_wire_prepared_certificate(p) for p in vc.prepared],
        "replica_id": vc.replica_id,
        "signature": vc.signature,
    }


def _unwire_view_change(value: Value) -> ViewChange:
    v = _map(value, "view-change")
    proof = v["commit_proof"]
    prepared = _list(v["prepared"], "view-change.prepared")
    return ViewChange(
        chain=cast(str, v["chain"]),
        new_view=cast(int, v["new_view"]),
        last_seq=cast(int, v["last_seq"]),
        commit_proof=None if proof is None else _unwire_commit_certificate(proof),
        prepared=tuple(_unwire_prepared_certificate(p) for p in prepared),
        replica_id=cast(str, v["replica_id"]),
        signature=cast(bytes, v["signature"]),
    )


def _wire_prepared_certificate(cert: PreparedCertificate) -> dict[str, Value]:
    return {
        "pre_prepare": _wire_vote(cert.pre_prepare),
        "prepares": [_wire_vote(p) for p in cert.prepares],
        "block": wire_block(cert.block),
    }


def _unwire_prepared_certificate(value: Value) -> PreparedCertificate:
    v = _map(value, "prepared-certificate")
    prepares = _list(v["prepares"], "prepared-certificate.prepares")
    return PreparedCertificate(
        pre_prepare=_unwire_pre_prepare(v["pre_prepare"]),
        prepares=tuple(_unwire_prepare(p) for p in prepares),
        block=unwire_block(v["block"]),
    )


def _wire_commit_certificate(cert: CommitCertificate) -> list[Value]:
    return [_wire_vote(commit) for commit in cert.commits]


def _unwire_commit_certificate(value: Value) -> CommitCertificate:
    items = _list(value, "commit-certificate")
    return CommitCertificate(tuple(_unwire_commit(v) for v in items))


def _wire_new_view(nv: NewView) -> dict[str, Value]:
    return {
        "chain": nv.chain,
        "view": nv.view,
        "view_changes": [_wire_view_change(vc) for vc in nv.view_changes],
        "proposals": [_wire_proposal(p) for p in nv.proposals],
        "replica_id": nv.replica_id,
        "signature": nv.signature,
    }


def _unwire_new_view(value: Value) -> NewView:
    v = _map(value, "new-view")
    view_changes = _list(v["view_changes"], "new-view.view_changes")
    proposals = _list(v["proposals"], "new-view.proposals")
    return NewView(
        chain=cast(str, v["chain"]),
        view=cast(int, v["view"]),
        view_changes=tuple(_unwire_view_change(vc) for vc in view_changes),
        proposals=tuple(_unwire_proposal(p) for p in proposals),
        replica_id=cast(str, v["replica_id"]),
        signature=cast(bytes, v["signature"]),
    )


def encode_message(message: Message) -> bytes:
    """Serialize one bus message. Used only by `P2PCSNetwork`'s `serialize=` hook (D3)."""
    if isinstance(message, ClientRequest):
        return encode(["client_request", _wire_client_request(message)])
    if isinstance(message, Prepare):
        return encode(["prepare", _wire_vote(message)])
    if isinstance(message, Commit):
        return encode(["commit", _wire_vote(message)])
    if isinstance(message, Proposal):
        return encode(["proposal", _wire_proposal(message)])
    if isinstance(message, ViewChange):
        return encode(["view_change", _wire_view_change(message)])
    if isinstance(message, NewView):
        return encode(["new_view", _wire_new_view(message)])
    raise CanonicalEncodingError(f"no wire encoding for {type(message).__name__}")


def decode_message(data: bytes) -> Message:
    """Inverse of `encode_message`. Reconstructs a fresh, independently-validated object."""
    envelope = decode(data)
    if not (isinstance(envelope, list) and len(envelope) == 2):
        raise CanonicalEncodingError("malformed message envelope")
    kind, body = envelope
    if kind == "client_request":
        return _unwire_client_request(body)
    if kind == "prepare":
        return _unwire_prepare(body)
    if kind == "commit":
        return _unwire_commit(body)
    if kind == "proposal":
        return _unwire_proposal(body)
    if kind == "view_change":
        return _unwire_view_change(body)
    if kind == "new_view":
        return _unwire_new_view(body)
    raise CanonicalEncodingError(f"unknown message kind {kind!r}")
