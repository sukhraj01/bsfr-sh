"""pBFT over one chain's replica set — pre-prepare, prepare, commit (Castro & Liskov, ref [24]).

Implements the "miners run pBFT, a threshold commits, append" step of Alg. 1 (`BC_DTBU`) and
Alg. 2 (`BC_SigRW`); see docs/ALGORITHMS.md. The paper names the protocol and gives nothing else;
the threshold and view change are DEV-10, the message format DEV-19, the view-change reduction
DEV-20, and the bus's latency model DEV-21.

Division of labour
------------------
Consensus decides **whether** a block is appended; `Chain` decides **whether it is valid**. A
replica never re-implements a block check. Before it prepares a block it asks its own chain —
`Chain.check_append()`, the same code `append()` runs — and on commit it calls `append()`, which
checks everything again. A replica that prepared a block its chain would refuse would let a
quorum commit something no one can append.

Normal case, one height at a time
---------------------------------
1. A `ClientRequest` (a batch of transactions) reaches every replica.
2. The primary of the current view builds the block on its chain head, signs it (it becomes
   `OID`/`OKU`), and broadcasts a `Proposal`: a signed `PrePrepare(chain, view, seq, digest)` with
   the block alongside (Q7).
3. A backup accepts the proposal if: the pre-prepare is authentic and from the view's primary,
   `block.current_hash == digest`, it has accepted no *different* pre-prepare at this
   `(view, seq)`, the block's owner is a member, and its chain would append the block. It then
   broadcasts a signed `Prepare`.
4. **Prepared** = accepted proposal + `2f` matching prepares from distinct non-primary replicas.
   A prepared replica broadcasts a signed `Commit`.
5. **Committed** = prepared + `commit_threshold` (`2f+1`) matching commits from distinct replicas.
   The replica appends the block; the matching commits become its proof of height.

`seq` is the chain height the block will occupy. At most one height is in flight: a primary
proposes `h+1` only after committing `h` (DEV-20 item 3). Messages for heights up to
`h + log_window` and views up to `view + log_window` are kept so reordering cannot lose them, and
are processed when the replica gets there.

What a replica rejects, and records as a `Rejection` with its reason
--------------------------------------------------------------------
* messages for another chain, or signed by a non-member — §V-3's permissioned property;
* messages that do not verify — which, because `(chain, view, seq, digest)` are all in the
  signed body, includes any message moved to a different view, height, block, or chain;
* messages for a height already committed, or for a view it has left;
* a second, different pre-prepare at one `(view, seq)` — the equivocation check;
* prepares and commits whose digest does not match the block it holds for that slot (votes
  that arrive *before* the proposal are held, and discarded if they turn out not to match);
* a second vote from one sender at one slot — **certificates count distinct signed senders**.

Byzantine behaviour
-------------------
Every outgoing message passes through `Replica.behaviour.outgoing()`. The default forwards it
unchanged. The test fixtures (silent, equivocating, wrong-signature, stale-view) replace it on a
running replica. The protocol code does not know they exist.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Protocol

from bsfr_sh.blockchain.block import Block
from bsfr_sh.blockchain.chain import Chain, ChainError, ChainPolicy
from bsfr_sh.blockchain.transaction import Transaction
from bsfr_sh.consensus.network import P2PCSNetwork, Timer
from bsfr_sh.consensus.protocol import (
    ClientRequest,
    Commit,
    CommitCertificate,
    Membership,
    Message,
    NewView,
    Prepare,
    PreparedCertificate,
    PrePrepare,
    Proposal,
    RejectReason,
    ViewChange,
    check_request_identity,
    decode_message,
    encode_message,
)
from bsfr_sh.consensus.view_change import (
    ViewChangeLog,
    build_new_view,
    build_view_change,
    verify_new_view,
    verify_view_change,
)
from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey
from bsfr_sh.util.config import Config
from bsfr_sh.util.logging import event, get_logger

__all__ = [
    "CLIENT_ID",
    "HONEST",
    "Behaviour",
    "Cluster",
    "ConsensusError",
    "Honest",
    "PBFTPolicy",
    "Rejection",
    "Replica",
]

_LOG: Final = get_logger("consensus.pbft")

#: Transport name requests are sent under. Not a member, and never needs to be.
CLIENT_ID: Final = "client"


def _roundtrip_message(payload: object) -> object:
    """The `P2PCSNetwork(serialize=...)` hook for `serialize_messages=True` (D3, closed).

    `consensus.network` must not know what a pBFT message is (`test_module_boundaries.py`), so it
    takes an opaque `object -> object` hook instead of importing `consensus.protocol` itself; this
    is that hook, built where the message types are already in scope.
    """
    return decode_message(encode_message(payload))  # type: ignore[arg-type]


class ConsensusError(RuntimeError):
    """Raised when the protocol reaches a state its own invariants say is impossible."""


# --------------------------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class PBFTPolicy:
    """Consensus tunables, from `configs/chain.yaml` `consensus.*`. Defaults mirror that file."""

    replicas: int = 4
    f: int = 1
    commit_threshold: int = 3
    view_change_timeout_s: float = 2.0
    message_delay_s: float = 0.0
    log_window: int = 4
    serialize_messages: bool = False

    def __post_init__(self) -> None:
        if self.view_change_timeout_s <= 0:
            raise ValueError("view_change_timeout_s must be positive")
        if self.message_delay_s < 0:
            raise ValueError("message_delay_s must be non-negative")
        if self.log_window < 1:
            raise ValueError("log_window must be at least 1")

    @classmethod
    def from_config(cls, config: Config) -> PBFTPolicy:
        """Build from a loaded `chain` config.

        The PAPER/DERIVED keys are required by `util.config`'s schema. `message_delay_s` and
        `log_window` are DECLARED in M2b and read with the documented defaults, as
        `SessionPolicy` does, so a config written before they existed still loads.
        """
        return cls(
            replicas=config.require("consensus.miner_nodes", int),
            f=config.require("consensus.faulty_nodes_f", int),
            commit_threshold=config.require("consensus.commit_threshold", int),
            view_change_timeout_s=float(config.get("consensus.view_change_timeout_s")),
            message_delay_s=float(config.get("consensus.message_delay_s", 0.0)),
            log_window=int(config.get("consensus.log_window", 4)),
            serialize_messages=bool(config.get("consensus.serialize_messages", False)),
        )


# --------------------------------------------------------------------------------------------
# Behaviour hook
# --------------------------------------------------------------------------------------------
class Behaviour(Protocol):
    """What a replica actually puts on the wire, given what the protocol asked it to send."""

    def outgoing(self, replica: Replica, recipient: str, message: Message) -> Sequence[Message]: ...


class Honest:
    """Send exactly what the protocol produced."""

    def outgoing(
        self,
        replica: Replica,  # noqa: ARG002 — part of the Behaviour signature
        recipient: str,  # noqa: ARG002
        message: Message,
    ) -> Sequence[Message]:
        return (message,)


HONEST: Final = Honest()


@dataclass(frozen=True)
class Rejection:
    """A message a replica refused, and why."""

    reason: RejectReason
    message_type: str
    sender: str
    detail: str = ""


@dataclass
class _Slot:
    """Everything a replica knows about one `(view, seq)`."""

    proposal: Proposal | None = None
    prepares: dict[str, Prepare] = field(default_factory=dict)
    commits: dict[str, Commit] = field(default_factory=dict)
    prepared: bool = False
    executed: bool = False


# --------------------------------------------------------------------------------------------
# Replica
# --------------------------------------------------------------------------------------------
class Replica:
    """One pBFT miner node — a `CS_l` in the P2PCS network of one chain.

    Implements Alg. 1, lines 4-10 and Alg. 2, lines 8-15: the leader `L` (the view's primary)
    assembles and broadcasts `β_j` (DEV-22), the replicas run pBFT, and at the `2f+1` threshold
    each appends; "else re-run consensus" is the view change (`consensus.view_change`).

    Holds its own `Chain` instance. Replicas of one chain share a genesis `Block` (frozen) and a
    bus; they share no mutable state with each other or with the other chain's replicas.
    """

    def __init__(
        self,
        *,
        replica_id: str,
        private_key: PrivateKey,
        membership: Membership,
        chain: Chain,
        network: P2PCSNetwork,
        policy: PBFTPolicy,
        submitters: Mapping[str, PublicKey],
        behaviour: Behaviour | None = None,
    ) -> None:
        if replica_id not in membership:
            raise ConsensusError(f"{replica_id!r} is not in the membership {membership.ids}")
        if membership.key(replica_id) != private_key.public_key:
            raise ConsensusError(f"{replica_id!r}: private key does not match the membership key")
        if len(chain) != 1:
            raise ConsensusError("a replica starts from a chain holding exactly its genesis block")
        self.replica_id = replica_id
        self._private_key = private_key
        self._public_bytes = private_key.public_key.to_bytes()
        self.membership = membership
        self.chain = chain
        self.network = network
        self.policy = policy
        self.submitters = submitters
        self.behaviour: Behaviour = behaviour if behaviour is not None else HONEST

        self.view = 0
        self._active = True  # False between starting a view change and installing the new view
        self._slots: dict[tuple[int, int], _Slot] = {}
        self._deferred: dict[tuple[int, int], Proposal] = {}
        self._pending: dict[bytes, ClientRequest] = {}
        self._committed_requests: set[bytes] = set()
        self._prepared_certs: dict[int, PreparedCertificate] = {}
        self._commit_proof: CommitCertificate | None = None
        self._vc_log = ViewChangeLog()
        self._vc_attempts = 0
        self._progress_timer: Timer | None = None
        self._vc_timer: Timer | None = None
        self.rejections: list[Rejection] = []
        #: ECDSA sign+verify calls on *consensus* messages (pre-prepare/prepare/commit/
        #: view-change/new-view) — DEV-32's M7-4 comparison against Raft, which signs none of
        #: its own. Excludes block signing/verification (`blockchain`'s concern, paid by both
        #: protocols alike) and `ClientRequest` (paid by both, since Raft still authenticates
        #: submitters the same way — DEV-20 item 5). View-change/new-view verification is not
        #: instrumented granularly (`consensus.view_change`'s helpers call `.verify()` internally
        #: without a hook back into this counter); the benchmark's happy-path runs never trigger
        #: a view change, so this only undercounts a code path the comparison does not measure.
        self.signature_ops = 0

        network.register(replica_id, self.receive)

    # -- read-only views -------------------------------------------------------------------------
    @property
    def height(self) -> int:
        return self.chain.height

    @property
    def active(self) -> bool:
        """Whether the replica is in a view (True) or between views (False)."""
        return self._active

    @property
    def is_primary(self) -> bool:
        return self.membership.primary(self.view) == self.replica_id

    @property
    def pending_requests(self) -> int:
        return len(self._pending)

    def is_prepared(self, view: int, seq: int, digest: bytes) -> bool:
        slot = self._slots.get((view, seq))
        if slot is not None and slot.prepared and slot.proposal is not None:
            return slot.proposal.pre_prepare.digest == digest
        cert = self._prepared_certs.get(seq)
        return cert is not None and cert.view == view and cert.digest == digest

    def prepare_voters(self, view: int, seq: int, digest: bytes) -> frozenset[str]:
        """Distinct senders whose prepare for `(view, seq, digest)` this replica holds."""
        slot = self._slots.get((view, seq))
        if slot is None:
            return frozenset()
        return frozenset(s for s, p in slot.prepares.items() if p.digest == digest)

    def proposal_at(self, view: int, seq: int) -> Proposal | None:
        slot = self._slots.get((view, seq))
        return None if slot is None else slot.proposal

    def rejected(self, reason: RejectReason) -> list[Rejection]:
        return [r for r in self.rejections if r.reason is reason]

    # -- inbound ---------------------------------------------------------------------------------
    def receive(self, sender: str, message: object) -> None:
        """Bus handler. `sender` is transport-level and is never used to authenticate."""
        if isinstance(message, ClientRequest):
            self._on_request(message)
        elif isinstance(message, Proposal):
            self._on_proposal(message)
        elif isinstance(message, Prepare):
            self._on_prepare(message)
        elif isinstance(message, Commit):
            self._on_commit(message)
        elif isinstance(message, ViewChange):
            self._on_view_change(message)
        elif isinstance(message, NewView):
            self._on_new_view(message)
        else:
            detail = "a pre-prepare travels only inside a Proposal, with its block"
            self._reject(
                RejectReason.MALFORMED,
                type(message).__name__,
                sender,
                detail if isinstance(message, PrePrepare) else "",
            )

    def _on_request(self, request: ClientRequest) -> None:
        reason = check_request_identity(request, self.submitters, self.chain.name)
        if reason is not None:
            self._reject(reason, "client-request", request.submitter_id, f"chain={request.chain}")
            return
        request_id = request.request_id
        if request_id in self._committed_requests or request_id in self._pending:
            return
        self._pending[request_id] = request
        self._arm_progress_timer()
        self._maybe_propose()

    def _screen(self, vote: PrePrepare | Prepare | Commit, kind: str) -> bool:
        """The checks every normal-case message passes before it is stored. Cheap ones first."""
        reason: RejectReason | None = None
        key = self.membership.key(vote.replica_id)
        if vote.chain != self.chain.name:
            reason = RejectReason.WRONG_CHAIN
        elif key is None:
            reason = RejectReason.NON_MEMBER
        elif vote.seq <= self.height:
            reason = RejectReason.ALREADY_COMMITTED
        elif vote.seq > self.height + self.policy.log_window:
            reason = RejectReason.OUT_OF_WINDOW
        elif vote.view < self.view or vote.view > self.view + self.policy.log_window:
            reason = RejectReason.WRONG_VIEW
        else:
            self.signature_ops += 1
            if not vote.verify(key):
                reason = RejectReason.BAD_SIGNATURE
        if reason is not None:
            self._reject(reason, kind, vote.replica_id, f"view={vote.view} seq={vote.seq}")
            return False
        return True

    def _on_proposal(self, proposal: Proposal) -> None:
        pre_prepare = proposal.pre_prepare
        if not self._screen(pre_prepare, "pre-prepare"):
            return
        if pre_prepare.replica_id != self.membership.primary(pre_prepare.view):
            self._reject(RejectReason.NOT_PRIMARY, "pre-prepare", pre_prepare.replica_id)
            return
        if not proposal.digest_matches:
            self._reject(
                RejectReason.DIGEST_MISMATCH,
                "pre-prepare",
                pre_prepare.replica_id,
                "block.current_hash != signed digest",
            )
            return
        if not self._ready_for(pre_prepare.view, pre_prepare.seq):
            held = self._deferred.setdefault(pre_prepare.slot, proposal)
            if held.pre_prepare.digest != pre_prepare.digest:
                self._reject(
                    RejectReason.CONFLICTING_PRE_PREPARE, "pre-prepare", pre_prepare.replica_id
                )
            return
        self._accept_proposal(proposal)

    def _ready_for(self, view: int, seq: int) -> bool:
        return self._active and view == self.view and seq == self.height + 1

    def _accept_proposal(self, proposal: Proposal, *, validated: bool = False) -> None:
        """Step 3 of the module docstring. The proposal is authentic and for `(view, h+1)`."""
        pre_prepare = proposal.pre_prepare
        slot = self._slot(pre_prepare.slot)
        if slot.proposal is not None:
            same = slot.proposal.pre_prepare.digest == pre_prepare.digest
            reason = RejectReason.DUPLICATE if same else RejectReason.CONFLICTING_PRE_PREPARE
            self._reject(reason, "pre-prepare", pre_prepare.replica_id)
            return
        if not validated:
            block = proposal.block
            owner_key = self.membership.key(block.owner_id)
            if owner_key is None or owner_key.to_bytes() != block.owner_pubkey:
                self._reject(
                    RejectReason.INVALID_BLOCK,
                    "pre-prepare",
                    pre_prepare.replica_id,
                    f"block owner {block.owner_id!r} is not a member under that key",
                )
                return
            try:
                self.chain.check_append(block)
            except ChainError as exc:
                self._reject(
                    RejectReason.INVALID_BLOCK, "pre-prepare", pre_prepare.replica_id, str(exc)
                )
                return
        slot.proposal = proposal
        # Votes that arrived before the proposal were held; the ones for another block go now.
        for store in (slot.prepares, slot.commits):
            for sender in [s for s, v in store.items() if v.digest != pre_prepare.digest]:
                del store[sender]
                self._reject(RejectReason.DIGEST_MISMATCH, "vote", sender, "held vote, other block")
        if pre_prepare.replica_id != self.replica_id:
            prepare = Prepare.create(
                chain=self.chain.name,
                view=pre_prepare.view,
                seq=pre_prepare.seq,
                digest=pre_prepare.digest,
                replica_id=self.replica_id,
                key=self._private_key,
            )
            self.signature_ops += 1
            slot.prepares[self.replica_id] = prepare
            self._broadcast(prepare)
        self._check_prepared(slot)

    def _on_prepare(self, prepare: Prepare) -> None:
        if not self._screen(prepare, "prepare"):
            return
        if prepare.replica_id == self.membership.primary(prepare.view):
            self._reject(RejectReason.PRIMARY_PREPARE, "prepare", prepare.replica_id)
            return
        slot = self._slot(prepare.slot)
        if self._store_vote(prepare, slot.prepares, slot, "prepare"):
            self._check_prepared(slot)

    def _on_commit(self, commit: Commit) -> None:
        if not self._screen(commit, "commit"):
            return
        slot = self._slot(commit.slot)
        if self._store_vote(commit, slot.commits, slot, "commit"):
            self._check_committed(slot)

    def _store_vote(
        self,
        vote: Prepare | Commit,
        store: dict[str, Prepare] | dict[str, Commit],
        slot: _Slot,
        kind: str,
    ) -> bool:
        """Keep at most one vote per signed sender per slot. Returns whether it was stored."""
        if slot.proposal is not None and slot.proposal.pre_prepare.digest != vote.digest:
            self._reject(RejectReason.DIGEST_MISMATCH, kind, vote.replica_id, "not the held block")
            return False
        existing = store.get(vote.replica_id)
        if existing is not None:
            same = existing.digest == vote.digest
            reason = RejectReason.DUPLICATE if same else RejectReason.CONFLICTING_VOTE
            self._reject(reason, kind, vote.replica_id)
            return False
        store[vote.replica_id] = vote  # type: ignore[assignment]
        return True

    # -- certificates ------------------------------------------------------------------------------
    def _check_prepared(self, slot: _Slot) -> None:
        """Step 4: accepted proposal + `2f` matching prepares from distinct non-primary replicas."""
        if slot.prepared or slot.proposal is None:
            return
        pre_prepare = slot.proposal.pre_prepare
        if not self._ready_for(pre_prepare.view, pre_prepare.seq):
            return
        votes = tuple(
            slot.prepares[s]
            for s in sorted(slot.prepares)
            if s != pre_prepare.replica_id and slot.prepares[s].digest == pre_prepare.digest
        )
        if len(votes) < self.membership.prepare_quorum:
            return
        slot.prepared = True
        held = self._prepared_certs.get(pre_prepare.seq)
        if held is None or held.view < pre_prepare.view:
            self._prepared_certs[pre_prepare.seq] = PreparedCertificate(
                pre_prepare, votes, slot.proposal.block
            )
        commit = Commit.create(
            chain=self.chain.name,
            view=pre_prepare.view,
            seq=pre_prepare.seq,
            digest=pre_prepare.digest,
            replica_id=self.replica_id,
            key=self._private_key,
        )
        self.signature_ops += 1
        slot.commits.setdefault(self.replica_id, commit)
        self._broadcast(commit)
        self._check_committed(slot)

    def _check_committed(self, slot: _Slot) -> None:
        """Step 5: prepared + `commit_threshold` matching commits from distinct replicas.

        Implements Alg. 1, lines 6-8 — threshold commit, then append to the chain.
        """
        if not slot.prepared or slot.executed or slot.proposal is None:
            return
        digest = slot.proposal.pre_prepare.digest
        votes = tuple(
            slot.commits[s] for s in sorted(slot.commits) if slot.commits[s].digest == digest
        )
        if len(votes) < self.membership.commit_threshold:
            return
        self._execute(slot, CommitCertificate(votes))

    def _execute(self, slot: _Slot, proof: CommitCertificate) -> None:
        assert slot.proposal is not None
        block = slot.proposal.block
        try:
            self.chain.append(block)
        except ChainError as exc:
            # The block passed check_append() at this same head when it was accepted. Failing now
            # means the chain changed under the protocol — a bug, not an input to handle.
            raise ConsensusError(
                f"{self.replica_id}: committed block failed append: {exc}"
            ) from exc
        slot.executed = True
        self._commit_proof = proof
        self._vc_attempts = 0
        request_id = block.merkle_root
        self._pending.pop(request_id, None)
        self._committed_requests.add(request_id)
        height = self.height
        self._slots = {k: s for k, s in self._slots.items() if k[1] > height}
        self._prepared_certs = {q: c for q, c in self._prepared_certs.items() if q > height}
        event(
            _LOG,
            "pbft_commit",
            level=logging.DEBUG,
            chain=self.chain.name,
            replica=self.replica_id,
            height=height,
            view=self.view,
            digest=block.current_hash[:8].hex(),
            sim_time=self.network.now,
        )
        self._restart_progress_timer()
        self._drain_deferred()
        self._maybe_propose()

    def _drain_deferred(self) -> None:
        height = self.height
        self._deferred = {
            k: p for k, p in self._deferred.items() if k[1] > height and k[0] >= self.view
        }
        if not self._active:
            return
        proposal = self._deferred.pop((self.view, height + 1), None)
        if proposal is not None:
            self._accept_proposal(proposal)
        else:
            # Votes may have completed a slot whose proposal was accepted earlier in this view.
            slot = self._slots.get((self.view, height + 1))
            if slot is not None:
                self._check_prepared(slot)

    # -- proposing -------------------------------------------------------------------------------
    def _maybe_propose(self) -> None:
        """Step 2: the primary proposes the oldest pending request at `h+1`, if nothing is there.

        Implements Alg. 1, lines 3-5 as amended by DEV-22 — the leader assembles `β_j`.
        """
        if not self._active or not self.is_primary:
            return
        seq = self.height + 1
        slot = self._slots.get((self.view, seq))
        if slot is not None and slot.proposal is not None:
            return
        for request_id, request in list(self._pending.items()):
            block = self.chain.draft_next(
                owner_id=self.replica_id,
                owner_pubkey=self._public_bytes,
                transactions=request.transactions,
                timestamp=request.timestamp,
            ).seal(self._private_key)
            try:
                self.chain.check_append(block)
            except ChainError as exc:
                # A request no block can be built from would otherwise be re-proposed forever.
                self._pending.pop(request_id)
                event(_LOG, "pbft_request_dropped", replica=self.replica_id, reason=str(exc))
                continue
            pre_prepare = PrePrepare.create(
                chain=self.chain.name,
                view=self.view,
                seq=seq,
                digest=block.current_hash,
                replica_id=self.replica_id,
                key=self._private_key,
            )
            self.signature_ops += 1
            proposal = Proposal(pre_prepare, block)
            self._accept_proposal(proposal, validated=True)
            self._broadcast(proposal)
            return

    # -- timers ----------------------------------------------------------------------------------
    def _arm_progress_timer(self) -> None:
        if self._progress_timer is not None and self._progress_timer.active:
            return
        if not self._pending or not self._active:
            return
        self._progress_timer = self.network.schedule(
            self.policy.view_change_timeout_s, self._on_progress_timeout
        )

    def _restart_progress_timer(self) -> None:
        if self._progress_timer is not None:
            self._progress_timer.cancel()
            self._progress_timer = None
        self._arm_progress_timer()

    def _on_progress_timeout(self) -> None:
        self._progress_timer = None
        self._start_view_change(self.view + 1)

    def _on_view_change_timeout(self) -> None:
        self._vc_timer = None
        self._start_view_change(self.view + 1)

    # -- view change -----------------------------------------------------------------------------
    def _start_view_change(self, target: int) -> None:
        """Leave the current view for `target`. See `consensus.view_change`, step 1."""
        if target <= self.view:
            return  # already in, or already heading to, this view or a later one
        self.view = target
        self._active = False
        if self._progress_timer is not None:
            self._progress_timer.cancel()
            self._progress_timer = None
        vc = build_view_change(
            chain=self.chain.name,
            new_view=target,
            last_seq=self.height,
            commit_proof=self._commit_proof,
            prepared=tuple(self._prepared_certs.values()),
            replica_id=self.replica_id,
            key=self._private_key,
        )
        self._vc_log.record(vc)
        self._vc_attempts += 1
        if self._vc_timer is not None:
            self._vc_timer.cancel()
        # Step 5: wait T for the new view, then 2T for the next, then 4T.
        wait = self.policy.view_change_timeout_s * 2 ** (self._vc_attempts - 1)
        self._vc_timer = self.network.schedule(wait, self._on_view_change_timeout)
        event(
            _LOG,
            "pbft_view_change",
            chain=self.chain.name,
            replica=self.replica_id,
            new_view=target,
            height=self.height,
            carried=len(vc.prepared),
            sim_time=self.network.now,
        )
        self._broadcast(vc)
        self._maybe_send_new_view()

    def _on_view_change(self, vc: ViewChange) -> None:
        if (reason := verify_view_change(vc, self.membership, self.chain.name)) is not None:
            self._reject(RejectReason.BAD_VIEW_CHANGE, "view-change", vc.replica_id, reason)
            return
        if vc.new_view < self.view or (vc.new_view == self.view and self._active):
            self._reject(
                RejectReason.WRONG_VIEW, "view-change", vc.replica_id, f"for {vc.new_view}"
            )
            return
        self._vc_log.record(vc)
        target = self._vc_log.join_target(self.view, self.membership.join_quorum)
        if target is not None:
            self._start_view_change(target)
        self._maybe_send_new_view()

    def _maybe_send_new_view(self) -> None:
        """Step 3: as the new primary, announce the view once `2f+1` view-changes are in."""
        if self._active or not self.is_primary:
            return
        view_changes = self._vc_log.for_view(self.view)
        if len(view_changes) < self.membership.view_change_quorum:
            return
        nv = build_new_view(
            chain=self.chain.name,
            view=self.view,
            view_changes=view_changes,
            replica_id=self.replica_id,
            key=self._private_key,
        )
        self._broadcast(nv)
        self._install(nv)

    def _on_new_view(self, nv: NewView) -> None:
        if nv.view < self.view or (nv.view == self.view and self._active):
            self._reject(RejectReason.WRONG_VIEW, "new-view", nv.replica_id, f"for {nv.view}")
            return
        if (reason := verify_new_view(nv, self.membership, self.chain.name)) is not None:
            self._reject(RejectReason.BAD_NEW_VIEW, "new-view", nv.replica_id, reason)
            return
        self._install(nv)

    def _install(self, nv: NewView) -> None:
        """Enter `nv.view` and process the re-proposals it carries. Step 4."""
        self.view = nv.view
        self._active = True
        if self._vc_timer is not None:
            self._vc_timer.cancel()
            self._vc_timer = None
        self._vc_log.discard_below(nv.view + 1)
        event(
            _LOG,
            "pbft_new_view",
            chain=self.chain.name,
            replica=self.replica_id,
            view=nv.view,
            reproposed=len(nv.proposals),
            sim_time=self.network.now,
        )
        for proposal in nv.proposals:
            # A replica below the re-proposed height is lagging and has no state transfer to
            # catch up with (DEV-20 item 2); one above it has already committed that height.
            if proposal.pre_prepare.seq == self.height + 1:
                self._accept_proposal(proposal)
        self._drain_deferred()
        self._arm_progress_timer()
        self._maybe_propose()

    # -- outbound --------------------------------------------------------------------------------
    def _broadcast(self, message: Message) -> None:
        for recipient in self.membership.ids:
            if recipient != self.replica_id:
                for out in self.behaviour.outgoing(self, recipient, message):
                    self.network.send(self.replica_id, recipient, out)

    # -- bookkeeping -----------------------------------------------------------------------------
    def _slot(self, key: tuple[int, int]) -> _Slot:
        slot = self._slots.get(key)
        if slot is None:
            slot = self._slots[key] = _Slot()
        return slot

    def _reject(self, reason: RejectReason, kind: str, sender: str, detail: str = "") -> None:
        self.rejections.append(Rejection(reason, kind, sender, detail))

    def __repr__(self) -> str:
        state = "active" if self._active else "view-changing"
        return (
            f"Replica({self.replica_id!r}, chain={self.chain.name}, view={self.view} {state}, "
            f"height={self.height})"
        )


# --------------------------------------------------------------------------------------------
# Cluster
# --------------------------------------------------------------------------------------------
class Cluster:
    """One chain's replica set: `n` replicas, one bus, one shared genesis block.

    `BC_DTBU` and `BC_SigRW` each get their own `Cluster` — their own bus, their own replicas,
    their own `Chain` instances (CLAUDE.md §4). Nothing here is shared between two clusters.
    """

    def __init__(
        self,
        *,
        chain_name: str,
        keys: Mapping[str, PrivateKey],
        genesis: Block,
        policy: PBFTPolicy,
        seed: int,
        submitters: Mapping[str, PublicKey],
        chain_policy: ChainPolicy | None = None,
        start_time: float = 0.0,
    ) -> None:
        if len(keys) != policy.replicas:
            raise ConsensusError(
                f"{chain_name}: {len(keys)} replica keys supplied, config says "
                f"consensus.miner_nodes={policy.replicas}"
            )
        self.chain_name = chain_name
        self.policy = policy
        self.submitters = dict(submitters)
        self.network = P2PCSNetwork(
            message_delay_s=policy.message_delay_s,
            seed=seed,
            start_time=start_time,
            serialize=_roundtrip_message if policy.serialize_messages else None,
        )
        self.membership = Membership(
            {rid: key.public_key for rid, key in keys.items()},
            f=policy.f,
            commit_threshold=policy.commit_threshold,
        )
        self.replicas: dict[str, Replica] = {}
        for rid in self.membership.ids:
            chain = Chain(chain_name, policy=chain_policy)
            chain.adopt_genesis(genesis)
            self.replicas[rid] = Replica(
                replica_id=rid,
                private_key=keys[rid],
                membership=self.membership,
                chain=chain,
                network=self.network,
                policy=policy,
                submitters=self.submitters,
            )

    def submit(
        self,
        transactions: tuple[Transaction, ...],
        *,
        timestamp: float,
        submitter_id: str,
        key: PrivateKey,
    ) -> bytes:
        """Send a signed request to every replica, as a submitting `CS_l` would. Returns its id.

        Implements Alg. 1, line 4 / Alg. 2, line 9 — hand the encrypted transactions to P2PCS.
        `submitter_id` must be one of `self.submitters` for the request to survive
        `check_request_identity` on the other end (DEV-20 item 5 / debt D4); callers outside the
        configured set can still call this (nothing here enforces membership on send), but every
        replica will reject what arrives, which is exactly the boundary check being tested.
        """
        request = ClientRequest.create(
            chain=self.chain_name,
            transactions=transactions,
            timestamp=timestamp,
            submitter_id=submitter_id,
            key=key,
        )
        self.network.broadcast(CLIENT_ID, request, self.membership.ids)
        return request.request_id

    def run(self, *, until: float | None = None) -> int:
        return self.network.run(until=until)

    def heights(self) -> dict[str, int]:
        return {rid: r.height for rid, r in self.replicas.items()}

    def client_confirmation_threshold(self) -> int:
        """`f+1` — `consensus.interface.ConsensusCluster`'s client-trust rule for pBFT."""
        return self.policy.f + 1

    def tick_seconds(self) -> float:
        """`consensus.interface.ConsensusCluster`'s poll granularity while a request is pending."""
        return self.policy.message_delay_s or self.policy.view_change_timeout_s

    @property
    def signature_ops(self) -> int:
        """Total consensus-message ECDSA operations across every replica — see `Replica`."""
        return sum(r.signature_ops for r in self.replicas.values())

    def __repr__(self) -> str:
        return f"Cluster({self.chain_name}, {self.heights()}, t={self.network.now:.3f})"
