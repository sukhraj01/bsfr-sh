"""Raft over one chain's replica set (Ongaro & Ousterhout) — the M7-4 comparison against pBFT.

Why this exists
----------------
`docs/PAPER_NOTES.md` FLAW-5 shows §V-3's argument for pBFT is broken (it borrows PoW's 51%
threshold for a protocol whose real safety bound is a third, not a half). That leaves the
question the paper never asks: pBFT is *Byzantine*-fault-tolerant, but the paper's own deployment
is four cloud servers the operator controls. If the real threat model is "a server crashes or
drops offline," a *crash*-fault-tolerant protocol gives the same availability — one of four
nodes down, three of four still committing — at a fraction of the cost. Raft is that protocol:
the standard CFT alternative, and simpler.

What "simpler" buys, structurally, at `n=4`
--------------------------------------------
* **No signatures in the consensus path.** `RequestVote`/`AppendEntries` carry no ECDSA
  signature at all — contrast `consensus.protocol`'s `VOTE_FIELDS`, signed under a type-specific
  domain for every pre-prepare/prepare/commit. A `Cluster`'s `signature_ops` counts these; a
  `RaftCluster`'s is always zero. This is not an oversight to fix later — it is the mechanism of
  the trade-off this module exists to demonstrate (see "What Raft does not protect against").
* **Two message hops, not three.** pBFT: pre-prepare, prepare, commit. Raft: `AppendEntries`,
  then the leader locally counts acks and tells everyone the result on the next heartbeat — no
  third round where followers cross-check each other.
* **`O(n)` messages per round, not `O(n^2)`.** A pBFT backup broadcasts its prepare and its
  commit to every other replica (`Replica._broadcast`, DEV-19); a Raft follower only ever talks
  to the leader. All fan-out is leader-to-follower, once per follower, per round.

Design, scoped to what the M7-4 benchmark needs
------------------------------------------------
One log entry in flight at a time, exactly like pBFT's one-height-in-flight rule (DEV-20 item 3)
— the fairest way to compare two protocols is to give them the same discipline everywhere they
are not the thing being compared. A leader proposes the next pending `ClientRequest` only after
the previous entry has committed. This also sidesteps most of real Raft's log-matching
complexity (backtracking `nextIndex` on a mismatch): with one entry ever in flight, the previous
entry is always either committed everywhere or not yet sent, so `prevLogIndex`/`prevLogTerm`
either trivially matches or the follower is lagging behind a crashed/partitioned leader, which
the next election resolves.

Reused unchanged from pBFT's infrastructure: `consensus.network.P2PCSNetwork` (same bus, same
`serialize=` hook, same `LinkFaults` for crash/partition tests — nothing Raft-specific about
"a message got dropped"), and `consensus.protocol.ClientRequest` / `check_request_identity` for
submitter authentication (DEV-20 item 5 is a property of *who may submit*, not of which consensus
protocol orders the submissions, so both protocols keep it).

Out of scope, and why it does not matter for this comparison
---------------------------------------------------------------
* **Log compaction / snapshotting.** Nothing here ever needs to discard log history — cases 1-3
  commit at most 15 entries. Real deployments need this; a 15-block benchmark does not.
* **Cluster membership changes.** `RaftPolicy.replicas` is fixed at cluster construction, same as
  pBFT's `Membership`. Neither protocol's benchmark reconfigures a running cluster.
* **`nextIndex` backtracking / log-matching beyond one entry.** See above — a consequence of the
  one-entry-in-flight discipline, not a missing feature relative to what this session measures.
* **Retransmission.** Same reduction pBFT already accepted (DEV-20 item 6): a dropped message is
  never resent; liveness under loss comes from timeouts (heartbeat causes a resend of the same
  pending entry on the next tick; an election timeout causes a new leader).

What Raft does not protect against — the qualitative half of the comparison
--------------------------------------------------------------------------
A Raft follower applies whatever the leader's `AppendEntries` tells it to, *unconditionally*: it
checks the leader's term and the previous-entry consistency, but never cross-checks its own
accepted entry against any other follower's. A byzantine leader can therefore send **different**
block content to different followers at the same `(term, index)`, each claiming `leader_commit`
already covers it — standard, spec-compliant Raft on both ends, no bug required — and each
follower will append and apply its own, different, valid-looking block. pBFT's equivalent
attempt fails structurally: a backup only commits once it holds `commit_threshold` *matching*
votes from distinct replicas (`consensus.pbft.Replica._check_committed`), so two followers
committing different content at one height would require `2f+1` matching votes for each side,
which needs more faulty replicas than `f` allows. `tests/unit/test_raft_byzantine.py` demonstrates
this directly: it is the expected result, not a defect in this implementation.
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Final, Protocol, cast

from bsfr_sh.blockchain.block import Block
from bsfr_sh.blockchain.chain import Chain, ChainError, ChainPolicy
from bsfr_sh.blockchain.transaction import Transaction
from bsfr_sh.consensus.network import P2PCSNetwork, Timer
from bsfr_sh.consensus.protocol import (
    ClientRequest,
    check_request_identity,
    unwire_block,
    wire_block,
)
from bsfr_sh.consensus.protocol import decode_message as decode_pbft_message
from bsfr_sh.consensus.protocol import encode_message as encode_pbft_message
from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey
from bsfr_sh.util.config import Config
from bsfr_sh.util.logging import event, get_logger
from bsfr_sh.util.serialization import CanonicalEncodingError, Value, decode, encode

__all__ = [
    "CLIENT_ID",
    "HONEST",
    "AppendEntries",
    "AppendEntriesResponse",
    "Honest",
    "LogEntry",
    "RaftBehaviour",
    "RaftCluster",
    "RaftNode",
    "RaftPolicy",
    "RequestVote",
    "RequestVoteResponse",
    "Role",
]

_LOG: Final = get_logger("consensus.raft")

#: Transport name requests are sent under. Mirrors `consensus.pbft.CLIENT_ID`.
CLIENT_ID: Final = "client"


class ConsensusError(RuntimeError):
    """Raised when the protocol reaches a state its own invariants say is impossible."""


class Role(Enum):
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


# --------------------------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class RaftPolicy:
    """Consensus tunables, from `configs/chain.yaml` `consensus.raft.*`.

    Election timeouts are randomized per node in `[election_timeout_min_s, election_timeout_max_s)`
    — the standard Raft device for avoiding split votes — using a per-cluster seeded
    `random.Random`, never Python's global RNG, so a run is reproducible from its seed
    (CLAUDE.md §4b) exactly as `consensus.network.P2PCSNetwork`'s own fault jitter is.
    """

    replicas: int = 4
    election_timeout_min_s: float = 0.15
    election_timeout_max_s: float = 0.30
    heartbeat_interval_s: float = 0.05
    message_delay_s: float = 0.0
    serialize_messages: bool = False

    def __post_init__(self) -> None:
        if self.replicas < 3:
            raise ValueError("raft needs at least 3 replicas for a majority to tolerate any fault")
        if not 0.0 < self.election_timeout_min_s < self.election_timeout_max_s:
            raise ValueError("0 < election_timeout_min_s < election_timeout_max_s required")
        if self.heartbeat_interval_s <= 0:
            raise ValueError("heartbeat_interval_s must be positive")
        if self.heartbeat_interval_s >= self.election_timeout_min_s:
            raise ValueError(
                "heartbeat_interval_s must be well under election_timeout_min_s, or a live "
                "leader's own followers time out waiting between heartbeats"
            )
        if self.message_delay_s < 0:
            raise ValueError("message_delay_s must be non-negative")

    @property
    def majority(self) -> int:
        """`floor(n/2) + 1` — the same fault count pBFT tolerates at `n=4` (`f=1`), different
        failure model: this many nodes must be *up*, not merely *honest*."""
        return self.replicas // 2 + 1

    @classmethod
    def from_config(cls, config: Config) -> RaftPolicy:
        return cls(
            replicas=config.require("consensus.miner_nodes", int),
            election_timeout_min_s=float(config.get("consensus.raft.election_timeout_min_s", 0.15)),
            election_timeout_max_s=float(config.get("consensus.raft.election_timeout_max_s", 0.30)),
            heartbeat_interval_s=float(config.get("consensus.raft.heartbeat_interval_s", 0.05)),
            message_delay_s=float(config.get("consensus.message_delay_s", 0.0)),
            serialize_messages=bool(config.get("consensus.serialize_messages", False)),
        )


# --------------------------------------------------------------------------------------------
# Messages — no signatures. See the module docstring's "no signatures in the consensus path".
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class LogEntry:
    term: int
    index: int
    block: Block


@dataclass(frozen=True)
class RequestVote:
    chain: str
    term: int
    candidate_id: str
    last_log_index: int
    last_log_term: int


@dataclass(frozen=True)
class RequestVoteResponse:
    chain: str
    term: int
    voter_id: str
    granted: bool


@dataclass(frozen=True)
class AppendEntries:
    chain: str
    term: int
    leader_id: str
    prev_log_index: int
    prev_log_term: int
    entries: tuple[LogEntry, ...]
    leader_commit: int


@dataclass(frozen=True)
class AppendEntriesResponse:
    chain: str
    term: int
    follower_id: str
    success: bool
    match_index: int


#: Everything a Raft node can receive.
RaftMessage = (
    ClientRequest | RequestVote | RequestVoteResponse | AppendEntries | AppendEntriesResponse
)


# --------------------------------------------------------------------------------------------
# Wire encoding — D3's serialize=True path, mirroring consensus.protocol's shape exactly.
# --------------------------------------------------------------------------------------------
def _wire_log_entry(entry: LogEntry) -> dict[str, Value]:
    return {"term": entry.term, "index": entry.index, "block": wire_block(entry.block)}


def _unwire_log_entry(value: Value) -> LogEntry:
    if not isinstance(value, Mapping):
        raise CanonicalEncodingError("log-entry envelope must be a mapping")
    return LogEntry(
        term=cast(int, value["term"]),
        index=cast(int, value["index"]),
        block=unwire_block(value["block"]),
    )


def encode_raft_message(message: RaftMessage) -> bytes:
    """Serialize one Raft-specific bus message. `ClientRequest` goes through `consensus.protocol`
    instead — see `_roundtrip_message` below — since that wire format is shared with pBFT."""
    if isinstance(message, RequestVote):
        body: dict[str, Value] = {
            "chain": message.chain,
            "term": message.term,
            "candidate_id": message.candidate_id,
            "last_log_index": message.last_log_index,
            "last_log_term": message.last_log_term,
        }
        return encode(["request_vote", body])
    if isinstance(message, RequestVoteResponse):
        body = {
            "chain": message.chain,
            "term": message.term,
            "voter_id": message.voter_id,
            "granted": message.granted,
        }
        return encode(["request_vote_response", body])
    if isinstance(message, AppendEntries):
        body = {
            "chain": message.chain,
            "term": message.term,
            "leader_id": message.leader_id,
            "prev_log_index": message.prev_log_index,
            "prev_log_term": message.prev_log_term,
            "entries": [_wire_log_entry(e) for e in message.entries],
            "leader_commit": message.leader_commit,
        }
        return encode(["append_entries", body])
    if isinstance(message, AppendEntriesResponse):
        body = {
            "chain": message.chain,
            "term": message.term,
            "follower_id": message.follower_id,
            "success": message.success,
            "match_index": message.match_index,
        }
        return encode(["append_entries_response", body])
    raise CanonicalEncodingError(f"no wire encoding for {type(message).__name__}")


def decode_raft_message(data: bytes) -> RaftMessage:
    envelope = decode(data)
    if not (isinstance(envelope, list) and len(envelope) == 2):
        raise CanonicalEncodingError("malformed message envelope")
    kind, v = envelope
    if not isinstance(v, Mapping):
        raise CanonicalEncodingError("malformed message body")
    if kind == "request_vote":
        return RequestVote(
            chain=cast(str, v["chain"]),
            term=cast(int, v["term"]),
            candidate_id=cast(str, v["candidate_id"]),
            last_log_index=cast(int, v["last_log_index"]),
            last_log_term=cast(int, v["last_log_term"]),
        )
    if kind == "request_vote_response":
        return RequestVoteResponse(
            chain=cast(str, v["chain"]),
            term=cast(int, v["term"]),
            voter_id=cast(str, v["voter_id"]),
            granted=cast(bool, v["granted"]),
        )
    if kind == "append_entries":
        entries_field = v["entries"]
        if not isinstance(entries_field, list):
            raise CanonicalEncodingError("append-entries.entries must be a list")
        return AppendEntries(
            chain=cast(str, v["chain"]),
            term=cast(int, v["term"]),
            leader_id=cast(str, v["leader_id"]),
            prev_log_index=cast(int, v["prev_log_index"]),
            prev_log_term=cast(int, v["prev_log_term"]),
            entries=tuple(_unwire_log_entry(e) for e in entries_field),
            leader_commit=cast(int, v["leader_commit"]),
        )
    if kind == "append_entries_response":
        return AppendEntriesResponse(
            chain=cast(str, v["chain"]),
            term=cast(int, v["term"]),
            follower_id=cast(str, v["follower_id"]),
            success=cast(bool, v["success"]),
            match_index=cast(int, v["match_index"]),
        )
    raise CanonicalEncodingError(f"unknown message kind {kind!r}")


def _roundtrip_message(payload: object) -> object:
    """The `P2PCSNetwork(serialize=...)` hook for `RaftPolicy.serialize_messages` (D3's shape,
    applied to Raft): `ClientRequest` reuses pBFT's wire format (shared submitter-auth type),
    everything else is Raft's own."""
    if isinstance(payload, ClientRequest):
        return decode_pbft_message(encode_pbft_message(payload))
    return decode_raft_message(encode_raft_message(payload))  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------------
# Behaviour hook — same shape as `consensus.pbft.Behaviour`, for the same reason: byzantine test
# fixtures replace what a node actually puts on the wire without the protocol code knowing.
# --------------------------------------------------------------------------------------------
class RaftBehaviour(Protocol):
    def outgoing(
        self, node: RaftNode, recipient: str, message: RaftMessage
    ) -> Sequence[RaftMessage]: ...


class Honest:
    def outgoing(
        self,
        node: RaftNode,  # noqa: ARG002
        recipient: str,  # noqa: ARG002
        message: RaftMessage,
    ) -> Sequence[RaftMessage]:
        return (message,)


HONEST: Final = Honest()


# --------------------------------------------------------------------------------------------
# Node
# --------------------------------------------------------------------------------------------
class RaftNode:
    """One Raft node — a `CS_l` in the P2PCS network of one chain, Raft's side of DEV-32.

    Holds its own `Chain`, exactly like `consensus.pbft.Replica`. Unlike a pBFT replica, a Raft
    node's log entries are *not* validated-and-applied together (`chain.append`) — an entry is
    validated (`chain.check_append`) when it first enters the node's log, and applied
    (`chain.append`) only once `commit_index` reaches it, because the log can still be
    overwritten by a later leader's conflicting entry until then. This is a real Raft property
    (an appended-but-uncommitted entry can be discarded) that pBFT does not have (a proposal is
    either not yet accepted, or its digest is fixed for that slot forever).
    """

    def __init__(
        self,
        *,
        node_id: str,
        peers: tuple[str, ...],
        private_key: PrivateKey,
        chain: Chain,
        network: P2PCSNetwork,
        policy: RaftPolicy,
        submitters: Mapping[str, PublicKey],
        rng: random.Random,
        behaviour: RaftBehaviour | None = None,
    ) -> None:
        if len(chain) != 1:
            raise ConsensusError("a node starts from a chain holding exactly its genesis block")
        self.node_id = node_id
        self.peers = peers
        self._private_key = private_key
        self._public_bytes = private_key.public_key.to_bytes()
        self.chain = chain
        self.network = network
        self.policy = policy
        self.submitters = submitters
        self._rng = rng
        self.behaviour: RaftBehaviour = behaviour if behaviour is not None else HONEST

        self.role = Role.FOLLOWER
        self.current_term = 0
        self.voted_for: str | None = None
        self.log: list[LogEntry] = []
        self.commit_index = 0
        self._last_applied = 0
        self._next_index: dict[str, int] = {}
        self._match_index: dict[str, int] = {}
        self._votes_received: set[str] = set()
        self._pending: dict[bytes, ClientRequest] = {}
        self._committed_requests: set[bytes] = set()
        self._in_flight: LogEntry | None = None
        self._election_timer: Timer | None = None
        self._heartbeat_timer: Timer | None = None
        self.rejections: list[str] = []

        network.register(node_id, self.receive)

    # -- read-only views -------------------------------------------------------------------------
    @property
    def height(self) -> int:
        return self.chain.height

    @property
    def is_leader(self) -> bool:
        return self.role is Role.LEADER

    @property
    def last_log_index(self) -> int:
        return self.log[-1].index if self.log else 0

    @property
    def last_log_term(self) -> int:
        return self.log[-1].term if self.log else 0

    def _term_at(self, index: int) -> int:
        if index == 0:
            return 0
        return self.log[index - 1].term

    # -- startup ---------------------------------------------------------------------------------
    def start(self) -> None:
        """Arm the initial election timer. Called once per node after every node is registered."""
        self._reset_election_timer()

    # -- inbound -----------------------------------------------------------------------------------
    def receive(self, sender: str, message: object) -> None:
        """Bus handler. `sender` is transport-level, exactly as `consensus.pbft.Replica.receive`
        documents — never used to authenticate anything."""
        if isinstance(message, ClientRequest):
            self._on_request(message)
        elif isinstance(message, RequestVote):
            self._on_request_vote(message)
        elif isinstance(message, RequestVoteResponse):
            self._on_request_vote_response(message)
        elif isinstance(message, AppendEntries):
            self._on_append_entries(message)
        elif isinstance(message, AppendEntriesResponse):
            self._on_append_entries_response(message)
        else:
            self.rejections.append(f"malformed message from {sender}: {type(message).__name__}")

    def _on_request(self, request: ClientRequest) -> None:
        reason = check_request_identity(request, self.submitters, self.chain.name)
        if reason is not None:
            self.rejections.append(f"client-request from {request.submitter_id}: {reason.value}")
            return
        request_id = request.request_id
        if request_id in self._committed_requests or request_id in self._pending:
            return
        self._pending[request_id] = request
        self._maybe_propose()

    # -- term bookkeeping --------------------------------------------------------------------------
    def _observe_term(self, term: int) -> None:
        """Step down to follower on any message carrying a higher term (the one rule every RPC
        handler in real Raft applies first)."""
        if term > self.current_term:
            self.current_term = term
            self.voted_for = None
            self.role = Role.FOLLOWER
            self._votes_received.clear()
            self._cancel_heartbeat_timer()

    # -- election --------------------------------------------------------------------------------
    def _reset_election_timer(self) -> None:
        if self._election_timer is not None:
            self._election_timer.cancel()
        timeout = self._rng.uniform(
            self.policy.election_timeout_min_s, self.policy.election_timeout_max_s
        )
        self._election_timer = self.network.schedule(timeout, self._on_election_timeout)

    def _on_election_timeout(self) -> None:
        self._election_timer = None
        if self.role is Role.LEADER:
            return
        self.role = Role.CANDIDATE
        self.current_term += 1
        self.voted_for = self.node_id
        self._votes_received = {self.node_id}
        event(
            _LOG,
            "raft_election_started",
            chain=self.chain.name,
            node=self.node_id,
            term=self.current_term,
            sim_time=self.network.now,
        )
        self._reset_election_timer()
        vote_request = RequestVote(
            chain=self.chain.name,
            term=self.current_term,
            candidate_id=self.node_id,
            last_log_index=self.last_log_index,
            last_log_term=self.last_log_term,
        )
        self._broadcast(vote_request)

    def _on_request_vote(self, message: RequestVote) -> None:
        if message.chain != self.chain.name:
            return
        self._observe_term(message.term)
        if message.term < self.current_term:
            self._send(
                message.candidate_id,
                RequestVoteResponse(
                    chain=self.chain.name,
                    term=self.current_term,
                    voter_id=self.node_id,
                    granted=False,
                ),
            )
            return
        log_ok = (message.last_log_term, message.last_log_index) >= (
            self.last_log_term,
            self.last_log_index,
        )
        may_vote = self.voted_for in (None, message.candidate_id)
        granted = log_ok and may_vote
        if granted:
            self.voted_for = message.candidate_id
            self._reset_election_timer()
        self._send(
            message.candidate_id,
            RequestVoteResponse(
                chain=self.chain.name,
                term=self.current_term,
                voter_id=self.node_id,
                granted=granted,
            ),
        )

    def _on_request_vote_response(self, message: RequestVoteResponse) -> None:
        if message.chain != self.chain.name:
            return
        self._observe_term(message.term)
        if self.role is not Role.CANDIDATE or message.term != self.current_term:
            return
        if message.granted:
            self._votes_received.add(message.voter_id)
            if len(self._votes_received) >= self.policy.majority:
                self._become_leader()

    def _become_leader(self) -> None:
        self.role = Role.LEADER
        self._votes_received.clear()
        if self._election_timer is not None:
            self._election_timer.cancel()
            self._election_timer = None
        for peer in self.peers:
            self._next_index[peer] = self.last_log_index + 1
            self._match_index[peer] = 0
        event(
            _LOG,
            "raft_became_leader",
            chain=self.chain.name,
            node=self.node_id,
            term=self.current_term,
            sim_time=self.network.now,
        )
        self._send_heartbeat()
        self._arm_heartbeat_timer()
        self._maybe_propose()

    # -- heartbeats / replication ------------------------------------------------------------------
    def _arm_heartbeat_timer(self) -> None:
        self._heartbeat_timer = self.network.schedule(
            self.policy.heartbeat_interval_s, self._on_heartbeat_timeout
        )

    def _cancel_heartbeat_timer(self) -> None:
        if self._heartbeat_timer is not None:
            self._heartbeat_timer.cancel()
            self._heartbeat_timer = None

    def _on_heartbeat_timeout(self) -> None:
        self._heartbeat_timer = None
        if self.role is not Role.LEADER:
            return
        self._send_heartbeat()
        self._arm_heartbeat_timer()

    def _send_heartbeat(self) -> None:
        """Resend the in-flight entry (if any) or an empty `AppendEntries`, to every peer.

        Standing in for real Raft's per-follower `nextIndex`-driven catch-up: with one entry ever
        in flight (module docstring), "resend everything since `nextIndex`" and "resend the one
        entry, if any" are the same statement.
        """
        for peer in self.peers:
            self._replicate_to(peer)

    def _replicate_to(self, peer: str) -> None:
        entries = (self._in_flight,) if self._in_flight is not None else ()
        prev_index = self.commit_index
        message = AppendEntries(
            chain=self.chain.name,
            term=self.current_term,
            leader_id=self.node_id,
            prev_log_index=prev_index,
            prev_log_term=self._term_at(prev_index),
            entries=entries,
            leader_commit=self.commit_index,
        )
        self._send(peer, message)

    def _maybe_propose(self) -> None:
        """Leader proposes the oldest pending request at `commit_index + 1`, one at a time."""
        if self.role is not Role.LEADER or self._in_flight is not None:
            return
        for request_id, request in list(self._pending.items()):
            block = self.chain.draft_next(
                owner_id=self.node_id,
                owner_pubkey=self._public_bytes,
                transactions=request.transactions,
                timestamp=request.timestamp,
            ).seal(self._private_key)
            try:
                self.chain.check_append(block)
            except ChainError as exc:
                self._pending.pop(request_id)
                event(_LOG, "raft_request_dropped", node=self.node_id, reason=str(exc))
                continue
            entry = LogEntry(term=self.current_term, index=self.commit_index + 1, block=block)
            self.log = [*self.log[: self.commit_index], entry]
            self._in_flight = entry
            self._match_index[self.node_id] = entry.index
            self._send_heartbeat()
            return

    def _on_append_entries(self, message: AppendEntries) -> None:
        if message.chain != self.chain.name:
            return
        self._observe_term(message.term)
        if message.term < self.current_term:
            self._send(
                message.leader_id,
                AppendEntriesResponse(
                    chain=self.chain.name,
                    term=self.current_term,
                    follower_id=self.node_id,
                    success=False,
                    match_index=0,
                ),
            )
            return
        # A valid leader for this term: follow it, whatever role we were in (§5.2).
        self.role = Role.FOLLOWER
        self._reset_election_timer()

        if message.prev_log_index > self.last_log_index or (
            message.prev_log_index > 0
            and self._term_at(message.prev_log_index) != message.prev_log_term
        ):
            self._send(
                message.leader_id,
                AppendEntriesResponse(
                    chain=self.chain.name,
                    term=self.current_term,
                    follower_id=self.node_id,
                    success=False,
                    match_index=0,
                ),
            )
            return

        for entry in message.entries:
            existing = self.log[entry.index - 1] if entry.index <= len(self.log) else None
            if existing is not None and existing.term != entry.term:
                self.log = self.log[: entry.index - 1]
                existing = None
            if existing is None:
                # No independent validation against a *different* follower's copy — a byzantine
                # leader can send different, individually well-formed blocks to different
                # followers here. See the module docstring's closing section and
                # `tests/unit/test_raft_byzantine.py`.
                self.log.append(entry)

        if message.entries:
            match_index = message.entries[-1].index
        else:
            match_index = min(message.prev_log_index, self.last_log_index)

        if message.leader_commit > self.commit_index:
            self.commit_index = min(message.leader_commit, self.last_log_index)
            self._apply_committed()

        self._send(
            message.leader_id,
            AppendEntriesResponse(
                chain=self.chain.name,
                term=self.current_term,
                follower_id=self.node_id,
                success=True,
                match_index=match_index,
            ),
        )

    def _on_append_entries_response(self, message: AppendEntriesResponse) -> None:
        if message.chain != self.chain.name:
            return
        self._observe_term(message.term)
        if self.role is not Role.LEADER or message.term != self.current_term:
            return
        if not message.success:
            return
        self._match_index[message.follower_id] = max(
            self._match_index.get(message.follower_id, 0), message.match_index
        )
        self._advance_commit_index()

    def _advance_commit_index(self) -> None:
        """`N` commits once a majority's `match_index >= N` and `log[N].term == current_term`
        (Raft's leader-completeness safety rule — never commit an entry from an earlier term on
        vote count alone, §5.4.2)."""
        if self._in_flight is None or self._in_flight.index <= self.commit_index:
            return
        n = self._in_flight.index
        if self._term_at(n) != self.current_term:
            return
        acked = sum(1 for peer in self.peers if self._match_index.get(peer, 0) >= n) + 1
        if acked < self.policy.majority:
            return
        self.commit_index = n
        self._in_flight = None
        self._apply_committed()
        self._send_heartbeat()
        self._maybe_propose()

    def _apply_committed(self) -> None:
        while self._last_applied < self.commit_index:
            entry = self.log[self._last_applied]
            try:
                self.chain.append(entry.block)
            except ChainError as exc:
                raise ConsensusError(
                    f"{self.node_id}: committed entry failed append: {exc}"
                ) from exc
            self._last_applied += 1
            request_id = entry.block.merkle_root
            self._pending.pop(request_id, None)
            self._committed_requests.add(request_id)
            event(
                _LOG,
                "raft_commit",
                chain=self.chain.name,
                node=self.node_id,
                height=self.height,
                term=entry.term,
                digest=entry.block.current_hash[:8].hex(),
                sim_time=self.network.now,
            )

    # -- outbound --------------------------------------------------------------------------------
    def _send(self, recipient: str, message: RaftMessage) -> None:
        for out in self.behaviour.outgoing(self, recipient, message):
            self.network.send(self.node_id, recipient, out)

    def _broadcast(self, message: RaftMessage) -> None:
        for peer in self.peers:
            self._send(peer, message)

    def __repr__(self) -> str:
        return (
            f"RaftNode({self.node_id!r}, chain={self.chain.name}, role={self.role.value}, "
            f"term={self.current_term}, height={self.height})"
        )


# --------------------------------------------------------------------------------------------
# Cluster
# --------------------------------------------------------------------------------------------
class RaftCluster:
    """One chain's Raft node set. Mirrors `consensus.pbft.Cluster`'s shape exactly, and satisfies
    `consensus.interface.ConsensusCluster` the same way — see that module for what unifies them.
    """

    def __init__(
        self,
        *,
        chain_name: str,
        keys: Mapping[str, PrivateKey],
        genesis: Block,
        policy: RaftPolicy,
        seed: int,
        submitters: Mapping[str, PublicKey],
        chain_policy: ChainPolicy | None = None,
        start_time: float = 0.0,
    ) -> None:
        if len(keys) != policy.replicas:
            raise ConsensusError(
                f"{chain_name}: {len(keys)} node keys supplied, config says "
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
        ids = tuple(sorted(keys))
        self.nodes: dict[str, RaftNode] = {}
        for index, rid in enumerate(ids):
            chain = Chain(chain_name, policy=chain_policy)
            chain.adopt_genesis(genesis)
            self.nodes[rid] = RaftNode(
                node_id=rid,
                peers=tuple(i for i in ids if i != rid),
                private_key=keys[rid],
                chain=chain,
                network=self.network,
                policy=policy,
                submitters=self.submitters,
                # `seed + index` mirrors `consensus.pbft.Cluster`'s key derivation
                # (`keypair_from_secret(seed + index + 1)`) — an int, not a hash of `rid`, so a
                # run is reproducible independent of Python's per-process string-hash
                # randomization (CLAUDE.md §4b).
                rng=random.Random(seed + index * 7919 + 1),
            )
        for node in self.nodes.values():
            node.start()

    @property
    def replicas(self) -> Mapping[str, RaftNode]:
        """Alias for `consensus.interface.ConsensusCluster`'s `replicas` field."""
        return self.nodes

    def submit(
        self,
        transactions: tuple[Transaction, ...],
        *,
        timestamp: float,
        submitter_id: str,
        key: PrivateKey,
    ) -> bytes:
        """Same contract as `consensus.pbft.Cluster.submit` — see that docstring."""
        request = ClientRequest.create(
            chain=self.chain_name,
            transactions=transactions,
            timestamp=timestamp,
            submitter_id=submitter_id,
            key=key,
        )
        self.network.broadcast(CLIENT_ID, request, self.nodes.keys())
        return request.request_id

    def run(self, *, until: float | None = None) -> int:
        return self.network.run(until=until)

    def heights(self) -> dict[str, int]:
        return {rid: n.height for rid, n in self.nodes.items()}

    def client_confirmation_threshold(self) -> int:
        """`1` — see `consensus.interface.ConsensusCluster`'s docstring for why this is not `f+1`
        weakened by an oversight: a non-byzantine Raft node only ever reflects an entry the
        leader already confirmed via a real majority."""
        return 1

    def tick_seconds(self) -> float:
        return self.policy.message_delay_s or self.policy.heartbeat_interval_s

    @property
    def signature_ops(self) -> int:
        """Always zero — Raft's consensus messages carry no ECDSA signature. See the module
        docstring's "no signatures in the consensus path"."""
        return 0

    def __repr__(self) -> str:
        return f"RaftCluster({self.chain_name}, {self.heights()}, t={self.network.now:.3f})"
