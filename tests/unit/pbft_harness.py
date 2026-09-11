"""Consensus test harness: fixture keys, cluster builders, transactions, byzantine behaviours.

Not a test module (no `test_` prefix); imported by the consensus tests.

Byzantine behaviours
--------------------
Each is a `consensus.pbft.Behaviour`: it sees every message its replica is about to send and
decides what actually goes on the wire. Drop one into a running cluster with
`cluster.replicas[rid].behaviour = Silent()`. The replica's *protocol logic* stays honest — what
is faulty is what it tells the others — which is exactly the adversary pBFT is specified against.

* `Silent` — sends nothing. A crashed or partitioned node, or a byzantine one withholding votes.
* `Equivocating` — as primary, sends different blocks under one `(view, seq)`; as a backup,
  votes for a digest per recipient that matches no block.
* `WrongSignature` — every message re-signed with a key that is not its registered one.
* `StaleView` — every message re-stamped with an older view and correctly re-signed, as a node
  stuck in a view the cluster has left would send.

Keys are fixture-derived (CLAUDE.md §4b), so every run is byte-reproducible.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from bsfr_sh.blockchain.block import BlockDraft
from bsfr_sh.blockchain.chain import BC_DTBU, build_genesis
from bsfr_sh.blockchain.transaction import BackupPayload, Transaction, encrypt_backup
from bsfr_sh.consensus.pbft import Cluster, PBFTPolicy, Replica
from bsfr_sh.consensus.protocol import (
    Commit,
    Message,
    NewView,
    Prepare,
    Proposal,
    ViewChange,
    resign,
)
from bsfr_sh.crypto.ecdsa import KeyPair, PrivateKey, keypair_from_secret
from bsfr_sh.crypto.hashing import h
from bsfr_sh.util.config import load_config

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
#: The configured policy — n=4, f=1, threshold 3, timeout, delay 0. Never re-literalled here.
POLICY = PBFTPolicy.from_config(CONFIG)

DTBU_IDS = ("CS_0", "CS_1", "CS_2", "CS_3")
SIGRW_IDS = ("CS_4", "CS_5", "CS_6", "CS_7")
GENESIS_TIME = 1000.0
#: Long enough for several view changes at the configured timeout; short enough to stay fast.
HORIZON_S = 15 * POLICY.view_change_timeout_s

#: `A` — holds a valid secp256r1 key that no membership lists.
OUTSIDER: KeyPair = keypair_from_secret(0xBAD0BAD0)
#: `CS_l` whose public key the test transactions are encrypted to. Not a replica.
RECIPIENT: KeyPair = keypair_from_secret(0x5EED5EED)


def replica_keys(ids: Iterable[str]) -> dict[str, PrivateKey]:
    return {rid: keypair_from_secret(0xC0FFEE00 + int(rid.split("_")[1])).private for rid in ids}


def make_cluster(
    chain_name: str = BC_DTBU,
    ids: Sequence[str] = DTBU_IDS,
    *,
    seed: int = 7,
    policy: PBFTPolicy = POLICY,
) -> Cluster:
    keys = replica_keys(ids)
    genesis = build_genesis(owner_id=ids[0], private_key=keys[ids[0]], timestamp=GENESIS_TIME)
    return Cluster(chain_name=chain_name, keys=keys, genesis=genesis, policy=policy, seed=seed)


def make_transactions(tag: str, count: int = 2, payload_bytes: int = 64) -> tuple[Transaction, ...]:
    return tuple(
        encrypt_backup(
            recipient=RECIPIENT.public,
            tx_id=f"{tag}-{i:03d}",
            payload=BackupPayload(
                system_id=f"SYS_{i % 8}", data=bytes([i % 256]) * payload_bytes, captured_at=1
            ),
            created_at=1,
        )
        for i in range(count)
    )


def submit_block(cluster: Cluster, index: int, *, count: int = 2) -> bytes:
    return cluster.submit(
        make_transactions(f"{cluster.chain_name}-b{index}", count),
        timestamp=GENESIS_TIME + 1 + index,
    )


def run_for(cluster: Cluster, seconds: float = HORIZON_S) -> None:
    """Run the bus for a bounded stretch of simulated time. Byzantine runs may never go idle."""
    cluster.run(until=cluster.network.now + seconds)


def honest(cluster: Cluster, byzantine: Iterable[str] = ()) -> list[Replica]:
    skip = set(byzantine)
    return [r for rid, r in cluster.replicas.items() if rid not in skip]


def assert_no_fork(replicas: Sequence[Replica]) -> None:
    """Safety: no two of these replicas hold different blocks at any height."""
    top = max(r.height for r in replicas)
    for height in range(top + 1):
        held = {r.chain.block_at(height).current_hash for r in replicas if r.height >= height}
        assert len(held) == 1, f"fork at height {height}: {len(held)} different blocks"


def key_of(replica: Replica) -> PrivateKey:
    return replica._private_key


# --------------------------------------------------------------------------------------------
# Behaviours
# --------------------------------------------------------------------------------------------
def _restamp(message: Message, key: PrivateKey, **changes: object) -> Message:
    if isinstance(message, Proposal):
        return Proposal(resign(message.pre_prepare, key, **changes), message.block)
    if isinstance(message, Prepare | Commit | ViewChange | NewView):
        return resign(message, key, **changes)
    return message


class Silent:
    """Never responds."""

    def outgoing(self, replica: Replica, recipient: str, message: Message) -> Sequence[Message]:
        return ()


@dataclass
class Equivocating:
    """Different blocks under the same `(view, seq)`; votes for blocks that do not exist.

    `assignment` maps a recipient to the block variants it is sent, in order: variant 0 is the
    block the replica's own protocol logic proposed, variant `k>0` a sibling with the same
    transactions and parent but a fresh `RN` — hence a different digest. A recipient absent from
    the mapping is sent nothing. With no mapping, every recipient gets its own distinct sibling.
    """

    assignment: Mapping[str, Sequence[int]] | None = None
    #: Also garble prepares and commits. False = equivocate on proposals only, vote honestly.
    votes: bool = True
    _siblings: dict[tuple[int, int, int], Proposal] = field(default_factory=dict)

    def outgoing(self, replica: Replica, recipient: str, message: Message) -> Sequence[Message]:
        if isinstance(message, Proposal):
            if self.assignment is None:
                variants: Sequence[int] = (replica.membership.ids.index(recipient) + 1,)
            else:
                variants = self.assignment.get(recipient, ())
            return tuple(self.variant(replica, message, k) for k in variants)
        if self.votes and isinstance(message, Prepare | Commit):
            bogus = h(message.digest + recipient.encode())
            return (resign(message, key_of(replica), digest=bogus),)
        return (message,)

    def variant(self, replica: Replica, proposal: Proposal, k: int) -> Proposal:
        if k == 0:
            return proposal
        pre_prepare = proposal.pre_prepare
        slot = (pre_prepare.view, pre_prepare.seq, k)
        if slot not in self._siblings:
            block = proposal.block
            sibling = BlockDraft(
                owner_id=block.owner_id,
                owner_pubkey=block.owner_pubkey,
                transactions=block.transactions,
                prev_hash=block.prev_hash,
                timestamp=block.timestamp,
            ).seal(key_of(replica))
            self._siblings[slot] = Proposal(
                resign(pre_prepare, key_of(replica), digest=sibling.current_hash), sibling
            )
        return self._siblings[slot]


@dataclass
class WrongSignature:
    """Every message signed with a key that is not the replica's registered one."""

    key: PrivateKey = field(default_factory=lambda: OUTSIDER.private)

    def outgoing(self, replica: Replica, recipient: str, message: Message) -> Sequence[Message]:
        return (_restamp(message, self.key),)


@dataclass
class StaleView:
    """Every message stamped `lag` views behind and correctly re-signed with the real key."""

    lag: int = 1

    def outgoing(self, replica: Replica, recipient: str, message: Message) -> Sequence[Message]:
        key = key_of(replica)
        if isinstance(message, ViewChange):
            return (resign(message, key, new_view=message.new_view - self.lag),)
        if isinstance(message, Proposal | Prepare | Commit | NewView):
            view = message.pre_prepare.view if isinstance(message, Proposal) else message.view
            return (_restamp(message, key, view=view - self.lag),)
        return (message,)


#: Factories, so each test gets fresh behaviour state.
BEHAVIOURS = {
    "silent": Silent,
    "equivocating": Equivocating,
    "wrong_signature": WrongSignature,
    "stale_view": StaleView,
}


@dataclass
class DropCommitsInView:
    """Network fault, not byzantine: commits for `view` are lost. Leaves replicas prepared."""

    view: int = 0

    def outgoing(self, replica: Replica, recipient: str, message: Message) -> Sequence[Message]:
        if isinstance(message, Commit) and message.view == self.view:
            return ()
        return (message,)


@dataclass
class Compose:
    """Apply behaviours in order; each sees the previous one's output."""

    parts: tuple[object, ...]

    def outgoing(self, replica: Replica, recipient: str, message: Message) -> Sequence[Message]:
        out: list[Message] = [message]
        for part in self.parts:
            out = [m2 for m in out for m2 in part.outgoing(replica, recipient, m)]  # type: ignore[attr-defined]
        return tuple(out)


@dataclass
class Collusion:
    """Shared state for two colluding byzantine replicas splitting the honest ones in two.

    `side_b` receives the sibling block; everyone else the original. Both colluders then vote,
    to each honest replica, for whichever block that replica holds.
    """

    side_b: frozenset[str]
    digests: dict[tuple[int, int], tuple[bytes, bytes]] = field(default_factory=dict)


@dataclass
class Colluding:
    collusion: Collusion
    _equivocator: Equivocating = field(default_factory=Equivocating)

    def outgoing(self, replica: Replica, recipient: str, message: Message) -> Sequence[Message]:
        side_b = recipient in self.collusion.side_b
        if isinstance(message, Proposal):
            a = message
            b = self._equivocator.variant(replica, message, 1)
            slot = (a.pre_prepare.view, a.pre_prepare.seq)
            self.collusion.digests[slot] = (a.pre_prepare.digest, b.pre_prepare.digest)
            return (b if side_b else a,)
        if isinstance(message, Prepare | Commit):
            pair = self.collusion.digests.get((message.view, message.seq))
            if pair is not None:
                wanted = pair[1] if side_b else pair[0]
                if message.digest != wanted:
                    return (resign(message, key_of(replica), digest=wanted),)
        return (message,)
