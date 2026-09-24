"""Raft test harness: fixture keys, cluster builders, transactions, a byzantine leader fixture.

Not a test module (no `test_` prefix); imported by the raft tests. Mirrors `pbft_harness.py`'s
shape deliberately — same fixture-key discipline (CLAUDE.md §4b), same `run_for`/`assert_no_fork`
pattern — so the two test suites read as comparable, which is the point of M7-4.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from bsfr_sh.blockchain.block import Block, BlockDraft
from bsfr_sh.blockchain.chain import BC_DTBU, build_genesis
from bsfr_sh.blockchain.transaction import BackupPayload, Transaction, encrypt_backup
from bsfr_sh.consensus.raft import AppendEntries, LogEntry, RaftCluster, RaftNode, RaftPolicy
from bsfr_sh.crypto.ecdsa import KeyPair, PrivateKey, PublicKey, keypair_from_secret
from bsfr_sh.util.config import load_config

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
#: The configured policy — n=4, randomized election timeout, heartbeat well under it.
POLICY = RaftPolicy.from_config(CONFIG)

DTBU_IDS = ("CS_0", "CS_1", "CS_2", "CS_3")
GENESIS_TIME = 1000.0
#: Long enough for several elections at the configured timeouts; short enough to stay fast.
HORIZON_S = 200 * POLICY.election_timeout_max_s

#: `CS_l` whose public key the test transactions are encrypted to. Not a node.
RECIPIENT: KeyPair = keypair_from_secret(0x5EED5EED)
#: The default authorized `ClientRequest` submitter every `make_cluster()` cluster trusts.
SUBMITTER_ID: str = "SUBMITTER"
SUBMITTER: KeyPair = keypair_from_secret(0x5AB4171E)


def node_keys(ids: Iterable[str]) -> dict[str, PrivateKey]:
    return {rid: keypair_from_secret(0xC0FFEE00 + int(rid.split("_")[1])).private for rid in ids}


def make_cluster(
    chain_name: str = BC_DTBU,
    ids: Sequence[str] = DTBU_IDS,
    *,
    seed: int = 7,
    policy: RaftPolicy = POLICY,
    submitters: Mapping[str, PublicKey] | None = None,
) -> RaftCluster:
    keys = node_keys(ids)
    genesis = build_genesis(owner_id=ids[0], private_key=keys[ids[0]], timestamp=GENESIS_TIME)
    if submitters is None:
        submitters = {SUBMITTER_ID: SUBMITTER.public}
    return RaftCluster(
        chain_name=chain_name,
        keys=keys,
        genesis=genesis,
        policy=policy,
        seed=seed,
        submitters=submitters,
    )


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


def submit_block(cluster: RaftCluster, index: int, *, count: int = 2) -> bytes:
    return cluster.submit(
        make_transactions(f"{cluster.chain_name}-b{index}", count),
        timestamp=GENESIS_TIME + 1 + index,
        submitter_id=SUBMITTER_ID,
        key=SUBMITTER.private,
    )


def run_for(cluster: RaftCluster, seconds: float = HORIZON_S) -> None:
    """Run the bus for a bounded stretch of simulated time. Byzantine runs may never go idle."""
    cluster.run(until=cluster.network.now + seconds)


def leader_of(cluster: RaftCluster) -> RaftNode:
    leaders = [n for n in cluster.nodes.values() if n.is_leader]
    assert len(leaders) == 1, f"expected exactly one leader, found {[n.node_id for n in leaders]}"
    return leaders[0]


def honest(cluster: RaftCluster, byzantine: Iterable[str] = ()) -> list[RaftNode]:
    skip = set(byzantine)
    return [n for rid, n in cluster.nodes.items() if rid not in skip]


def assert_no_fork(nodes: Sequence[RaftNode]) -> None:
    """Safety: no two of these nodes hold different blocks at any (applied) height."""
    top = max(n.height for n in nodes)
    for height in range(top + 1):
        held = {n.chain.block_at(height).current_hash for n in nodes if n.height >= height}
        assert len(held) == 1, f"fork at height {height}: {len(held)} different blocks"


def key_of(node: RaftNode) -> PrivateKey:
    return node._private_key


def resealed(block: Block, key: PrivateKey) -> Block:
    """A fresh sibling of `block`: same owner/parent/timestamp, a different `RN` (hence digest)."""
    return BlockDraft(
        owner_id=block.owner_id,
        owner_pubkey=block.owner_pubkey,
        transactions=block.transactions,
        prev_hash=block.prev_hash,
        timestamp=block.timestamp,
    ).seal(key)


# --------------------------------------------------------------------------------------------
# The one byzantine fixture this suite needs
# --------------------------------------------------------------------------------------------
@dataclass
class EquivocatingLeader:
    """As leader, sends genuinely different transaction data to different followers at one
    `(term, index)` — both variants honestly signed with the leader's own real key, since a
    byzantine leader in Raft needs no forged signature to lie; it simply says different things to
    different people. `side_b` gets `variant_transactions`; everyone else gets whatever the
    protocol honestly proposed. See `consensus/raft.py`'s module docstring and
    `tests/unit/test_raft_byzantine.py`.
    """

    side_b: frozenset[str]
    variant_transactions: tuple[Transaction, ...]
    _variant: LogEntry | None = field(default=None, init=False, repr=False)

    def outgoing(self, node: RaftNode, recipient: str, message: object) -> Sequence[object]:
        if isinstance(message, AppendEntries) and message.entries and recipient in self.side_b:
            original = message.entries[0]
            if self._variant is None or self._variant.index != original.index:
                key = key_of(node)
                block = original.block
                fabricated = BlockDraft(
                    owner_id=block.owner_id,
                    owner_pubkey=block.owner_pubkey,
                    transactions=self.variant_transactions,
                    prev_hash=block.prev_hash,
                    timestamp=block.timestamp,
                ).seal(key)
                self._variant = LogEntry(term=original.term, index=original.index, block=fabricated)
            message = AppendEntries(
                chain=message.chain,
                term=message.term,
                leader_id=message.leader_id,
                prev_log_index=message.prev_log_index,
                prev_log_term=message.prev_log_term,
                entries=(self._variant,),
                leader_commit=message.leader_commit,
            )
        return (message,)
