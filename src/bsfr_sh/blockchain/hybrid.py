"""`HybridChain` — a private chain plus a public anchor chain. M7-5, DEV-33.

`blockchain.anchor` defines what one commitment *is*; this module schedules and commits them
against real `Chain`/`Block` objects. §VIII of the paper lists hybrid blockchain as its own stated
future work and gives no design at all — everything below is DECLARED, not derived from the
paper, and is recorded as such in `docs/DEVIATIONS.md` DEV-33.

Layering: this module holds no `consensus` or `framework` dependency, on purpose
------------------------------------------------------------------------------------
`docs/ARCHITECTURE.md`'s dependency direction is `util <- crypto <- blockchain <- consensus <-
framework`, enforced by `tests/unit/test_module_boundaries.py`. An early version of this module
drove the anchor chain through a full `consensus.pbft.Cluster` (even at a single node) so that
"the anchor chain has its own consensus" would be literally a pBFT instance — `test_module_
boundaries.py::test_nothing_below_framework_imports_it` correctly rejected it, because reaching
for `framework._block_pipeline` to submit-and-wait for that cluster pulled `blockchain` upward
across a boundary the rest of the codebase holds absolutely. The fix is not a workaround, it is
the right design: the anchor chain's "own consensus" for a single authority *is* sign-and-append —
there is no second replica to convince, so pBFT's message rounds would be pure overhead with
nothing underneath them. `HybridChain` therefore appends anchor blocks directly with
`Chain.append`, the same primitive `blockchain.chain.Chain` already offers any caller, and needs
nothing from `consensus` at all.

What this leaves for the framework layer to do
----------------------------------------------
`HybridChain` never reads a private cluster's replicas itself — doing that safely (checking that
enough replicas agree before trusting a height, the same rule `framework._block_pipeline.
read_chain` already implements for every other consumer) is a `consensus.interface.ConsensusCluster`
question, and that boundary lives above this module. Every method here that needs the private
chain's current state (`sync`, `verify_anchor`, `verify_range`) takes an already-trusted `Chain`
as a parameter instead of owning a reference to one. The caller — `framework.hybrid_pipeline`, a
thin module *above* this one — is what calls `framework._block_pipeline.read_chain(cluster)` to
get that trusted `Chain` and hands it in. This is what "hybrid is transparent to the framework"
means concretely: `phase1_backup.run`/`phase2_collection.run` are untouched (still take a plain
`consensus.pbft.Cluster`, exactly as before M7-5), and `framework.hybrid_pipeline.append` is one
thin wrapper that calls the existing pipeline first and this module's `sync`/`flush` after.

Anchor scheduling: opportunistic, plus one flush
---------------------------------------------------
`AnchorPolicy.frequency` is the cost/integrity lever the task brief asks for: 1 anchors every
private block (maximum integrity, maximum anchor traffic); `N` anchors every `N`-th block (`N`x
less anchor traffic, up to `N-1` blocks' tampering window). `sync()` anchors every due multiple of
`frequency` between the last-anchored height and the given chain's current height; `flush()`
additionally anchors the current head even when it is *not* an exact multiple, closing out a
trailing partial window rather than leaving it anchored only at the next multiple. Together these
give exactly `ceil(blocks_committed / frequency)` anchors for one `sync()`-then-`flush()` pair:
`floor(B/N)` from the multiples, plus one more from the flush if `B` is not itself a multiple of
`N`. Calling `sync()`-then-`flush()` many times with `frequency > 1` flushes after every call,
which can anchor more often than one global `ceil(total/N)` would — documented, not fixed, because
avoiding it needs state that persists *across* the paper's own once-per-phase append pattern for
no benefit any test here needs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from bsfr_sh.blockchain.anchor import AnchorRecord, create_anchor_record
from bsfr_sh.blockchain.block import Block
from bsfr_sh.blockchain.chain import Chain, ChainError
from bsfr_sh.blockchain.transaction import read_anchor_record, wrap_anchor_record
from bsfr_sh.crypto.ecdsa import PrivateKey
from bsfr_sh.util.config import Config
from bsfr_sh.util.logging import event, get_logger

__all__ = [
    "AnchorPolicy",
    "AnchorVerification",
    "HybridChain",
    "HybridChainError",
    "anchor_chain_name",
]

_LOG = get_logger("blockchain.hybrid")


class HybridChainError(RuntimeError):
    """Raised when an anchor cannot be built or appended, or a verification target is invalid."""


@dataclass(frozen=True)
class AnchorPolicy:
    """The cost/integrity lever. See the module docstring."""

    #: Anchor every Nth private block. 1 = every block (default: maximum integrity).
    frequency: int = 1

    def __post_init__(self) -> None:
        if self.frequency < 1:
            raise HybridChainError(f"anchor frequency must be at least 1, got {self.frequency}")

    @classmethod
    def from_config(cls, config: Config) -> AnchorPolicy:
        return cls(frequency=config.require("hybrid.anchor_frequency", int))


@dataclass(frozen=True)
class AnchorVerification:
    """The result of checking one private-chain height against the anchor chain.

    `anchored=False` means exactly what the security tests need it to mean: no anchor covers this
    height (either `frequency > 1` skipped it, or it has not been reached yet), so nothing here
    can be claimed either way. `anchored=True, verified=False` is the tamper-detected case.
    """

    block_height: int
    anchored: bool
    verified: bool
    record: AnchorRecord | None


def anchor_chain_name(private_chain_name: str, config: Config) -> str:
    """`f"{private_chain_name}{hybrid.anchor_chain_suffix}"` — read once, here, per CLAUDE.md §2:
    a config-declared value is never re-literalled at a call site."""
    suffix = config.require("hybrid.anchor_chain_suffix", str)
    return f"{private_chain_name}{suffix}"


#: Anchor block owner id, DECLARED — the anchor chain has exactly one signing authority (the
#: module docstring's "sign-and-append" design), so there is nothing for this to disambiguate
#: between; it exists only because `Chain.draft_next` requires an `owner_id`.
_ANCHOR_OWNER_ID: Final = "anchor_authority"


class HybridChain:
    """Schedules and commits `AnchorRecord`s for one private chain onto one anchor chain.

    Owns the anchor chain's genesis and signing key (a single authority — see the module
    docstring) but never owns, or caches, the private chain's state: every method that needs it
    takes an already-trusted `Chain` as a parameter, so this class carries no opinion about how
    that trust was established (pBFT quorum agreement, in every caller this codebase has).
    """

    def __init__(
        self,
        *,
        private_chain_name: str,
        anchor_chain_name: str,
        anchor_key: PrivateKey,
        policy: AnchorPolicy | None = None,
        genesis_timestamp: float = 0.0,
    ) -> None:
        if anchor_chain_name == private_chain_name:
            raise HybridChainError(
                f"anchor chain name {anchor_chain_name!r} must differ from the private chain's "
                f"{private_chain_name!r}, or the two would collide in any shared chain registry"
            )
        self.private_chain_name = private_chain_name
        self._anchor_key = anchor_key
        self.anchor_chain = Chain(anchor_chain_name)
        self.anchor_chain.create_genesis(
            owner_id=_ANCHOR_OWNER_ID, private_key=anchor_key, timestamp=genesis_timestamp
        )
        self.policy = policy if policy is not None else AnchorPolicy()
        self._last_anchored_height = 0  # genesis (height 0) is never anchored
        self._records: dict[int, AnchorRecord] = {}

    @property
    def anchored_heights(self) -> tuple[int, ...]:
        return tuple(sorted(self._records))

    # -- committing -------------------------------------------------------------------------------
    def sync(self, private_chain: Chain, *, timestamp: float) -> tuple[AnchorRecord, ...]:
        """Anchor every due multiple of `policy.frequency` up to `private_chain`'s current height.

        `private_chain` must be a height the caller already trusts (`framework._block_pipeline.
        read_chain`'s quorum-agreement rule, in every real caller) — this method does not, and
        architecturally cannot, check that itself. See the module docstring.
        """
        if private_chain.name != self.private_chain_name:
            raise HybridChainError(
                f"sync() got a {private_chain.name!r} chain, expected {self.private_chain_name!r}"
            )
        height = private_chain.height
        due = self._last_anchored_height + self.policy.frequency
        committed = []
        while due <= height:
            committed.append(self._append_anchor(private_chain.block_at(due), due, timestamp))
            self._last_anchored_height = due
            due += self.policy.frequency
        return tuple(committed)

    def flush(self, private_chain: Chain, *, timestamp: float) -> AnchorRecord | None:
        """Anchor the current head even if it is not an exact multiple of `policy.frequency`.

        Call `sync()` first — `flush()` only closes out a trailing partial window; it does not
        walk earlier due multiples itself. See the module docstring's scheduling section.
        """
        if private_chain.name != self.private_chain_name:
            raise HybridChainError(
                f"flush() got a {private_chain.name!r} chain, expected {self.private_chain_name!r}"
            )
        height = private_chain.height
        if self._last_anchored_height >= height:
            return None
        record = self._append_anchor(private_chain.block_at(height), height, timestamp)
        self._last_anchored_height = height
        return record

    def _append_anchor(self, block: Block, height: int, timestamp: float) -> AnchorRecord:
        record = create_anchor_record(
            anchored_chain=self.private_chain_name,
            block_height=height,
            block=block,
            timestamp=timestamp,
            creator_id=_ANCHOR_OWNER_ID,
            private_key=self._anchor_key,
        )
        tx = wrap_anchor_record(
            tx_id=f"anchor-{self.private_chain_name}-{height}-{block.current_hash.hex()[:16]}",
            plaintext=record.to_bytes(),
            created_at=int(timestamp),
        )
        draft = self.anchor_chain.draft_next(
            owner_id=_ANCHOR_OWNER_ID,
            owner_pubkey=self._anchor_key.public_key.to_bytes(),
            transactions=(tx,),
            timestamp=timestamp,
        )
        self.anchor_chain.append(draft.seal(self._anchor_key))
        self._records[height] = record
        event(
            _LOG,
            "anchor_committed",
            anchored_chain=self.private_chain_name,
            anchor_chain=self.anchor_chain.name,
            height=height,
        )
        return record

    # -- verification ---------------------------------------------------------------------------
    def verify_anchor(self, private_chain: Chain, block_height: int) -> AnchorVerification:
        """Check the private block at `block_height` against the anchor chain's record for it.

        Reads `private_chain` fresh on every call — nothing here is cached — so a block replaced
        in the private chain's own storage after being read once is still caught: this is what
        test (a), "tamper an anchored block", relies on. `private_chain` carries the same
        trusted-by-the-caller requirement `sync()`'s docstring states.
        """
        record = self._records.get(block_height)
        if record is None:
            return AnchorVerification(block_height, anchored=False, verified=False, record=None)
        try:
            block = private_chain.block_at(block_height)
        except ChainError as exc:
            raise HybridChainError(
                f"cannot read {self.private_chain_name} height {block_height} to verify: {exc}"
            ) from exc
        return AnchorVerification(
            block_height,
            anchored=True,
            verified=record.matches(block, height=block_height),
            record=record,
        )

    def verify_range(
        self, private_chain: Chain, start: int, end: int
    ) -> tuple[AnchorVerification, ...]:
        """`verify_anchor` for every height in `[start, end]`, inclusive."""
        if start > end:
            raise HybridChainError(f"start ({start}) must not exceed end ({end})")
        if start < 1:
            raise HybridChainError("start must be at least 1; genesis (height 0) is never anchored")
        return tuple(self.verify_anchor(private_chain, h) for h in range(start, end + 1))

    def verify_anchor_chain_integrity(self) -> None:
        """Raise `ChainError` if the anchor chain's own storage has been tampered with.

        This is test (c)'s check, and its own docstring states the assumption it rests on: this
        catches tampering of the anchor chain's *stored* blocks (a rewritten header, a broken
        link, a bad signature) exactly as `Chain.verify_integrity` catches it for any chain. It
        does **not** model an attacker who controls the anchor authority's own signing key from
        the start — in production the anchor chain is a real public blockchain with its own,
        separate consensus, and an operator who also controlled that would defeat the entire
        hybrid design, not just this check. See `docs/DEVIATIONS.md` DEV-33.
        """
        self.anchor_chain.verify_integrity()

    def read_anchor_record_from_chain(self, block_height: int) -> AnchorRecord | None:
        """Decode the `AnchorRecord` committed on the anchor chain for `block_height`, if any.

        Reads through the anchor chain's own transactions, not `self._records` — a second, slower
        path to the same answer `verify_anchor` uses `self._records` for, useful for a test or a
        genuinely external verifier that only has the anchor chain and none of `HybridChain`'s
        in-process bookkeeping.
        """
        for block in self.anchor_chain:
            for tx in block.transactions:
                record = AnchorRecord.from_bytes(read_anchor_record(tx))
                if (
                    record.anchored_chain == self.private_chain_name
                    and record.block_height == block_height
                ):
                    return record
        return None

    def __repr__(self) -> str:
        return (
            f"HybridChain(private={self.private_chain_name!r}, "
            f"anchor={self.anchor_chain.name!r}, frequency={self.policy.frequency}, "
            f"anchored={len(self._records)})"
        )
