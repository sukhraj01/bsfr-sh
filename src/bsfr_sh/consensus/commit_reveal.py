"""Commit-then-reveal defense against honeypot poisoning. M7-14, DEV-40.

`docs/THREAT_MODEL.md` Gap 1 / DEV-38's own numbers: M7-12's statistical drift detector cannot
catch anchor-point injection at any budget, for a structural reason, not a tuning failure — the
attack's engineered midpoint between the two class centroids sits, in a roughly class-balanced
corpus, almost exactly at the *population* mean, so the batch designed to look most like an
attack looks the *least* anomalous of the three. That midpoint is only computable because the
adversary can see the honest distribution *before* deciding what to submit. This module removes
that advantage at the protocol level, not the statistics level: a node commits to its entire
batch — every feature value, not a count or a label hash (a commitment to size alone would let an
adversary commit early and fill the batch with anything at reveal time) — before any other node's
contribution for the round is visible, then reveals. A node that never reveals, or whose reveal
does not reproduce its commitment, is excluded from the round; the remaining verified batches are
merged and handed to the existing `framework._block_pipeline` unchanged.

Two things this module deliberately does NOT do
-------------------------------------------------
1. It does not decide *what* an honest vs. adversarial batch looks like — that is
   `detection/poisoning.py`'s and `scripts/m7_14_commit_reveal_defense.py`'s job. This module only
   provides the commit/verify/exclude mechanics; the *information constraint* the protocol is
   supposed to create (an adversary must decide its batch before seeing this round's honest data)
   is enforced by the caller's control flow — specifically, by never handing this round's honest
   batches to whatever produced the adversary's batch before `submit_with_commit_reveal` is
   called. A cryptographic commitment cannot, by itself, stop a caller who already leaked the
   honest data through some other channel; it can only prove, after the fact, that nobody *revised*
   their commitment once they saw it.
2. It does not add a new consensus message type or change `consensus/pbft.py` at all. Phase 3
   ("the verified batches are merged and committed through normal pBFT") is exactly
   `framework._block_pipeline.run`, called with the merged batch — the same function
   `phase2_collection` already calls for direct submission. Commit-reveal wraps that pipeline;
   it does not fork it (mirrors `consensus/validated_commit.py`'s own "reuses the threshold
   arithmetic, adds no new vote" posture, DEV-38). Because `consensus/` may depend only on
   `crypto/`/`blockchain/`/`util/` (CLAUDE.md §3 — `consensus/validated_commit.py`'s dependency on
   `detection/` is already the one named exception, and this module is not a second one), the
   pipeline-wrapping step itself (Phase 3's actual call into `framework._block_pipeline.run`)
   lives one layer up, in `framework.commit_reveal_pipeline.submit_with_commit_reveal` — this
   module provides Phases 1-2 and the merge decision (`CommitRevealRound`/`RoundResult`), framework
   calls them and then hands the merged batch to the pipeline it already owns.

The three-phase protocol
--------------------------
Phase 1 (commit): each contributing node computes `C_l = H(batch_l || r_l)` — `r_l` a random
blinding factor — and broadcasts only `C_l`. Binding the *entire* batch (`SignatureRecordPayload.
to_bytes()`, which includes `features` and `label`) into the pre-image, not a summary of it, is
what stops a node committing to "10 records" and then filling them in arbitrarily at reveal.

Phase 2 (reveal): each node reveals `(batch_l, r_l)`. Every other participant recomputes
`H(batch_l || r_l)` and checks it against `C_l`. A node that fails to reveal, or reveals a batch/
blinding-factor pair that does not reproduce its own commitment, is excluded from this round —
reported in `RoundResult`, never raised as an exception, so one non-revealing or malformed
participant cannot abort an otherwise-healthy round for the rest.

Phase 3 (merge + consensus): the verified batches are concatenated, in a canonical (sorted by
node id) order for determinism, and submitted as one `ClientRequest` through the existing pBFT
pipeline — unmodified.

Withholding is a liveness cost, not a safety cost (item 4c). `WithholdTracker` tracks each node's
consecutive-round non-reveal streak and, after `max_consecutive_withholds` in a row (default: the
same `f=1`-at-`n=4` bound `docs/ARCHITECTURE.md` §consensus already documents, not an
independently chosen number), stops inviting that node as a participant at all — a separate,
above-the-protocol decision a caller opts into, not something `CommitRevealRound` enforces itself.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from bsfr_sh.blockchain.transaction import SignatureRecordPayload
from bsfr_sh.crypto.hashing import tagged_h
from bsfr_sh.util.serialization import encode

__all__ = [
    "DEFAULT_MAX_CONSECUTIVE_WITHHOLDS",
    "DOMAIN_COMMIT_REVEAL_BATCH",
    "CommitRevealError",
    "CommitRevealRound",
    "Commitment",
    "Reveal",
    "RoundResult",
    "WithholdTracker",
    "commit_batch",
    "verify_reveal",
]

#: This round's commitment digest position. Distinct from every other `DOMAIN_*` in
#: `crypto.hashing` so a commitment can never be replayed as, or mistaken for, any other digest
#: this project computes.
DOMAIN_COMMIT_REVEAL_BATCH: Final = "bsfr_sh.hash.commit_reveal.batch.v1"

_BLINDING_FACTOR_BYTES: Final = 32

#: item 4c / `docs/ARCHITECTURE.md` §consensus: `n=4, f=1`. A node that withholds this many
#: consecutive rounds behaves indistinguishably from a permanently crashed or Byzantine replica,
#: so it is dropped from future rounds' participant list — the same fault count pBFT itself is
#: already built to tolerate, not a second, independently chosen threshold.
DEFAULT_MAX_CONSECUTIVE_WITHHOLDS: Final = 3


class CommitRevealError(ValueError):
    """Raised for a malformed commit/reveal *call* (unknown participant, double submission,
    empty participant list). Never raised for a Byzantine reveal mismatch or a withheld reveal —
    those are outcomes `CommitRevealRound.finalize()` reports in `RoundResult`, not exceptions,
    so one bad participant cannot abort the round for everyone else.
    """


def _batch_preimage(batch: Sequence[SignatureRecordPayload]) -> bytes:
    """Canonical encoding of an entire batch, every payload's every field included.

    `SignatureRecordPayload.to_bytes()` already covers `features`/`label`/`missing_mask`/etc. in
    one canonical encoding (`util/serialization.py`); wrapping the list of them in `encode()`
    gives one unambiguous, order-sensitive pre-image for the whole batch, so a node cannot commit
    to a batch's size (or its labels) alone and fill in different feature content at reveal time —
    item 1's explicit requirement.
    """
    return encode([payload.to_bytes() for payload in batch])


@dataclass(frozen=True)
class Commitment:
    """`C_l` — what a node broadcasts in Phase 1. Carries no information about `batch_l` beyond
    what a 32-byte digest can leak (nothing, under SHA-256's own assumptions)."""

    node_id: str
    digest: bytes


def commit_batch(
    node_id: str,
    batch: Sequence[SignatureRecordPayload],
    *,
    blinding_factor: bytes | None = None,
) -> tuple[Commitment, bytes]:
    """Phase 1: `C_l = H(batch_l || r_l)`.

    Returns the commitment to broadcast and the blinding factor the caller must hold until reveal
    (this function does not persist it anywhere). `blinding_factor` is only ever supplied
    explicitly by a test that needs a deterministic digest; production callers let this draw a
    fresh `os.urandom` value every round — it only needs to be unpredictable before reveal, never
    secret afterward, matching the module docstring's own framing.
    """
    r = blinding_factor if blinding_factor is not None else os.urandom(_BLINDING_FACTOR_BYTES)
    digest = tagged_h(DOMAIN_COMMIT_REVEAL_BATCH, _batch_preimage(batch), r)
    return Commitment(node_id=node_id, digest=digest), r


@dataclass(frozen=True)
class Reveal:
    """`(batch_l, r_l)` — what a node broadcasts in Phase 2."""

    node_id: str
    batch: tuple[SignatureRecordPayload, ...]
    blinding_factor: bytes


def verify_reveal(commitment: Commitment, reveal: Reveal) -> bool:
    """Does `H(reveal.batch || reveal.blinding_factor)` reproduce `commitment.digest`?

    Changing even one feature value, one label, or the blinding factor itself after committing
    changes the digest and fails this check — the property the TESTS section's "commitment
    verification fails for a node that changes its batch after committing" asks for.
    """
    if commitment.node_id != reveal.node_id:
        return False
    digest = tagged_h(
        DOMAIN_COMMIT_REVEAL_BATCH, _batch_preimage(reveal.batch), reveal.blinding_factor
    )
    return digest == commitment.digest


@dataclass(frozen=True)
class RoundResult:
    """One round's outcome. `merged` is in a canonical (participant-id-sorted) order — deterministic
    regardless of the order nodes happened to submit in, the same discipline `blockchain.chain`
    requires of everything that ends up inside a Merkle tree."""

    merged: tuple[SignatureRecordPayload, ...]
    included_node_ids: tuple[str, ...]
    excluded_node_ids: tuple[str, ...]
    exclusion_reasons: Mapping[str, str]


class CommitRevealRound:
    """Orchestrates one round for a fixed set of participating node ids.

    Usage: every participant calls `submit_commitment` once; every participant that intends to
    reveal calls `submit_reveal` once; `finalize()` verifies every reveal against its commitment
    and returns the merged, verified batch plus which nodes were excluded and why. A node that
    never reveals, or whose reveal does not match its own commitment, is excluded — reported,
    never raised — so one Byzantine or crashed participant cannot abort an otherwise-healthy
    round (the `f=1` crash-tolerance the TESTS section asks for).
    """

    def __init__(self, participant_ids: Sequence[str]) -> None:
        if not participant_ids:
            raise CommitRevealError("a round needs at least one participant")
        if len(set(participant_ids)) != len(participant_ids):
            raise CommitRevealError("duplicate participant id in one round")
        self._participants = tuple(participant_ids)
        self._commitments: dict[str, Commitment] = {}
        self._reveals: dict[str, Reveal] = {}

    @property
    def participant_ids(self) -> tuple[str, ...]:
        return self._participants

    def submit_commitment(self, commitment: Commitment) -> None:
        if commitment.node_id not in self._participants:
            raise CommitRevealError(f"{commitment.node_id!r} is not a participant this round")
        if commitment.node_id in self._commitments:
            raise CommitRevealError(f"{commitment.node_id!r} already committed this round")
        self._commitments[commitment.node_id] = commitment

    def submit_reveal(self, reveal: Reveal) -> None:
        if reveal.node_id not in self._participants:
            raise CommitRevealError(f"{reveal.node_id!r} is not a participant this round")
        if reveal.node_id in self._reveals:
            raise CommitRevealError(f"{reveal.node_id!r} already revealed this round")
        self._reveals[reveal.node_id] = reveal

    def finalize(self) -> RoundResult:
        included: list[str] = []
        excluded: list[str] = []
        reasons: dict[str, str] = {}
        merged: list[SignatureRecordPayload] = []
        for node_id in sorted(self._participants):
            commitment = self._commitments.get(node_id)
            reveal = self._reveals.get(node_id)
            if commitment is None:
                excluded.append(node_id)
                reasons[node_id] = "no commitment submitted"
            elif reveal is None:
                excluded.append(node_id)
                reasons[node_id] = "withheld reveal"
            elif not verify_reveal(commitment, reveal):
                excluded.append(node_id)
                reasons[node_id] = "reveal does not match commitment"
            else:
                included.append(node_id)
                merged.extend(reveal.batch)
        return RoundResult(
            merged=tuple(merged),
            included_node_ids=tuple(included),
            excluded_node_ids=tuple(excluded),
            exclusion_reasons=reasons,
        )


class WithholdTracker:
    """Tracks each node's consecutive-round non-participation streak across many rounds and
    decides permanent exclusion (item 4c: "how many rounds can the adversary withhold before the
    honest nodes notice and exclude it permanently").

    A withheld or invalid batch never enters the merged set regardless, every single round,
    whether or not the withholding node has crossed the permanent-exclusion line yet — this
    tracker only decides whether to keep *inviting* the node as a future participant. That is why
    withholding is a liveness cost (the round proceeds without the withheld batch immediately) and
    not a safety cost (nothing unverified ever enters the merged set) — the same distinction
    `docs/THREAT_MODEL.md` Gap 3 already draws for pBFT's own view-change liveness fragility.
    """

    def __init__(
        self, *, max_consecutive_withholds: int = DEFAULT_MAX_CONSECUTIVE_WITHHOLDS
    ) -> None:
        if max_consecutive_withholds < 1:
            raise CommitRevealError("max_consecutive_withholds must be at least 1")
        self._max = max_consecutive_withholds
        self._streaks: dict[str, int] = {}
        self._permanently_excluded: set[str] = set()

    @property
    def permanently_excluded(self) -> frozenset[str]:
        return frozenset(self._permanently_excluded)

    def record_round(self, result: RoundResult) -> None:
        """Call once per round, after `CommitRevealRound.finalize()`."""
        for node_id in result.included_node_ids:
            self._streaks[node_id] = 0
        for node_id in result.excluded_node_ids:
            streak = self._streaks.get(node_id, 0) + 1
            self._streaks[node_id] = streak
            if streak >= self._max:
                self._permanently_excluded.add(node_id)

    def eligible_participants(self, all_node_ids: Sequence[str]) -> tuple[str, ...]:
        """`all_node_ids`, minus anyone this tracker has permanently excluded — what a caller
        should pass as next round's `participant_ids`."""
        return tuple(n for n in all_node_ids if n not in self._permanently_excluded)
