"""Pre-commit semantic validation for `BC_SigRW` — M7-12, the defense M7-11 measured the absence
of.

`docs/THREAT_MODEL.md` Gap 1 (measured, M7-11): a validly-signed, validly-linked block carrying a
poisoned `Sig_RW`/`FT_RW` record commits exactly as cleanly as an honest one, because
`Chain.check_append()`'s five checks (`docs/ARCHITECTURE.md` §blockchain) are all structural or
cryptographic; none inspect what a record actually says. `consensus/pbft.py`'s own division of
labour is the integration point this module uses rather than inventing a new one: "Consensus
decides whether, `Chain` decides valid... A replica prepares a block only if its own
`Chain.check_append()` accepts it." `ValidatedSigRWChain` widens that one gate — it runs
`detection.drift.DriftDetector` over the block's decrypted `Sig_RW` batch before `check_append()`
returns, so an honest replica that would otherwise vote to commit a distributionally anomalous
batch instead raises `ChainError` and is rejected by its own pBFT loop exactly like a bad
signature would be. `consensus/pbft.py`'s vote-counting logic (prepare/commit thresholds, view
change) is untouched by this module — the only pbft.py change this session makes is
`Cluster.__init__` taking an optional `chain_factory` (default `Chain`, so `BC_DTBU`'s commit
path is byte-for-byte unchanged, per this session's OUT OF SCOPE line).

Why the threshold arithmetic itself is the enforcement mechanism
------------------------------------------------------------------
Nothing here changes how many matching prepares/commits a slot needs. If every honest replica's
`ValidatedSigRWChain` independently rejects a poisoned proposal (`Chain.check_append` raising
before the replica ever sends a `Prepare`), the `2f` prepare quorum and `2f+1` commit threshold
simply never see enough honest votes to be reached — a Tier-2 adversary who also controls one
consensus replica can still vote to accept its own poison, but `f=1` means at most one dissenting
vote, never enough. This is why the mechanism is called *pre-commit consensus refusal*, not a new
kind of vote: it reuses `n=4, f=1, threshold=3` exactly as `docs/ARCHITECTURE.md` §consensus
already documents them.

Two new trust assumptions this module adds (`docs/THREAT_MODEL.md` states both formally)
--------------------------------------------------------------------------------------------
**TA-6, decryption.** `blockchain/transaction.py`'s own docstring names the invariant this module
narrows: "Miners in M2b validate blocks they cannot read; that is the point." `Sig_RW`/`FT_RW`
payloads are hybrid-encrypted to one recipient (DEV-01); a consensus replica does not hold that
key by default. A drift check over plaintext features cannot run without plaintext features, so
`ValidatedSigRWChain` requires a decryption key for every batch it scores. This widens "miners
validate blocks they cannot read" to "these particular miners can, for this one chain, so they
can also judge whether what they read looks honest" — a real, costed change to the confidentiality
model, not a detail to wave past. A transaction none of the supplied keys open is skipped, not
raised on (`extract_feature_batch`): this validates what it *can* read, and is blind to the rest.

**TA-7, shared policy.** Every honest replica must run `DriftDetector` with the same
`detection.drift.DriftPolicy` and see batches in the same order — the latter already guaranteed
by pBFT's total order within one chain. A replica with a different threshold, a different
decryption capability, or a profile that has silently diverged from its peers' disagrees with
them about whether to vote, and that disagreement is itself exploitable by an adversary who can
induce it.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import numpy as np

from bsfr_sh.blockchain.block import Block
from bsfr_sh.blockchain.chain import Chain, ChainError, ChainPolicy
from bsfr_sh.blockchain.transaction import (
    PAYLOAD_TYPE_SIGNATURE_RECORD,
    SignatureRecordPayload,
    TransactionError,
    decrypt,
)
from bsfr_sh.consensus.pbft import ChainFactory
from bsfr_sh.crypto.ecdsa import PrivateKey
from bsfr_sh.detection.drift import DriftDetector, DriftPolicy, DriftReport
from bsfr_sh.util.logging import event, get_logger

__all__ = [
    "ValidatedSigRWChain",
    "build_validated_sigrw_chain_factory",
    "extract_feature_batch",
]

_LOG = get_logger("consensus.validated_commit")


def extract_feature_batch(block: Block, *, decrypt_keys: Sequence[PrivateKey]) -> np.ndarray | None:
    """Decrypt every readable `Sig_RW` transaction in `block` and stack its `FT_RW` vector.

    Tries each key in `decrypt_keys` in turn — a block may in principle carry records encrypted
    to different recipients. A transaction none of them open is skipped, not raised on (TA-6's
    stated blind spot). Returns `None` if the block carries no readable `Sig_RW` record, which
    `ValidatedSigRWChain.check_append` reads as "nothing to score," not as a rejection.
    """
    rows: list[tuple[float, ...]] = []
    for tx in block.transactions:
        if tx.payload_type != PAYLOAD_TYPE_SIGNATURE_RECORD:
            continue
        for key in decrypt_keys:
            try:
                plaintext = decrypt(key, tx)
            except TransactionError:
                continue
            record = SignatureRecordPayload.from_bytes(plaintext)
            rows.append(record.features)
            break
    if not rows:
        return None
    return np.asarray(rows, dtype=float)


class ValidatedSigRWChain(Chain):
    """A `BC_SigRW` `Chain` whose `check_append()` also runs `DriftDetector` over the block's
    decrypted `Sig_RW` batch.

    One instance per replica: `consensus.pbft.Cluster.__init__` already builds one `Chain` per
    replica, so passing this class's factory in gives each replica its own independent
    `DriftDetector` and therefore its own running profile — "each honest replica maintains a
    running statistical profile" (task brief) is exactly this, at exactly that granularity.

    `Chain.append()` calls `self.check_append(block)` internally (see `blockchain/chain.py`), so
    overriding only `check_append` already gates both the pre-vote check (`Replica.
    _accept_proposal`) and the at-commit re-check (`Replica._execute`) — no separate override
    needed there. `append()` is overridden only to call `DriftDetector.update()` once the block
    has actually landed, never on a batch that was merely checked and rejected.
    """

    __slots__ = ("_decrypt_keys", "_detector", "drift_events")

    def __init__(
        self,
        name: str,
        *,
        policy: ChainPolicy | None,
        detector: DriftDetector,
        decrypt_keys: Sequence[PrivateKey],
    ) -> None:
        super().__init__(name, policy=policy)
        self._detector = detector
        self._decrypt_keys = tuple(decrypt_keys)
        self.drift_events: list[DriftReport] = []

    @property
    def detector(self) -> DriftDetector:
        return self._detector

    def check_append(self, block: Block) -> None:
        """`Chain.check_append`'s five checks, plus a sixth: does this batch's feature
        distribution look like the chain's own history, or like an attempt to move it?
        """
        super().check_append(block)
        batch = extract_feature_batch(block, decrypt_keys=self._decrypt_keys)
        if batch is None:
            return
        report = self._detector.score_batch(batch)
        if not report.drift_detected:
            return
        self.drift_events.append(report)
        event(
            _LOG,
            "drift_detected",
            level=logging.WARNING,
            chain=self.name,
            method=report.method.value,
            score=report.score,
            threshold=report.threshold,
            offending_features=list(report.offending_features),
            n_history_batches=report.n_history_batches,
        )
        raise ChainError(
            f"{self.name}: batch fails drift check ({report.method.value} "
            f"score={report.score:.4f} >= threshold={report.threshold:.4f}); "
            f"offending features: {', '.join(report.offending_features) or '(aggregate only)'}"
        )

    def append(self, block: Block) -> None:
        super().append(block)
        batch = extract_feature_batch(block, decrypt_keys=self._decrypt_keys)
        if batch is not None:
            self._detector.update(batch)


def build_validated_sigrw_chain_factory(
    *,
    n_features: int,
    decrypt_keys: Sequence[PrivateKey],
    feature_names: Sequence[str] | None = None,
    drift_policy: DriftPolicy | None = None,
) -> ChainFactory:
    """A `consensus.pbft.Cluster(chain_factory=...)` value for a `BC_SigRW` cluster.

    Called once per replica by `Cluster.__init__`'s membership loop, so each call builds a fresh
    `DriftDetector` — one independent running profile per replica, never one shared object (a
    shared detector would silently defeat TA-7's "independently agree" framing by making
    agreement trivial rather than a real assumption about matching policy and message order).
    """

    def factory(name: str, *, policy: ChainPolicy | None) -> Chain:
        detector = DriftDetector(n_features, feature_names=feature_names, policy=drift_policy)
        return ValidatedSigRWChain(
            name, policy=policy, detector=detector, decrypt_keys=decrypt_keys
        )

    return factory
