"""BitcoinHeist: loading it, verifying it, and the two evaluation modes. Targets 1-2, DEV-06.

The paper evaluates on the BitcoinHeist Ransomware Address Dataset (ref [15], Akcora et al.,
IJCAI 2021): 2,916,697 rows, 2,875,284 of them benign and 41,413 ransomware — **1.42% positive**.
`docs/EXPERIMENTS.md` Target 2 holds the shape; this module is the code that reads it.

Three things here are decisions rather than plumbing.

`address` is dropped at read time (DEV-07's neighbour)
------------------------------------------------------
`address` is the wallet identifier. It is not a feature: a model that sees it can memorise which
addresses were labelled ransomware, which is leakage dressed as accuracy. The paper never says it
was dropped. It is excluded in `usecols`, so it is never materialised — 2.9M Python strings as
`object` dtype cost more memory than all nine numeric columns put together, on a box with 8 GB.

The counts are verified before anything is fitted
-------------------------------------------------
Every reproduction claim is anchored to §VII's numbers, so `load_bitcoinheist` checks them and
raises rather than continuing on a file that is a different version of the dataset. A number
produced from unverified data is not a reproduction of anything.

`paper_mode`'s size is bounded by arithmetic, and that is a finding
-------------------------------------------------------------------
The paper resamples to 90% ransomware / 10% benign. Only 41,413 ransomware rows exist in the whole
dataset, so such a split holds at most `41,413 / 0.9 ≈ 46,014` rows — **1.6% of the 2.9M rows the
paper cites**. The headline 98.98% accuracy therefore comes from a ~46K-row experiment on a
class balance that does not occur anywhere outside the resample. `paper_mode_arithmetic()` is a
pure function so this can be asserted without touching the file, and the realised `n` is recorded
in `RESULTS.md`.

M4b — the second half of FLAW-2's dual feature source
-------------------------------------------------------
Everything above is `bitcoinheist`: the paper's actual evaluation data. `BitcoinHeistBackend`,
`HoneypotBackend`, `DatasetBackend` and `backend_from_config` at the bottom of this module are the
"selected by config, never hardcoded" half `docs/ALGORITHMS.md` Alg. 3 promises — the honeypot
path the framework actually describes (§IV-C), decrypted from `BC_SigRW` via `load_from_chain()`
rather than read from `data/honeypot/*.csv` directly. Both backends produce a `DetectionDataset`,
the one shape `detection.profiles` and `detection.detector` need; `LoadedDataset` above stays
BitcoinHeist-specific (resamples, groups, `matches_paper_counts`) because none of that generalises
to a corpus this project generated itself.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from bsfr_sh.blockchain.chain import BC_SigRW, Chain, ChainError
from bsfr_sh.blockchain.transaction import (
    PAYLOAD_TYPE_SIGNATURE_RECORD,
    SignatureRecordPayload,
    Transaction,
    TransactionError,
)
from bsfr_sh.honeypot import features as ft
from bsfr_sh.honeypot.collector import BENIGN, MALICIOUS
from bsfr_sh.util.config import Config

__all__ = [
    "BENIGN_LABEL",
    "DROPPED_COLUMNS",
    "EXPECTED_POSITIVE_RATE",
    "EXPECTED_RANSOMWARE",
    "EXPECTED_ROWS",
    "EXPECTED_WHITE",
    "FEATURE_COLUMNS",
    "GROUP_COLUMN",
    "LABEL_COLUMN",
    "BitcoinHeistBackend",
    "DatasetBackend",
    "DatasetError",
    "DatasetSpec",
    "Decryptor",
    "DetectionDataset",
    "FamilyDataset",
    "HoneypotBackend",
    "LoadedDataset",
    "backend_from_config",
    "encode_group_column",
    "grouped_stratified_holdout",
    "load_bitcoinheist",
    "load_bitcoinheist_families",
    "load_from_chain",
    "paper_mode_arithmetic",
    "paper_mode_resample",
    "stratified_folds",
    "stratified_holdout",
    "subsample_index",
    "verify_counts",
]

#: §VII / the dataset card. Anchors every reproduction claim in this milestone.
EXPECTED_ROWS: Final = 2_916_697
EXPECTED_WHITE: Final = 2_875_284
EXPECTED_RANSOMWARE: Final = 41_413
EXPECTED_POSITIVE_RATE: Final = EXPECTED_RANSOMWARE / EXPECTED_ROWS  # 0.014199...

LABEL_COLUMN: Final = "label"
BENIGN_LABEL: Final = "white"
#: Identifier, never a feature. See the module docstring.
DROPPED_COLUMNS: Final = ("address",)
#: Q10 (docs/DEVIATIONS.md DEV-06): the grouping key for a split that keeps one address's rows
#: together, and the column an "address kept" ablation would encode.
GROUP_COLUMN: Final = "address"
FEATURE_COLUMNS: Final = (
    "year",
    "day",
    "length",
    "weight",
    "count",
    "looped",
    "neighbors",
    "income",
)

#: Narrow dtypes: the whole point of dropping `address` is undone by loading the rest as float64.
_DTYPES: Final = {
    "year": "int16",
    "day": "int16",
    "length": "int32",
    "weight": "float32",
    "count": "int32",
    "looped": "int32",
    "neighbors": "int32",
    "income": "float64",  # satoshi counts reach 5e15; float32 would round them
    "label": "string",
    "address": "string",
}


class DatasetError(ValueError):
    """Raised when the dataset is missing, misshapen, or not the one the paper used."""


@dataclass(frozen=True)
class DatasetSpec:
    """Where the data is and how `configs/ml.yaml` says to read it."""

    path: Path
    feature_columns: tuple[str, ...] = FEATURE_COLUMNS
    label_column: str = LABEL_COLUMN
    benign_label: str = BENIGN_LABEL
    drop_columns: tuple[str, ...] = DROPPED_COLUMNS
    subsample_rows: int | None = None
    subsample_stratified: bool = True
    #: `group_column` loads a column purely for grouping (`grouped_stratified_holdout`); it never
    #: reaches the feature matrix unless `encode_group_as_feature` also asks for that. The
    #: production config (`configs/ml.yaml`) sets this to `address` (D6, DEV-06 amendment);
    #: `encode_group_as_feature` stays Q10-only — production never turns the group into a feature.
    group_column: str | None = None
    encode_group_as_feature: bool = False

    @classmethod
    def from_config(
        cls, config: Config, *, root: Path, subsample: bool | None = None
    ) -> DatasetSpec:
        """Build from the `ml` config. `subsample=None` follows `dataset.subsample.enabled`."""
        enabled = bool(config.get("dataset.subsample.enabled", False))
        if subsample is not None:
            enabled = subsample
        rows = int(config.get("dataset.subsample.rows", 0)) or None
        return cls(
            path=root / "data" / "raw" / "BitcoinHeistData.csv",
            feature_columns=tuple(config.require("dataset.feature_columns", list)),
            label_column=config.require("dataset.label_column", str),
            benign_label=config.require("dataset.benign_label", str),
            drop_columns=tuple(config.require("dataset.drop_columns", list)),
            subsample_rows=rows if enabled else None,
            subsample_stratified=bool(config.get("dataset.subsample.stratified", True)),
            group_column=config.get("dataset.group_column", None),
        )


@dataclass(frozen=True)
class LoadedDataset:
    """The dataset as a feature matrix and a binary target, plus what was counted on the way in."""

    features: pd.DataFrame
    labels: np.ndarray
    source: Path
    n_rows: int
    n_positive: int
    n_negative: int
    #: True when the full file matched §VII exactly. False after subsampling, and recorded as such.
    matches_paper_counts: bool
    families: int
    #: The raw grouping key per row (`address`), aligned with `features`/`labels`. `None` unless
    #: `DatasetSpec.group_column` was set; the production config sets it (D6, DEV-06 amendment).
    groups: np.ndarray | None = None

    @property
    def positive_rate(self) -> float:
        return self.n_positive / self.n_rows

    @property
    def columns(self) -> tuple[str, ...]:
        return tuple(self.features.columns)

    def as_dict(self) -> dict[str, object]:
        """For the run sidecar."""
        return {
            "source": self.source.name,
            "n_rows": self.n_rows,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "positive_rate": self.positive_rate,
            "matches_paper_counts": self.matches_paper_counts,
            "ransomware_families": self.families,
            "columns": list(self.columns),
        }


def verify_counts(n_rows: int, n_positive: int, n_negative: int) -> None:
    """Raise unless the counts are §VII's. Called before any model is fitted."""
    actual = (n_rows, n_negative, n_positive)
    expected = (EXPECTED_ROWS, EXPECTED_WHITE, EXPECTED_RANSOMWARE)
    if actual != expected:
        raise DatasetError(
            "BitcoinHeist counts do not match the paper: "
            f"rows {n_rows} (expected {EXPECTED_ROWS}), "
            f"benign {n_negative} (expected {EXPECTED_WHITE}), "
            f"ransomware {n_positive} (expected {EXPECTED_RANSOMWARE}). "
            "Every reproduction claim is anchored to these numbers, so this is a stop, not a "
            "warning: fetch the dataset named in docs/EXPERIMENTS.md Target 2."
        )


def load_bitcoinheist(spec: DatasetSpec, *, verify: bool = True, seed: int = 0) -> LoadedDataset:
    """Read the CSV into a feature matrix and a binary target. Implements Target 2's loading.

    `verify=True` requires the file to be exactly the paper's. Subsampling (for the 8 GB box, see
    CLAUDE.md §6) happens *after* verification, so the check is always against the whole file.
    """
    if not spec.path.exists():
        raise DatasetError(
            f"{spec.path} is missing. `make data` fetches and verifies it; the dataset is "
            "gitignored because it is 2.9M rows."
        )
    usecols = [*spec.feature_columns, spec.label_column]
    if spec.group_column and spec.group_column not in usecols:
        usecols = [*usecols, spec.group_column]
    dtypes = {name: _DTYPES[name] for name in usecols if name in _DTYPES}
    frame = pd.read_csv(spec.path, usecols=usecols, dtype=dtypes)

    for dropped in spec.drop_columns:
        if dropped == spec.group_column:
            continue  # loaded only for grouping (D6); never reaches `features` below
        if dropped in frame.columns:  # pragma: no cover - usecols already excluded it
            raise DatasetError(f"{dropped!r} reached the frame; it must be excluded at read time")

    label_text = frame[spec.label_column]
    labels = (label_text != spec.benign_label).to_numpy(dtype=np.int8)
    families = int(label_text[label_text != spec.benign_label].nunique())
    n_rows = len(frame)
    n_positive = int(labels.sum())
    n_negative = n_rows - n_positive
    if verify:
        verify_counts(n_rows, n_positive, n_negative)

    features = frame[list(spec.feature_columns)]
    if spec.encode_group_as_feature:
        if not spec.group_column:
            raise DatasetError("encode_group_as_feature requires group_column to be set")
        features = features.copy()
        features[spec.group_column] = encode_group_column(frame[spec.group_column])

    groups = frame[spec.group_column].to_numpy() if spec.group_column else None

    matches = (n_rows, n_negative, n_positive) == (
        EXPECTED_ROWS,
        EXPECTED_WHITE,
        EXPECTED_RANSOMWARE,
    )

    if spec.subsample_rows is not None and spec.subsample_rows < n_rows:
        index = subsample_index(
            labels, spec.subsample_rows, stratified=spec.subsample_stratified, seed=seed
        )
        features = features.iloc[index]
        labels = labels[index]
        if groups is not None:
            groups = groups[index]
        n_rows = len(index)
        n_positive = int(labels.sum())
        n_negative = n_rows - n_positive
        matches = False

    return LoadedDataset(
        features=features.reset_index(drop=True),
        labels=labels,
        source=spec.path,
        n_rows=n_rows,
        n_positive=n_positive,
        n_negative=n_negative,
        matches_paper_counts=matches,
        families=families,
        groups=groups,
    )


@dataclass(frozen=True)
class FamilyDataset:
    """Like `LoadedDataset`, but the target is the family name (`"white"` or one of the 28
    ransomware families), never binarized. M7-16: whether the same 8 address-level graph features
    that support the binary ransomware/benign boundary also support 28+1 separate ones.

    Deliberately its own type rather than a `LoadedDataset` field — `LoadedDataset.labels` is
    typed and used everywhere downstream as `np.int8`, and overloading it with strings would make
    every existing binary caller a silent trap.
    """

    features: pd.DataFrame
    family_labels: np.ndarray  # dtype object: "white" or a family name, unmerged
    source: Path
    n_rows: int
    n_positive: int
    n_negative: int
    #: True when the full file matched §VII exactly (same meaning as `LoadedDataset`'s field).
    matches_paper_counts: bool
    #: The raw grouping key per row (`address`), aligned with `features`/`family_labels`.
    groups: np.ndarray | None = None

    @property
    def positive_rate(self) -> float:
        return self.n_positive / self.n_rows

    @property
    def columns(self) -> tuple[str, ...]:
        return tuple(self.features.columns)

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source.name,
            "n_rows": self.n_rows,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "positive_rate": self.positive_rate,
            "matches_paper_counts": self.matches_paper_counts,
            "columns": list(self.columns),
        }


def load_bitcoinheist_families(
    spec: DatasetSpec, *, verify: bool = True, seed: int = 0
) -> FamilyDataset:
    """Like `load_bitcoinheist`, but keeps the family name as the target instead of binarizing it.

    Reuses the same read path — `usecols`, dtypes, the `address` drop, §VII count verification,
    and `subsample_index`'s stratified sampling (stratified on the binary ransomware/benign split,
    since that is the rate §VII anchors; family balance within the ransomware side is exactly the
    thing `detection.multiclass.merge_rare_families` handles downstream, not a sampling decision).
    Kept as a sibling function rather than a `binarize: bool` flag on `load_bitcoinheist` so the
    already-tested binary path is untouched by this addition.
    """
    if not spec.path.exists():
        raise DatasetError(
            f"{spec.path} is missing. `make data` fetches and verifies it; the dataset is "
            "gitignored because it is 2.9M rows."
        )
    usecols = [*spec.feature_columns, spec.label_column]
    if spec.group_column and spec.group_column not in usecols:
        usecols = [*usecols, spec.group_column]
    dtypes = {name: _DTYPES[name] for name in usecols if name in _DTYPES}
    frame = pd.read_csv(spec.path, usecols=usecols, dtype=dtypes)

    for dropped in spec.drop_columns:
        if dropped == spec.group_column:
            continue  # loaded only for grouping; never reaches `features` below
        if dropped in frame.columns:  # pragma: no cover - usecols already excluded it
            raise DatasetError(f"{dropped!r} reached the frame; it must be excluded at read time")

    family_labels = frame[spec.label_column].astype(object).to_numpy()
    is_positive = family_labels != spec.benign_label
    n_rows = len(frame)
    n_positive = int(is_positive.sum())
    n_negative = n_rows - n_positive
    if verify:
        verify_counts(n_rows, n_positive, n_negative)

    features = frame[list(spec.feature_columns)]
    groups = frame[spec.group_column].to_numpy() if spec.group_column else None

    matches = (n_rows, n_negative, n_positive) == (
        EXPECTED_ROWS,
        EXPECTED_WHITE,
        EXPECTED_RANSOMWARE,
    )

    if spec.subsample_rows is not None and spec.subsample_rows < n_rows:
        index = subsample_index(
            is_positive.astype(np.int8),
            spec.subsample_rows,
            stratified=spec.subsample_stratified,
            seed=seed,
        )
        features = features.iloc[index]
        family_labels = family_labels[index]
        if groups is not None:
            groups = groups[index]
        n_rows = len(index)
        n_positive = int((family_labels != spec.benign_label).sum())
        n_negative = n_rows - n_positive
        matches = False

    return FamilyDataset(
        features=features.reset_index(drop=True),
        family_labels=family_labels,
        source=spec.path,
        n_rows=n_rows,
        n_positive=n_positive,
        n_negative=n_negative,
        matches_paper_counts=matches,
        groups=groups,
    )


def encode_group_column(values: pd.Series) -> np.ndarray:
    """Ordinal-encode a string column via scikit-learn's `LabelEncoder`. Q10 only.

    This is the encoding a straightforward implementation reaches for when told to keep an
    identifier column as a feature: one call, sorted unique values, dense integer codes, no
    awareness that it is handing the model a near-unique key. That is deliberate here — it names
    what an unexamined "kept address" baseline actually does, not a strawman built to fail.
    """
    codes: np.ndarray = LabelEncoder().fit_transform(values.to_numpy()).astype(np.int64)
    return codes


def subsample_index(labels: np.ndarray, rows: int, *, stratified: bool, seed: int) -> np.ndarray:
    """`rows` indices into `labels`, stratified by class if asked. Public since M6b: `DatasetSpec`
    uses it to build the configured dev-box subsample, and `scripts/run_detection.py` reuses it
    to size a KNN-only subsample when the full honest_mode data does not fit the memory ceiling.
    """
    rng = np.random.default_rng(seed)
    if not stratified:
        return np.sort(rng.choice(len(labels), size=rows, replace=False))
    positive = np.flatnonzero(labels == 1)
    negative = np.flatnonzero(labels == 0)
    take_positive = max(1, round(rows * len(positive) / len(labels)))
    take_positive = min(take_positive, len(positive))
    take_negative = min(rows - take_positive, len(negative))
    chosen = np.concatenate(
        [
            rng.choice(positive, size=take_positive, replace=False),
            rng.choice(negative, size=take_negative, replace=False),
        ]
    )
    chosen.sort()
    return chosen


# --------------------------------------------------------------------------------------------
# paper_mode — the reproduction target (DEV-06)
# --------------------------------------------------------------------------------------------
def paper_mode_arithmetic(n_positive: int, positive_fraction: float) -> tuple[int, int, int]:
    """How large the paper's resample can be: `(n_total, n_pos, n_neg)`. Pure, so it is testable.

    Every positive row is used, because positives are the scarce class; the benign count follows.
    At the paper's 90% with 41,413 positives this is 46,014 rows — see the module docstring.
    """
    if not 0.0 < positive_fraction < 1.0:
        raise DatasetError(f"positive_fraction must be in (0, 1), got {positive_fraction}")
    if n_positive <= 0:
        raise DatasetError("no positive rows to resample")
    n_negative = int(n_positive * (1.0 - positive_fraction) / positive_fraction)
    return n_positive + n_negative, n_positive, n_negative


@dataclass(frozen=True)
class Resample:
    """The paper's 90/10 split, and the arithmetic that bounded it."""

    features: pd.DataFrame
    labels: np.ndarray
    n_rows: int
    n_positive: int
    n_negative: int
    positive_fraction: float
    #: Rows in the dataset this was drawn from — the contrast the paper never states.
    drawn_from: int
    #: Q10 only. Carried through from `LoadedDataset.groups` when present.
    groups: np.ndarray | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "n_rows": self.n_rows,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "positive_fraction": self.positive_fraction,
            "drawn_from_rows": self.drawn_from,
            "share_of_dataset": self.n_rows / self.drawn_from,
        }


def paper_mode_resample(
    data: LoadedDataset, *, positive_fraction: float = 0.90, seed: int = 0
) -> Resample:
    """Implements §VII's resample: every ransomware row, plus benign rows to hit the ratio."""
    n_total, n_pos, n_neg = paper_mode_arithmetic(data.n_positive, positive_fraction)
    rng = np.random.default_rng(seed)
    positive = np.flatnonzero(data.labels == 1)
    negative = rng.choice(np.flatnonzero(data.labels == 0), size=n_neg, replace=False)
    index = np.concatenate([positive, negative])
    index.sort()
    return Resample(
        features=data.features.iloc[index].reset_index(drop=True),
        labels=data.labels[index],
        n_rows=n_total,
        n_positive=n_pos,
        n_negative=n_neg,
        positive_fraction=positive_fraction,
        drawn_from=data.n_rows,
        groups=data.groups[index] if data.groups is not None else None,
    )


# --------------------------------------------------------------------------------------------
# Splits
# --------------------------------------------------------------------------------------------
def stratified_holdout(
    labels: np.ndarray, *, test_size: float, seed: int
) -> tuple[np.ndarray, np.ndarray]:
    """A stratified train/test split as index arrays. Disjoint by construction."""
    if not 0.0 < test_size < 1.0:
        raise DatasetError(f"test_size must be in (0, 1), got {test_size}")
    rng = np.random.default_rng(seed)
    train: list[np.ndarray] = []
    test: list[np.ndarray] = []
    for value in np.unique(labels):
        rows = np.flatnonzero(labels == value)
        rng.shuffle(rows)
        cut = round(len(rows) * test_size)
        test.append(rows[:cut])
        train.append(rows[cut:])
    return np.sort(np.concatenate(train)), np.sort(np.concatenate(test))


def grouped_stratified_holdout(
    labels: np.ndarray, groups: np.ndarray | None, *, test_size: float, seed: int
) -> tuple[np.ndarray, np.ndarray]:
    """A train/test split where every group lands entirely on one side. Q10 (DEV-06 follow-up).

    BitcoinHeist rows are `(address, year, day)` tuples and every address carries exactly one
    label end to end (checked directly against the real file: 0 of 2,631,095 addresses have two).
    `weight`/`length`/`count`/`looped`/`neighbors`/`income` are address-level graph features, so
    rows sharing an address are near duplicates — `stratified_holdout` can put them on both sides
    of the boundary, and this cannot.

    Stratified per label the same way `stratified_holdout` is: unique groups within one label are
    shuffled and assigned to test in shuffle order until the running row count first reaches the
    target, so the whole group that crosses the target goes to test. Group sizes are lumpy (up to
    420 rows for one address), so the achieved test share is only approximate — callers should
    read it back off the returned indices rather than assume `test_size` was hit exactly.

    M7-16 finding: membership via a hash set, not `np.isin`
    ---------------------------------------------------------
    Every caller through M4a/Q10/D6 only ever ran this on the ~46K-row `paper_mode` resample, so
    nothing before M7-16 exercised the majority class (`white`, 2.87M rows, ~2.6M unique
    addresses) at full scale. `np.isin` on object-dtype arrays this large does not take the
    sorted/hash fast path numpy uses for numeric dtypes; membership-testing ~860K candidate
    addresses (30% of 2.87M) against every row is effectively O(n*m) and does not finish in any
    practical time (measured: killed after 10+ minutes on the isolated case alone). A Python
    `set` (hash-based, like `pandas.Series.isin` uses internally) turns this back into the
    O(n + m) it should always have been, confirmed against a 2.9M-row real run.
    """
    if not 0.0 < test_size < 1.0:
        raise DatasetError(f"test_size must be in (0, 1), got {test_size}")
    if groups is None:
        raise DatasetError("grouped_stratified_holdout requires groups, got None")
    rng = np.random.default_rng(seed)
    train_parts: list[np.ndarray] = []
    test_parts: list[np.ndarray] = []
    for value in np.unique(labels):
        row_idx = np.flatnonzero(labels == value)
        group_ids = groups[row_idx]
        unique_groups, counts = np.unique(group_ids, return_counts=True)
        order = rng.permutation(len(unique_groups))
        unique_groups = unique_groups[order]
        counts = counts[order]
        target = round(len(row_idx) * test_size)
        cut = int(np.searchsorted(np.cumsum(counts), target)) + 1
        cut = min(cut, len(unique_groups))
        # M7-16 finding: a class can have so few unique groups that the ordinary cut would put
        # *all* of it in test, leaving nothing to train on — real for this dataset, not a
        # constructed edge case: `montrealRazy` and `montrealGlobeImposter` are each confined to
        # exactly one address, so the whole class is one indivisible group. Reserve at least one
        # group for training whenever more than one exists; a genuinely single-group class goes
        # to training entirely (it cannot be split either way, and a class no model has ever
        # seen cannot be scored on held-out data anyway, so training exposure is the only useful
        # side to keep it on). This never engages for the binary paper_mode/honest_mode splits —
        # both classes there have thousands of groups — so it changes nothing already published.
        cut = min(cut, len(unique_groups) - 1) if len(unique_groups) > 1 else 0
        test_group_set = set(unique_groups[:cut].tolist())
        in_test = np.fromiter(
            (group in test_group_set for group in group_ids), dtype=bool, count=len(group_ids)
        )
        test_parts.append(row_idx[in_test])
        train_parts.append(row_idx[~in_test])
    return np.sort(np.concatenate(train_parts)), np.sort(np.concatenate(test_parts))


def stratified_folds(
    labels: np.ndarray, *, folds: int, seed: int
) -> Iterator[tuple[np.ndarray, np.ndarray]]:
    """Stratified k-fold index pairs. Each fold holds the class rate of the whole.

    Written here rather than taken from sklearn so the property the tests check — the class rate
    per fold, and disjoint train/test — is a property of code this project owns.
    """
    if folds < 2:
        raise DatasetError(f"folds must be at least 2, got {folds}")
    rng = np.random.default_rng(seed)
    assignment = np.empty(len(labels), dtype=np.int64)
    for value in np.unique(labels):
        rows = np.flatnonzero(labels == value)
        rng.shuffle(rows)
        assignment[rows] = np.arange(len(rows)) % folds
    for fold in range(folds):
        test = np.flatnonzero(assignment == fold)
        train = np.flatnonzero(assignment != fold)
        yield train, test


def class_rate(labels: Sequence[int] | np.ndarray) -> float:
    array = np.asarray(labels)
    return float(array.sum() / len(array)) if len(array) else 0.0


# --------------------------------------------------------------------------------------------
# M4b — the honeypot backend, and the interface both backends share (FLAW-2, Alg. 3 line 1)
# --------------------------------------------------------------------------------------------
#: One key holder's decryption of one transaction. Defined locally rather than imported from
#: `recovery.locator` — `detection/` may depend on `blockchain/` but not on `recovery/`
#: (docs/ARCHITECTURE.md dependency direction; `test_module_boundaries.py` pins the allowed set).
Decryptor = Callable[[Transaction], bytes]


@dataclass(frozen=True)
class DetectionDataset:
    """The one shape both backends produce: what `detection.profiles`/`detection.detector` need.

    Deliberately smaller than `LoadedDataset`: `matches_paper_counts`, `families` and `groups`
    are BitcoinHeist-specific bookkeeping that has no honeypot analogue, so they stay on
    `LoadedDataset` rather than being forced onto a shared type with meaningless defaults.
    """

    features: np.ndarray
    labels: np.ndarray
    feature_names: tuple[str, ...]
    sample_ids: tuple[str, ...]
    source: str
    n_rows: int
    n_positive: int
    n_negative: int

    def __post_init__(self) -> None:
        if len(self.sample_ids) != self.n_rows or len(self.labels) != self.n_rows:
            raise DatasetError(
                f"{self.source}: n_rows={self.n_rows} does not match "
                f"{len(self.sample_ids)} sample_ids / {len(self.labels)} labels"
            )

    @property
    def positive_rate(self) -> float:
        return self.n_positive / self.n_rows if self.n_rows else 0.0

    def as_dict(self) -> dict[str, object]:
        """For a run sidecar — mirrors `LoadedDataset.as_dict()`."""
        return {
            "source": self.source,
            "n_rows": self.n_rows,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "positive_rate": self.positive_rate,
            "feature_names": list(self.feature_names),
        }


@runtime_checkable
class DatasetBackend(Protocol):
    """What `BitcoinHeistBackend` and `HoneypotBackend` both satisfy. Alg. 3 line 1, FLAW-2."""

    def load(self) -> DetectionDataset: ...


@dataclass(frozen=True)
class BitcoinHeistBackend:
    """The paper's actual evaluation data, wrapped into the shared interface (reproduction)."""

    spec: DatasetSpec
    seed: int
    verify: bool = True

    def load(self) -> DetectionDataset:
        loaded = load_bitcoinheist(self.spec, verify=self.verify, seed=self.seed)
        return DetectionDataset(
            features=loaded.features.to_numpy(dtype=np.float64),
            labels=loaded.labels.astype(np.int8),
            feature_names=loaded.columns,
            sample_ids=tuple(str(index) for index in range(loaded.n_rows)),
            source=str(loaded.source),
            n_rows=loaded.n_rows,
            n_positive=loaded.n_positive,
            n_negative=loaded.n_negative,
        )


def load_from_chain(chain: Chain, decrypt: Decryptor) -> DetectionDataset:
    """Implements Alg. 3, line 1 for the honeypot path: decrypt `BC_SigRW` into `FT_RW` vectors.

    Every block is re-verified before its transactions are trusted (mirrors
    `recovery.locator.scan`'s discipline). A `SIG_RW` transaction this key cannot open is another
    collector's and is skipped, not an error. `schema` and vector length are checked against
    `honeypot.features` before a single value is trusted — a bare vector with no schema is a
    guess, not a dataset (docs/ARCHITECTURE.md §honeypot).
    """
    if chain.name != BC_SigRW:
        raise DatasetError(f"honeypot records live on {BC_SigRW}, not {chain.name} (§V-5)")
    features: list[tuple[float, ...]] = []
    labels: list[int] = []
    sample_ids: list[str] = []
    for height in range(chain.height + 1):
        try:
            block = chain.verify_block(height)
        except ChainError as exc:
            raise DatasetError(
                f"{chain.name} failed verification at height {height}: {exc}"
            ) from exc
        for tx in block.transactions:
            if tx.payload_type != PAYLOAD_TYPE_SIGNATURE_RECORD:
                continue
            try:
                payload = SignatureRecordPayload.from_bytes(decrypt(tx))
            except TransactionError:
                continue  # encrypted to another key holder; see recovery.locator's equivalent
            if payload.schema != ft.SCHEMA:
                raise DatasetError(
                    f"{tx.tx_id!r} has schema {payload.schema!r}, expected {ft.SCHEMA!r}"
                )
            if len(payload.features) != len(ft.FEATURE_NAMES):
                raise DatasetError(
                    f"{tx.tx_id!r} has {len(payload.features)} features, "
                    f"expected {len(ft.FEATURE_NAMES)}"
                )
            if payload.label not in (MALICIOUS, BENIGN):
                raise DatasetError(
                    f"{tx.tx_id!r} has no ground-truth label; detection needs one to train on"
                )
            features.append(payload.features)
            labels.append(1 if payload.label == MALICIOUS else 0)
            sample_ids.append(payload.sample_id)
    if not features:
        raise DatasetError(f"{chain.name} has no SIG_RW records this key can decrypt")
    y = np.array(labels, dtype=np.int8)
    return DetectionDataset(
        features=np.array(features, dtype=np.float64),
        labels=y,
        feature_names=ft.FEATURE_NAMES,
        sample_ids=tuple(sample_ids),
        source=f"{chain.name} (height {chain.height})",
        n_rows=len(y),
        n_positive=int(y.sum()),
        n_negative=len(y) - int(y.sum()),
    )


@dataclass(frozen=True)
class HoneypotBackend:
    """Decrypts `BC_SigRW` and yields `FT_RW` vectors — the framework's own path (FLAW-2).

    Takes a `Chain` and a `Decryptor` rather than building either: `detection/` does not run
    consensus or orchestrate phases (`test_detection_does_not_orchestrate`), so whoever wired
    `framework.phase2_collection` to a cluster hands this backend the result.
    """

    chain: Chain
    decrypt: Decryptor

    def load(self) -> DetectionDataset:
        return load_from_chain(self.chain, self.decrypt)


def backend_from_config(
    config: Config,
    *,
    root: Path,
    seed: int,
    chain: Chain | None = None,
    decrypt: Decryptor | None = None,
) -> DatasetBackend:
    """Alg. 3's dual feature source (FLAW-2): `dataset.name` picks the backend, never a hardcoded
    call site. `chain`/`decrypt` are live objects a YAML file cannot name, so they are required
    only when `dataset.name` is `honeypot`.
    """
    name = config.require("dataset.name", str)
    if name == "bitcoinheist":
        return BitcoinHeistBackend(spec=DatasetSpec.from_config(config, root=root), seed=seed)
    if name == "honeypot":
        if chain is None or decrypt is None:
            raise DatasetError(
                "dataset.name: honeypot requires both a chain and a decrypt callable"
            )
        return HoneypotBackend(chain=chain, decrypt=decrypt)
    raise DatasetError(f"dataset.name is {name!r}; expected 'bitcoinheist' or 'honeypot'")
