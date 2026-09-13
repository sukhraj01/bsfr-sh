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
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

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
    "DatasetError",
    "DatasetSpec",
    "LoadedDataset",
    "encode_group_column",
    "grouped_stratified_holdout",
    "load_bitcoinheist",
    "paper_mode_arithmetic",
    "paper_mode_resample",
    "stratified_folds",
    "stratified_holdout",
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
    #: Q10 only — the production config path never sets these. `group_column` loads a column
    #: purely for grouping (e.g. a later `grouped_stratified_holdout`); it never reaches the
    #: feature matrix unless `encode_group_as_feature` also asks for that.
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
    #: Q10 only. The raw grouping key per row (e.g. `address`), aligned with `features`/`labels`.
    #: `None` unless `DatasetSpec.group_column` was set — the production config path never sets it.
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
        index = _subsample_index(
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


def encode_group_column(values: pd.Series) -> np.ndarray:
    """Ordinal-encode a string column via scikit-learn's `LabelEncoder`. Q10 only.

    This is the encoding a straightforward implementation reaches for when told to keep an
    identifier column as a feature: one call, sorted unique values, dense integer codes, no
    awareness that it is handing the model a near-unique key. That is deliberate here — it names
    what an unexamined "kept address" baseline actually does, not a strawman built to fail.
    """
    codes: np.ndarray = LabelEncoder().fit_transform(values.to_numpy()).astype(np.int64)
    return codes


def _subsample_index(labels: np.ndarray, rows: int, *, stratified: bool, seed: int) -> np.ndarray:
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
        in_test = np.isin(group_ids, unique_groups[:cut])
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
