"""The on-disk corpus: `data/honeypot/`, its manifest, and the draws M4 will train and test on.

Two carriers, one schema
------------------------
A record reaches M4 either as a row here or as a `SignatureRecordPayload` decrypted from
`BC_SigRW`. The columns and the on-chain fields are the same values under the same names
(`docs/ARCHITECTURE.md` §honeypot). The chain is the framework's path; this file is how M4 gets a
corpus without running consensus for every experiment.

Train and test come from different draws
----------------------------------------
`build_draw()` takes a seed and produces an independent draw. The writer emits two of them under
two different seeds and records both in the manifest. This is not a convenience: two samples from
one generator call can share latent parameters, so a train/test split made by *shuffling one draw*
leaks. M4 must load `corpus_train.csv` and `corpus_eval.csv`, never shuffle one of them into both
roles.

The manifest also carries the corpus's intended difficulty, so M4 can tell whether its accuracy is
a result or an artefact.

The committed corpus is the dataset (Q9, closed in M4a)
-------------------------------------------------------
`corpus_train.csv` and `corpus_eval.csv` as committed *are* M4's data. Experiments do not
regenerate them. A corpus that moves between runs makes two results incomparable, because the model
and the data would both have changed and no difference could be attributed to either. Regeneration
is a deliberate act: it bumps `GENERATOR_VERSION` and lands as its own commit.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

from bsfr_sh.honeypot import features as ft
from bsfr_sh.honeypot import preprocess
from bsfr_sh.honeypot.collector import AMBIGUOUS_FRACTION, RawSample, synthesize

__all__ = [
    "EXPECTED_BAYES_ACCURACY",
    "GENERATOR_VERSION",
    "METADATA_COLUMNS",
    "CorpusManifest",
    "CorpusRecord",
    "build_draw",
    "read_corpus",
    "write_corpus",
    "write_manifest",
]

#: Bump when the generator's distributions change: a corpus is only comparable within one version.
GENERATOR_VERSION: Final = "hp-gen.v1"

#: The accuracy a *perfect* classifier should reach on this corpus, by construction. The confusable
#: pairs put `AMBIGUOUS_FRACTION / 2 = 0.125` of irreducible error in place before any other
#: overlap is counted; the rest of the overlap costs a few points more. M4 must read any number
#: near 1.0 as a bug in the data, not a triumph of the model.
EXPECTED_BAYES_ACCURACY: Final = 0.85

#: Columns that are provenance, not inputs. M4 trains on `FEATURE_NAMES` and nothing else.
METADATA_COLUMNS: Final = (
    "sample_id",
    "label",
    "profile",
    "collected_at",
    "missing_mask",
    "content_digest",
)


@dataclass(frozen=True)
class CorpusRecord:
    """One row: provenance, the label, and the `FT_RW` vector."""

    sample_id: str
    label: str
    profile: str
    collected_at: int
    missing_mask: int
    content_digest: str
    values: tuple[float, ...]


@dataclass(frozen=True)
class CorpusManifest:
    """Everything needed to regenerate and to interpret the corpus."""

    generator_version: str
    schema: str
    feature_names: tuple[str, ...]
    metadata_columns: tuple[str, ...]
    draws: dict[str, dict[str, int]]
    malicious_fraction: float
    ambiguous_fraction: float
    expected_bayes_accuracy: float
    note: str


def build_draw(
    *, seed: int, count: int, malicious_fraction: float = 0.5
) -> tuple[tuple[CorpusRecord, ...], preprocess.CleaningReport]:
    """One independent draw: synthesize → clean → featurise. Deterministic in `seed`."""
    raw: tuple[RawSample, ...] = synthesize(count, seed=seed, malicious_fraction=malicious_fraction)
    cleaned, report = preprocess.clean(raw)
    records = tuple(
        CorpusRecord(
            sample_id=sample.sample_id,
            label=sample.label,
            profile=sample.profile,
            collected_at=sample.collected_at,
            missing_mask=vector.missing_mask,
            content_digest="",
            values=vector.values,
        )
        for sample, vector in ((s, ft.build(s)) for s in cleaned)
    )
    return records, report


def write_corpus(path: Path, records: Sequence[CorpusRecord]) -> Path:
    """Write one draw as CSV: metadata columns first, then the features in schema order."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([*METADATA_COLUMNS, *ft.FEATURE_NAMES])
        for record in records:
            writer.writerow(
                [
                    record.sample_id,
                    record.label,
                    record.profile,
                    record.collected_at,
                    record.missing_mask,
                    record.content_digest,
                    *(f"{value:.6g}" for value in record.values),
                ]
            )
    return path


def read_corpus(path: Path) -> tuple[CorpusRecord, ...]:
    """Read a draw back. The header must match the current schema, or this raises."""
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        raise ValueError(f"{path} is empty")
    header, *body = rows
    expected = [*METADATA_COLUMNS, *ft.FEATURE_NAMES]
    if header != expected:
        raise ValueError(f"{path} header does not match {ft.SCHEMA}")
    width = len(METADATA_COLUMNS)
    return tuple(
        CorpusRecord(
            sample_id=row[0],
            label=row[1],
            profile=row[2],
            collected_at=int(row[3]),
            missing_mask=int(row[4]),
            content_digest=row[5],
            values=tuple(float(value) for value in row[width:]),
        )
        for row in body
    )


def write_manifest(path: Path, manifest: CorpusManifest) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = asdict(manifest)
    payload["feature_names"] = list(manifest.feature_names)
    payload["metadata_columns"] = list(manifest.metadata_columns)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def manifest_for(draws: dict[str, dict[str, int]], *, malicious_fraction: float) -> CorpusManifest:
    return CorpusManifest(
        generator_version=GENERATOR_VERSION,
        schema=ft.SCHEMA,
        feature_names=ft.FEATURE_NAMES,
        metadata_columns=METADATA_COLUMNS,
        draws=draws,
        malicious_fraction=malicious_fraction,
        ambiguous_fraction=AMBIGUOUS_FRACTION,
        expected_bayes_accuracy=EXPECTED_BAYES_ACCURACY,
        note=(
            "Train and eval are independent draws from different seeds, never one draw shuffled. "
            "Features are the columns named in feature_names; every other column is provenance. "
            "A classifier scoring far above expected_bayes_accuracy is reading a leak, not a "
            "signal."
        ),
    )
