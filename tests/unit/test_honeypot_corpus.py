"""`honeypot.corpus`: the on-disk draws M4 will read, and the manifest that explains them."""

from __future__ import annotations

import json
import math

import pytest

from bsfr_sh.honeypot.corpus import (
    EXPECTED_BAYES_ACCURACY,
    GENERATOR_VERSION,
    METADATA_COLUMNS,
    build_draw,
    manifest_for,
    read_corpus,
    write_corpus,
    write_manifest,
)
from bsfr_sh.honeypot.features import FEATURE_NAMES, SCHEMA


def test_a_draw_is_deterministic_in_its_seed() -> None:
    first, _ = build_draw(seed=5, count=60)
    second, _ = build_draw(seed=5, count=60)
    assert first == second


def test_two_draws_share_no_samples() -> None:
    """M4's eval split must be a different draw, not a shuffle: ids may never collide."""
    train, _ = build_draw(seed=5, count=60)
    evaluate, _ = build_draw(seed=6, count=60)
    assert not {r.sample_id for r in train} & {r.sample_id for r in evaluate}


def test_a_draw_round_trips_through_csv(tmp_path) -> None:
    records, _ = build_draw(seed=5, count=40)
    path = write_corpus(tmp_path / "corpus_train.csv", records)
    loaded = read_corpus(path)
    assert [r.sample_id for r in loaded] == [r.sample_id for r in records]
    assert [r.label for r in loaded] == [r.label for r in records]
    assert [r.missing_mask for r in loaded] == [r.missing_mask for r in records]
    for original, restored in zip(records, loaded, strict=True):
        for a, b in zip(original.values, restored.values, strict=True):
            assert math.isclose(a, b, rel_tol=1e-5, abs_tol=1e-9)


def test_the_header_is_the_schema(tmp_path) -> None:
    records, _ = build_draw(seed=5, count=5)
    path = write_corpus(tmp_path / "c.csv", records)
    header = path.read_text(encoding="utf-8").splitlines()[0].split(",")
    assert header == [*METADATA_COLUMNS, *FEATURE_NAMES]


def test_a_corpus_with_a_foreign_header_is_refused(tmp_path) -> None:
    path = tmp_path / "c.csv"
    path.write_text("a,b,c\n1,2,3\n", encoding="utf-8")
    with pytest.raises(ValueError, match="header"):
        read_corpus(path)


def test_the_manifest_records_what_a_consumer_needs(tmp_path) -> None:
    draws = {
        "train": {"seed": 5, "requested": 40, "kept": 39},
        "eval": {"seed": 6, "requested": 20, "kept": 20},
    }
    path = write_manifest(tmp_path / "manifest.json", manifest_for(draws, malicious_fraction=0.5))
    manifest = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["schema"] == SCHEMA
    assert manifest["generator_version"] == GENERATOR_VERSION
    assert manifest["feature_names"] == list(FEATURE_NAMES)
    assert manifest["draws"]["train"]["seed"] != manifest["draws"]["eval"]["seed"]
    assert manifest["expected_bayes_accuracy"] == EXPECTED_BAYES_ACCURACY
    assert "shuffled" in manifest["note"] or "shuffle" in manifest["note"]


def test_the_committed_corpus_matches_its_manifest() -> None:
    """The corpus in `data/honeypot/` must be regenerable from the seeds it records."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "data" / "honeypot"
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for name in ("train", "eval"):
        stored = read_corpus(root / f"corpus_{name}.csv")
        assert len(stored) == manifest["draws"][name]["kept"]
        regenerated, _ = build_draw(
            seed=manifest["draws"][name]["seed"],
            count=manifest["draws"][name]["requested"],
            malicious_fraction=manifest["malicious_fraction"],
        )
        assert [r.sample_id for r in regenerated] == [r.sample_id for r in stored]
