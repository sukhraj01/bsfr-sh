"""Seeding: one call, three sources, and an honest record of what it could not do."""

from __future__ import annotations

import os
import random
from collections.abc import Iterator

import numpy as np
import pytest

from bsfr_sh.util.seeding import DEFAULT_SEED, SeedState, numpy_generator, seed_all


@pytest.fixture(autouse=True)
def _restore_environment() -> Iterator[None]:
    before = os.environ.get("PYTHONHASHSEED")
    yield
    if before is None:
        os.environ.pop("PYTHONHASHSEED", None)
    else:
        os.environ["PYTHONHASHSEED"] = before


def _sample() -> tuple[list[float], list[float]]:
    return (
        [random.random() for _ in range(5)],
        list(np.random.random(5)),
    )


def test_same_seed_gives_the_same_streams() -> None:
    seed_all(1234)
    first = _sample()
    seed_all(1234)
    assert _sample() == first


def test_different_seeds_give_different_streams() -> None:
    seed_all(1234)
    first = _sample()
    seed_all(4321)
    assert _sample() != first


def test_seed_all_reports_what_it_did() -> None:
    state = seed_all(7)
    assert isinstance(state, SeedState)
    assert state.seed == 7
    assert state.numpy_seeded is True
    assert state.pythonhashseed == "7"
    assert os.environ["PYTHONHASHSEED"] == "7"
    assert set(state.as_dict()) == {
        "seed",
        "numpy_seeded",
        "pythonhashseed",
        "pythonhashseed_effective_this_process",
    }


def test_pythonhashseed_is_reported_as_ineffective_when_set_late() -> None:
    """The honest part: setting PYTHONHASHSEED mid-process does not re-seed this interpreter.

    Recording it as ineffective is what stops a future reader concluding that string hashing was
    deterministic in a run where it was not. Nothing in this project may depend on it either way.
    """
    os.environ.pop("PYTHONHASHSEED", None)
    assert seed_all(11).pythonhashseed_effective_this_process is False
    # A second call in the same process now finds the value already in place.
    assert seed_all(11).pythonhashseed_effective_this_process is True


def test_default_seed_is_fixed_not_time_derived() -> None:
    assert seed_all().seed == DEFAULT_SEED
    assert seed_all().seed == DEFAULT_SEED


@pytest.mark.parametrize("bad", [-1, 2**32, "1234", 12.0, True])
def test_invalid_seeds_are_rejected(bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        seed_all(bad)  # type: ignore[arg-type]


def test_numpy_generator_is_reproducible_and_independent() -> None:
    a = numpy_generator(99).random(5)
    b = numpy_generator(99).random(5)
    assert np.array_equal(a, b)
    # Drawing from a local generator must not disturb the global stream, or results would depend
    # on which components happened to run first.
    seed_all(5)
    expected = [random.random() for _ in range(3)]
    seed_all(5)
    numpy_generator(1).random(100)
    assert [random.random() for _ in range(3)] == expected
