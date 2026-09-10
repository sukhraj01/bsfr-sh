"""One call that seeds every source of randomness this project uses.

Determinism is a requirement, not a nicety (CLAUDE.md §4): every entry point takes `--seed`, and
a benchmark number that cannot be regenerated is not a result. Seeding three sources in three
places is how one of them gets forgotten, so there is exactly one function.

What is seeded
--------------
* `random` — nonces and synthetic sample generation in `honeypot/`.
* `numpy.random` legacy global state — what scikit-learn reads when `random_state` is left unset.
* `PYTHONHASHSEED` — with the caveat below.

The `PYTHONHASHSEED` caveat
---------------------------
Setting `PYTHONHASHSEED` from inside a running interpreter does **not** change that
interpreter's string hashing: the seed is consumed once at start-up. Setting it here does two
useful things anyway — child processes (`n_jobs > 1`, an Ada batch step, a subprocess in a test)
inherit a fixed value, and the value is recorded in the run sidecar so a non-reproducible run
can be told apart from a mis-seeded one.

What it does *not* do is make `hash()`, set iteration, or dict-of-mixed-keys ordering safe to
depend on. Nothing in this project may depend on those; `util.serialization` is built so that it
cannot (mapping entries are sorted by encoded key, sets are rejected outright).
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import Final

import numpy as np

__all__ = ["DEFAULT_SEED", "SeedState", "numpy_generator", "seed_all"]

#: Used when an entry point is run without `--seed`. A fixed default, never a time-derived one:
#: an unseeded run that silently varies is worse than one that is obviously always the same.
DEFAULT_SEED: Final = 20260910

_MAX_SEED: Final = 2**32 - 1


@dataclass(frozen=True)
class SeedState:
    """Record of what was seeded, for the run sidecar."""

    seed: int
    numpy_seeded: bool
    pythonhashseed: str
    pythonhashseed_effective_this_process: bool

    def as_dict(self) -> dict[str, object]:
        effective = self.pythonhashseed_effective_this_process
        return {
            "seed": self.seed,
            "numpy_seeded": self.numpy_seeded,
            "pythonhashseed": self.pythonhashseed,
            "pythonhashseed_effective_this_process": effective,
        }


def seed_all(seed: int = DEFAULT_SEED) -> SeedState:
    """Seed `random`, NumPy's global state and `PYTHONHASHSEED`; return what was done.

    Call once, at the entry point, before anything random happens. Modules do not re-seed —
    a module that seeds mid-run makes the run depend on import order.
    """
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError(f"seed must be an int, got {type(seed).__name__}")
    if not 0 <= seed <= _MAX_SEED:
        raise ValueError(f"seed must be in [0, {_MAX_SEED}], got {seed}")

    random.seed(seed)
    np.random.seed(seed)

    previous = os.environ.get("PYTHONHASHSEED")
    os.environ["PYTHONHASHSEED"] = str(seed)

    return SeedState(
        seed=seed,
        numpy_seeded=True,
        pythonhashseed=str(seed),
        # True only if the interpreter was already started with this value; see module docstring.
        pythonhashseed_effective_this_process=previous == str(seed),
    )


def numpy_generator(seed: int = DEFAULT_SEED) -> np.random.Generator:
    """A local NumPy `Generator`, which is preferred over the global state.

    Global seeding exists for libraries that reach for it; our own code should take an explicit
    generator so that two components cannot consume each other's random stream and make results
    depend on execution order.
    """
    return np.random.default_rng(seed)
