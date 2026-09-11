"""YAML configuration loading and validation.

Why this module is stricter than "call `yaml.safe_load`":

* **Validation.** A config value that is missing or the wrong type should fail at load time with
  a filename and a key path, not four layers down inside a consensus round.
* **Cross-field checks.** `commit_threshold` must equal `2f + 1` for `miner_nodes = 3f + 1`
  (DEV-10). A config that quietly violates that would still run and would still produce numbers —
  numbers that no longer describe the paper's setup.

This module deliberately does **not** hash. Every bench sidecar carries a `config_hash`
(docs/EXPERIMENTS.md, output contract), but computing it here would mean `util` importing
`crypto.hashing` — and the dependency runs `util <- crypto`, never back
(docs/ARCHITECTURE.md §Dependency direction). CLAUDE.md §7 additionally requires exactly one
`hashlib` importer in the tree, which is `crypto.hashing`.

So `Config` carries no digest. The consumer that needs one composes the two layers::

    from bsfr_sh.crypto.hashing import config_hash
    from bsfr_sh.util.config import load_config

    cfg = load_config("configs/chain.yaml")
    digest = config_hash(cfg.kind, cfg.data)

`Config.data` is the whole validated document, so the digest still depends on the config's
*content* and not on YAML key order, comments, or whitespace. This arrangement retired debt D1;
the earlier one had `util.config` calling `hashlib` directly, which no rule in the project
actually permitted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TypeVar

import yaml

__all__ = [
    "Config",
    "ConfigError",
    "load_config",
    "load_configs",
]

T = TypeVar("T")

_MISSING: Final = object()

#: Bumped when a config file's required shape changes incompatibly.
SUPPORTED_SCHEMA_VERSION: Final = 1


class ConfigError(ValueError):
    """Raised when a config file is missing, malformed, or fails validation."""


# --------------------------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------------------------
# Deliberately shallow: this validates the keys that other modules will *depend on existing*,
# not every key in the file. A schema that mirrors the whole file becomes a second copy of the
# config and rots. Add a row here when code starts reading a key.
_REQUIRED: Final[dict[str, tuple[tuple[str, type | tuple[type, ...]], ...]]] = {
    "chain": (
        ("consensus.protocol", str),
        ("consensus.miner_nodes", int),
        ("consensus.faulty_nodes_f", int),
        ("consensus.commit_threshold", int),
        ("consensus.view_change_timeout_s", (int, float)),
        ("block.transactions_per_block", int),
        ("cases", dict),
        ("chains", dict),
        ("transaction.payload_bytes", int),
        ("crypto.hash", str),
        ("crypto.signature.algorithm", str),
        ("crypto.signature.curve", str),
        ("merkle.odd_node_policy", str),
    ),
    "ml": (
        ("dataset.name", str),
        ("dataset.label_column", str),
        ("dataset.benign_label", str),
        ("dataset.drop_columns", list),
        ("dataset.feature_columns", list),
        ("modes.paper_mode.metrics", list),
        ("modes.honest_mode.metrics", list),
        ("models", dict),
    ),
    "bench": (
        ("run.cases", list),
        ("run.chains", list),
        ("timing.repeats", int),
        ("timing.warmup_runs", int),
        ("timing.aggregate", str),
        ("output.tables_dir", str),
        ("output.figures_dir", str),
        ("output.logs_dir", str),
        ("output.sidecar_fields", list),
    ),
}

#: The four algorithms Table II requires. A config that drops one silently would produce a table
#: with a missing row that looks like a formatting problem rather than a missing experiment.
_REQUIRED_MODELS: Final = (
    "random_forest",
    "logistic_regression",
    "decision_tree",
    "k_nearest_neighbours",
)


@dataclass(frozen=True)
class Config:
    """A validated config file.

    Deliberately no `config_hash` field — see the module docstring. Pass `kind` and `data` to
    `crypto.hashing.config_hash()` at the point a digest is actually needed.
    """

    kind: str
    schema_version: int
    path: Path
    data: Mapping[str, Any]

    def get(self, dotted: str, default: Any = _MISSING) -> Any:
        """Look up a dotted key path, e.g. ``consensus.commit_threshold``."""
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, Mapping) or part not in node:
                if default is _MISSING:
                    raise ConfigError(f"{self.path}: missing key {dotted!r}")
                return default
            node = node[part]
        return node

    def require(self, dotted: str, expected: type[T]) -> T:
        """Look up a dotted key path and assert its type."""
        value = self.get(dotted)
        # bool is a subclass of int; asking for an int and getting `true` is a config bug.
        if expected is int and isinstance(value, bool):
            raise ConfigError(f"{self.path}: {dotted!r} is a bool, expected int")
        if not isinstance(value, expected):
            raise ConfigError(
                f"{self.path}: {dotted!r} is {type(value).__name__}, expected {expected.__name__}"
            )
        return value


# --------------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------------
def load_config(path: str | Path, *, expected_kind: str | None = None) -> Config:
    """Load and validate one YAML config file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    try:
        raw: Any = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping, got {type(raw).__name__}")

    kind = raw.get("kind")
    if not isinstance(kind, str):
        raise ConfigError(f"{path}: missing top-level 'kind' (one of {sorted(_REQUIRED)})")
    if kind not in _REQUIRED:
        raise ConfigError(f"{path}: unknown kind {kind!r}, expected one of {sorted(_REQUIRED)}")
    if expected_kind is not None and kind != expected_kind:
        raise ConfigError(f"{path}: expected kind {expected_kind!r}, found {kind!r}")

    version = raw.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ConfigError(f"{path}: missing or non-integer 'schema_version'")
    if version != SUPPORTED_SCHEMA_VERSION:
        raise ConfigError(
            f"{path}: schema_version {version} is not supported "
            f"(this build understands {SUPPORTED_SCHEMA_VERSION})"
        )

    cfg = Config(kind=kind, schema_version=version, path=path, data=raw)
    _validate(cfg)
    return cfg


def load_configs(
    paths: Sequence[str | Path], *, root: str | Path | None = None
) -> dict[str, Config]:
    """Load several configs and return them keyed by kind."""
    base = Path(root) if root is not None else None
    loaded: dict[str, Config] = {}
    for entry in paths:
        path = Path(entry) if base is None else base / entry
        cfg = load_config(path)
        if cfg.kind in loaded:
            raise ConfigError(f"two configs of kind {cfg.kind!r}: {loaded[cfg.kind].path}, {path}")
        loaded[cfg.kind] = cfg
    return loaded


# --------------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------------
def _validate(cfg: Config) -> None:
    for dotted, expected in _REQUIRED[cfg.kind]:
        value = cfg.get(dotted)
        if isinstance(value, bool) and expected is int:
            raise ConfigError(f"{cfg.path}: {dotted!r} is a bool, expected int")
        if not isinstance(value, expected):
            names = (
                expected.__name__
                if isinstance(expected, type)
                else "/".join(t.__name__ for t in expected)
            )
            raise ConfigError(f"{cfg.path}: {dotted!r} is {type(value).__name__}, wanted {names}")
    validator = _CROSS_CHECKS.get(cfg.kind)
    if validator is not None:
        validator(cfg)


def _validate_chain(cfg: Config) -> None:
    nodes = cfg.require("consensus.miner_nodes", int)
    f = cfg.require("consensus.faulty_nodes_f", int)
    threshold = cfg.require("consensus.commit_threshold", int)
    # pBFT's whole safety argument is n >= 3f+1 with a 2f+1 commit quorum (DEV-10). Getting this
    # wrong does not crash anything; it just silently benchmarks a protocol that is not pBFT.
    if nodes != 3 * f + 1:
        raise ConfigError(
            f"{cfg.path}: consensus.miner_nodes={nodes} is not 3f+1 for f={f} "
            f"(expected {3 * f + 1})"
        )
    if threshold != 2 * f + 1:
        raise ConfigError(
            f"{cfg.path}: consensus.commit_threshold={threshold} is not 2f+1 for f={f} "
            f"(expected {2 * f + 1}); see docs/DEVIATIONS.md DEV-10"
        )
    if cfg.require("block.transactions_per_block", int) <= 0:
        raise ConfigError(f"{cfg.path}: block.transactions_per_block must be positive")
    if cfg.require("transaction.payload_bytes", int) <= 0:
        raise ConfigError(f"{cfg.path}: transaction.payload_bytes must be positive")

    cases = cfg.require("cases", dict)
    if not cases:
        raise ConfigError(f"{cfg.path}: 'cases' is empty; the paper defines three (5/10/15 blocks)")
    for name, blocks in cases.items():
        if not isinstance(blocks, int) or isinstance(blocks, bool) or blocks <= 0:
            raise ConfigError(f"{cfg.path}: cases.{name} must be a positive integer")

    chains = cfg.require("chains", dict)
    # CLAUDE.md §4: BC_DTBU and BC_SigRW are separate objects. Both must be configured, or a
    # benchmark silently reports one chain twice.
    for required in ("BC_DTBU", "BC_SigRW"):
        if required not in chains:
            raise ConfigError(f"{cfg.path}: chains.{required} is not configured")


def _validate_ml(cfg: Config) -> None:
    models = cfg.require("models", dict)
    missing = [name for name in _REQUIRED_MODELS if name not in models]
    if missing:
        raise ConfigError(
            f"{cfg.path}: models missing {missing}; Table II requires all four "
            f"(random forest, logistic regression, decision tree, KNN)"
        )
    # DEV-06: both evaluation modes exist and both are reported. One without the other is the
    # exact failure this project is meant to avoid.
    for mode in ("paper_mode", "honest_mode"):
        metrics = cfg.get(f"modes.{mode}.metrics")
        if not isinstance(metrics, list) or not metrics:
            raise ConfigError(f"{cfg.path}: modes.{mode}.metrics must be a non-empty list")
    fraction = cfg.get("modes.paper_mode.positive_fraction", None)
    if fraction is not None and not 0.0 < float(fraction) < 1.0:
        raise ConfigError(f"{cfg.path}: modes.paper_mode.positive_fraction must be in (0, 1)")
    label = cfg.require("dataset.label_column", str)
    if label in cfg.require("dataset.feature_columns", list):
        raise ConfigError(f"{cfg.path}: dataset.label_column {label!r} is also a feature column")
    for dropped in cfg.require("dataset.drop_columns", list):
        if dropped in cfg.require("dataset.feature_columns", list):
            raise ConfigError(f"{cfg.path}: {dropped!r} is both dropped and used as a feature")


def _validate_bench(cfg: Config) -> None:
    repeats = cfg.require("timing.repeats", int)
    # docs/EXPERIMENTS.md protocol, Targets 3 and 4: median of N >= 5, warm-up discarded.
    if repeats < 5:
        raise ConfigError(
            f"{cfg.path}: timing.repeats={repeats} is below the 5 required by "
            f"docs/EXPERIMENTS.md; a single sample is not a measurement"
        )
    if cfg.require("timing.warmup_runs", int) < 1:
        raise ConfigError(f"{cfg.path}: timing.warmup_runs must be at least 1")
    if cfg.require("timing.aggregate", str) != "median":
        raise ConfigError(f"{cfg.path}: timing.aggregate must be 'median' (CLAUDE.md §4)")
    if not cfg.require("run.cases", list):
        raise ConfigError(f"{cfg.path}: run.cases is empty")
    chains = cfg.require("run.chains", list)
    for required in ("BC_DTBU", "BC_SigRW"):
        if required not in chains:
            raise ConfigError(f"{cfg.path}: run.chains must include {required}")
    for field in ("config_hash", "seed"):
        if field not in cfg.require("output.sidecar_fields", list):
            raise ConfigError(
                f"{cfg.path}: output.sidecar_fields must include {field!r}; without it a result "
                f"cannot be traced back to the run that produced it (CLAUDE.md §2)"
            )


_CROSS_CHECKS: Final[dict[str, Any]] = {
    "chain": _validate_chain,
    "ml": _validate_ml,
    "bench": _validate_bench,
}
