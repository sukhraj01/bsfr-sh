"""Config loading, validation and the stability of `config_hash`.

The hash matters as much as the values: `results/logs/<run_id>.json` records a config hash, and
if that hash is not reproducible then no figure in `results/` can be tied to the configuration
that produced it (CLAUDE.md §2, docs/EXPERIMENTS.md output contract).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from bsfr_sh.util.config import (
    Config,
    ConfigError,
    combined_config_hash,
    config_hash,
    load_config,
    load_configs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "configs"
SHIPPED = ("chain.yaml", "ml.yaml", "bench.yaml")


# ---------------------------------------------------------------------------------------------
# The configs we actually ship
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", SHIPPED)
def test_shipped_configs_load_and_validate(name: str) -> None:
    cfg = load_config(CONFIG_DIR / name)
    assert cfg.kind == name.removesuffix(".yaml")
    assert cfg.schema_version == 1
    assert len(cfg.config_hash) == 64


def test_shipped_chain_config_matches_the_paper_setup() -> None:
    """The values docs/EXPERIMENTS.md says the paper pins down. Drift here is a silent
    reproduction failure: the run still succeeds, it just no longer describes BSFR-SH."""
    cfg = load_config(CONFIG_DIR / "chain.yaml")
    assert cfg.require("consensus.miner_nodes", int) == 4
    assert cfg.require("consensus.faulty_nodes_f", int) == 1
    assert cfg.require("consensus.commit_threshold", int) == 3  # 2f+1, DEV-10
    assert cfg.require("block.transactions_per_block", int) == 100
    assert cfg.require("cases", dict) == {"case_1": 5, "case_2": 10, "case_3": 15}
    assert set(cfg.require("chains", dict)) == {"BC_DTBU", "BC_SigRW"}
    assert cfg.require("crypto.signature.algorithm", str) == "ecdsa"
    assert cfg.require("crypto.signature.curve", str) == "secp256r1"


def test_shipped_ml_config_has_four_models_and_both_modes() -> None:
    cfg = load_config(CONFIG_DIR / "ml.yaml")
    assert set(cfg.require("models", dict)) == {
        "random_forest",
        "logistic_regression",
        "decision_tree",
        "k_nearest_neighbours",
    }
    # DEV-06: both modes, always.
    assert cfg.require("modes.paper_mode.positive_fraction", float) == 0.90
    assert cfg.get("modes.honest_mode.split") == "natural"
    assert "accuracy" in cfg.require("modes.paper_mode.metrics", list)
    assert "pr_auc" in cfg.require("modes.honest_mode.metrics", list)


def test_shipped_bench_config_follows_the_measurement_protocol() -> None:
    cfg = load_config(CONFIG_DIR / "bench.yaml")
    assert cfg.require("timing.repeats", int) >= 5
    assert cfg.require("timing.aggregate", str) == "median"
    assert cfg.require("timing.warmup_runs", int) >= 1
    sidecar = cfg.require("output.sidecar_fields", list)
    assert {"config_hash", "seed"} <= set(sidecar)


def test_load_configs_keys_by_kind() -> None:
    loaded = load_configs(SHIPPED, root=CONFIG_DIR)
    assert set(loaded) == {"chain", "ml", "bench"}


def test_expected_kind_mismatch_is_an_error() -> None:
    with pytest.raises(ConfigError, match=r"expected kind 'ml'"):
        load_config(CONFIG_DIR / "chain.yaml", expected_kind="ml")


# ---------------------------------------------------------------------------------------------
# Hash stability
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", SHIPPED)
def test_hash_is_stable_across_loads(name: str) -> None:
    assert load_config(CONFIG_DIR / name).config_hash == load_config(CONFIG_DIR / name).config_hash


def test_hash_ignores_key_order_comments_and_whitespace(tmp_path: Path) -> None:
    source = yaml.safe_load((CONFIG_DIR / "chain.yaml").read_text())
    reordered = dict(reversed(list(source.items())))
    rewritten = tmp_path / "chain.yaml"
    rewritten.write_text(
        "# a comment the original did not have\n\n"
        + yaml.safe_dump(reordered, sort_keys=False, default_flow_style=False)
        + "\n\n"
    )
    assert load_config(rewritten).config_hash == load_config(CONFIG_DIR / "chain.yaml").config_hash


def test_hash_changes_when_any_value_changes(tmp_path: Path) -> None:
    source = yaml.safe_load((CONFIG_DIR / "chain.yaml").read_text())
    source["transaction"]["payload_bytes"] = 8192
    changed = tmp_path / "chain.yaml"
    changed.write_text(yaml.safe_dump(source))
    assert load_config(changed).config_hash != load_config(CONFIG_DIR / "chain.yaml").config_hash


def test_hash_is_domain_separated_by_kind() -> None:
    data = {"kind": "chain", "schema_version": 1}
    assert config_hash("chain", data) != config_hash("ml", data)


def test_combined_hash_is_order_independent() -> None:
    loaded = load_configs(SHIPPED, root=CONFIG_DIR)
    forwards = [loaded["chain"], loaded["ml"], loaded["bench"]]
    assert combined_config_hash(forwards) == combined_config_hash(list(reversed(forwards)))


def test_combined_hash_rejects_two_configs_of_one_kind() -> None:
    cfg = load_config(CONFIG_DIR / "chain.yaml")
    with pytest.raises(ConfigError, match="two configs of kind"):
        combined_config_hash([cfg, cfg])


# ---------------------------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------------------------
def _write(tmp_path: Path, data: object, name: str = "c.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data))
    return path


def _chain(tmp_path: Path, **overrides: object) -> Path:
    data = yaml.safe_load((CONFIG_DIR / "chain.yaml").read_text())
    for dotted, value in overrides.items():
        node = data
        parts = dotted.split("__")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value
    return _write(tmp_path, data)


def test_missing_file_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read config"):
        load_config(tmp_path / "nope.yaml")


def test_invalid_yaml_is_a_clear_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("kind: chain\n  bad indent: [\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(path)


@pytest.mark.parametrize(
    ("data", "match"),
    [
        ([1, 2, 3], "top level must be a mapping"),
        ({"schema_version": 1}, "missing top-level 'kind'"),
        ({"kind": "nonsense", "schema_version": 1}, "unknown kind"),
        ({"kind": "chain"}, "schema_version"),
        ({"kind": "chain", "schema_version": 99}, "not supported"),
    ],
)
def test_malformed_top_level_is_rejected(tmp_path: Path, data: object, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load_config(_write(tmp_path, data))


def test_missing_required_key_is_rejected(tmp_path: Path) -> None:
    data = yaml.safe_load((CONFIG_DIR / "chain.yaml").read_text())
    del data["block"]["transactions_per_block"]
    with pytest.raises(ConfigError, match="transactions_per_block"):
        load_config(_write(tmp_path, data))


def test_commit_threshold_must_be_2f_plus_1(tmp_path: Path) -> None:
    # The failure this catches is invisible at run time: a threshold of 2 still commits blocks,
    # it just is not pBFT any more, and the benchmark would describe a different protocol.
    path = _chain(tmp_path, consensus__commit_threshold=2)
    with pytest.raises(ConfigError, match="not 2f\\+1"):
        load_config(path)


def test_miner_nodes_must_be_3f_plus_1(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not 3f\\+1"):
        load_config(_chain(tmp_path, consensus__miner_nodes=5))


def test_both_chains_must_be_configured(tmp_path: Path) -> None:
    data = yaml.safe_load((CONFIG_DIR / "chain.yaml").read_text())
    del data["chains"]["BC_SigRW"]
    with pytest.raises(ConfigError, match=r"chains\.BC_SigRW"):
        load_config(_write(tmp_path, data))


@pytest.mark.parametrize("field", ["transaction__payload_bytes", "block__transactions_per_block"])
def test_positive_integers_are_enforced(tmp_path: Path, field: str) -> None:
    with pytest.raises(ConfigError, match="must be positive"):
        load_config(_chain(tmp_path, **{field: 0}))


def test_dropping_a_model_is_rejected(tmp_path: Path) -> None:
    data = yaml.safe_load((CONFIG_DIR / "ml.yaml").read_text())
    del data["models"]["k_nearest_neighbours"]
    with pytest.raises(ConfigError, match="Table II requires all four"):
        load_config(_write(tmp_path, data))


def test_label_column_cannot_also_be_a_feature(tmp_path: Path) -> None:
    data = yaml.safe_load((CONFIG_DIR / "ml.yaml").read_text())
    data["dataset"]["feature_columns"].append(data["dataset"]["label_column"])
    with pytest.raises(ConfigError, match="also a feature column"):
        load_config(_write(tmp_path, data))


def test_dropped_column_cannot_also_be_a_feature(tmp_path: Path) -> None:
    data = yaml.safe_load((CONFIG_DIR / "ml.yaml").read_text())
    data["dataset"]["feature_columns"].append("address")
    with pytest.raises(ConfigError, match="both dropped and used as a feature"):
        load_config(_write(tmp_path, data))


def test_single_sample_benchmark_is_rejected(tmp_path: Path) -> None:
    data = yaml.safe_load((CONFIG_DIR / "bench.yaml").read_text())
    data["timing"]["repeats"] = 1
    with pytest.raises(ConfigError, match="not a measurement"):
        load_config(_write(tmp_path, data))


def test_mean_aggregation_is_rejected(tmp_path: Path) -> None:
    data = yaml.safe_load((CONFIG_DIR / "bench.yaml").read_text())
    data["timing"]["aggregate"] = "mean"
    with pytest.raises(ConfigError, match="must be 'median'"):
        load_config(_write(tmp_path, data))


def test_sidecar_must_carry_config_hash_and_seed(tmp_path: Path) -> None:
    data = yaml.safe_load((CONFIG_DIR / "bench.yaml").read_text())
    data["output"]["sidecar_fields"] = ["run_id"]
    with pytest.raises(ConfigError, match="cannot be traced back"):
        load_config(_write(tmp_path, data))


# ---------------------------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------------------------
def test_get_and_require() -> None:
    cfg = load_config(CONFIG_DIR / "chain.yaml")
    assert cfg.get("consensus.protocol") == "pbft"
    assert cfg.get("consensus.nothing.here", "fallback") == "fallback"
    with pytest.raises(ConfigError, match="missing key"):
        cfg.get("consensus.nothing.here")
    with pytest.raises(ConfigError, match="expected str"):
        cfg.require("consensus.miner_nodes", str)


def test_require_int_rejects_a_bool(tmp_path: Path) -> None:
    # YAML's `yes`/`true` are bools, and `isinstance(True, int)` is True, so this is a real
    # config typo that would otherwise sail through as the integer 1.
    path = _write(tmp_path, {"kind": "chain", "schema_version": 1, "n": True})
    cfg = Config(kind="chain", schema_version=1, path=path, data={"n": True}, config_hash="x")
    with pytest.raises(ConfigError, match="is a bool"):
        cfg.require("n", int)
