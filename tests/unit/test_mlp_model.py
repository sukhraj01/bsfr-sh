"""`detection.mlp_model`: the MLP plugged into the four-algorithm profile machinery.

M7-10, DEV-36.
"""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.neural_network import MLPClassifier

from bsfr_sh.detection import profiles as detection_profiles
from bsfr_sh.detection.detector import DetectionModule
from bsfr_sh.detection.mlp_model import MODEL_NAME, build_mlp, train_mlp
from bsfr_sh.util.config import Config

_ML_CONFIG_DATA = {
    "kind": "ml",
    "schema_version": 1,
    "dataset": {
        "name": "bitcoinheist",
        "label_column": "label",
        "benign_label": "white",
        "drop_columns": ["address"],
        "feature_columns": ["year", "day"],
    },
    "modes": {
        "paper_mode": {"metrics": ["accuracy"]},
        "honest_mode": {"metrics": ["mcc"]},
    },
    "models": {
        "random_forest": {"enabled": True},
        "logistic_regression": {"enabled": True},
        "decision_tree": {"enabled": True},
        "k_nearest_neighbours": {"enabled": True},
    },
    "mlp_detector": {
        "enabled": True,
        "hidden_layer_sizes": [8, 4],
        "activation": "relu",
        "solver": "adam",
        "alpha": 0.001,
        "batch_size": "auto",
        "learning_rate_init": 0.01,
        "max_iter": 200,
        "early_stopping": False,
        "validation_fraction": 0.1,
        "n_iter_no_change": 10,
    },
}


def _config() -> Config:
    return Config(kind="ml", schema_version=1, path="<test>", data=_ML_CONFIG_DATA)  # type: ignore[arg-type]


def _toy_data(seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    n = 120
    x0 = rng.normal(loc=0.0, scale=1.0, size=(n // 2, 4))
    x1 = rng.normal(loc=3.0, scale=1.0, size=(n // 2, 4))
    x = np.vstack([x0, x1])
    y = np.array([0] * (n // 2) + [1] * (n // 2), dtype=np.int8)
    return x, y


def test_build_mlp_injects_seed_and_declared_hyperparameters() -> None:
    model = build_mlp(_config(), seed=42)
    assert isinstance(model, MLPClassifier)
    assert model.random_state == 42
    assert model.hidden_layer_sizes == [8, 4]
    assert model.alpha == pytest.approx(0.001)


def test_build_mlp_does_not_pass_enabled_as_a_constructor_kwarg() -> None:
    # MLPClassifier.__init__ has no 'enabled' parameter; this raises TypeError if the config's
    # 'enabled' flag leaks through unpopped.
    build_mlp(_config(), seed=1)


def test_train_mlp_returns_single_entry_mapping_named_mlp() -> None:
    x, y = _toy_data()
    models = train_mlp(x, y, _config(), seed=7)
    assert set(models) == {MODEL_NAME}
    assert hasattr(models[MODEL_NAME], "predict_proba")


def test_mlp_plugs_into_the_shared_profile_and_detector_machinery_unchanged() -> None:
    """The point of this module: zero changes to `detection.profiles`/`detection.detector` are
    needed to score an MLP through the same NProf/AProf mechanism the four-algorithm ensemble
    uses."""
    x, y = _toy_data()
    models = train_mlp(x, y, _config(), seed=7)
    normal, abnormal = detection_profiles.build(models, x, y, feature_names=("a", "b", "c", "d"))
    detector = DetectionModule(models=models, normal=normal, abnormal=abnormal)

    # A clearly-benign-cluster point and a clearly-malicious-cluster point should not both land
    # on the same side -- otherwise the wiring, not the model's accuracy, would be broken.
    benign_like = np.array([0.0, 0.0, 0.0, 0.0])
    malicious_like = np.array([3.0, 3.0, 3.0, 3.0])
    benign_decision = detector.decide("s0", benign_like)
    malicious_decision = detector.decide("s1", malicious_like)
    assert benign_decision.is_ransomware != malicious_decision.is_ransomware
