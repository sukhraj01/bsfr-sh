"""The first time Phase 2's output feeds Phase 3's input, through a real pBFT cluster.

`tests/unit/test_phase3_detection.py` covers Phase 3's own wiring against directly-appended
chains — fast, no consensus. This is the fuller claim: `framework.phase2_collection.run()` builds
two independent `BC_SigRW` chains through actual pBFT rounds (the same path
`tests/integration/test_sigrw_scale.py` exercises for Phase 2 alone), and
`framework.phase3_detection.run()` reads them with no shortcut back to the honeypot's raw samples
or the committed CSV corpus. This is the sequence the paper's own Fig. 3 requires and never
demonstrates (FLAW-2).
"""

from __future__ import annotations

import pytest
from m3b_harness import make_node, make_server
from pbft_harness import REPO_ROOT, SIGRW_IDS, make_cluster

from bsfr_sh.blockchain.chain import BC_SigRW
from bsfr_sh.framework import phase2_collection as phase2
from bsfr_sh.framework import phase3_detection as phase3
from bsfr_sh.framework._block_pipeline import PipelinePolicy
from bsfr_sh.util.config import load_config

pytestmark = pytest.mark.integration

CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
CHAIN_CONFIG = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
POLICY = PipelinePolicy.from_config(CHAIN_CONFIG)
TRAIN_COUNT = 300
EVAL_COUNT = 150


def test_phase3_detects_over_a_chain_phase2_built_through_consensus() -> None:
    node, collector = make_node(seed=5150), make_server(50)
    train_cluster = make_cluster(BC_SigRW, SIGRW_IDS, seed=11)
    eval_cluster = make_cluster(BC_SigRW, SIGRW_IDS, seed=12)

    # One honeypot, two sequential harvests: the second draw's seed is the first's plus one,
    # deployed the same way `scripts/make_honeypot_corpus.py` derives Q9's train/eval seeds.
    train_report = phase2.run(
        node=node,
        collector=collector,
        cluster=train_cluster,
        policy=POLICY,
        count=TRAIN_COUNT,
        timestamp=2001.0,
    )
    eval_report = phase2.run(
        node=node,
        collector=collector,
        cluster=eval_cluster,
        policy=POLICY,
        count=EVAL_COUNT,
        timestamp=2001.0,
    )
    assert train_report.committed > 0
    assert eval_report.committed > 0

    train_chain = train_cluster.replicas[SIGRW_IDS[0]].chain
    eval_chain = eval_cluster.replicas[SIGRW_IDS[0]].chain

    handed_off = []
    report = phase3.run(
        train_chain=train_chain,
        eval_chain=eval_chain,
        decrypt=collector.decrypt,
        config=CONFIG,
        seed=5150,
        on_detect=handed_off.append,
    )

    assert report.train.n_rows == train_report.committed
    assert report.evaluation.n_rows == eval_report.committed
    assert set(report.train.sample_ids).isdisjoint(report.evaluation.sample_ids)
    assert len(report.detections) == report.evaluation.n_rows
    assert len(handed_off) == report.positives_detected
    assert 0.0 <= report.honest.precision <= 1.0
    assert 0.0 <= report.honest.recall <= 1.0
