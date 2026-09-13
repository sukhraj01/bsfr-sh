"""`framework.phase3_detection`: Alg. 3 lines 1-9, wired end to end from two `BC_SigRW` chains.

Chains here are built by direct append (fast, no consensus) — this file is about Phase 3's own
wiring, not consensus fidelity. `tests/integration/test_phase2_feeds_phase3.py` runs the same
wiring through a real pBFT cluster, which is where "Phase 2's output feeds Phase 3's input" is
actually demonstrated end to end.
"""

from __future__ import annotations

import ast
from pathlib import Path

from m3a_harness import OWNER, append_in_blocks, make_server
from pbft_harness import GENESIS_TIME, REPO_ROOT

from bsfr_sh.blockchain.chain import BC_SigRW, Chain, build_genesis
from bsfr_sh.blockchain.transaction import encrypt_signature_record
from bsfr_sh.detection.detector import Detection
from bsfr_sh.framework import phase2_collection as phase2
from bsfr_sh.framework import phase3_detection as phase3
from bsfr_sh.honeypot.collector import synthesize
from bsfr_sh.honeypot.preprocess import clean
from bsfr_sh.util.config import load_config

CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")


def _chain_from_draw(*, seed: int, count: int, collector, per_block: int = 10) -> Chain:
    raw = synthesize(count, seed=seed, malicious_fraction=0.5)
    cleaned, _report = clean(raw)
    records = phase2.build_records(cleaned, collector)
    chain = Chain(BC_SigRW)
    chain.adopt_genesis(
        build_genesis(owner_id="CS_0", private_key=OWNER.private, timestamp=GENESIS_TIME)
    )
    transactions = [
        encrypt_signature_record(
            recipient=collector.public_key,
            tx_id=record.sample_id,
            payload=record,
            created_at=record.collected_at,
        )
        for record in records
    ]
    append_in_blocks(chain, transactions, per_block=per_block)
    return chain


def test_phase3_runs_end_to_end_from_two_chains() -> None:
    collector = make_server(40)
    train_chain = _chain_from_draw(seed=9001, count=300, collector=collector)
    eval_chain = _chain_from_draw(seed=9002, count=150, collector=collector)

    report = phase3.run(
        train_chain=train_chain,
        eval_chain=eval_chain,
        decrypt=collector.decrypt,
        config=CONFIG,
        seed=9001,
    )

    assert report.train.n_rows > 0
    assert report.evaluation.n_rows > 0
    assert len(report.detections) == report.evaluation.n_rows
    assert 0.0 <= report.honest.precision <= 1.0
    assert 0.0 <= report.honest.recall <= 1.0
    assert report.positives_detected == sum(d.is_ransomware for d in report.detections)


def test_train_and_eval_draws_never_share_a_sample() -> None:
    """Q9's hygiene, carried into Phase 3: two independent draws, never one playing both roles."""
    collector = make_server(41)
    train_chain = _chain_from_draw(seed=9101, count=200, collector=collector)
    eval_chain = _chain_from_draw(seed=9102, count=100, collector=collector)

    report = phase3.run(
        train_chain=train_chain,
        eval_chain=eval_chain,
        decrypt=collector.decrypt,
        config=CONFIG,
        seed=9101,
    )
    assert set(report.train.sample_ids).isdisjoint(report.evaluation.sample_ids)


def test_the_handoff_fires_exactly_on_reported_positives() -> None:
    collector = make_server(42)
    train_chain = _chain_from_draw(seed=9201, count=250, collector=collector)
    eval_chain = _chain_from_draw(seed=9202, count=120, collector=collector)
    handed_off: list[Detection] = []

    report = phase3.run(
        train_chain=train_chain,
        eval_chain=eval_chain,
        decrypt=collector.decrypt,
        config=CONFIG,
        seed=9201,
        on_detect=handed_off.append,
    )
    assert len(handed_off) == report.positives_detected
    assert all(d.is_ransomware for d in handed_off)


def _imported_modules(module) -> set[str]:
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imports.add(node.module)
    return imports


def test_profiles_come_from_the_chain_not_the_committed_corpus() -> None:
    """If this module could read data/honeypot/ instead of the chain, it would not be wired.

    Checked by import graph rather than substring search: the module's own docstring is free to
    *mention* `honeypot.corpus` when explaining why it does not read it.
    """
    imports = _imported_modules(phase3)
    assert "bsfr_sh.honeypot.corpus" not in imports
    assert not any(name.startswith("bsfr_sh.honeypot.corpus") for name in imports)


def test_phase3_does_not_orchestrate_consensus_itself() -> None:
    """The chains it reads must already exist; Phase 3 only decrypts, trains, profiles, detects."""
    imports = _imported_modules(phase3)
    assert "bsfr_sh.consensus.pbft" not in imports
    assert "bsfr_sh.framework._block_pipeline" not in imports
