"""The exit condition for the whole framework: Fig. 3, all five phases, both chains, one test.

    SYS_i --(1) backup--> CS_l --(2) BC_DTBU--> committed through pBFT
    HP_RW --(3) ransomware data--> CS_l --(4) BC_SigRW--> committed through pBFT (two draws)
    CS_l  --(5) detect--> RW found --(6) mitigate--> isolate, remediate, Case-2
    CS_l  --(7) format + restore via Phase 5--> SYS_i has its data back, byte-identical

Every phase before this one has its own integration test against a real pBFT cluster
(`test_backup_recovery.py` for 1+5, `test_phase2_feeds_phase3.py` for 2+3). This is the first test
that runs all five in the sequence the paper's own sequence diagram draws and never demonstrates
itself (FLAW-2) — `docs/ALGORITHMS.md`'s "Sequence (Fig. 3)" section names this file as its spec.

Attributing a detection to the backed-up system is `docs/DEVIATIONS.md` DEV-29's gap: the paper
never says how a honeypot detection maps to a specific `SYS_i`. This test supplies that mapping
itself, the way any real Phase 3/4 caller would have to.
"""

from __future__ import annotations

import pytest
from m3a_harness import make_server, make_system
from m3b_harness import make_node
from pbft_harness import REPO_ROOT, SIGRW_IDS, make_cluster

from bsfr_sh.blockchain.chain import BC_SigRW
from bsfr_sh.framework import phase1_backup as phase1
from bsfr_sh.framework import phase2_collection as phase2
from bsfr_sh.framework import phase3_detection as phase3
from bsfr_sh.framework import phase4_mitigation as phase4
from bsfr_sh.framework import phase5_recovery as phase5
from bsfr_sh.framework._block_pipeline import PipelinePolicy, read_chain
from bsfr_sh.util.config import load_config

pytestmark = pytest.mark.integration

CHAIN_CONFIG = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
ML_CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
BACKUP_POLICY = phase1.BackupPolicy.from_config(CHAIN_CONFIG)
SIGRW_POLICY = PipelinePolicy.from_config(CHAIN_CONFIG)
TRAIN_COUNT = 300
EVAL_COUNT = 150


def test_backup_honeypot_detection_mitigation_and_recovery_all_five_phases() -> None:
    # --- Phase 1: SYS_i's data reaches BC_DTBU through pBFT (Fig. 3, steps 1-2) -----------------
    key_holder, front = make_server(10), make_server(11)
    dtbu_cluster = make_cluster(submitters={key_holder.identity: key_holder.public_key})
    victim = make_system(1, 4096)
    original_data = victim.data
    phase1.run(
        systems=[victim],
        collector=key_holder,
        cluster=dtbu_cluster,
        policy=BACKUP_POLICY,
        captured_at=100,
        timestamp=1001.0,
    )

    # --- Phase 2: the honeypot's two independent draws reach BC_SigRW (Fig. 3, steps 3-4) ------
    node, collector = make_node(seed=6060), make_server(50)
    sigrw_submitters = {collector.identity: collector.public_key}
    train_cluster = make_cluster(BC_SigRW, SIGRW_IDS, seed=21, submitters=sigrw_submitters)
    eval_cluster = make_cluster(BC_SigRW, SIGRW_IDS, seed=22, submitters=sigrw_submitters)
    train_report = phase2.run(
        node=node,
        collector=collector,
        cluster=train_cluster,
        policy=SIGRW_POLICY,
        count=TRAIN_COUNT,
        timestamp=2001.0,
    )
    eval_report = phase2.run(
        node=node,
        collector=collector,
        cluster=eval_cluster,
        policy=SIGRW_POLICY,
        count=EVAL_COUNT,
        timestamp=2001.0,
    )
    assert train_report.committed > 0
    assert eval_report.committed > 0

    # --- Phase 3: detect over what Phase 2 committed (Fig. 3, step 5) --------------------------
    handed_off = []
    detection_report = phase3.run(
        train_chain=train_cluster.replicas[SIGRW_IDS[0]].chain,
        eval_chain=eval_cluster.replicas[SIGRW_IDS[0]].chain,
        decrypt=collector.decrypt,
        config=ML_CONFIG,
        seed=6060,
        on_detect=handed_off.append,
    )
    assert detection_report.positives_detected > 0
    assert len(handed_off) == detection_report.positives_detected
    positive = handed_off[0]

    # --- Phase 4: isolate, remediate via Case-2 (Fig. 3, steps 6-7) ----------------------------
    format_calls: list[str] = []

    def format_system() -> None:
        format_calls.append(victim.identity)
        victim.wipe()

    def restore():
        return phase5.run(
            system=victim,
            front=front,
            key_holder=key_holder,
            chain=read_chain(dtbu_cluster),
        )

    mitigation_report = phase4.run(
        detection=positive,
        system_id=victim.identity,
        case=phase4.MitigationCase.RESTORE,
        detected_at=3001.0,
        isolated_at=3001.5,
        remediation_started_at=3002.0,
        resolved_at=3003.0,
        format_system=format_system,
        restore=restore,
    )

    # --- Exit condition: detected, isolated, formatted and restored, byte-identical ------------
    assert format_calls == [victim.identity]
    assert victim.data == original_data
    assert mitigation_report.outcome == "RESTORED"
    assert mitigation_report.resolved.infected.system_id == victim.identity
    assert mitigation_report.resolved.infected.sample_id == positive.sample_id
