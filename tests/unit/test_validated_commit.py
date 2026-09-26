"""`consensus.validated_commit` — pre-commit drift validation wrapping `BC_SigRW`'s `Chain`. M7-12.

Builds its own `Sig_RW` transactions (a fixed-dimension synthetic feature vector, not real
`FT_RW`) so this stays a fast, self-contained consensus test; `scripts/m7_12_poisoning_defense.py`
is where the real honeypot corpus and the M7-11 poisoning strategies get exercised end to end.
"""

from __future__ import annotations

import numpy as np
from pbft_harness import (
    GENESIS_TIME,
    RECIPIENT,
    SIGRW_IDS,
    SUBMITTER,
    SUBMITTER_ID,
    make_cluster,
)

from bsfr_sh.blockchain.chain import BC_SigRW
from bsfr_sh.blockchain.transaction import (
    SignatureRecordPayload,
    Transaction,
    encrypt_signature_record,
)
from bsfr_sh.consensus.pbft import Cluster
from bsfr_sh.consensus.validated_commit import (
    ValidatedSigRWChain,
    build_validated_sigrw_chain_factory,
    extract_feature_batch,
)
from bsfr_sh.detection.drift import DriftPolicy

N_FEATURES = 3
_POLICY = DriftPolicy(min_history=2, threshold=3.0, feature_threshold=3.0)


def _signature_transactions(
    tag: str, count: int, *, center: float, rng: np.random.Generator
) -> tuple[Transaction, ...]:
    out = []
    for i in range(count):
        features = tuple(float(center + v) for v in rng.normal(0.0, 0.05, size=N_FEATURES))
        payload = SignatureRecordPayload(
            sample_id=f"{tag}-{i:03d}",
            content_digest=b"\x00" * 32,
            attestation=b"\x00" * 64,
            features=features,
            collected_at=1_000 + i,
            schema="test.v1",
            label="RW",
        )
        out.append(
            encrypt_signature_record(
                recipient=RECIPIENT.public,
                tx_id=f"{tag}-{i:03d}",
                payload=payload,
                created_at=1_000 + i,
            )
        )
    return tuple(out)


def _submit_batch(cluster: Cluster, tag: str, *, center: float, rng: np.random.Generator) -> bytes:
    return cluster.submit(
        _signature_transactions(tag, 4, center=center, rng=rng),
        timestamp=GENESIS_TIME + 1,
        submitter_id=SUBMITTER_ID,
        key=SUBMITTER.private,
    )


def _defended_cluster() -> Cluster:
    factory = build_validated_sigrw_chain_factory(
        n_features=N_FEATURES, decrypt_keys=(RECIPIENT.private,), drift_policy=_POLICY
    )
    return make_cluster(chain_name=BC_SigRW, ids=SIGRW_IDS, chain_factory=factory)


# -- extract_feature_batch ------------------------------------------------------------------------


def test_extract_feature_batch_decrypts_sig_rw_transactions() -> None:
    rng = np.random.default_rng(0)
    txs = _signature_transactions("x", 3, center=1.0, rng=rng)
    from bsfr_sh.blockchain.block import BlockDraft
    from bsfr_sh.blockchain.chain import build_genesis
    from bsfr_sh.crypto.ecdsa import keypair_from_secret

    owner = keypair_from_secret(99)
    genesis = build_genesis(owner_id="owner", private_key=owner.private, timestamp=0.0)
    block = BlockDraft(
        owner_id="owner",
        owner_pubkey=owner.public.to_bytes(),
        transactions=txs,
        prev_hash=genesis.current_hash,
        timestamp=1.0,
    ).seal(owner.private)
    batch = extract_feature_batch(block, decrypt_keys=(RECIPIENT.private,))
    assert batch is not None
    assert batch.shape == (3, N_FEATURES)


def test_extract_feature_batch_returns_none_for_wrong_key() -> None:
    from bsfr_sh.blockchain.block import BlockDraft
    from bsfr_sh.blockchain.chain import build_genesis
    from bsfr_sh.crypto.ecdsa import keypair_from_secret

    rng = np.random.default_rng(0)
    txs = _signature_transactions("x", 2, center=1.0, rng=rng)
    owner = keypair_from_secret(99)
    genesis = build_genesis(owner_id="owner", private_key=owner.private, timestamp=0.0)
    block = BlockDraft(
        owner_id="owner",
        owner_pubkey=owner.public.to_bytes(),
        transactions=txs,
        prev_hash=genesis.current_hash,
        timestamp=1.0,
    ).seal(owner.private)
    wrong_key = keypair_from_secret(0xDEAD).private
    assert extract_feature_batch(block, decrypt_keys=(wrong_key,)) is None


# -- consensus integration --------------------------------------------------------------------


def test_defended_cluster_commits_clean_batches() -> None:
    cluster = _defended_cluster()
    rng = np.random.default_rng(1)
    for i in range(4):
        _submit_batch(cluster, f"clean{i}", center=0.0, rng=rng)
        cluster.run()
    assert set(cluster.heights().values()) == {4}
    for replica in cluster.replicas.values():
        assert isinstance(replica.chain, ValidatedSigRWChain)
        assert replica.chain.drift_events == []


def test_defended_cluster_rejects_a_batch_the_undefended_cluster_commits() -> None:
    undefended = make_cluster(chain_name=BC_SigRW, ids=SIGRW_IDS)
    defended = _defended_cluster()

    for cluster in (undefended, defended):
        rng = np.random.default_rng(2)
        for i in range(3):
            _submit_batch(cluster, f"clean{i}", center=0.0, rng=rng)
            cluster.run()

    assert set(undefended.heights().values()) == {3}
    assert set(defended.heights().values()) == {3}

    poison_rng = np.random.default_rng(999)
    _submit_batch(undefended, "poison", center=50.0, rng=poison_rng)
    undefended.run()
    assert set(undefended.heights().values()) == {4}, "undefended cluster should commit the batch"

    poison_rng = np.random.default_rng(999)
    _submit_batch(defended, "poison", center=50.0, rng=poison_rng)
    # Bounded run: with every honest replica independently refusing the same request, the
    # request never commits, so the bus never goes idle on its own (`pbft_harness.run_for`'s own
    # rationale — "Byzantine runs may never go idle" applies just as well to an all-honest
    # cluster that unanimously refuses one request). A generous but finite horizon is enough to
    # observe that the block never lands.
    defended.run(until=defended.network.now + 8 * defended.policy.view_change_timeout_s)
    assert set(defended.heights().values()) == {3}, "defended cluster must reject the shifted batch"
    flagged = [r for r in defended.replicas.values() if r.chain.drift_events]  # type: ignore[attr-defined]
    assert flagged, "at least one honest replica must have logged a drift event"
