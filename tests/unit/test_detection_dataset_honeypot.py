"""`detection.dataset`'s honeypot half: `load_from_chain`, `HoneypotBackend`, and backend
selection by config (FLAW-2, Alg. 3 line 1). `test_detection_dataset.py` covers the BitcoinHeist
half; this file is the M4b counterpart.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from m3a_harness import OWNER, append_in_blocks, make_server
from pbft_harness import GENESIS_TIME

from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW, Chain, build_genesis
from bsfr_sh.blockchain.transaction import encrypt_signature_record
from bsfr_sh.detection.dataset import (
    BitcoinHeistBackend,
    DatasetBackend,
    DatasetError,
    DatasetSpec,
    HoneypotBackend,
    backend_from_config,
    load_from_chain,
)
from bsfr_sh.framework import phase2_collection as phase2
from bsfr_sh.honeypot import features as ft
from bsfr_sh.honeypot.collector import synthesize
from bsfr_sh.honeypot.preprocess import clean
from bsfr_sh.util.config import Config

BITCOINHEIST_DATASET_CONFIG = {
    "name": "bitcoinheist",
    "label_column": "label",
    "benign_label": "white",
    "drop_columns": ["address"],
    "feature_columns": ["year", "day"],
}


def _config(dataset: dict) -> Config:
    return Config(kind="ml", schema_version=1, path=Path("test-ml.yaml"), data={"dataset": dataset})


def _sig_rw_chain(records, collector, *, per_block: int = 5) -> Chain:
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


def _draw_and_chain(*, seed: int, count: int, collector, per_block: int = 5):
    raw = synthesize(count, seed=seed, malicious_fraction=0.5)
    cleaned, _report = clean(raw)
    records = phase2.build_records(cleaned, collector)
    return cleaned, records, _sig_rw_chain(records, collector, per_block=per_block)


# -- the round trip: corpus's own generator -> Phase 2 -> BC_SigRW -> HoneypotBackend -----------
def test_round_trip_features_survive_corpus_to_chain_to_backend() -> None:
    collector = make_server(20)
    cleaned, _records, chain = _draw_and_chain(seed=777, count=200, collector=collector)
    pre_chain = {sample.sample_id: ft.build(sample) for sample in cleaned}

    dataset = load_from_chain(chain, collector.decrypt)
    on_chain = dict(zip(dataset.sample_ids, dataset.features, strict=True))

    assert set(on_chain) == set(pre_chain)
    for sample_id, vector in pre_chain.items():
        assert on_chain[sample_id] == pytest.approx(vector.values)
    assert dataset.feature_names == ft.FEATURE_NAMES
    assert dataset.n_rows == len(cleaned)
    assert dataset.n_positive + dataset.n_negative == dataset.n_rows


def test_load_from_chain_labels_match_the_emulators_ground_truth() -> None:
    collector = make_server(21)
    cleaned, _records, chain = _draw_and_chain(seed=778, count=120, collector=collector)
    truth = {sample.sample_id: sample.label for sample in cleaned}

    dataset = load_from_chain(chain, collector.decrypt)
    for sample_id, label in zip(dataset.sample_ids, dataset.labels, strict=True):
        assert (label == 1) == (truth[sample_id] == "RW")


def test_load_from_chain_skips_records_it_cannot_decrypt_but_keeps_the_rest() -> None:
    """Another collector's records share `BC_SigRW`; they are skipped, not an error."""
    mine, theirs = make_server(22), make_server(23)
    _cleaned_a, records_a, _ = _draw_and_chain(seed=779, count=60, collector=mine)
    _cleaned_b, records_b, _ = _draw_and_chain(seed=780, count=60, collector=theirs)

    chain = Chain(BC_SigRW)
    chain.adopt_genesis(
        build_genesis(owner_id="CS_0", private_key=OWNER.private, timestamp=GENESIS_TIME)
    )
    transactions = [
        encrypt_signature_record(
            recipient=mine.public_key, tx_id=r.sample_id, payload=r, created_at=r.collected_at
        )
        for r in records_a
    ] + [
        encrypt_signature_record(
            recipient=theirs.public_key, tx_id=r.sample_id, payload=r, created_at=r.collected_at
        )
        for r in records_b
    ]
    append_in_blocks(chain, transactions, per_block=7)

    dataset = load_from_chain(chain, mine.decrypt)
    assert set(dataset.sample_ids) == {r.sample_id for r in records_a}


def test_load_from_chain_refuses_a_chain_that_is_not_bc_sigrw() -> None:
    chain = Chain(BC_DTBU)
    chain.adopt_genesis(
        build_genesis(owner_id="CS_0", private_key=OWNER.private, timestamp=GENESIS_TIME)
    )
    with pytest.raises(DatasetError, match="BC_SigRW"):
        load_from_chain(chain, lambda tx: b"")  # never called, refused before decrypt runs


def test_load_from_chain_raises_when_nothing_decrypts() -> None:
    stranger = make_server(24)
    collector = make_server(25)
    _cleaned, _records, chain = _draw_and_chain(seed=781, count=30, collector=collector)
    with pytest.raises(DatasetError, match="no SIG_RW records"):
        load_from_chain(chain, stranger.decrypt)


# -- backend selection by config, both satisfying the same interface ----------------------------
def test_bitcoinheist_backend_satisfies_the_shared_interface() -> None:
    backend = BitcoinHeistBackend(spec=DatasetSpec(path=Path("unused.csv")), seed=0)
    assert isinstance(backend, DatasetBackend)


def test_honeypot_backend_satisfies_the_shared_interface() -> None:
    collector = make_server(26)
    _cleaned, _records, chain = _draw_and_chain(seed=782, count=40, collector=collector)
    backend = HoneypotBackend(chain=chain, decrypt=collector.decrypt)
    assert isinstance(backend, DatasetBackend)
    dataset = backend.load()
    assert dataset.n_rows > 0


def test_backend_from_config_selects_bitcoinheist() -> None:
    backend = backend_from_config(_config(BITCOINHEIST_DATASET_CONFIG), root=Path(), seed=0)
    assert isinstance(backend, BitcoinHeistBackend)


def test_backend_from_config_selects_honeypot() -> None:
    collector = make_server(27)
    _cleaned, _records, chain = _draw_and_chain(seed=783, count=40, collector=collector)
    backend = backend_from_config(
        _config({"name": "honeypot"}),
        root=Path(),
        seed=0,
        chain=chain,
        decrypt=collector.decrypt,
    )
    assert isinstance(backend, HoneypotBackend)


def test_backend_from_config_honeypot_requires_chain_and_decrypt() -> None:
    with pytest.raises(DatasetError, match="chain and a decrypt"):
        backend_from_config(_config({"name": "honeypot"}), root=Path(), seed=0)


def test_backend_from_config_rejects_an_unknown_name() -> None:
    with pytest.raises(DatasetError, match="bitcoinheist"):
        backend_from_config(_config({"name": "carrier_pigeon"}), root=Path(), seed=0)
