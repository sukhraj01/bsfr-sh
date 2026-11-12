"""Phase 2 / P2-F: one server holds the only key to every backup it collected. Split it.

Alg. 1 line 2 encrypts each backup to the collecting cloud server's public key (DEV-01, DEV-25).
`BC_DTBU` then replicates the *ciphertext* to all four pBFT servers, but the private key that opens
it exists on one server. Two consequences, both demonstrated here on the real pipeline:

* **availability** — ransomware (or a disk failure) on that one server makes every backup it
  collected unrecoverable, although four intact copies of the chain remain;
* **confidentiality** — an attacker who steals that one key reads every backup it collected from
  *any* replica's copy of the chain.

Part A runs Alg. 1 through real pBFT on a 4-server `BC_DTBU`, then attempts Alg. 5 recovery after
the key holder is lost, and an attacker read after it is compromised.

Part B is the proposed repair (DEV-48): split each backup's data key into 4 Shamir shares, one
wrapped to each server, any `t` of which open it (`crypto.threshold_kem`). For every one of the 16
subsets of servers it *actually attempts* (a) recovery by the hospital using only the servers not
in the subset, and (b) decryption by an attacker holding exactly the subset's keys, for
t = 1..4 and for Phase 1's single-holder scheme. The attacker path bypasses the API's share-count
check and tries the AEAD directly, so "cannot open" is a cryptographic result, not a refusal.

Part C measures what the repair costs per 4 KiB backup chunk: seal/open time and key bytes.

Usage::

    python scripts/p2f_key_holder.py --seed 20261112
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bsfr_sh.blockchain.chain import BC_DTBU, build_genesis  # noqa: E402
from bsfr_sh.blockchain.transaction import TransactionError  # noqa: E402
from bsfr_sh.consensus.pbft import Cluster, PBFTPolicy  # noqa: E402
from bsfr_sh.crypto import kem  # noqa: E402
from bsfr_sh.crypto import threshold_kem as tk  # noqa: E402
from bsfr_sh.crypto.aead import AeadError, AeadKey, Sealed  # noqa: E402
from bsfr_sh.crypto.ecdsa import keypair_from_secret  # noqa: E402
from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, config_hash  # noqa: E402
from bsfr_sh.crypto.kem import KemError  # noqa: E402
from bsfr_sh.crypto.secret_sharing import combine  # noqa: E402
from bsfr_sh.framework import phase1_backup as phase1  # noqa: E402
from bsfr_sh.framework import phase5_recovery as phase5  # noqa: E402
from bsfr_sh.framework._block_pipeline import read_chain  # noqa: E402
from bsfr_sh.framework.entities import CloudServer, System  # noqa: E402
from bsfr_sh.recovery import restore as alg5  # noqa: E402
from bsfr_sh.recovery.locator import RecoveryError, identify  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

N_SERVERS = 4
SYSTEM_BYTES = 48 * 1024
TIMING_REPEATS = 200
P_GRID = (0.01, 0.05, 0.10, 0.20)
RECOVERY_ERRORS = (RecoveryError, KemError, TransactionError)


# --------------------------------------------------------------------------------------------
# Part A — the real pipeline, Phase 1 scheme
# --------------------------------------------------------------------------------------------
def part_a(seed: int) -> dict[str, Any]:
    chain_cfg = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
    servers = [
        CloudServer(identity=f"CS_{i}", keypair=keypair_from_secret(0xC5C5_0000 + seed % 1000 + i))
        for i in range(N_SERVERS)
    ]
    key_holder, front = servers[0], servers[1]
    keys = {s.identity: s.keypair.private for s in servers}
    cluster = Cluster(
        chain_name=BC_DTBU,
        keys=keys,
        genesis=build_genesis(owner_id="CS_0", private_key=keys["CS_0"], timestamp=1000.0),
        policy=PBFTPolicy.from_config(chain_cfg),
        seed=seed,
        submitters={key_holder.identity: key_holder.public_key},
    )
    systems = [
        System(identity=f"SYS_{i}", keypair=keypair_from_secret(0x5E5E_0000 + i),
               data=random.Random(seed + i).randbytes(SYSTEM_BYTES))
        for i in range(4)
    ]  # fmt: skip
    originals = {s.identity: s.data for s in systems}
    phase1.run(systems=systems, collector=key_holder, cluster=cluster,
               policy=phase1.BackupPolicy.from_config(chain_cfg), captured_at=100,
               timestamp=1001.0)  # fmt: skip
    chain = read_chain(cluster)
    heights = sorted({len(r.chain) for r in cluster.replicas.values()})

    def try_recover(system: System, holder: CloudServer) -> bool:
        system.wipe()
        try:
            phase5.run(system=system, front=front, key_holder=holder, chain=chain)
        except RECOVERY_ERRORS:
            return False
        return system.data == originals[system.identity]

    healthy = sum(try_recover(s, key_holder) for s in systems)
    # CS_0 is gone (ransomware on the server, its private key with it). Every other server tries.
    lost = {
        other.identity: sum(try_recover(s, other) for s in systems) for other in servers[1:]
    }
    # CS_0's key is stolen. The attacker reads a *different* replica's copy of the chain.
    victim_replica = sorted(cluster.replicas)[-1]
    replica_chain = cluster.replicas[victim_replica].chain
    exposed = 0
    for s in systems:
        locs = identify(replica_chain, s.identity, decrypt=key_holder.decrypt)
        plan = alg5.begin(s.identity, locs)
        _, data = alg5.request_decrypt(replica_chain, plan, key_holder.decrypt)
        exposed += int(data == originals[s.identity])
    return {
        "systems": len(systems),
        "bytes_per_system": SYSTEM_BYTES,
        "replicas_holding_full_chain": len(cluster.replicas),
        "replica_chain_heights": heights,
        "recovered_with_key_holder": healthy,
        "recovered_after_key_holder_lost_by_other_server": lost,
        "attacker_with_key_holder_key_read_systems": exposed,
        "attacker_read_from_replica": victim_replica,
    }


# --------------------------------------------------------------------------------------------
# Part B — the repair, every subset of servers actually tried
# --------------------------------------------------------------------------------------------
SCHEMES = ("single_holder", "t1_of_4", "t2_of_4", "t3_of_4", "t4_of_4")


def _attacker_opens(ct: tk.ThresholdCiphertext, holders: list[Any], meta: dict[str, Any]) -> bool:
    """Bypass the share-count check: combine whatever shares the attacker has and try the AEAD."""
    if not holders:
        return False
    shares = [tk.unwrap_share(h.private, ct, meta) for h in holders]
    aad = tk._payload_aad(tk._metadata_bytes(meta), ct.threshold, ct.wrapped_shares)
    try:
        AeadKey(combine(shares)).unseal(Sealed(nonce=ct.nonce, ciphertext=ct.ciphertext), aad)
    except AeadError:
        return False
    return True


def part_b(seed: int) -> dict[str, Any]:
    holders = [keypair_from_secret(0x7E5E_0000 + seed % 1000 + i) for i in range(N_SERVERS)]
    payload = random.Random(seed).randbytes(4096)
    meta = {"tx_id": "p2f", "payload_type": "backup", "created_at": 100}
    subsets = [s for k in range(N_SERVERS + 1) for s in itertools.combinations(range(N_SERVERS), k)]
    results: dict[str, list[dict[str, Any]]] = {}
    for scheme in SCHEMES:
        rows = []
        if scheme == "single_holder":
            hybrid = kem.seal_payload(holders[0].public, payload, meta)
        else:
            t = int(scheme[1])
            ct = tk.seal_payload_threshold([h.public for h in holders], t, payload, meta)
        for subset in subsets:
            survivors = [i for i in range(N_SERVERS) if i not in subset]
            if scheme == "single_holder":
                def single(idx: list[int]) -> bool:
                    if 0 not in idx:
                        return False
                    return kem.open_payload(holders[0].private, hybrid, meta) == payload
                recovers, leaks = single(survivors), single(list(subset))
            else:
                try:
                    shares = [tk.unwrap_share(holders[i].private, ct, meta) for i in survivors]
                    recovers = tk.open_with_shares(ct, shares, meta) == payload
                except KemError:
                    recovers = False
                leaks = _attacker_opens(ct, [holders[i] for i in subset], meta)
            rows.append({"subset": list(subset), "size": len(subset),
                         "hospital_recovers_if_subset_lost": recovers,
                         "attacker_reads_if_subset_compromised": leaks})  # fmt: skip
        results[scheme] = rows

    summary: dict[str, Any] = {}
    for scheme, rows in results.items():
        def worst(key: str, bad: bool) -> int | None:
            sizes = [r["size"] for r in rows if r[key] is bad]
            return min(sizes) if sizes else None
        by_size = {
            k: {"loss_fraction": statistics.fmean(not r["hospital_recovers_if_subset_lost"]
                                                  for r in rows if r["size"] == k),
                "leak_fraction": statistics.fmean(r["attacker_reads_if_subset_compromised"]
                                                  for r in rows if r["size"] == k)}
            for k in range(N_SERVERS + 1)
        }  # fmt: skip
        derived = {}
        for p in P_GRID:
            weight = {tuple(r["subset"]): p ** r["size"] * (1 - p) ** (N_SERVERS - r["size"])
                      for r in rows}  # fmt: skip
            derived[str(p)] = {
                "p_data_loss": sum(weight[tuple(r["subset"])] for r in rows
                                   if not r["hospital_recovers_if_subset_lost"]),
                "p_leak": sum(weight[tuple(r["subset"])] for r in rows
                              if r["attacker_reads_if_subset_compromised"]),
            }  # fmt: skip
        summary[scheme] = {
            "fewest_servers_lost_to_lose_backups": worst("hospital_recovers_if_subset_lost", False),
            "fewest_servers_compromised_to_leak": worst("attacker_reads_if_subset_compromised", True),
            "by_size": by_size,
            "derived_independent_failure_probability": derived,
        }
    return {"subsets_tried": len(subsets), "summary": summary, "rows": results}


# --------------------------------------------------------------------------------------------
# Part C — cost per 4 KiB backup chunk
# --------------------------------------------------------------------------------------------
def part_c(seed: int) -> dict[str, Any]:
    holders = [keypair_from_secret(0x7E5E_0000 + seed % 1000 + i) for i in range(N_SERVERS)]
    payload = random.Random(seed).randbytes(4096)
    meta = {"tx_id": "p2f", "payload_type": "backup", "created_at": 100}

    def median_us(fn: Any) -> float:
        samples = []
        for _ in range(TIMING_REPEATS):
            start = time.perf_counter()
            fn()
            samples.append(time.perf_counter() - start)
        return statistics.median(samples) * 1e6

    hybrid = kem.seal_payload(holders[0].public, payload, meta)
    ct = tk.seal_payload_threshold([h.public for h in holders], 2, payload, meta)
    two = holders[:2]
    return {
        "single_holder": {
            "seal_us": median_us(lambda: kem.seal_payload(holders[0].public, payload, meta)),
            "open_us": median_us(lambda: kem.open_payload(holders[0].private, hybrid, meta)),
            "key_material_bytes": len(hybrid.wrapped_key),
        },
        "t2_of_4": {
            "seal_us": median_us(
                lambda: tk.seal_payload_threshold([h.public for h in holders], 2, payload, meta)
            ),
            "open_us": median_us(
                lambda: tk.open_with_shares(
                    ct, [tk.unwrap_share(h.private, ct, meta) for h in two], meta
                )
            ),
            "key_material_bytes": ct.key_material_bytes(),
        },
        "payload_bytes": len(payload),
        "repeats": TIMING_REPEATS,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261112)
    args = parser.parse_args()
    seed_all(args.seed)
    run_id = log.configure()
    chain_cfg = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")

    a = part_a(args.seed)
    sys.stderr.write(f"A: {json.dumps(a)}\n")
    b = part_b(args.seed)
    for scheme, s in b["summary"].items():
        sys.stderr.write(
            f"B: {scheme:<14} lose-after={s['fewest_servers_lost_to_lose_backups']} "
            f"leak-after={s['fewest_servers_compromised_to_leak']} "
            f"p=0.10 -> {s['derived_independent_failure_probability']['0.1']}\n"
        )
    c = part_c(args.seed)
    sys.stderr.write(f"C: {json.dumps(c)}\n")

    lines = ["scheme,fewest_lost_to_lose_backups,fewest_compromised_to_leak,"
             + ",".join(f"p_loss_at_{p},p_leak_at_{p}" for p in P_GRID)]  # fmt: skip
    for scheme, s in b["summary"].items():
        d = s["derived_independent_failure_probability"]
        lines.append(
            f"{scheme},{s['fewest_servers_lost_to_lose_backups']},"
            f"{s['fewest_servers_compromised_to_leak']},"
            + ",".join(f"{d[str(p)]['p_data_loss']:.6f},{d[str(p)]['p_leak']:.6f}" for p in P_GRID)
        )
    (REPO_ROOT / "results" / "tables" / "p2f_key_holder.csv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    sidecar = {
        "run_id": run_id,
        "purpose": "P2-F: single backup-key holder vs t-of-4 threshold key wrapping",
        "seed": args.seed,
        "config_hash": config_hash(chain_cfg.kind, chain_cfg.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                                  text=True, cwd=REPO_ROOT).stdout.strip(),  # fmt: skip
        "host": log.env_snapshot(),
        "part_a_real_pipeline": a,
        "part_b_subsets": b,
        "part_c_cost": c,
    }
    (REPO_ROOT / "results" / "logs" / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, default=float) + "\n", encoding="utf-8"
    )
    _figure(b["summary"])
    print(json.dumps({"run_id": run_id}))
    return 0


def _figure(summary: dict[str, Any]) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = {"single_holder": "Phase 1:\none key holder", "t1_of_4": "key copied\nto all 4",
              "t2_of_4": "split,\nany 2 of 4", "t3_of_4": "split,\nany 3 of 4",
              "t4_of_4": "split,\nall 4 needed"}  # fmt: skip
    schemes = list(SCHEMES)
    lose = [summary[s]["fewest_servers_lost_to_lose_backups"] or 5 for s in schemes]
    leak = [summary[s]["fewest_servers_compromised_to_leak"] or 5 for s in schemes]
    fig, ax = plt.subplots(figsize=(9, 3.9))
    x = range(len(schemes))
    w = 0.36
    b1 = ax.bar([i - w / 2 - 0.01 for i in x], lose, w, color="#1f4e9c",
                label="servers that must be LOST before backups are gone")  # fmt: skip
    b2 = ax.bar([i + w / 2 + 0.01 for i in x], leak, w, color="#b22222",
                label="servers that must be STOLEN before backups leak")  # fmt: skip
    for bars in (b1, b2):
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() - 0.12,
                    f"{int(bar.get_height())}", ha="center", va="top", color="white",
                    fontweight="bold", fontsize=10)  # fmt: skip
    ax.axhline(2, color="#8a8a8a", ls="--", lw=1)
    ax.text(0.0, 2.05, "pBFT itself breaks at 2", ha="center", va="bottom",
            fontsize=8, color="#555555")  # fmt: skip
    ax.set_xticks(list(x), [labels[s] for s in schemes], fontsize=9)
    ax.set_ylim(0, 4.9)
    ax.set_yticks([0, 1, 2, 3, 4])
    ax.set_ylabel("servers, of 4 (higher = safer)")
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="upper left", fontsize=8, frameon=False)
    ax.set_title("One key holder: one bad server loses or leaks every backup. Split key: both need "
                 "2+", loc="left", fontsize=11)  # fmt: skip
    fig.tight_layout()
    fig.savefig(REPO_ROOT / "results" / "figures" / "p2f_key_holder.png", dpi=170)


if __name__ == "__main__":
    raise SystemExit(main())
