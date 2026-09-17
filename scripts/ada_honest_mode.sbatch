#!/bin/bash
# Full-scale honest_mode on Ada (ada.iiit.ac.in) — the run that cannot happen on the 8 GB dev box.
#
# Why this exists rather than "we skipped KNN": CLAUDE.md §6 says heavy ML runs go to Ada and that
# full-scale runs are explicitly opt-in. M4a projected the cost *before* running anything
# (`detection.models.knn_projection`) and found KNN at 2.9M rows needs ~17.94 GB for the distance
# block alone, against a 2.9M x 583K = 1.36e12 distance computation count per fold. That is not a
# slow run on the dev box; it is an impossible one there. So it is named here instead of being
# quietly dropped from the results table.
#
# M6b, 2026-09-17: adapted from the M4a placeholder to this account's *real*, discovered limits —
# discovered by submitting small test jobs this session, not guessed:
#
#   * `/share1/<user>` — the M4a-era plan for a working directory — is **login-node-only**. A
#     compute node's own `df -h` never lists it, and a job that tries to write there fails at
#     output-file-open time with no script output at all (this session's `envtest`/`envtest2`
#     jobs, before this fix). `/home2` (home) *is* NFS-mounted on compute nodes, but this
#     account has only ~3.5 GB free there — too tight for a venv plus the dataset plus results.
#     Compute nodes do have node-local `/scratch` (1.8 TB, no per-user quota) — see below.
#   * account "research", QOS "low": `sacctmgr show qos low` → `MaxTRESPU = cpu=10, mem=32000M`.
#     The M4a placeholder's `--mem=64G --cpus-per-task=16` violates both before the job ever
#     reaches a node.
#   * partition "u22" is the only one this account may use (`scontrol show partition`: u22-cpu/
#     ihub/plafnet2/rrc all `AllowAccounts=` a different group). u22's own cap,
#     `MaxMemPerCPU=3000`, means the QOS's 10-cpu ceiling caps total memory at 30000M anyway —
#     the two limits agree, not by luck, by how this cluster is carved up.
#   * `--mem-per-cpu=3000 --cpus-per-task=10` requests exactly that ceiling (30000M ≈ 29.3 GiB),
#     comfortably above the 17.94 GB projection with real headroom for pandas/RF/interpreter/OS —
#     verified against `detection.models.largest_feasible_n(8, 5, ceiling_gb=29.3,
#     headroom=0.65)`, which returns a feasible n *larger than the full 2,916,697 rows*: KNN runs
#     on every row, not a subsample, at these numbers. If a future account/QOS change lowers the
#     ceiling below that, `run_detection.py` subsamples KNN automatically and names the ceiling
#     it used — it does not silently drop the model (CLAUDE.md §2).
#   * the login node's own internet egress is slow and unreliable (~14 KB/s to UCI's archive,
#     timing out in testing) — but a *compute* node's is fast (a UCI request that timed out after
#     15s from the login node completed in 0.1s from gnode002, this session's `envtest4`). So the
#     dataset is fetched *inside* the job, on the compute node, not rsynced in from the dev box.
#
# Consequence for how this runs: submit from a small, code-only checkout under `/home2/<user>`
# (rsync the repo there excluding `.venv`, `data/raw`, `.git`). The job itself copies that
# checkout into `/scratch/$SLURM_JOB_ID`, builds the venv and fetches the dataset *there* (fast,
# unlimited local disk), runs the real work there, and copies only the results (sidecar JSON, the
# Table II CSV, stdout) back to the home checkout — `/scratch` dies with the job, `/home2` does
# not, and the login node (hence `scp` back to the dev box) can reach `/home2` but not `/scratch`.
#
#   # from the dev box:
#   rsync -az --exclude=.venv --exclude=data/raw --exclude=.git ./ ada:~/bsfr-sh/
#   ssh ada 'cd ~/bsfr-sh && sbatch scripts/ada_honest_mode.sbatch'
#
#SBATCH --job-name=bsfr-honest
#SBATCH --account=research
#SBATCH --qos=low
#SBATCH --partition=u22
#SBATCH --time=05:00:00
#SBATCH --cpus-per-task=10
#SBATCH --mem-per-cpu=3000
#SBATCH --nodes=1

set -euo pipefail

HOME_CHECKOUT="${SLURM_SUBMIT_DIR:-$HOME/bsfr-sh}"
WORK="/scratch/${SLURM_JOB_ID}/bsfr-sh"
# `/scratch` is wiped when the job ends, so a venv built there is rebuilt — meaning
# re-downloaded — on every attempt. At the ~30-75 KB/s bulk-transfer rate observed all session
# (dev-box<->Ada, and Ada's own compute-node<->PyPI), that is over an hour paid again on every
# retry. Persisting the built venv to `$HOME_CHECKOUT` (NFS-shared, survives the job) means only
# the *first* successful attempt pays it; every retry after a transient failure elsewhere in the
# script (the dataset fetch, say — see below) just copies it back into a fresh scratch dir.
PERSIST_VENV="$HOME_CHECKOUT/.venv-ada-persist"

echo "node: $(hostname)   home checkout: $HOME_CHECKOUT   scratch work dir: $WORK"

mkdir -p "$(dirname "$WORK")"
rsync -a --exclude='.venv' --exclude='.venv-ada-persist' --exclude='data/raw/*.csv' \
    "$HOME_CHECKOUT/" "$WORK/"
cd "$WORK"
mkdir -p results/logs results/tables results/figures data/raw

module load u22/python/3.12.4

if [ -x "$PERSIST_VENV/bin/python" ]; then
    echo "reusing persisted venv from a previous attempt: $PERSIST_VENV"
    cp -r "$PERSIST_VENV" .venv
else
    echo "building venv fresh (slow bulk transfer expected, ~30-75 KB/s observed this session)"
    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install -e ".[dev]"
    cp -r .venv "$PERSIST_VENV"
fi

# Fast from the compute node (see header); slow/unreliable from the login node. Retry/resume-
# capable (scripts/fetch_bitcoinheist.py) — the first submission of this job (2700027) died here
# on an IncompleteRead after ~55 KB of a ~50 MB archive; a single-shot urlopen had no defence
# against that, a Range-header retry does.
.venv/bin/python scripts/fetch_bitcoinheist.py

# --full disables the configured subsample: all 2,916,697 rows at their natural 1.42% positive
# rate, stratified 5-fold. --memory-ceiling-gb/--memory-headroom match this job's real SLURM
# allocation (see the header) rather than the 8 GB dev-box default, so KNN runs at full scale
# here instead of being subsampled the way a local `make honest` names and subsamples it.
.venv/bin/python scripts/run_detection.py \
    --seed "${SEED:-20260912}" \
    --mode honest \
    --full \
    --memory-ceiling-gb 29.3 \
    --memory-headroom 0.65 \
    | tee "$HOME_CHECKOUT/ada_honest_stdout_${SLURM_JOB_ID}.log"

# /scratch dies with the job; copy results back to the NFS-mounted home checkout.
cp -r results/logs/*.json "$HOME_CHECKOUT/results/logs/" 2>/dev/null || true
cp results/tables/table2_honest_mode.csv "$HOME_CHECKOUT/results/tables/table2_honest_mode_ada.csv"

echo "done. On the login node: $HOME_CHECKOUT/results/logs/, table2_honest_mode_ada.csv, and"
echo "ada_honest_stdout_${SLURM_JOB_ID}.log (has the RESULTS.md lines) are ready to scp back."
