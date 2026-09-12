#!/bin/bash
# Full-scale honest_mode on the Ada HPC cluster — the run that cannot happen on the 8 GB dev box.
#
# Why this exists rather than "we skipped KNN": CLAUDE.md §6 says heavy ML runs go to Ada and that
# full-scale runs are explicitly opt-in. M4a projected the cost *before* running anything
# (`detection.models.knn_projection`) and found KNN at 2.9M rows needs ~19 GB for the distance
# block alone, against a 2.9M x 583K = 1.36e12 distance computation count per fold. That is not a
# slow run on this machine; it is an impossible one. So it is named here instead of being quietly
# dropped from the results table.
#
# NOT YET RUN. This project has no Ada access from the development environment, so the script is
# written, committed and unverified — anyone running it should expect to adjust the module names
# and the account/partition to match the cluster's current configuration. It is a prepared job,
# not a measured result, and nothing in RESULTS.md may cite it until it has actually run.
#
#   sbatch scripts/ada_honest_mode.sbatch
#
#SBATCH --job-name=bsfr-honest
#SBATCH --output=results/logs/ada-%j.out
#SBATCH --error=results/logs/ada-%j.err
#SBATCH --time=08:00:00
#SBATCH --mem=64G                  # 19 GB projected peak for KNN, plus the 2.9M-row frame
#SBATCH --cpus-per-task=16
#SBATCH --nodes=1

set -euo pipefail

module load python/3.11 || echo "adjust the module name for this cluster"

cd "${SLURM_SUBMIT_DIR:-$(pwd)}"

if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install -e ".[dev]"
fi

# The dataset is gitignored, so fetch and verify it against §VII's counts on the cluster too.
.venv/bin/python scripts/fetch_bitcoinheist.py

# --full disables the configured subsample: all 2,916,697 rows at their natural 1.42% positive
# rate, stratified 5-fold. Every model including KNN runs here; the sidecar records which.
.venv/bin/python scripts/run_detection.py \
    --seed "${SEED:-20260912}" \
    --mode honest \
    --full

echo "sidecar and RESULTS.md lines are in results/logs/; copy the lines into RESULTS.md"
