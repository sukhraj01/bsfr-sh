# BSFR-SH — entry points. The full list lives in CLAUDE.md §5; this file implements exactly
# those targets and no others. Targets belonging to a later milestone fail loudly rather than
# succeeding silently, so a green run never means "nothing happened".
#
# Interpreter: 3.11 is preferred because it is the version the reproduction is pinned to
# (docs/EXPERIMENTS.md). Override with `make setup PYTHON=python3.12`.

PYTHON ?= $(shell command -v python3.11 2>/dev/null || command -v python3.12 2>/dev/null || command -v python3.13 2>/dev/null || command -v python3 2>/dev/null)
VENV := .venv
VENV_PY := $(VENV)/bin/python
SEED ?= 20260910
# `scripts/run_detection.py`'s own default, and the seed every published paper_mode/honest_mode
# number in RESULTS.md was measured at (M4a, Q10, D6). A separate variable from SEED above,
# deliberately: SEED is the crypto/blockchain convention: (util.seeding.DEFAULT_SEED); reusing it
# here would make `make repro`'s default run disagree with the already-published 0.9442/0.9697.
ML_SEED ?= 20260912

.DEFAULT_GOAL := test
.PHONY: setup data test test-all repro honest figures lint

# --- guards -----------------------------------------------------------------------------------
define REQUIRE_VENV
@test -x $(VENV_PY) || { echo "error: $(VENV) is missing. Run 'make setup' first."; exit 1; }
endef

# --- M0 ---------------------------------------------------------------------------------------
setup:
	@test -n "$(PYTHON)" || { echo "error: no python3 on PATH."; exit 1; }
	@$(PYTHON) -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
		|| { echo "error: $(PYTHON) is older than 3.11 (see pyproject.toml requires-python)."; exit 1; }
	$(PYTHON) -m venv $(VENV)
	$(VENV_PY) -m pip install --upgrade pip
	$(VENV_PY) -m pip install -e ".[dev]"
	@echo "setup complete: $(VENV) ($$($(VENV_PY) --version))"

# --- M4a ---------------------------------------------------------------------------------------
# Fetches BitcoinHeist into data/raw/ (gitignored, ~50 MB zipped) and verifies it against §VII's
# counts before anything can use it. A dataset that does not match is a stop, not a warning:
# every reproduction claim in M4 is anchored to 2,916,697 / 2,875,284 / 41,413.
data:
	$(REQUIRE_VENV)
	$(VENV_PY) scripts/fetch_bitcoinheist.py

test:
	$(REQUIRE_VENV)
	$(VENV_PY) -m pytest tests/unit

test-all:
	$(REQUIRE_VENV)
	$(VENV_PY) -m pytest tests

lint:
	$(REQUIRE_VENV)
	$(VENV_PY) -m ruff check src tests
	$(VENV_PY) -m ruff format --check src tests
	$(VENV_PY) -m mypy

# --- M6b ------------------------------------------------------------------------------------
# paper_mode only: the 90/10 resample, all four models, Table II + Figs. 4-5. Needs the full
# BitcoinHeist dataset (every ransomware row) — `make data` first on a fresh clone. Does not
# touch Ada; the resample is ~46K rows and runs anywhere (docs/DEVIATIONS.md DEV-06).
repro:
	$(REQUIRE_VENV)
	$(VENV_PY) scripts/run_detection.py --seed $(ML_SEED) --mode paper --full

# honest_mode only, full 2.9M rows: natural 1.42% balance, stratified 5-fold, PR-AUC/MCC/minority
# F1. RF/LR/DT run locally regardless of scale; KNN is the one CLAUDE.md §6 memory hazard — at
# the 8 GB dev-box ceiling below it is *projected* and deferred with a named reason
# (`detection.models.knn_projection`/`fits_in_memory`), never silently skipped and never
# attempted first. The full-scale KNN number comes from `scripts/ada_honest_mode.sbatch` instead
# (docs/ROADMAP.md M6b) — this target never requires Ada itself.
honest:
	$(REQUIRE_VENV)
	$(VENV_PY) scripts/run_detection.py --seed $(ML_SEED) --mode honest --full --memory-ceiling-gb 8.0

# --- M6a ----------------------------------------------------------------------------------
# Figs. 6(a)-(d) plus the component-breakdown panel (Fig. 6(e)) and results/tables/
# target3_target4.csv. Table II and Figs. 4-5 are `make repro`/`make honest` above.
figures:
	$(REQUIRE_VENV)
	$(VENV_PY) scripts/run_bench.py --seed $(SEED)
