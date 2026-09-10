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

# --- later milestones ---------------------------------------------------------------------------
# These exist so the contract in CLAUDE.md §5 is complete and so a caller gets a milestone
# number instead of "No rule to make target".
data:
	@echo "make data: not implemented until M4 (detection layer)."
	@echo "  It will fetch and checksum BitcoinHeist (2,916,697 rows) into data/raw/."
	@echo "  See docs/EXPERIMENTS.md 'Target 2 — Dataset' and docs/ROADMAP.md M4."
	@exit 1

repro:
	@echo "make repro: not implemented until M6 (benchmarks and figures)."
	@echo "  It will run the paper-faithful path: 90/10 resample, cases 1-3 (5/10/15 blocks)."
	@echo "  See docs/DEVIATIONS.md DEV-06 and docs/ROADMAP.md M6."
	@exit 1

honest:
	@echo "make honest: not implemented until M6 (benchmarks and figures)."
	@echo "  It will run the natural 1.42% class balance with stratified CV and PR-AUC."
	@echo "  See docs/DEVIATIONS.md DEV-06 and docs/ROADMAP.md M6."
	@exit 1

figures:
	@echo "make figures: not implemented until M6 (benchmarks and figures)."
	@echo "  It will emit Table II and Figs. 4, 5, 6a-6d into results/ with sidecar JSON."
	@echo "  See docs/EXPERIMENTS.md 'Output contract' and docs/ROADMAP.md M6."
	@exit 1
