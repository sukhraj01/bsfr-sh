# Session 2026-09-10-01 — M0-2, support files and the util layer

**Milestone:** M0 · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`, `docs/ROADMAP.md`,
`docs/ARCHITECTURE.md`, `docs/EXPERIMENTS.md`, `docs/DEVIATIONS.md`, `sessions/_TEMPLATE.md`,
`sessions/README.md` · **Duration:** one working session, interrupted by a usage
limit and resumed on 2026-09-11

---

## Brief *(written before any work)*

**Task:** Build the M0 support files — `pyproject.toml`, `Makefile`, `.gitignore`,
`configs/{chain,ml,bench}.yaml` — and the four `util/` modules (config, logging, seeding,
canonical serialization) with unit tests.

**Exit condition:** `make setup` and `make test` both exit 0, with `make test` collecting and
passing real `tests/unit/` tests for the util layer (pytest exits 5 on an empty collection, so an
empty suite is not a checkable state).

**Out of scope:** no crypto primitives, no `Block`/`Chain`, no pBFT, no ML, no honeypot.
`serialization.py` defines the byte encoding only — it does not import or implement hashing or
signing (M1/M2). Q1 (ECDSA backend) is not pre-judged: `cryptography` is declared as a dependency,
but no code is written against it.

**Prior context needed:** `docs/ARCHITECTURE.md` for the `Block`/`Transaction` field order that
canonical serialization must mirror (Alg. 1 line 3) and the `util <- crypto <- ...` dependency
direction; `docs/EXPERIMENTS.md` §Setup for the values the paper pins down (4 miners, 100 tx/block,
5/10/15 blocks, four ML models); `docs/DEVIATIONS.md` DEV-06 (two evaluation modes), DEV-10 (2f+1
threshold), DEV-12 (cases vary blocks, not devices); `docs/ROADMAP.md` for the M0 checklist.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Beyond those two, read only what the
context ladder in CLAUDE.md §4 specifies for this task — do not load docs/
wholesale. sessions/ is empty; this is session 01, so there is no prior
handover to find.

First, create sessions/2026-09-10-01-m0-support-files.md from
sessions/_TEMPLATE.md and fill in the brief (task, exit condition, out of
scope, prior context). Do that before writing any code.

TASK — M0-2, support files and the util layer.

1. pyproject.toml
   Python 3.11+. Package is src/bsfr_sh (src layout). Runtime deps:
   cryptography, scikit-learn, pandas, numpy, matplotlib, pyyaml. Dev deps:
   pytest, ruff, mypy. Configure ruff and mypy --strict over src/ here rather
   than in separate config files.

2. Makefile
   Exactly the targets listed in CLAUDE.md §5 — no more. Targets whose
   implementation belongs to a later milestone (data, repro, honest, figures)
   should exist and exit with a clear "not implemented until M<n>" message
   rather than silently doing nothing or being absent.

3. configs/chain.yaml, configs/ml.yaml, configs/bench.yaml
   Every value the paper pins down goes here as a default, not as a literal in
   code later: 4 miner nodes, pBFT commit threshold 2f+1, 100 transactions per
   block, cases at 5/10/15 blocks, the four ML algorithms, the two evaluation
   modes from DEV-06. Where the paper specifies nothing — transaction payload
   size (Q2), ML hyperparameters — put an explicit declared default with a
   comment saying the paper is silent. Silent defaults are how undocumented
   deviations happen.

4. src/bsfr_sh/util/
   - config.py — load YAML, validate, and expose a stable config hash. The
     hash goes into every bench sidecar, so it must be order-independent and
     reproducible across runs.
   - logging.py — structured logging with a run_id. No print anywhere in this
     project; this is the reason.
   - seeding.py — one call that seeds python random, numpy, and PYTHONHASHSEED
     together.
   - serialization.py — canonical deterministic byte encoding.

   serialization.py is the load-bearing piece and the reason this task exists
   before M1. Field order for block encoding must match the Block header order
   in docs/ARCHITECTURE.md, which mirrors Alg. 1 line 3. Requirements:
   deterministic across runs and Python versions, length-prefixed so no field
   boundary is ambiguous, and never dependent on dict iteration order. If two
   modules ever serialize the same block differently, the hashes diverge and
   pBFT breaks in a way that looks like a consensus bug for hours. Write the
   round-trip and determinism tests now, not in M1.

EXIT CONDITION
`make setup` and `make test` both succeed. Note that pytest exits 5 on an
empty collection, so add the util tests as part of this task — "green on an
empty suite" is not a checkable state.

OUT OF SCOPE
No crypto primitives, no Block or Chain class, no pBFT, no ML, no honeypot.
serialization.py defines the encoding; it does not import or implement hashing
or signing. Those are M1 and M2.

OPEN QUESTION
Q1 in PROJECT_STATE.md (which ECDSA backend) is decided in M1 by benchmark.
Include `cryptography` as a dependency now; do not pre-judge Q1 by writing any
code against it.

END OF SESSION
Complete the session file: what was done with AI/human attribution, findings
including any dead ends, and the handover block. Rewrite PROJECT_STATE.md —
rewrite, not append — and confirm it is still under 200 lines. Tick M0 in
docs/ROADMAP.md. Commit with a message explaining why, not what.
```

---

## What was done

Everything below is **AI-generated (Claude Opus 5), human-directed**: the task brief, the scope
boundaries and the milestone gating were specified by the human; the file contents were written
by the agent in one session and reviewed against the brief. Nothing here is hand-written by a
human, and nothing was copied from an external source.

| File | Lines | Why |
|---|---|---|
| `pyproject.toml` | 113 | src-layout package, deps, and ruff + pytest + `mypy --strict` config in one file rather than four |
| `Makefile` | 70 | the eight targets of CLAUDE.md §5, no more; `data`/`repro`/`honest`/`figures` fail loudly with a milestone number |
| `.gitignore` | 25 | `data/raw`, `data/processed`, venv and tool caches stay out of git |
| `configs/chain.yaml` | 72 | 4 miners, 2f+1 = 3, 100 tx/block, cases 5/10/15, curve/AEAD/Merkle policy |
| `configs/ml.yaml` | 95 | four algorithms, both DEV-06 modes, all hyperparameters declared |
| `configs/bench.yaml` | 61 | median of 5, warm-up discarded, TPS marked derived, sidecar field list |
| `src/bsfr_sh/util/serialization.py` | 448 | the canonical encoding — tags, length prefixes, sorted maps, declared struct order |
| `src/bsfr_sh/util/config.py` | 349 | YAML load, schema + cross-field validation, order-independent config hash |
| `src/bsfr_sh/util/logging.py` | 209 | JSON-line structured logging carrying one `run_id` per run |
| `src/bsfr_sh/util/seeding.py` | 96 | one call for `random`, NumPy and `PYTHONHASHSEED` |
| `tests/unit/test_serialization.py` | 406 | round-trip, determinism, cross-process stability, golden vectors, block field order |
| `tests/unit/test_config.py` | 274 | shipped configs validate, hash stability, every validation rule |
| `tests/unit/test_logging.py` | 105 | one line per event, one handler, reserved-key collisions |
| `tests/unit/test_seeding.py` | 94 | reproducible streams, honest `PYTHONHASHSEED` reporting |
| `tests/unit/test_module_boundaries.py` | 105 | no `print`, no stray `hashlib`, `util` never imports upward |

Also: `docs/ROADMAP.md` M0 ticked and current milestone moved to M1; `docs/DEVIATIONS.md`
gained DEV-15 and DEV-16; `src/bsfr_sh/py.typed` added so downstream type-checking works.

**Verification (all run, all clean):**

```
make setup     -> .venv, Python 3.11.14, 34 packages
make test      -> 186 passed in 0.28s
make test-all  -> 186 passed (tests/integration is still empty)
make lint      -> ruff check clean, ruff format clean, mypy --strict clean (15 files)
make data      -> "not implemented until M4", exit non-zero
make repro / honest / figures -> "not implemented until M6", exit non-zero
```

## Findings

**1. The config hash needed SHA-256 before `crypto/hashing.py` exists — flagged, not hidden.**
CLAUDE.md §7 routes all hashing through `crypto.hashing.h()`, but `crypto/` is M1 and was
explicitly out of scope, while `util/config.py` needs a digest now because every bench sidecar
carries a config hash. Resolution: `util/config.py` holds the single deliberate `hashlib` call
site, commented as such, and `tests/unit/test_module_boundaries.py` pins the exemption to exactly
that one file via `HASHLIB_ALLOWED`. **M1 must replace it with `crypto.hashing.h()` and remove
the exemption** — the test will keep failing-forward until it does. The alternative (writing
`crypto/hashing.py` early) would have been a quieter scope violation, not a smaller one.

**2. `PYTHONHASHSEED` cannot be made effective from inside a running interpreter.** It is
consumed once at start-up, so `os.environ["PYTHONHASHSEED"] = ...` in `seed_all()` only affects
child processes. Rather than pretend otherwise, `SeedState` carries
`pythonhashseed_effective_this_process`, which is `False` on the first call in a fresh process.
The real defence is structural: `util.serialization` sorts mapping entries by encoded key and
rejects sets outright, so nothing in the encoding path can depend on hash randomisation. This is
now proven, not asserted — `test_encoding_is_stable_across_processes_with_different_hash_seeds`
runs the encoder in subprocesses under three different hash seeds and compares bytes.

**3. Dead end: the bool/int dict-key case in the round-trip test was silently wrong.** The
parametrised value `{1: "int key", "1": "str key", True: "bool key"}` looks like three entries
and is two — Python collapses `True` and `1` to one key, so the case tested something other than
what it claimed. `ruff` F601 caught it; the case was split in two. Worth recording because the
same collision will bite again in M2 if any block or transaction field is ever keyed by a bool.
The *encoder* does distinguish them (separate tags), which
`test_distinct_values_have_distinct_encodings` covers.

**4. The strict struct key-set check caught its first real bug within minutes of existing.** The
golden-vector test initially passed the full ten-field block to `BlockPart.HASH`, which refused
it: `unexpected=['current_hash', 'signature']`. That is precisely the self-referential-hash bug
`BLOCK_HASHED_FIELDS` exists to prevent, caught in M0 against a dict, three milestones before
there is a `Block` class to get it wrong.

**5. Tooling contradictions worth knowing before M1.** `ruff format` will join a wrapped
expression into a 101-character line that `ruff check` then rejects as E501; three call sites were
restructured (intermediate variables) rather than fighting it with `noqa`. Separately,
`mypy --strict` with `warn_unused_configs` reports pre-emptive per-module override stanzas for
libraries nothing imports yet, so the `sklearn`/`matplotlib`/`pandas` overrides were removed —
M4 and M6 add them when the imports appear. A config that warns on a clean run trains you to
ignore its output.

**6. Environment note.** The default `python3` on this box is 3.14; the reproduction is pinned to
3.11 (docs/EXPERIMENTS.md). The Makefile therefore prefers `python3.11`, then 3.12, then 3.13,
then `python3`, and hard-fails below 3.11 with the reason. `make setup PYTHON=...` overrides.

## Numbers

None. No benchmark was run this session, so **`RESULTS.md` was deliberately not touched** — it
takes one line per benchmark run, and test counts and setup timings are not benchmark results.
The first line will be written in M1 when Q1 (ECDSA backend) is decided by measurement.

## Deviations opened or changed

- **DEV-15 · FILL · Declared transaction payload size** — the paper never states one, yet every
  Fig. 6 number depends on it (Q2 / GAP-2). `configs/chain.yaml` declares 4096 bytes, with a
  1024/4096/16384 sensitivity sweep for M6.
- **DEV-16 · FILL · Declared ML hyperparameters and split ratio** — the paper reports none, so
  ours are declared in `configs/ml.yaml` (including `paper_mode.test_size: 0.30` and
  `max_iter: 1000` for logistic regression) rather than inherited silently from scikit-learn.

Both entries were added because the values *shipped* this session as config defaults. A declared
default that lives only in a YAML comment is not pre-registered; DEVIATIONS.md is the registry.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** `git clone` → `make setup` → `make test` is a working path, and `make test` runs
186 real tests rather than an empty suite. The canonical encoding is fixed, pinned by golden
vectors, and proven stable across processes; `BLOCK_FIELD_ORDER`, `BLOCK_HASHED_FIELDS` and
`BLOCK_SIGNED_FIELDS` are declared in `util.serialization` so M2's `Block` has one place to agree
with. Config values the paper pins down are now in `configs/`, validated on load, and covered by
a hash that goes into every future sidecar. `make lint` (ruff + `mypy --strict`) is clean, so M1
starts from zero debt.

**Next task:** M1-1 — build `crypto/hashing.py` (the single SHA-256 entry point, which also
retires the `hashlib` exemption in `tests/unit/test_module_boundaries.py`), then benchmark
`cryptography` against a pure-Python ECDSA to close Q1, then the rest of the `crypto/` layer.

**New blockers:** none.

**Questions opened / closed:**
- **Q1** (ECDSA backend) — untouched by design. `cryptography` is a declared dependency; no code
  imports it. Still resolved by benchmark in M1.
- **Q2** (transaction payload size) — *partially* closed. A declared default (4096 B) now ships
  in `configs/chain.yaml` and is registered as DEV-15. The question stays open in
  `PROJECT_STATE.md` until M6 runs the sensitivity sweep, because the number is a choice, not yet
  a justified one.
- **Q3, Q4** — untouched.
- **New (Q5):** should `util.config` gain a merged-run config object, or do entry points keep
  loading the three files independently? Deferred to M6, when `bench/` is the first consumer that
  needs more than one config at once. `combined_config_hash()` already exists for that case.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run — *n/a, no benchmark was run; see Numbers above*
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated if the paper was departed from — DEV-15, DEV-16
- [x] Committed, message explains *why*
