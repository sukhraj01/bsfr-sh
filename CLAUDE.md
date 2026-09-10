# CLAUDE.md

Operating contract for any Claude Code session in this repo. Read this first, every session.

---

## 1. What this project is

A full, from-scratch Python implementation of **BSFR-SH** — the blockchain-enabled ransomware
defense framework from:

> M. Wazid, A. K. Das, S. Shetty, "BSFR-SH: Blockchain-Enabled Security Framework Against
> Ransomware Attacks for Smart Healthcare," *IEEE Transactions on Consumer Electronics*,
> vol. 69, no. 1, pp. 18–28, Feb. 2023. DOI: 10.1109/TCE.2022.3208795

This is a **course project built as an extendable research base**, not a one-shot reproduction.
That means three obligations, in priority order:

1. **Reproduce** every claim the paper makes (Table II, Figs. 4, 5, 6a–6d).
2. **Re-evaluate** those claims honestly where the paper's methodology inflates them.
3. **Repair** the design gaps the paper leaves open, without breaking (1).

Never collapse these into one number. Reproduced results and honest results live in
separate result files and are always reported side by side. See `docs/DEVIATIONS.md`.

---

## 2. Non-negotiables

**Never implement a live ransom payment path.** Algorithm 4, Case-3 of the paper automates
paying an attacker and requesting a decryption key. We implement it as a *simulated decision
branch only*: it emits a policy decision object and a log record. It must never construct,
sign, or broadcast a real transaction, contact a network endpoint, or touch a wallet. Any code
in `src/bsfr_sh/mitigation/` that appears to do so is a bug — stop and flag it.

**Never write real malware.** The "honeypot" module synthesizes *feature vectors and signature
digests* representing ransomware behaviour. It does not generate, download, execute, or store
executable malicious code. Sample generation is statistical, not behavioural.

**Never claim a number we did not measure.** Every figure in `results/` traces to a run log in
`results/logs/` with a config hash and a seed. If a number is quoted from the paper rather than
measured, it is labelled `paper_reported`, never `measured`.

**Never silently "fix" the paper.** Deviations get an entry in `docs/DEVIATIONS.md` with a
rationale, before the code lands.

---

## 3. Repository layout

```
bsfr-sh/
├── CLAUDE.md               <- you are here. how to work.
├── PROJECT_STATE.md        <- what is true right now. 200-line hard cap.
├── RESULTS.md              <- every benchmark ever run, append-only, one line each
├── README.md               <- human-facing overview
├── sessions/               <- one file per session, append-only archive
│   ├── _TEMPLATE.md
│   └── YYYY-MM-DD-NN-<slug>.md
├── knowledge/ai-usage-log/ <- transcripts, attribution material for the report
├── pyproject.toml
├── Makefile                <- entry points: make repro, make honest, make figures
├── docs/
│   ├── PAPER_NOTES.md      <- section-by-section reading of the paper
│   ├── NOTATION.md         <- Table I symbols -> code identifiers
│   ├── ALGORITHMS.md       <- Algorithms 1-5 -> module mapping
│   ├── ARCHITECTURE.md     <- how our modules fit together
│   ├── DEVIATIONS.md       <- every place we depart from the paper, and why
│   ├── EXPERIMENTS.md      <- target numbers + reproduction protocol
│   └── ROADMAP.md          <- milestones and current status
├── configs/                <- YAML run configs (case-1/2/3, ML splits)
├── data/
│   ├── raw/                <- BitcoinHeist CSV (gitignored)
│   ├── processed/          <- cached splits (gitignored)
│   └── honeypot/           <- synthesized signature/feature corpus
├── results/{tables,figures,logs}/
├── scripts/                <- thin CLI wrappers, no logic
├── src/bsfr_sh/
│   ├── crypto/             <- ECDSA, Merkle, SHA-256, session keys, AEAD
│   ├── blockchain/         <- Transaction, Block, Chain
│   ├── consensus/          <- pBFT: leader election, 3-phase commit
│   ├── honeypot/           <- collection, signature gen, feature building
│   ├── detection/          <- dataset, profiles, RF/LR/DT/KNN, detector
│   ├── mitigation/         <- isolation + Case-1/2/3 state machine
│   ├── recovery/           <- restore from BC_DTBU
│   ├── framework/          <- orchestrator wiring Phases 1-5
│   ├── bench/              <- timing harness, table + figure emitters
│   └── util/               <- config, logging, seeding, serialization
└── tests/{unit,integration}/
```

**Rule:** `scripts/` and `src/bsfr_sh/bench/` may call into everything. Nothing calls back into
them. `crypto/` depends on nothing internal. `consensus/` depends only on `crypto/` and
`blockchain/`.

---

## 4. Session protocol — one session per task

**This project runs one session per task.** You start every session with no memory of the last
one. The files below are the only continuity that exists. Treat them as such: if something is not
written down, it did not happen.

### Start of session — read exactly this, in order

1. `CLAUDE.md` (this file) — auto-loaded
2. `PROJECT_STATE.md` — current truth, next task, blockers, open questions
3. **The context ladder below** — the docs for this task's layer, and nothing else

Then **write the session brief** into a new `sessions/YYYY-MM-DD-NN-<slug>.md` from
`sessions/_TEMPLATE.md`, *before* writing code. If the task does not fit in one sentence, it is
two tasks — say so and stop.

### Context ladder — what to read for what

| Task touches | Read | Do NOT read |
|---|---|---|
| any task | `PROJECT_STATE.md` | `sessions/*` in bulk, `RESULTS.md` in full |
| `crypto/`, `blockchain/`, `consensus/` | `docs/ARCHITECTURE.md`, `docs/NOTATION.md` | `docs/EXPERIMENTS.md` |
| a paper phase (1–5) | `docs/ALGORITHMS.md` + the matching `docs/PAPER_NOTES.md` §, `docs/NOTATION.md` | `docs/EXPERIMENTS.md` |
| `detection/` | `docs/EXPERIMENTS.md` Targets 1–2, `docs/DEVIATIONS.md` DEV-06/07 | `docs/ALGORITHMS.md` Alg. 1/2/5 |
| `bench/`, figures | `docs/EXPERIMENTS.md` Targets 3–4, `RESULTS.md` tail | `docs/PAPER_NOTES.md` |
| departing from the paper | `docs/DEVIATIONS.md` | — |
| "why did we do X?" | `grep -l sessions/ -e "X"`, then that one file | the rest of `sessions/` |

**Never read the whole `docs/` tree "for context."** It is ~8k words. Reading it costs more than
it returns and produces skimming, not understanding. Reading the wrong two files carefully beats
reading all nine badly.

### During session

Execute → verify → record. Every benchmark gets a line in `RESULTS.md` when it finishes, not at
the end. Log prompts verbatim into the session file as you go; reconstructing them later does not
work.

### End of session — non-negotiable, and the reason the next session functions

1. **Rewrite** `PROJECT_STATE.md`. Rewrite, not append — delete what is resolved. Check it is
   still under 200 lines.
2. **Append** to `RESULTS.md`, one line per run.
3. Tick `docs/ROADMAP.md`.
4. Add or amend `docs/DEVIATIONS.md` if the paper was departed from.
5. Complete the session file: what was done, findings (**including dead ends** — an unrecorded
   dead end gets retried), and the Handover block. The **Next task** line becomes the next
   session's brief verbatim, so write it as an instruction, not a wish.
6. Commit. Message explains *why*.

A session that produced working code but no handover has failed. The code is worth less than the
context needed to continue it.

### Why the state file is capped

`PROJECT_STATE.md` is read at the start of every single session. Held at 200 lines it costs
seconds. Left to grow — the natural drift, since appending is easier than pruning — it becomes a
few thousand lines of mostly-resolved history, gets skimmed instead of read, and stops working
precisely when the project is complex enough to need it. Pruning it is part of the task, not
cleanup after the task.

---

## 4b. Working notes

**Start of a coding task.** Check `docs/ALGORITHMS.md` for the paper algorithm and line numbers
your module implements before writing anything.

Every public function that implements a paper step carries a docstring reference like
`Implements Alg. 2, lines 5-8.`

**Determinism.** Every entry point takes `--seed`. Crypto keypairs in tests are fixture-loaded,
never freshly generated, so test runs are byte-reproducible. Benchmarks are the only place
wall-clock timing is allowed to vary — and they report median of N runs, never a single sample.

**Two chains are separate objects.** `BC_DTBU` and `BC_SigRW` are independent `Chain` instances
with independent genesis blocks and independent pBFT node sets. Do not share state between them.
A bug here silently invalidates the whole benchmark.

**Timing discipline.** `bench/` measures wall-clock around block construction + consensus +
append. TPS is *derived*, never separately measured: `tps = total_transactions / total_seconds`.
This matches how the paper's own numbers were produced (verified — see `docs/EXPERIMENTS.md`).

---

## 5. Commands

```
make setup        # venv + deps
make data         # fetch/verify BitcoinHeist into data/raw
make test         # pytest, fast unit tests only
make test-all     # includes integration + consensus fuzz
make repro        # paper-faithful run: 90/10 split, cases 1-3
make honest       # true class balance, stratified CV, PR-AUC
make figures      # emit Table II + Figs 4, 5, 6a-6d into results/
make lint         # ruff + mypy
```

Never run `make repro` or `make honest` inside a normal dev loop — they are long. Use
`make test` for iteration.

---

## 6. Environment

- Local dev box: 8 GB RAM, no GPU. Fine for crypto, consensus, tests, and subsampled ML.
- Heavy ML runs (full 2.9M-row BitcoinHeist, KNN especially) go to the **Ada HPC cluster**.
- KNN on the full dataset is the memory hazard. Default configs subsample; full-scale runs are
  explicitly opt-in via `--full` and are expected to be submitted as a cluster job.
- Target Python 3.11+. Dependencies stay minimal: `cryptography`, `scikit-learn`, `pandas`,
  `numpy`, `matplotlib`, `pyyaml`, `pytest`.

---

## 7. Code conventions

- Type hints everywhere. `mypy --strict` on `src/`.
- Dataclasses for all protocol structures (`Block`, `Transaction`, `PrePrepare`, ...), frozen
  where the paper treats them as immutable.
- No bare `except`. No `print` — use `util.logging`.
- Hashing is always SHA-256 via `crypto.hashing.h()`. Never call `hashlib` directly outside
  that module.
- Signatures are always ECDSA/secp256r1 via `crypto.ecdsa`. The paper mandates ECDSA (ref [23]);
  do not substitute Ed25519 even though it would be nicer.
- Serialization for hashing is canonical and defined once in `util/serialization.py`. If two
  modules serialize a block differently, hashes diverge and consensus breaks.

---

## 8. Definition of done for a module

1. Implements the mapped algorithm lines, with docstring references.
2. Unit tests covering the happy path plus at least one adversarial case
   (tampered block, wrong signature, byzantine node, missing backup).
3. Entry in `docs/ARCHITECTURE.md` if it introduces a new boundary.
4. Entry in `docs/DEVIATIONS.md` if it departs from the paper.
5. `make lint` and `make test` clean.
