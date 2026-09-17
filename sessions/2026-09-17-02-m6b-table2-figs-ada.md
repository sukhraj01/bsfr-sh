# Session 2026-09-17-02 — M6b: Table II, Figs. 4-5, Ada honest_mode

**Milestone:** M6b · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/EXPERIMENTS.md` Targets 1-2, `RESULTS.md` tail (M4a/Q10 lines), `scripts/run_detection.py`,
`scripts/ada_honest_mode.sbatch`, `src/bsfr_sh/detection/models.py` (`knn_projection`,
`fits_in_memory`), `src/bsfr_sh/detection/metrics.py`, `configs/ml.yaml`,
`src/bsfr_sh/bench/emit.py` (M6a's existing module, to extend), `Makefile` · **Duration:** _

---

## Brief *(written before any work)*

**Task:** Emit Table II and Figs. 4-5 from M4a/M4b's already-measured detection numbers, wire
`make repro`/`make honest` to produce them, and run the deferred full-scale `honest_mode` KNN job
on Ada.

**Exit condition:** `make repro` and `make honest` both run end to end (tables, figures,
sidecars) without needing Ada. `results/tables/table2_paper_mode.csv` and
`table2_honest_mode.csv` exist with the columns owed (dataset, n, baseline). Figs. 4-5 exist in
both a paper-shape version and a baseline-annotated version, each with a sidecar. The Ada sbatch
is adapted to the cluster's real partitions/memory (not the placeholder from M4a) and submitted;
its results are folded in if the job completes within this session, recorded as submitted
regardless if not. `make test`/`make lint` stay green.

**Out of scope:** No new crypto/blockchain/consensus/honeypot/mitigation/recovery code. No Fig. 6
work (M6a, done). No report writing.

**Prior context needed:** `docs/DEVIATIONS.md` DEV-06 (class-balance fix, why two modes exist),
DEV-07 (Table II's added `dataset` column), DEV-08 (already amended in M6a — irrelevant here).
M4a's `RESULTS.md` lines are the paper_mode/honest_mode subsampled numbers this session builds
tables and figures from; nothing here re-runs the ML except the one new Ada-scale honest_mode.

**A note on Ada access.** `scripts/ada_honest_mode.sbatch`'s own header says "this project has no
Ada access from the development environment" — true at M4a, no longer true now: `ssh ada` from
this sandbox connects to `ada.iiit.ac.in` and `sinfo`/`squeue` work. This session verifies real
partition memory before adapting and submitting the job, rather than trusting that stale comment
or the placeholder `--mem=64G`.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1.
Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/EXPERIMENTS.md
Targets 1-2, RESULTS.md tail (the M4a and Q10 lines). Not
docs/ALGORITHMS.md, not docs/ARCHITECTURE.md.

Create the session file from the template and fill the brief first.

TASK — M6b. Table II, Figs. 4-5, and the Ada honest_mode KNN job.

1. Table II — bench/emit.py extension.
   Build the table exactly as the paper presents it (technique, accuracy,
   F1), then add the columns we owe:
     - dataset: which data each row was evaluated on (DEV-07)
     - n: sample size — 46,014 for ours, unknown for the others
     - baseline: the constant-classifier score on that row's split

   Rows 1-4 (Almashhadani, Hwang, Sharmeen, Bae) are paper_reported, not
   measured — label them as such. Our row uses the grouped-split 0.9442 from
   the D6 fix, not the earlier 0.9479.

   Output: results/tables/table2_paper_mode.csv and
   results/tables/table2_honest_mode.csv. The paper_mode table reproduces
   theirs; the honest_mode table is ours.

2. Figs. 4 and 5 — accuracy and F1 bar charts.
   Reproduce the paper's chart shape (grouped bars, same axis range) for
   comparability. Then produce a second version of each with the baseline
   drawn as a horizontal line. The baseline version is the one that makes
   the result legible — without it, Sharmeen's 0.960 F1 looks competitive
   when it's 0.013 above doing nothing.

3. Ada honest_mode — the deferred KNN run.
   scripts/ada_honest_mode.sbatch exists from M4a, committed unrun. This
   session runs it. The job is: full 2,916,697 rows, natural 1.42% positive,
   stratified 5-fold grouped by address, all four models including KNN.

   Before submitting: verify the memory projection from M4a (17.94 GB for
   KNN at 2.9M) against Ada's available memory per node, and set
   --mem-per-cpu accordingly. If the projection exceeds what SLURM will
   grant, subsample KNN to the largest feasible n and state the ceiling
   rather than skipping it.

   Results go to results/tables/table2_honest_mode.csv and RESULTS.md with
   mode=measured.

4. make repro and make honest.
   Wire these to produce the full output: tables, figures, sidecars. These
   are the two entry points someone else uses to verify our claims, and
   CLAUDE.md §5 already lists them. make repro runs paper_mode only; make
   honest runs honest_mode only. Neither should require Ada — if KNN at
   full scale needs it, make honest should run the three local models and
   print a message about the KNN job rather than failing.

WHAT THE HONEST_MODE TABLE SHOULD SHOW
Balanced accuracy, precision, recall, MCC, PR-AUC, minority-class F1,
and a confusion matrix per model. The constant-negative baseline
(accuracy 0.9858, recall 0.000) sits beside every row. The point is not
that the models are bad — it's that the paper's evaluation methodology
made it impossible to tell whether they were good.

EXIT CONDITION
make test and make lint green. make repro and make honest both produce
their outputs. Table II and Figs. 4-5 emitted with sidecars. Ada
honest_mode results recorded if the job completed; the SBATCH submitted
and the local-scale results recorded regardless.

OUT OF SCOPE
No new crypto, blockchain, consensus, honeypot, mitigation, or recovery
code. No Figs. 6 — those are done. No report writing.

END OF SESSION
Session file with attribution and dead ends. RESULTS.md lines for every
new run. Rewrite PROJECT_STATE.md, under 200 lines. Tick M6b and M6.
Commit explaining why.
```

---

## What was done

- `src/bsfr_sh/detection/models.py` — `largest_feasible_n()` (new): binary-searches
  `knn_projection`'s monotone peak for the largest row count that fits a given ceiling/headroom.
  **AI-generated.**
- `src/bsfr_sh/detection/dataset.py` — `_subsample_index` → `subsample_index` (made public;
  needed cross-module by `run_detection.py`'s new KNN fallback path). **AI-generated.**
- `scripts/run_detection.py` — `--memory-ceiling-gb`/`--memory-headroom` CLI flags threaded into
  `fits_in_memory()`; when KNN does not fit, `_run_honest_mode` now subsamples it to
  `largest_feasible_n()` and runs it there (`subsampled_for_memory` recorded) instead of
  deferring the model outright. `_fit_folds()` factored out so both the full-data and
  KNN-subsample paths share one fold-fitting routine. `_emit_reports()` calls the new
  `bench.emit` functions after each mode. **AI-generated.**
- `src/bsfr_sh/bench/emit.py` — `emit_table2_paper_mode`, `emit_table2_honest_mode`,
  `emit_fig4_5` (+ `_fig4_or_5` helper), `PAPER_TABLE2_ROWS`/`PAPER_BSFR_SH_ROW` constants.
  **AI-generated.**
- `Makefile` — `repro`/`honest` wired to `scripts/run_detection.py`; new `ML_SEED` variable
  (20260912, the seed every published detection number was measured at) kept separate from the
  existing `SEED` (20260910, the crypto/blockchain convention) so `make repro`'s default run
  does not disagree with the already-published 0.9442/0.9697. **AI-generated.**
- `pyproject.toml`: no change needed (matplotlib override already added in M6a).
- `tests/unit/test_detection_models.py` — three new tests for `largest_feasible_n`.
  **AI-generated.**
- `scripts/ada_honest_mode.sbatch` — rewritten twice this session (see Findings/dead ends): first
  to the account's real QOS/partition limits with a `/share1` working directory, then corrected
  to a `/scratch`-based design once `/share1` turned out to be login-node-only. **AI-generated.**
- Ada job submitted (job 2700027) from a small code-only checkout rsynced to
  `/home2/sukhraj.singh/bsfr-sh`. Ran 1h25m (venv built successfully) then died on the dataset
  download (`http.client.IncompleteRead`, ~55 KB into ~50 MB). **AI-generated.**
- `scripts/fetch_bitcoinheist.py` — `_download_with_retry()` (new): `Range`-header retry/resume
  loop (8 attempts) around the single-shot `urlopen` that had no defence against a dropped
  connection. **AI-generated.**
- `scripts/ada_honest_mode.sbatch` — persists the built venv to
  `$HOME_CHECKOUT/.venv-ada-persist` (NFS-shared) so a retry after a later transient failure does
  not repeat the ~1h `pip install`. Resubmitted as **job 2700090**; currently `PENDING`
  (`QOSMaxCpuPerUserLimit` — a second, unrelated job already on this account is using part of the
  shared 10-cpu QOS budget) — see Handover. **AI-generated.**
- `docs/DEVIATIONS.md` DEV-31 (new) — the memory-ceiling parameterisation and the `/share1`
  correction. `docs/ROADMAP.md` — M6a/M6b/M6 ticked. `RESULTS.md` — `make repro`/`make honest`
  lines appended (M6b section). **AI-generated.**

## Findings

- **`make repro` reproduces the D6 figure exactly** at its intended entry point (not just via a
  one-off script call): 0.9442/0.9697 (random forest), seed 20260912. Runs in ~7 seconds.
- **`make honest` at full scale (2,916,697 rows) is not slow enough to need Ada for RF/LR/DT.**
  Total wall time ~7m18s for all three plus a KNN subsample. RF's MCC rises from 0.331 (M4a's
  200K subsample) to 0.458 at full scale — more data helps, and the paper's own methodology never
  had the chance to show this since it never ran at the natural class balance at all.
- **`fits_in_memory()`'s hard-coded 8 GB ceiling was a real gap, not a hypothetical one.** Before
  this session's fix, the exact same code running on Ada (128GB+ available) would still have
  deferred KNN, because nothing told it the ceiling was different. Confirmed by running the
  unmodified logic mentally against Ada's numbers before touching the code — then fixed properly
  (parameterised, with a principled fallback) rather than special-cased for one cluster.
- **Dead end: `/share1` as the Ada working directory.** Chosen because it had a large, nearly-
  empty quota next to a ~3.5 GB-free home — looked like the obvious pick. Two small test jobs
  (`envtest`, `envtest2`) showed it is login-node-only storage: a compute node's `df -h` never
  lists it, and SLURM fails the job at output-file-open time with *no script output produced at
  all* (a job that "fails in 0 seconds with an empty log" is a strong signal to check the working
  directory, not the script). Corrected to a `/scratch`-per-job design after confirming (a) home
  *is* NFS-mounted on compute nodes and (b) compute nodes have large, unquota'd local `/scratch`.
  First rsync of the *full* checkout (including the 225 MB dataset) to `/share1` was abandoned
  mid-transfer once this was discovered — a code-only rsync to `/home2` (~2.2 MB) replaced it.
- **Dead end / corrected finding: "the compute node's internet is fast" was wrong.** `envtest4`'s
  probe (`curl` to `pypi.org`, 0.1s from a compute node vs. a login-node request that timed out at
  15s) was read as "compute nodes have fast egress, fetch the dataset there." It does not
  generalise: `pip install`'s real package downloads from that same compute node, in job 2700027,
  ran at the same ~60 KB/s the dev-box rsync and login-node curl both showed, and the dataset
  download that killed the job was at that same rate when it dropped. The `envtest4` probe
  measured latency to a small index page, not bulk-transfer bandwidth — a login-vs-compute
  difference that was never actually a login-vs-compute difference. The real, load-bearing
  characteristic is: **this account's bulk transfer is slow (~30-75 KB/s) everywhere, on every
  path tried this session** — dev-box-to-Ada, Ada-login-to-UCI, and Ada-compute-to-PyPI alike.
  Fetching the dataset inside the job is still the right design (no reason to pay the slow
  transfer twice, once to the dev box and once from Ada), but not because compute nodes are
  faster — because a resumable in-job fetch survives the slowness better than an external rsync
  where a drop mid-transfer has no protocol-level way to resume cheaply.
- **The dataset download itself needed the same lesson `envtest4` half-taught: don't trust a
  single fast probe as proof of throughput.** `fetch_bitcoinheist.py`'s single-shot `urlopen`
  had no retry; at ~30-75 KB/s sustained over a multi-minute transfer, a connection drop is not a
  rare event, and job 2700027 hit one after 1h25m of successful setup — an expensive place to
  fail with no resume. Fixed with a `Range`-header retry loop once, generically, in the fetch
  script itself rather than only in the sbatch, so `make data` gets the same robustness locally.
- **A second job on the same account, not started by this session, can silently gate a
  resubmission.** Job 2700090's `PENDING`/`QOSMaxCpuPerUserLimit` was not a bug in the new sbatch
  — `squeue -u $USER` showed a pre-existing, unrelated job (`2700069`, "a2-hist-...") already
  consuming 4 of the account's shared 10-cpu QOS budget. Left queued rather than reduced to fit,
  since SLURM starts a pending job automatically once resources free and a smaller request would
  have meant a smaller, non-full-scale KNN run for no real gain.
- **QOS/partition limits were discovered, not assumed, and they were stricter than the M4a
  placeholder in cpu/mem but looser than initially feared in what they'd allow.** `sacctmgr`/
  `scontrol` gave exact numbers (`cpu<=10, mem<=32000M`, partition `u22` only) before any real
  job was submitted — the small `envtest*` probes cost seconds of QOS budget, not hours.

## Numbers

- `make repro` (paper_mode, full, seed 20260912): `RESULTS.md` "Detection — Table II, Figs. 4-5,
  full-scale `honest_mode` (M6b)" section, run `20260917T175743Z-be5c55e0`.
- `make honest` (honest_mode, full, 8 GB local ceiling): same section, run
  `20260917T175754Z-f3b9e363`. `results/tables/table2_paper_mode.csv`,
  `results/tables/table2_honest_mode.csv`, Figs. 4-5 (+ baseline variants) all written locally.
- Ada job 2700027 (failed, IncompleteRead) and its resubmission as job 2700090 (PENDING): see
  Handover for final status as of session end.

## Deviations opened or changed

- DEV-31 added — `honest_mode`'s memory ceiling is now a parameter with a principled subsampling
  fallback (not a hard-coded 8 GB constant), and records the `/share1`-is-login-node-only
  correction and the dataset-download retry/resume fix to how the Ada job actually has to run.

---

## Handover *(written last)*

**State after:** `make repro`/`make honest` are real entry points now, both producing tables,
figures and sidecars without touching Ada. Table II (both modes) and Figs. 4-5 (+ baseline
variants) exist in `results/`. `detection.models.fits_in_memory()`'s ceiling is a parameter with
a principled subsampling fallback, not a hard-coded constant. `scripts/fetch_bitcoinheist.py`'s
download is now retry/resume-capable. The Ada `honest_mode` job has been submitted twice: job
2700027 ran 1h25m (venv built fine) then died on the dataset download (fixed, see Findings);
**job 2700090 is the live resubmission, currently `PENDING`** (`QOSMaxCpuPerUserLimit` — a
second, unrelated job on this account is using part of the shared 10-cpu QOS budget) and will
start automatically once that frees up. M6 (both halves) is closed regardless: every
`docs/EXPERIMENTS.md` target carries a `measured` or `paper_reported` label already, since the
local, full-scale `honest_mode` run (KNN subsampled) already covers Target 1/2 honestly — the
Ada job upgrades KNN from a named subsample to the full 2.9M rows, it does not unblock anything
that was blocked.

**Next task:** No implementation milestone is open. Whoever picks this up next should first check
`ssh ada 'sacct -j 2700090'`: if `COMPLETED`, retrieve and fold in the full-scale KNN result (see
`RESULTS.md`'s Ada paragraph for the exact commands); if still `PENDING` or `RUNNING`, no action
needed — it will finish or can be checked again later; if it is gone or `FAILED` for a new
reason, re-submit `scripts/ada_honest_mode.sbatch` from `/home2/sukhraj.singh/bsfr-sh` (already a
working checkout with a persisted venv at `.venv-ada-persist` — a resubmit from there is fast, it
skips the ~1h `pip install`). After that: M7 (stretch, `docs/ROADMAP.md`) or report writing.

**New blockers:** None that block further implementation. The Ada job is queued, not blocking —
M6b's exit condition explicitly allows "submitted, not completed."

**Questions opened / closed:** No numbered `PROJECT_STATE.md` questions touched this session
(Q4/Q8 remain open, both M7-scoped). The `/share1`-is-login-node-only finding and the pip/rsync
bandwidth throttle are recorded as Findings above and in DEV-31, not as numbered questions — they
are now-known facts about the Ada environment, not open decisions.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated if the paper was departed from
- [ ] Committed, message explains *why*
