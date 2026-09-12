# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-12 · **Milestone:** M4 (Phase 3, detection) · **Sessions completed:** 6

---

## One-line status

M3 is closed. Phases 1, 2 and 5 all run end to end: systems back up and restore byte-identical
through pBFT on `BC_DTBU`, and the honeypot's signature records reach `BC_SigRW` through the same
pipeline. A labelled corpus exists on disk with its seeds and its **intended difficulty** recorded.
`make test-all` runs 993 tests and `make lint` is clean. Next is M4, Phase 3.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Docs (`CLAUDE.md`, `docs/*`) | done | DEV-26, DEV-27 opened in M3b; DEV-05 amended twice |
| `pyproject.toml`, `Makefile`, `.gitignore`, `configs/` | done | `timing.index_maintenance: separate_column` added (M3b) |
| `util/`, `crypto/`, `blockchain/`, `consensus/` | done | `crypto/channel.py`, `blockchain/backup.py` from M3a |
| `framework/` entities, pipeline, phases 1, 2, 5 | **done** | M3a + M3b |
| `recovery/` | done | M3a |
| `honeypot/` | **done** | M3b: collector, preprocess, signatures, features, corpus |
| `data/honeypot/` corpus | **done** | 1467 train + 731 eval records, two seeds, manifest |
| `detection/`, phase 3 | not started | **M4 — start here** |
| `mitigation/`, phase 4 | not started | M5 |
| `bench/`, figures | not started | M6 |

## Current numbers

One `measured` benchmark row exists: the Q1 ECDSA backend bake-off (`RESULTS.md` §Ours). M3a and
M3b ran no benchmark, by design. Every reproduction target is still `paper_reported`.

**The corpus's difficulty, which M4 needs before it interprets anything.** By construction the
generator draws 25% of both classes from *confusable pairs* that share one parameter set, putting
a floor of 0.125 under the Bayes error. **Intended Bayes-optimal accuracy ≈ 0.85**
(`honeypot.corpus.EXPECTED_BAYES_ACCURACY`, also in the corpus manifest). Measured on the committed
corpus: the most separable single feature is `extension_change_rate` at 0.816, and a simple
baseline fitted on the train draw and scored on the eval draw reaches **0.830** balanced accuracy.
**A detector reporting far above ~0.85 on this data is reading a leak, not detecting anything.**

## What M4 must not re-derive

Established in M1–M3b; take these as given.

- **The corpus contract.** Train on `data/honeypot/corpus_train.csv`, evaluate on
  `corpus_eval.csv`. They are *independent draws from different seeds* — never shuffle one draw
  into both roles, because samples within one generator call can share latent parameters.
  `manifest.json` records both seeds, the schema and the expected difficulty.
- **Features are exactly `honeypot.features.FEATURE_NAMES`** (22, order named by `ft_rw.v1`).
  `label` is the target. `sample_id`, `profile`, `collected_at`, `content_digest`, `attestation`
  and `missing_mask` are metadata and must never enter the model
  (`honeypot.corpus.METADATA_COLUMNS` names them).
- **`missing_mask` marks unobserved features**; their values are placeholder zeros, not
  measurements. Impute if you like, but knowingly (DEV-27).
- **Do not "improve" the kill-chain feature.** `observed_stages` is truncated to the observable
  prefix on purpose. Restoring the full `stage_reached` puts the label in the feature vector and
  every model will find it (DEV-27, `test_honeypot_features.py`).
- **Two data sources, reported side by side** (FLAW-2): `bitcoinheist` for the paper's own
  evaluation, `honeypot` for the framework as described. Selected by config, never hardcoded.
- **Reading records off the chain:** decrypt with the key holder's key into
  `SignatureRecordPayload`; check `schema` before reading `features`.
- **Phase 2 is a payload builder over `_block_pipeline`** and changed nothing in it; Phase 3 has
  no reason to touch the pipeline either.
- **`honeypot/` never imports `framework/`.** `HP_RW`'s synthesis is `honeypot.collector.Honeypot`
  (no keys, no network); its session side is `framework.entities.HoneypotNode`. Pinned by
  `test_module_boundaries.py`.
- **Index maintenance is not in Alg. 1's timed path** — `phase1_backup.maintain_index()` is a
  separate call (DEV-05 M3b amendment, `configs/bench.yaml`).
- **Do not add per-transaction digest checks to `Chain`** — M3a tried, reverted; the block
  signature already covers every transaction's full encoding.
- **Test harnesses:** `pbft_harness.py` (clusters, byzantine behaviours), `m3a_harness.py`
  (entities, direct-append chains), `m3b_harness.py` (honeypot nodes, draws, AUC and baseline
  helpers). `tests/integration/conftest.py` puts them on the path.

## Next task

**M4 — Phase 3 detection.** Build `detection/dataset.py` with both backends
(`BitcoinHeistBackend`, `HoneypotBackend` reading the corpus or the chain), `detection/models.py`
(the four estimators with the declared hyperparameters in `configs/ml.yaml`),
`detection/profiles.py` (`NProf`/`AProf`), `detection/metrics.py` (both metric sets plus the
constant-classifier baselines), and `framework/phase3_detection.py` (Alg. 3). Exit: Table II's
BSFR-SH row reproduced in `paper_mode`, `honest_mode` numbers produced alongside (DEV-06), and the
honeypot backend's accuracy reported against the corpus's stated 0.85 — if it lands near 1.0,
stop and find the leak. If the two backends do not fit one session, split them and say so first.

## Blockers

None.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q2 | Transaction payload size — 4096 B *declared* (DEV-15), not justified | M6 result validity | **Deferred, deliberately.** Needs M6's sweep. DEV-24 pins the meaning and the measured framing overhead. |
| Q3 | Does BitcoinHeist need the full 2.9M rows locally, or is a stratified subsample enough for `paper_mode`? | M4 | measure at M4 start; full runs go to Ada regardless |
| Q4 | Do we need real feature-space evasion for M7, or is that out of scope for a course deliverable? | M7 | defer until M6 lands |
| Q5 | Should entry points load one merged config object or the three files independently? | M6 | decide when `bench/` becomes the first multi-config consumer |
| Q8 | Does anything before M7 need pBFT state transfer (DEV-20 item 2)? | M6 | only matters if M6 benchmarks a lossy network; decide at M6 start |
| Q9 | Should the honeypot corpus be regenerated per experiment, or is the committed pair the fixed dataset? | M4 | decide at M4 start; the manifest makes either reproducible |

## For the write-up

**§V-3.** pBFT's threshold is one *third*, not one half, so "PoW is 51%-vulnerable, therefore
pBFT" lowers the bar. At the paper's four nodes, two colluders fork it, and a test asserts the
fork. [FLAW-5] in `docs/PAPER_NOTES.md` §V; mapping in the M2b session file.

**§V-1 / §V-5 (M3a).** §V-1 holds at every place Phases 1, 2 and 5 use session keys. But session
keys protect bytes *in transit*, not at the servers, which is why §IV-E's two plaintext-holding
hops needed DEV-23's attested digest (GAP-8). §V-5 is substantiated only structurally.

**GAP-3 / FLAW-2 (M3b).** The paper defines neither the honeypot's output nor its features, then
evaluates on an unrelated Bitcoin dataset. M3b supplies the missing layer, so Phase 3 can consume
Phase 2's own output — the thing the paper claims and never does. Two further silences became
decisions: "remove the abnormalities" (DEV-26), which read as anomaly removal would delete the
positive class, and the kill-chain feature (DEV-27), which taken whole would be the label itself.

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D2 | `make lint` covers `src` and `tests` but not `scripts/`, and `mypy` only covers `src`. `scripts/` now has two files. | M6 |
| D3 | The bus passes Python objects and never serialises, so wire-encoding cost is absent from the consensus span and record wire size is measured nowhere. | M6 — serialise at the bus, or state in Target 3 that it was not |
| D4 | `ClientRequest` from `CS_l` to the replicas is still unauthenticated (DEV-20 item 5). Junk transactions can be committed; they can never be restored or attributed. | when a claim needs it |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| We wrote both the corpus generator and, in M4, its classifier — a result could measure the generator | M4's headline number means nothing | difficulty stated up front (0.85) and enforced: overlap, no single-feature giveaway, label-independent missingness, baseline on a separate draw (DEV-27) |
| Python timings diverge from the paper's Java | Targets 3 and 4 unverifiable | report ratios and shape, not seconds (DEV-13) |
| Zero-delay consensus is ~1 ms/block, so Fig. 6 measures encryption, not consensus | Target 3 claims something different | DEV-21: M6 runs delay 0 and delay > 0 in separate columns |
| KNN OOMs the 8 GB box on full BitcoinHeist | M4 stalls | subsample by default, `--full` goes to Ada |
| `honest_mode` numbers look like implementation failure | write-up confusion | publish the constant-classifier baseline next to every number |
| The canonical encoding changes after hashes exist | every stored hash silently unreproducible | `ENCODING_VERSION` plus pinned golden vectors |
| Validation migrates out of `Chain` | two definitions of a valid block | `check_append` / `verify_block` are the only validators |
| On-chain storage at 4 KiB per transaction | GAP-2's practicality question gets worse | report storage honestly (M7); M6's sweep states framing is included |

---

## Maintenance rule

This file is **replaced, not appended.** At session end:

1. Rewrite the tables above so they describe reality *now*.
2. Delete anything resolved. A closed question leaves this file entirely — its reasoning lives in
   the session log that closed it.
3. Do not paste benchmark output here. One aggregate number max; details go to `RESULTS.md`.
4. Do not paste narrative here. Narrative goes to `sessions/`.
5. If you are about to add a fifth row to a table that already has ten, something is being
   tracked at the wrong granularity — move it to `docs/ROADMAP.md`.

**Why the cap exists:** we run one session per task, so this file is read at the start of *every*
session. A 200-line file costs a few seconds of context. A 2,500-line one costs a meaningful
fraction of the window before any work begins, and the agent will skim rather than read it — which
is worse than not having it.

## Boundaries with other docs

| File | Holds | Volatility |
|---|---|---|
| `PROJECT_STATE.md` | what is true right now | rewritten every session |
| `docs/ROADMAP.md` | the plan, M0–M7, checkboxes | ticked, rarely restructured |
| `RESULTS.md` | every benchmark ever run, one line each | append-only |
| `sessions/` | what happened in each session | append-only, one file per session |
| `docs/DEVIATIONS.md` | departures from the paper | append-only |
| `CLAUDE.md` | how to work here | near-stable |

If a fact could go in two of these, it goes in exactly one — the leftmost row that fits.
