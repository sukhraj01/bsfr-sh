# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-13 · **Milestone:** M5 (mitigation, Phase 4) · **Sessions completed:** 9

---

## One-line status

M4b is closed. `detection.dataset` now has two backends behind one interface
(`BitcoinHeistBackend`, `HoneypotBackend`), selected by `dataset.name`, never hardcoded.
`NProf`/`AProf` are fitted profiles of the trained ensemble's own score, and `DetectionModule`
detects through them, not a raw model call. `framework.phase3_detection.run()` reads two
already-built `BC_SigRW` chains end to end and scores **0.8422 balanced accuracy** — between the
measured 0.830 baseline and the corpus's stated ~0.85 ceiling, not a leak.
`scripts/run_phase3_detection.py --seed 20260912` produces it from real Phase 2 + pBFT consensus.
D6 is retired: `scripts/run_detection.py`'s `paper_mode` now groups by address, so it and
`q10_leakage_ablation.py` agree at **0.9442/0.9697**. `make test` runs 1156 tests,
`make test-all` adds the integration suite (including the first Phase 2 → Phase 3 demonstration),
`make lint` is clean. Next is M5, mitigation.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Docs (`CLAUDE.md`, `docs/*`) | done | DEV-06 retired D6 (M4b); DEV-28 added (M4b) |
| `configs/`, `Makefile` | done | `ml.yaml` gained `dataset.group_column: address` |
| `util/`, `crypto/`, `blockchain/`, `consensus/` | done | |
| `framework/` phases 1, 2, 3, 5 | done | M3a, M3b, M4b. Phase 4 is M5 |
| `recovery/`, `honeypot/` | done | M3a, M3b |
| `data/honeypot/` corpus | done | fixed dataset (Q9): 1467 train + 731 eval, two seeds |
| `data/raw/` BitcoinHeist | **local only** | gitignored; `make data` refetches (~56 min here) |
| `detection/` dataset, models, metrics | done | M4a (BitcoinHeist) + M4b (honeypot backend, `train_all`) |
| `detection/` profiles, detector | done | M4b — `NProf`/`AProf`, `DetectionModule` |
| `mitigation/`, phase 4 | **not started** | **M5 — start here** |
| `bench/`, figures | not started | M6 |

## Current numbers

**BitcoinHeist, `paper_mode`, honest baseline** (n=46,014, address dropped, **grouped** split,
production entry point, run `20260913T131623Z-97f51129`, D6 retired): RF **0.9442/0.9697** ·
DT 0.9224/0.9569 · LR 0.9002/0.9475 · KNN 0.8892/0.9410 · constant-positive baseline
0.9000/0.9474. Published row: 0.9898/0.990 — **not reproduced**, unexplained (Q10, closed). This
is now the only figure `scripts/run_detection.py` and `scripts/q10_leakage_ablation.py` both
produce; cited consistently in `docs/DEVIATIONS.md` DEV-06, `docs/EXPERIMENTS.md`, and here.

**BitcoinHeist, `honest_mode`** (200K subsample, 5-fold, run `20260912T172809Z-d89aa1b6`): best
MCC is DT at 0.331, best PR-AUC is RF at 0.335, recall spans 0.00–0.36. A constant-negative
classifier scores 0.9858 accuracy — an illustration of accuracy's distribution-sensitivity
against the paper's 0.9898, not a like-for-like comparison. Full-scale (2.9M) is **deferred to
Ada, unrun**.

**Honeypot detection, Alg. 3 end to end** (`scripts/run_phase3_detection.py --seed 20260912`,
run `20260913T134602Z-ab45ac90`, train n=1467 eval n=731, real pBFT consensus both draws):
**balanced accuracy 0.8422**, precision 0.8439, recall 0.8272, MCC 0.6849, PR-AUC 0.9100 —
between the corpus's measured 0.830 baseline and its intended ~0.85 Bayes ceiling. Kept counts
matched `data/honeypot/manifest.json` exactly, confirming the generator reproduces bit-for-bit
through the real chain. Constant-positive baseline on the same eval draw: 0.5000 balanced
accuracy (exact, by construction).

## What M5 must not re-derive

- **Case-3 is simulated only, forever** (CLAUDE.md §2). It returns a `PolicyDecision` and writes a
  log record. No network import, no wallet, no transaction construction. `test_case3_is_inert.py`
  must assert this at import level, not just at the call site.
- **`detection.detector.Phase4Handoff`** (`Callable[[Detection], None]`) is the interface M4b
  built specifically for this milestone. Wire mitigation to it; do not add a new detection→
  mitigation call path or reach back into `detection/` to add one.
- **`detection/` and `honeypot/` may not import `framework/` or `mitigation/`** — pinned by
  `test_module_boundaries.py`. `mitigation/` sits at the same layer as `recovery/`: it may depend
  on `blockchain/`, `crypto/`, `util/`, and (for Case-2) `recovery/`, never on `framework/`.
  `framework/phase4_mitigation.py` is what wires it to `detection`'s handoff.
- **Isolation and recovery already exist.** Case-2 calls into `framework.phase5_recovery`, already
  built (M3a) — do not reimplement backup restoration inside `mitigation/`.
- **Every run writes a sidecar and a `measured` RESULTS.md line with its run_id.**
- **Project compute before running it** (CLAUDE.md §6) — not expected to bind for M5 (no ML, no
  full-dataset scale), but consensus fuzz tests (Colluding/Equivocating byzantine behaviours) are
  already in `pbft_harness.py` and should be reused, not rebuilt, for any Case-2/isolation test
  that needs a faulty replica.
- **Test harnesses:** `pbft_harness.py`, `m3a_harness.py`, `m3b_harness.py`.

## Next task

**M5 — Mitigation (Phase 4).** `mitigation/state.py` (the state machine
`DETECTED → ISOLATED → REMEDIATING → (RESTORED | CLEANED | POLICY_BLOCKED) → RESOLVED`, already
named in `docs/ARCHITECTURE.md`), `mitigation/cases.py` (Case-1 quarantine, GAP-4; Case-2 restore
via Phase 5; Case-3 simulated payment decision, GAP-3/policy), `mitigation/policy.py`
(`RW_amt` vs `DT-SYS_i-amt`), `framework/phase4_mitigation.py` wiring `detection.detector
.Phase4Handoff` to the state machine. Exit: a new `tests/integration/test_full_sequence.py` walks
Fig. 3 end to end (backup → collection → detection → mitigation → recovery), each of Cases 1-3
covered by at least one test, `test_case3_is_inert.py` green.

## Blockers

None. `data/raw/` is gitignored; a fresh clone needs `make data` (~56 minutes here) before any
BitcoinHeist run. README states the wait and the sha256.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q2 | Transaction payload size — 4096 B *declared* (DEV-15), not justified | M6 result validity | **Deferred.** Needs M6's sweep; DEV-24 pins the meaning and the measured framing overhead. |
| Q4 | Do we need real feature-space evasion for M7? | M7 | defer until M6 lands |
| Q5 | One merged config object or three files at the entry points? | M6 | decide when `bench/` becomes the first multi-config consumer |
| Q8 | Does anything before M7 need pBFT state transfer (DEV-20 item 2)? | M6 | only if M6 benchmarks a lossy network |

## For the write-up

**§V-3.** pBFT's threshold is one *third*, not one half, so "PoW is 51%-vulnerable, therefore pBFT"
lowers the bar; at four nodes two colluders fork it, and a test asserts the fork. [FLAW-5].

**§V-1 / §V-5 (M3a).** §V-1 holds wherever Phases 1, 2 and 5 use session keys, but session keys
protect bytes in transit, not at the servers — hence DEV-23's attested digest (GAP-8). §V-5 is
substantiated only structurally.

**FLAW-2, closed for the framework's own path (M3b, M4b).** The paper defines neither the
honeypot's output nor its features (GAP-3), then evaluates on an unrelated Bitcoin dataset. M3b
supplied the missing feature layer; M4b proved it reachable through the paper's own sequence —
`framework.phase3_detection.run()` reads real `BC_SigRW` chains `framework.phase2_collection.run()`
built through actual pBFT consensus, and scores a credible 0.8422 balanced accuracy against the
corpus's stated ~0.85 ceiling. M4a's BitcoinHeist row, by contrast, never touches Phases 1, 2, 4
or 5 at all. FLAW-2 is therefore sharper than "wrong dataset": the paper's own framework produces
a real, boundable result when actually run, and the paper substitutes an unrelated dataset for it.

**FLAW-4, extended, and the non-reproduction (M4a, Q10).** The 90/10 resample is degenerate *and*
bounded at 46,014 rows — 1.58% of the cited 2.9M. Our honest reproduction (address dropped,
grouped split) reaches 0.9442/0.9697 against a published 0.9898/0.990; Q10 tested and ruled out
`address`-as-feature and split-grouping as the explanation, so the gap is reported as
**unexplained**. Constant-positive on the paper's own 90/10 split scores 0.9000/0.9474, and
Sharmeen et al.'s published F1 of 0.960 clears that floor by only 0.013 (FLAW-1, extended).

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D2 | `make lint` covers `src` and `tests` but not `scripts/`, and `mypy` only covers `src`. `scripts/` now has seven files. | M6 |
| D3 | The bus never serialises, so wire-encoding cost is absent from the consensus span. | M6 |
| D4 | `ClientRequest` is unauthenticated (DEV-20 item 5). | when a claim needs it |
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8 and **removed in 1.10**; `configs/ml.yaml` still declares it. Migrate to `l1_ratio=0` before upgrading. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| We wrote both the honeypot generator and its classifier | M4b's number could measure the generator | difficulty stated up front (0.85), enforced by M3b's leakage tests, and checked against the *trained* ensemble (not just raw features) by `scripts/run_phase3_detection.py`'s leak guard |
| Python timings diverge from the paper's Java | Targets 3 and 4 unverifiable | report ratios and shape (DEV-13) |
| Zero-delay consensus measures encryption, not consensus | Target 3 claims something different | DEV-21: delay 0 and delay > 0 in separate columns |
| The non-reproduction is read as our bug rather than a finding | the write-up's central claim collapses | baselines published beside every number; Q10 tested and ruled out address/split leakage |
| `data/raw/` is gitignored and slow to fetch | a fresh machine cannot rerun M4a quickly | `make data` verifies counts; README + `provenance.json` state the wait and the sha256 |
| The canonical encoding changes after hashes exist | stored hashes silently unreproducible | `ENCODING_VERSION` plus pinned golden vectors |
| Validation migrates out of `Chain` | two definitions of a valid block | `check_append` / `verify_block` are the only validators |

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
session. A 200-line file costs a few seconds of context; a 2,500-line one costs a meaningful
fraction of the window before any work begins, and gets skimmed rather than read.

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
