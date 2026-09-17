# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-17 · **Milestone:** M6b (Table II, Figs. 4-5, Ada job) · **Sessions completed:** 11

---

## One-line status

M6a is closed: `bench/harness.py` times cases 1-3 (5/10/15 blocks x 100 tx, both chains, 4
nodes) by reusing `consensus.pbft.Cluster` and `framework._block_pipeline.commit` directly — no
new consensus machinery. `bench/emit.py` produces Figs. 6(a)-(d) (ours vs. paper, each with a
sidecar) plus Fig. 6(e), our own component-breakdown panel (compute/modelled-network/index/D3,
never summed into a number comparable to the paper's). `scripts/run_bench.py` wires it end to
end: a case-3 variance probe decides the repeat count instead of trusting the declared floor,
DEV-21's `4d`/`3d` network formula is verified against a real non-zero-delay run before being
trusted, D3's serialization omission is quantified (not just flagged) via
`util.serialization` throughput, and Q2's payload sweep ran and closed with the memory ceiling
projected rather than found by OOMing the dev box. `make test`: 1318 passed. `make lint` clean.
`make figures` now runs (M6a's half; Table II/Figs. 4-5 still `make repro`/`make honest` stubs).
Next is M6b: wire the ML entry points to M4a/M4b's already-built pipelines, plus the Ada job.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Docs (`CLAUDE.md`, `docs/*`) | done | DEV-29 added (M5) |
| `configs/`, `Makefile` | done | |
| `util/`, `crypto/`, `blockchain/`, `consensus/` | done | |
| `framework/` phases 1–5 | done | M3a, M3b, M4b, M5 |
| `recovery/`, `honeypot/`, `mitigation/` | done | M3a, M3b, M5 |
| `data/honeypot/` corpus | done | fixed dataset (Q9): 1467 train + 731 eval, two seeds |
| `data/raw/` BitcoinHeist | **local only** | gitignored; `make data` refetches (~56 min here) |
| `detection/` dataset, models, metrics, profiles, detector | done | M4a, M4b |
| `bench/harness.py`, `bench/emit.py`, Figs. 6a-e | done | M6a |
| `make repro` / `make honest` / Table II / Figs. 4-5 / Ada job | **not started** | **M6b — start here** |

## Current numbers

**BitcoinHeist, `paper_mode`, honest baseline** (n=46,014, address dropped, **grouped** split,
production entry point, run `20260913T131623Z-97f51129`, D6 retired): RF **0.9442/0.9697** ·
DT 0.9224/0.9569 · LR 0.9002/0.9475 · KNN 0.8892/0.9410 · constant-positive baseline
0.9000/0.9474. Published row: 0.9898/0.990 — **not reproduced**, unexplained (Q10, closed).

**BitcoinHeist, `honest_mode`** (200K subsample, 5-fold, run `20260912T172809Z-d89aa1b6`): best
MCC is DT at 0.331, best PR-AUC is RF at 0.335, recall spans 0.00–0.36. A constant-negative
classifier scores 0.9858 accuracy against the paper's 0.9898. Full-scale (2.9M) is **deferred to
Ada, unrun**.

**Honeypot detection, Alg. 3 end to end** (`scripts/run_phase3_detection.py --seed 20260912`,
run `20260913T134602Z-ab45ac90`, train n=1467 eval n=731, real pBFT consensus both draws):
**balanced accuracy 0.8422** — between the measured 0.830 baseline and the corpus's intended
~0.85 ceiling. Constant-positive baseline: 0.5000.

M5 produced no numbers — mitigation has no bench target (`docs/DEVIATIONS.md` DEV-29's note that
Alg. 4 is not benchmarked).

**Bench, M6a** (`scripts/run_bench.py --seed 20260917`, run `20260917T144843Z-fb4c2410`, n=25
repeats — case-3 variance probe read CV up to 45% on a noisy invocation, see `RESULTS.md`):
case-3 `BC_DTBU` 0.479s / `BC_SigRW` 0.691s, two-to-three orders of magnitude below the paper's
5.71s/6.76s (expected, DEV-13). Marginal per-block cost is **flat**, not sublinear like the
paper's — our own TPS is correspondingly flat (~2930-3190 `BC_DTBU`, ~2170-2230 `BC_SigRW`) where
the paper's six points rise. DEV-08 amended with this as a second, measured line of evidence for
the same "rising TPS is amortisation" conclusion. `BC_SigRW` is consistently ~35-45% slower than
`BC_DTBU` (paper: 18-41%), attributed to DEV-03's extra ECDSA sign per transaction. D3's
serialization omission: ≈0.2-0.3% of measured compute (DEV-30, new). Q2 closed: sweep ran at
1024/4096/16384 B, 4096 B default kept; a 10 MB payload would need ~67 GiB (4 replicas x
ciphertext overhead), not run.

## Next task

**M6b — Table II, Figs. 4-5, Ada `honest_mode`.** `scripts/run_detection.py` and
`scripts/run_phase3_detection.py` (M4a/M4b) already produce every number Table II needs;
`bench/emit.py` needs a `emit_table2()`/`emit_fig4_5()` pair reading from `RESULTS.md`'s existing
detection lines rather than re-running the ML. Wire `make repro` (paper-faithful 90/10, cases 1-3
— note cases 1-3 there means the ML split naming, not M6a's block-count cases) and `make honest`
(natural balance, stratified CV) to those scripts. Submit `scripts/ada_honest_mode.sbatch` on Ada
for the full 2.9M-row `honest_mode` run, **unrun** as of this session. Exit: every target in
`docs/EXPERIMENTS.md` carries a `measured` or `paper_reported` label — Targets 1/2 (M4a/M4b,
already measured) just need the figures; Target 5 (§V) is test-mapped only, no figure owed.

## Blockers

None. `data/raw/` is gitignored; a fresh clone needs `make data` (~56 minutes here) before any
BitcoinHeist run. README states the wait and the sha256.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q4 | Do we need real feature-space evasion for M7? | M7 | defer until M6b lands |
| Q8 | Does anything before M7 need pBFT state transfer (DEV-20 item 2)? | M7 | only if M7 benchmarks a lossy network |

## For the write-up

**§V-3.** pBFT's threshold is one *third*, not one half, so "PoW is 51%-vulnerable, therefore pBFT"
lowers the bar; at four nodes two colluders fork it, and a test asserts the fork. [FLAW-5].

**§V-1 / §V-5 (M3a).** §V-1 holds wherever Phases 1, 2 and 5 use session keys, but session keys
protect bytes in transit, not at the servers — hence DEV-23's attested digest (GAP-8). §V-5 is
substantiated only structurally.

**FLAW-2, closed for the framework's own path (M3b, M4b, M5).** The paper defines neither the
honeypot's output nor its features (GAP-3), then evaluates on an unrelated Bitcoin dataset. M3b
supplied the missing feature layer; M4b proved it reachable through the paper's own sequence; M5
closed the loop — `tests/integration/test_full_sequence.py` runs backup, collection, detection,
mitigation and recovery in one test, the sequence Fig. 3 draws and the paper itself never runs.
FLAW-2 is therefore sharper than "wrong dataset": the paper's own framework produces a real,
boundable, end-to-end result when actually run, and the paper substitutes an unrelated dataset for
half of it and never demonstrates the other half at all.

**FLAW-4, extended, and the non-reproduction (M4a, Q10).** The 90/10 resample is degenerate *and*
bounded at 46,014 rows — 1.58% of the cited 2.9M. Our honest reproduction (address dropped,
grouped split) reaches 0.9442/0.9697 against a published 0.9898/0.990; Q10 tested and ruled out
`address`-as-feature and split-grouping as the explanation, so the gap is reported as
**unexplained**.

**Alg. 4's two silent gaps (M5).** The paper never says which of Case-1/2/3 applies to a detection,
or how a honeypot detection names the `SYS_i` it concerns — Fig. 3 draws "detect" straight into
"mitigate" with nothing in between. DEV-29 makes both explicit caller inputs rather than guessing;
worth a paragraph in the critique alongside GAP-4 (erasure semantics) and DEV-09 (Case-3's premise
contradicting §II-C).

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D2 | `make lint` covers `src` and `tests` but not `scripts/`, and `mypy` only covers `src`. | M6b |
| D3 | The bus never serialises; magnitude now quantified (DEV-30, M6a: ≈0.2-0.3% of measured compute) but the omission itself is unfixed. | M7, if async pBFT lands |
| D4 | `ClientRequest` is unauthenticated (DEV-20 item 5). | when a claim needs it |
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| We wrote both the honeypot generator and its classifier | M4b's number could measure the generator | difficulty stated up front (0.85), enforced by M3b's leakage tests |
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
