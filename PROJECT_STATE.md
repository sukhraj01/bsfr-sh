# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-24 · **Milestone:** M7-4 done (pBFT vs Raft comparison); report recompile
still blocked · **Sessions completed:** 19

---

## One-line status

This session answered the question FLAW-5 leaves open (does BSFR-SH's 4-node deployment need
Byzantine tolerance, or would crash-fault-tolerant Raft do more cheaply?) by implementing Raft
alongside pBFT and benchmarking both.

- **`consensus/raft.py`** (new): a scoped-down Raft (leader election, log replication, majority
  commit, failover) over the same bus and `ClientRequest` auth path as pBFT. No signatures in the
  consensus path, by design — that asymmetry is the comparison's point. Scope reductions (no log
  compaction/membership changes/snapshotting, one entry in flight, no retransmission) mirror the
  precedent DEV-20 already set for pBFT's own view-change reduction.
- **`consensus/interface.py`** (new): `ConsensusCluster`, a `Protocol` both `pbft.Cluster` and
  `raft.RaftCluster` satisfy, so `framework._block_pipeline` no longer imports a specific
  consensus module. Small, targeted refactor (`chain_name`/`network`/`replicas` declared as
  read-only `@property` members so mypy checks them covariantly — a plain-attribute protocol
  member would demand invariant compatibility no concrete `dict` subtype satisfies). Production
  phases (`phase1_backup`, `phase2_collection`) untouched, still pBFT-only.
- **Measured (not estimated), `RESULTS.md` M7-4, run `20260924T045952Z-2eaa456f`:** pBFT sends a
  flat 28 messages/block in every case; Raft converges to ~16.8/block (~60% of pBFT's count at
  `n=4` — real, but far short of the O(n)-vs-O(n^2) asymptotic gap a larger cluster would show).
  Signature ops: pBFT = its own message count exactly; Raft = 0, every cell. **Timing gap (Raft
  7-11% faster) is much smaller than the message-count gap (~40% fewer)** — confirms DEV-08/DEV-21
  a second way: consensus messaging is a small fraction of wall-clock time at zero simulated
  delay, so cutting it buys a proportionally smaller speedup than the message count alone suggests.
- **The qualitative half — a byzantine Raft leader forks honest followers with a single faulty
  node** (pBFT needs two colluding, per FLAW-5's own bound): different, honestly-signed
  transaction sets sent to different followers at one log index, both "commit" locally, neither
  side's own chain-integrity check catches it. Standing regression test:
  `tests/unit/test_raft_byzantine.py`. Crash tolerance (1-of-4 silent) is symmetric — both
  protocols still commit.
- `docs/DEVIATIONS.md` DEV-32 (full writeup), `docs/report/report.tex` new §"Consensus Comparison:
  pBFT vs.\ Raft" (source only — see Blockers), `docs/ARCHITECTURE.md` §consensus, `docs/ROADMAP.md`
  M7 ticked.

`make test` (1360+ tests, all new Raft tests included) and `make lint` (ruff + mypy) both green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | `consensus/raft.py` + `consensus/interface.py` added this session |
| `docs/report/report.tex` | done, **needs recompile (3 sessions stale)** | M7-3's section, D3's supplement, and this session's M7-4 section all added, none ever rendered |
| `verification/` | done (M7-1) | unchanged |
| `docs/STORAGE_ANALYSIS.md` | done (M7-2) | unchanged |
| `scripts/run_adversarial_robustness.py` | done (M7-3) | unchanged |
| `scripts/run_consensus_comparison.py` | done (M7-4) | new this session — the pBFT/Raft matrix + fault tests |

## Current numbers

New this session: `RESULTS.md` "M7-4 — pBFT vs Raft consensus comparison" section, run
`20260924T045952Z-2eaa456f`. Everything else unchanged since the last session.

## Next task

**Get a working LaTeX toolchain and compile `docs/report/report.pdf`.** Unchanged from the last
two sessions — still the clear, singular next action. `brew install --cask basictex` is the right
cask (~100-110 MB, not full `mactex`'s ~4 GB) but the default CTAN mirror this environment
resolves to has been too slow to finish twice now. Try a different network, a pinned faster
mirror, or a pre-existing install. After installing: `cd docs/report && pdflatex report.tex` twice
(cross-references), then check every table/figure renders — specifically M7-3's figures, the D3
supplement, and this session's M7-4 table and section — before committing `report.pdf`.

**After that**, one optional M7 stretch item remains (`docs/ROADMAP.md` M7, not required for the
deliverable): hybrid blockchain, the paper's own listed future work.

## Blockers

**No LaTeX toolchain in this environment, three times confirmed.** See Next task above. `docker`/
`pdflatex`/`xelatex`/`latexmk` all absent from `PATH`.

`data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length sufficient, or expand toward 10-12 pages? | report sign-off | reviewer judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 tested and ruled out address/split leakage; report states the gap as measured-but-unexplained |
| `docs/report/report.pdf` is stale relative to `report.tex` (3 sessions now) | a reader of the PDF misses §Adversarial Robustness, the D3 supplement, and §Consensus Comparison | this file states it plainly every session until compiled; do not treat `report.pdf` as current |
| Scyther binary not committed (third-party, single-platform) | a fresh clone can't re-run the verification without a manual download | exact release URL + sha256 in `verification/README.md`; the raw output is committed, so the claims don't depend on re-running it |
| The BC_SigRW/BC_DTBU timing gap is condition-dependent (35-45% off, ~25-27% on) | a reader citing "the gap" without saying which condition is wrong half the time | both figures now in `RESULTS.md`/`docs/EXPERIMENTS.md`/the report supplement, each labelled with its condition |
| Raft's message-count ratio (~60% of pBFT) is measured only at `n=4`; a reader might extrapolate the O(n)/O(n^2) asymptotic gap and expect a bigger number | over-claiming Raft's advantage at other cluster sizes | `docs/DEVIATIONS.md` DEV-32 and the report both state the ratio is small-`n`-specific, not the asymptotic one |

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
