# Session 2026-09-27-02 — federated detection and disagreement-based poisoning signal

**Milestone:** M7-15 · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/THREAT_MODEL.md` (full), `RESULTS.md` M7-11/M7-12/M7-14 lines, `docs/ARCHITECTURE.md`
§detection + §consensus, `docs/DEVIATIONS.md` DEV-38/DEV-40 (for format/precedent),
`scripts/m7_11_honeypot_poisoning.py` (poisoning strategies + sweep harness pattern),
`src/bsfr_sh/detection/{poisoning,adversarial,detector,profiles,models}.py` · **Duration:** ~2h

---

## Brief *(written before any work)*

**Task:** Build a federated/replicated detection module (`detection.federated`: `FederatedDetector`,
majority-vote `VotingPolicy`, `DisagreementAnalyzer`) that exploits the paper's own architectural
redundancy (four cloud servers, each independently training on the same `BC_SigRW` chain) to detect
honeypot poisoning via cross-replica model disagreement rather than statistics (M7-12) or protocol
restriction (M7-14) — then measure it against M7-11's three poisoning strategies at three budgets
under three scenarios (poisoner-trains-clean, algorithm-diversity, private-holdout self-check), and
report the result honestly, including the scenario-A irony (the "outlier" node can be the correct
one).

**Exit condition:** `detection/federated.py` exists with unit tests covering majority-vote
correctness, the divergent-node identification, and the scenario-A irony property; a new script
measures 3 scenarios x 3 strategies x 3 budgets (27 cells) against the committed corpus and prints
`RESULTS.md`-ready lines; the four-defense (M7-11/12/14/15) comparison table exists; `docs/
THREAT_MODEL.md` Gap 1 gains this defense's honest verdict; `make test` and `make lint` are green.

**Out of scope:** no changes to `detection/poisoning.py` (the attack code); no real federated
learning (gradient sharing, FedAvg); no actual distributed training — all four "nodes" run
in-process, sequentially, on the same machine, same as every other M7-x poisoning experiment's
posture toward `consensus/`.

**Prior context needed:** M7-11 (attack + budgets), M7-12 (statistical defense, its own null
result and *why*), M7-14 (protocol defense, its own null result and *why*) — this session's job is
to add the third leg of that arc honestly, not to re-argue the first two.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. [Full M7-15 task brief as given by the user — federated detection and disagreement-based
   poisoning signal, three scenarios (poisoner-trains-clean, algorithm-diversity, private-holdout),
   detection/federated.py, evaluation against M7-11's three strategies at 5/10/20% budgets,
   four-defense comparison table, report write-up, tests, RESULTS.md lines, THREAT_MODEL.md
   update, PROJECT_STATE.md rewrite, commit and push.]
```

---

## What was done

- **AI-generated, human-reviewed** `src/bsfr_sh/detection/federated.py` — `FederatedDetector`
  (thin wrapper over N `DetectionModule`s), `majority_vote`/`vote` (strict-majority decision plus
  per-node disagreement-fraction flagging, tie-at-`n=4` resolves to benign), `analyze_disagreement`
  (`DisagreementReport`: per-node agreement rate, single most-divergent node — `None` on perfect
  agreement or an exact tie, never an arbitrary pick — and, given ground truth, individual/
  majority/excluding-outlier accuracy). Zero new dependencies beyond `detection.adversarial`/
  `detection.detector`, both already inside `detection/`'s boundary — no `consensus/` import at
  all, unlike M7-12's named exception.
- **AI-generated** `tests/unit/test_federated_detection.py` — 12 tests: no-dissent reproduction,
  3-vs-1 override, tie resolution, empty-input rejection, threshold flagging, divergent-node
  identification, perfect-agreement/exact-tie null cases, the scenario-A irony property (worked
  through by hand first to confirm the arithmetic before writing the assertions), the scenario-B
  non-negative-vs-worst-model property.
- **AI-generated** `scripts/m7_15_federated_detection.py` — the 27-cell evaluation (3 scenarios x
  3 of M7-11's strategies x 3 budgets: 5/10/20%), reusing `fit_detector`/`clean_metrics` patterns
  from `scripts/m7_11_honeypot_poisoning.py`. Ran once against the committed corpus at `SEED
  20260912` (kept identical to M7-11/12/14's own seed — a first run at a different seed drifted
  the baseline by exactly the CSV-vs-chain gap DEV-27 already explains, caught by the script's own
  reproduction check before any cell was measured, not discovered after the fact).
- **Human-directed, AI-executed** documentation updates: `RESULTS.md` (M7-15 section, 27+2 lines),
  `docs/DEVIATIONS.md` (DEV-41), `docs/THREAT_MODEL.md` (Gap 1's federated-detection subsection +
  cross-references), `docs/ARCHITECTURE.md` (§detection, `federated.py` entry), `docs/ROADMAP.md`
  (M7-15 ticked + milestone header), `docs/report/report.tex` (new §"Federated Detection:
  Exploiting Replicated Redundancy" after §m7-14, comparison table, abstract/intro/conclusion
  extension-count and defense-count updates), `PROJECT_STATE.md` (full rewrite).
- Recompiled `docs/report/report.pdf` via `tectonic` (no `pdflatex`/`latexmk` in this environment;
  `tectonic` was already installed and is a drop-in substitute) — 28 pages, up from 26. Fixed one
  overfull-hbox warning in the new comparison table (`\resizebox` wrap) before the final compile;
  the five other overfull/underfull warnings tectonic reports are pre-existing, in sections this
  session did not touch (verified by line number), and were not introduced by this session's edit.

## Findings

- **The scenario-A irony is real but not universal.** It holds for `label_flip`/`feature_poison`
  (the poisoner's clean model is genuinely more accurate than the honest nodes' degraded one) but
  inverts for `anchor_point_injection`, where M7-11 already found poisoning sometimes *improves*
  accuracy — so the "outlier" disagreement flags there is unremarkably the worse model, and no
  irony exists. Worth stating precisely rather than as a blanket claim: a designed property of the
  detection mechanism (disagreement != correctness) surfaces differently depending on which
  poisoning strategy is in play.
- **Excluding the identified outlier never changes anything in scenario A (all 9 cells).** At a
  3-honest-vs-1-poisoner split, majority voting has already fully suppressed the lone dissenter's
  influence before any exclusion step runs — a finding worth naming explicitly so a reader does not
  assume "flag it, then exclude it" adds protection beyond the vote itself.
- **Scenario B's hard-vote-of-single-algorithms is not a strict improvement over the paper's own
  soft-vote-of-four-algorithms baseline.** It recovers the *worst individual model's* accuracy
  (always true, 9/9 cells) but underperforms the standard `DM_CSl` ensemble on `label_flip`/
  `feature_poison` and is roughly even on `anchor_point_injection`. Caught this before writing it
  up as an unqualified win by explicitly comparing scenario B's row against M7-11's cited baseline
  in the comparison table — the two architectures (soft-vote-one-detector vs. hard-vote-four-
  detectors) are not the same thing, and conflating them would have overclaimed the result.
- **KNN and Decision Tree score bit-identical balanced accuracy across all three budgets for
  `anchor_point_injection`** (0.6602 / 0.8203 exactly). Initially looked like a bug (suspected the
  budget wasn't actually varying the poisoned draw); traced it to the strategy and confirmed the
  budget *does* vary `n_poisoned` correctly — the injected anchor cluster apparently never enters
  any eval row's k=5 neighbourhood or crosses an existing tree split at any of the tested budgets.
  A genuine, measured model-class insensitivity, not a harness bug. Recorded as a finding rather
  than silently smoothed over.
- **Scenario C's private-holdout signal is weak and inconsistent** — only 1 of 9 cells clears the
  stated detectability band, and the project's most damaging strategy (`label_flip`) is not
  reliably caught even at 20% budget. Attributed explicitly to `n=4` nodes and a ~65-row holdout's
  sampling variance, the same "does zero sit inside the band" convention M7-14 used for its own
  robustness check — not treated as evidence the idea is wrong, just under-powered at this scale.
- **Dead end, recorded so it is not retried:** first script run used a fresh seed
  (`SEED = 20260927`, today's date) rather than the established `20260912`. The baseline drifted
  by 0.0014 — exactly DEV-27's known CSV-vs-chain-path gap — which the script's own reproduction
  check caught before any real cell was measured. Fixed by matching M7-11/12/14's seed exactly;
  worth remembering that *any* new M7-x poisoning script must reuse `SEED = 20260912`, not a
  fresh one, or its baseline will not match the established 0.8408 reference.

## Numbers

27 measured cells (3 scenarios x 3 strategies x 3 budgets) plus the four-defense comparison table.
Full lines: `RESULTS.md` "M7-15" section (appended, not summarized here — this is the narrative
pointer, that is the queryable copy). Sidecar: `results/logs/20260927T053738Z-fc5e7c20.json`.
Figure: `results/figures/fig15a_federated_scenarios.png`.

## Deviations opened or changed

- **DEV-41 (new).** Federated detection via cross-replica disagreement: architecturally the
  cleanest of the three poisoning defenses (no new protocol message, no new trust assumption
  beyond M7-12's existing decrypt-capable-replica one) but not, on this corpus, a stronger one —
  scenario (a)'s outlier can be the correct model by design, scenario (b) underperforms the
  paper's own soft-vote ensemble, scenario (c) catches only 1 of 9 cells. Full text in
  `docs/DEVIATIONS.md`.

---

## Handover *(written last)*

**State after:** M7 stretch's third and final poisoning defense is delivered. The poisoning arc is
now: attack (M7-11), statistical defense (M7-12, catches nothing measurable), protocol defense
(M7-14, changes nothing measurable), federated defense (M7-15, real but narrow/inconsistent — the
first of the three that costs nothing beyond the paper's own architecture, and the only one with
an honestly mixed rather than cleanly-null result). `docs/report/report.pdf` is 28 pages.

**Next task:** None forced (see `PROJECT_STATE.md` "Next task" — ranked: a disagreement-
coordination mechanism, scenario-C at larger scale, M7-14's concept-drift follow-up, or the
report's page-count gap, now 28pp vs. the original <20pp target).

**New blockers:** None.

**Questions opened / closed:** Q11 (report length) restated, not resolved — now 28pp, two
sessions past the original <20pp target (was 26pp after M7-14).

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines (144)
- [x] `RESULTS.md` appended, one line per run
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated if the paper was departed from (DEV-41)
- [x] Committed, message explains *why*
