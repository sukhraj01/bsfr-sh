# Session 2026-09-25-05 — M7-9: formal threat model

**Milestone:** M7-9 (stretch) · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/PAPER_NOTES.md` §V (and §I-III for the paper's actual threat-model content, or lack of it),
`docs/DEVIATIONS.md` DEV-02, DEV-32, DEV-33 (plus DEV-20 for the view-change gap, DEV-34 for the
honeypot-representativeness gap), `RESULTS.md` M7-3/M7-4/M7-5 sections, `verification/README.md`
(M7-1's Scyther claims table), relevant test names in `tests/unit/test_pbft_byzantine.py`,
`tests/unit/test_pbft.py`, `tests/unit/test_raft_byzantine.py` · **Duration:** _

---

## Brief *(written before any work)*

**Task:** Construct the threat model the paper never states — assets, four adversary tiers, trust
assumptions, a coverage matrix mapping §V's five informal claims onto our measured/verified
results, and a gap analysis of what remains uncovered — as two documents: a standalone
`docs/THREAT_MODEL.md` and a shorter report section built around the coverage matrix and gaps.

**Exit condition:** `docs/THREAT_MODEL.md` committed with all five parts (assets, tiers, trust
assumptions, coverage matrix, gaps); report section added and `report.pdf` recompiled with
`tectonic`; every coverage-matrix cell cites a specific test name, verification claim ID, or
`RESULTS.md` line; `make test` still green (no new tests expected — this is a documentation
session, not an implementation one).

**Out of scope:** no new implementation, no new experiments, no code changes of any kind, no
fixes to any gap this session identifies — the gaps are findings to record, not tickets to close.

**Prior context needed:** `docs/PAPER_NOTES.md` §V (the five informal claims and FLAW-5/GAP-6)
is the thing being replaced with a structured argument. DEV-02 (session protocol, M7-1's subject),
DEV-32 (Raft comparison, the Tier-2/Tier-3 pBFT-vs-Raft finding), DEV-33 (hybrid chain, the
Tier-3 detection mechanism) supply the tier-by-tier defenses and their cited test/measurement
evidence directly — this session synthesizes them into one argument rather than re-deriving any
of the underlying results.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/PAPER_NOTES.md
§V (all five security arguments), docs/DEVIATIONS.md DEV-02 (session
protocol), DEV-32 (Raft comparison), DEV-33 (hybrid chain). RESULTS.md
lines for M7-1 (Scyther), M7-3 (adversarial), M7-4 (Raft), M7-5 (hybrid).

Create the session file from the template and fill the brief first.

TASK — M7-9. Formal threat model.

[full brief: assets (patient data, signature DB, ground truth, availability)
with the chain and property that protects each; four adversary tiers
(external network attacker / single compromised server f=1 / two
compromised servers f=2 / adversarial ML evasion) each with capability,
defense, cited test/verification result, and honest limitation; explicit
trust assumptions; a coverage matrix mapping each §V claim to tier(s)
addressed, verification method, result, and known limitations; a gap
analysis (honeypot data poisoning, registration-authority insider threat,
consensus DoS/liveness, backup-chain side channels) stating tier and
whether any extension partially addresses each, not inventing solutions —
see task text for full detail]

EXIT CONDITION
docs/THREAT_MODEL.md committed. Report updated and recompiled with tectonic.
No new code, no new tests beyond make test confirming nothing broke.
Every cell in the coverage matrix cites a specific test, verification
result, or RESULTS.md line.

OUT OF SCOPE
No new implementations, no new experiments, no fixes to any gap identified.
The gaps are findings, not tasks.

END OF SESSION
Session file. Rewrite PROJECT_STATE.md. Tick M7-9. Commit and push.
```

---

## What was done

- **`docs/THREAT_MODEL.md`** (new, AI-generated): the standalone reference. Five parts: (1) assets
  (patient data, signature DB, detection ground truth, system availability — each with the chain
  and specific property, e.g. "confidentiality via hybrid encryption" not just "the chain
  protects it"); (2) four adversary tiers by capability (external network attacker / one
  compromised server f=1 / two compromised servers f=2 / adversarial ML evasion), each with
  capability, defense, a specific cited test or verification result, and an honestly-stated
  limitation; (3) five explicit trust assumptions the paper never states; (4) a coverage matrix
  mapping every §V claim (plus a sixth row for the adversarial-ML surface the paper's vocabulary
  has no way to name) to tier/method/result/limitation; (5) a four-item gap analysis (honeypot
  data poisoning, registration-authority insider threat, consensus DoS, backup-chain side
  channels), each stated as a finding with no solution proposed.
- **`docs/report/report.tex`** new §"Threat Model" (new, AI-generated), placed before §Conclusion
  — after (not interleaved with) every section it synthesizes (Critique, Adversarial Robustness,
  Adversarial Retraining, Consensus Comparison, Hybrid Blockchain), since it references all of
  them. Shorter than the standalone doc per the brief: one framing paragraph, the coverage-matrix
  table, then the gap analysis — the two "novel contribution" parts the brief singled out.
- **Two LaTeX bugs found and fixed while building the table**, neither of which existed before
  this session's edits: (a) code identifiers in the new table were written with Markdown-style
  backticks instead of `\texttt{}` (every other table in this report uses `\texttt{}` — checked
  the convention before assuming it, not after); (b) the "Tier" column for claim (4) held an
  essay-length sentence in a non-wrapping `c`-type column, which alone produced a 144.7pt overfull
  `\hbox` spanning the whole table. Fixed by moving qualifying detail out of the Tier column into
  the Method column (which wraps) and shortening Tier cells to bare tier numbers; `\allowbreak`
  inserted after underscores in the two longest `\texttt{}` test-file names so they can wrap
  inside their column instead of overflowing it. Recompiled clean: the only remaining overfull
  warnings (lines 489/595/687) point at content well before this session's insertion point (this
  section is appended right before `\section{Conclusion}`, at what was line ~1614 before any
  edits) and were unaffected by anything changed here, confirming they predate this session.
- **`docs/ROADMAP.md`**: M7-9 item added, top milestone line updated.

## Findings

- **The paper's §II is not a threat model, despite DEV-33's own report text calling it one in
  passing** (`docs/report/report.tex` line ~1608, "the paper's threat model (§ II)"). Checked
  `docs/PAPER_NOTES.md` §II directly before writing this section's framing paragraph: §II is a
  ransomware taxonomy (four types, eight distribution vectors, a seven-stage kill chain) with **no
  adversary-capability content at all** — it says what ransomware *is*, never what a network
  attacker, a compromised operator, or an adversarial-ML attacker can *do*. This project's own
  earlier prose (DEV-33) used "threat model" loosely to mean "the paper's closest gesture at
  naming who might attack"; this session's new text is precise about the distinction without
  contradicting or rewriting that earlier line — both readings agree the paper's treatment is
  thin, this session just says exactly how thin.
- **Hybrid anchoring's contribution at Tier 2 is narrower than it first appears, and the brief's
  own framing needed a correction to be exactly accurate.** The task brief described "hybrid
  anchoring detects tampering by this adversary after the fact" for Tier 2 (f=1). Checked this
  precisely: pBFT's own safety property already prevents a bad block from being *committed* at
  f=1 — nothing reaches the point of needing after-the-fact detection at the consensus layer for
  that specific failure mode. What hybrid anchoring actually adds at Tier 2 is detection of a
  *different* attack surface: a compromised server silently rewriting its own already-committed
  local storage, bypassing consensus entirely rather than trying to win a pBFT round. Stated this
  distinction explicitly in both documents rather than reusing the brief's slightly imprecise
  framing verbatim.
- **Two §V claims resolve cleanly to opposite verdicts once tiers are separated, exactly
  demonstrating why the paper's flattened treatment (FLAW-5) was the problem.** Claim (3)'s Sybil
  half is fully verified; its "51%" half is actively wrong (not merely unverified) once `f=2` is
  tested directly (`test_f2_colluding_equivocators_can_fork_honest_replicas_the_bound_is_exactly_f`)
  — writing these as one MIXED row rather than splitting further would have hidden exactly the
  conflation FLAW-5 already named as the paper's own error.
- **Gap 3 (consensus DoS) is not a new finding — it already existed in DEV-20 — but had never
  been connected to §V-4's "resists DoS" claim before this session.** DEV-20 documents the
  liveness cost of the reduced view change as an implementation trade-off; nothing in this
  project's existing docs had previously stated the connection "this is the reason §V-4's DoS
  claim does not fully hold." Synthesis, not new measurement — consistent with the session's own
  scope (no new experiments).

## Numbers

None — this is a documentation session. No new measurements; every number in
`docs/THREAT_MODEL.md` and the new report section is a citation of an existing `RESULTS.md` line,
test name, or `verification/` claim (M7-1, M7-3, M7-4, M7-5, M7-7, M7-8).

## Deviations opened or changed

None. This session synthesizes existing results into a new argument; it does not implement
anything the paper specifies differently, so there is nothing for `docs/DEVIATIONS.md` to record.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** the paper's §V no longer stands unexamined — every one of its five claims has a
tier, a verification method, a result, and a stated limitation, cross-referenced against six
prior sessions' worth of security-relevant work that previously sat in separate report sections
with no argument tying them together. `docs/THREAT_MODEL.md` is the durable reference; the report
section is the reader-facing summary of it.

**Next task:** None forced. `docs/THREAT_MODEL.md`'s own gap analysis names four candidate future
sessions (honeypot data poisoning, registration-authority insider threat, consensus DoS, backup-
chain side channels) — explicitly not proposed as tasks by this session's own scope constraint,
but available if a future session wants one. Otherwise, async pBFT with modelled network latency
remains the one open `docs/ROADMAP.md` M7 item.

**New blockers:** None.

**Questions opened / closed:** No `PROJECT_STATE.md` Q-numbers touched; this session did not open
or close a numbered open question, only M7-9's own checklist item.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines (137)
- [x] `docs/THREAT_MODEL.md` created, all five parts present
- [x] Report section added, `report.pdf` recompiled with `tectonic` (clean — no new warnings)
- [x] `docs/ROADMAP.md` boxes ticked (M7-9 added, top milestone line updated)
- [x] `make test` (1547 tests, unchanged) and `make lint` (ruff + mypy) still green
- [x] Committed, message explains *why*
