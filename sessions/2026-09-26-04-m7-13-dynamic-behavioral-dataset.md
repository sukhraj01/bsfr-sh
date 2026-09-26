# Session 2026-09-26-04 — M7-13: dynamic behavioral malware dataset

**Milestone:** M7-13 · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/ARCHITECTURE.md` §honeypot, `docs/DEVIATIONS.md` DEV-03/DEV-27/DEV-34/DEV-35,
`RESULTS.md` M7-7/M7-10 lines, `src/bsfr_sh/honeypot/{features,collector,ember_mapping,
external_mapping}.py`, `scripts/{m7_7_real_malware_transfer,m7_10a_ember_transfer,
m7_10b_neural_detector}.py`, `tests/unit/test_honeypot_ember_mapping.py` · **Duration:** long
(dataset search dominated)

---

## Brief *(written before any work)*

**Task:** find, map, and evaluate (never retrain) a real dynamic-behavioral malware dataset
against `FT_RW`, extending M7-7 (ClaMP, 3/22)/M7-10 (EMBER, 6/22) with a dataset that can ground
the execution-time groups (process, network, persistence) no static dataset can touch.

**Exit condition:** at least one dynamic dataset mapped and evaluated, coverage fraction computed
and compared to ClaMP/EMBER, per-group permutation-importance comparison done, `RESULTS.md` lines
for every measurement, `make test`/`make lint` green.

**Out of scope:** retraining on real data, changing `FT_RW`'s schema, changing the generator.

**Prior context needed:** DEV-34 (ClaMP mapping + its `MappingKind` convention), DEV-35 (EMBER
mapping, coverage-fraction precedent, its stricter DIRECT-vs-PROXY bar), `docs/ARCHITECTURE.md`
§honeypot (the 22-feature/7-group schema this session maps against).

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/ARCHITECTURE.md
   §honeypot (FT_RW schema), docs/DEVIATIONS.md DEV-03, DEV-27, DEV-34.
   RESULTS.md lines for M7-7 (ClaMP, 0.5000) and M7-10 (EMBER status).

   Create the session file from the template and fill the brief first.

   TASK — M7-13. Dynamic behavioral malware dataset.
   [full brief: candidates in order (1) BODMAS github.com/UrbSec/BODMAS, (2) CICMalDroid-2020,
   (3) MalwareBazaar+Triage/Hatching, (4) Cuckoo public instances (cuckoo.cert.ee); map all 22
   FT_RW features as MAPPED/PROXY/MISSING against whichever candidate works first with >=12/22
   coverage; evaluate the synthetic-trained detector on it (never retrain); per-group permutation
   importance, real vs synthetic; KS tests per mapped feature vs ClaMP/EMBER; write up; DEV entry;
   rewrite PROJECT_STATE.md; tick M7-13; commit and push. Full text as given in the task message.]
```

---

## What was done

**Candidate search (the dominant cost this session).** Checked all four named candidates, in
order, against their actual data rather than the brief's description of them (CLAUDE.md: "do not
trust README descriptions"):

1. **BODMAS** — the brief's URL (`github.com/UrbSec/BODMAS`) does not exist; the real repo is
   `github.com/whyisyoung/BODMAS`. Fetched its README and the dataset's own project page
   (`whyisyoung.github.io/BODMAS`): BODMAS's feature vectors are explicitly "extract[ed] ...
   using the LIEF project (version 0.9.0), **the same as the Ember dataset**" — 2381-dim static
   structural features, not the dynamic sandbox behavioral features (API categories, registry
   ops, network ops) the brief attributed to it. **Ruled out**: it would only reproduce EMBER's
   coverage under a different name, not add the execution-time groups this session needs.
2. **CICMalDroid-2020** — genuinely dynamic (CopperDroid VMI sandbox: syscalls, binder calls,
   composite behaviors, network PCAP over 13,077 executed APKs) but gated behind a UNB
   `cicresearch.ca` download form requiring name/email/institution/job title/country and manual
   review, exactly as the brief itself flagged as a risk ("may require a research-access form —
   check before investing time"). **Not obtainable this session** without creating an external
   record under the user's identity and waiting on manual approval.
3. **MalwareBazaar + Triage** — MalwareBazaar's API now requires an Auth-Key obtained through
   abuse.ch's own account-registration portal (confirmed: an unauthenticated `get_info` POST
   returns `{"error": "Unauthorized"}`, where older docs implied no key was needed); Hatching
   Triage's docs endpoint (`tria.ge/docs/cloud-api/`) returned HTTP 403, and its public reports
   listing (`tria.ge/reports`) redirects to a login-gated SPA. **Not obtainable this session**
   without creating an account under the user's identity — the same class of blocker as (2), just
   a lighter-weight form.
4. **Cuckoo public instances** — `cuckoo.cert.ee` did not respond at all (connection failure,
   curl exit 000) within a 15s timeout. **Unreachable**, matching the brief's own caveat
   ("availability varies").

All four named candidates failed for distinct, verified reasons — none fabricated, none assumed
from a README alone. Rather than stop the session on "no candidate reachable" (which the exit
condition does not accept, and which CLAUDE.md's "never claim a number we did not measure" makes
the alternative — inventing a mapping — worse than useless), searched one step further within the
same spirit as candidate 3 (a real, published, Cuckoo-derived API-call dataset) for a **freely
downloadable, no-registration** option, since none of the above three account-gated resources
could be obtained without the user personally creating an external account — an action this
session does not take unilaterally (CLAUDE.md's operating posture on actions affecting external,
shared systems).

**Found: `github.com/mpasco/MalbehavD-V1`** — the dataset backing Maniriho, Mahmood & Chowdhury,
"API-MalDetect: Automated malware detection framework for Windows based on API calls and deep
learning techniques," *J. Network and Computer Applications*, 2023. 2,570 real Windows PE files
(1,285 malware + 1,285 benign, perfectly balanced), each executed in an isolated Cuckoo-sandbox
environment (VirtualBox VMs) and represented as its **observed API call sequence** (up to 175
calls, 291 distinct API names across the corpus) — genuine dynamic, execution-time behavioral
data, MIT-licensed, committed directly to a public GitHub repo with no download form. Verified by
downloading the raw CSV directly (`raw.githubusercontent.com`, not the repo's rendered README) and
inspecting row counts, label balance, and the full API-name vocabulary before writing any mapping
— the "inspect the actual data" instruction applied to this candidate as much as to BODMAS.

**Files created:**
- `data/external/malbehavd/README.md` — provenance (source, license, fetch method, sha256,
  verified counts). AI-generated.
- `data/external/malbehavd/MalBehavD-V1-dataset.csv` — the dataset itself, committed (2.3MB, same
  posture as ClaMP's committed CSV — small enough, openly licensed).
- `src/bsfr_sh/honeypot/malbehavd_mapping.py` — the `FT_RW` mapping, mirroring
  `ember_mapping.py`'s structure and `MappingKind` convention exactly.
- `tests/unit/test_honeypot_malbehavd_mapping.py` — mirrors `test_honeypot_ember_mapping.py`.
- `scripts/m7_13_malbehavd_transfer.py` — evaluation script, mirrors `m7_10a_ember_transfer.py`
  plus per-group permutation importance (real vs. synthetic) the brief adds for this session.

All AI-generated; mapping decisions cross-checked against the actual vocabulary dump (291 API
names) before being written, not assumed from memory of what a "typical" malware trace contains.

**Files modified:**
- `RESULTS.md` — M7-13 section appended (measurements below).
- `docs/DEVIATIONS.md` — DEV-39 added.
- `docs/ROADMAP.md` — M7-13 ticked, top milestone line updated.
- `docs/report/report.tex` — §"Real-Data Transfer" extended with a MalbehavD-V1 subsection
  (coverage table, transfer-result diagnosis, one merged figure environment); Conclusion's
  transfer-evaluation sentence updated to reflect three datasets instead of two. Recompiled with
  `tectonic` — still 25 pages (no page-count regression), no LaTeX errors, only pre-existing
  underfull/overfull-hbox warnings plus the same two the EMBER table already had.
- `PROJECT_STATE.md` — rewritten (see below).

---

## Findings

- **The session brief's own dataset descriptions cannot be trusted uncritically — verified two
  layers deep, not one.** BODMAS's *code repository URL* in the brief was simply wrong
  (`UrbSec/BODMAS` doesn't exist), and its *feature description* was also wrong (the brief called
  it dynamic-behavioral; the actual dataset, per its own project page, reuses EMBER's static LIEF
  pipeline verbatim). CLAUDE.md's "do not trust README descriptions" needed to be applied to the
  task brief itself, not just to the dataset's own documentation once found.
- **Two of the four named candidates are blocked by account/form gating that has tightened over
  time, not just "may require a form."** MalwareBazaar's API now hard-requires an Auth-Key
  (confirmed empirically: unauthenticated `get_info` returns `{"error": "Unauthorized"}`); this
  reads as a recent tightening rather than a static fact the brief could have anticipated exactly.
  Neither this nor CICMalDroid's UNB form is something this session resolves by waiting or
  retrying — both need the user to personally create an account/submit a request, which is a
  judgment call about acting under someone else's identity on an external service, not a technical
  obstacle to route around.
- **A freely-downloadable, no-registration, genuinely dynamic dataset exists and was not on the
  brief's list**: `github.com/mpasco/MalbehavD-V1`, found via a GitHub code search for the
  well-known "Angelo Oliveira" Kaggle API-call-sequence dataset's lineage, which led to the actual
  academic paper's own repo. Worth remembering for any future session that needs real dynamic
  malware behavioral data without a research-access gate.
- **Coverage growing does not imply transfer improving — the M7-13 result is the clearest version
  of this finding across all three real-data sessions.** 12/22 features and 5/7 groups (including
  process and network, which no static dataset can reach at all) still produced exactly the same
  `bal_acc=0.5000` ClaMP (3/22, 1 group) and EMBER (6/22, 2-3 groups) produced. The per-group
  permutation-importance check (real_drop=0.0000 for literally every group, including the 5
  mapped ones) was essential to seeing *why*: the ensemble's decision has already saturated to a
  constant prediction before any feature-level analysis can say anything. Without that check, this
  session would have reported "still 0.5000, mechanism unclear" — a materially weaker finding.
- **The within-dataset Mann-Whitney separation check (not requested explicitly by name in the
  brief, added because it was the obvious next question) is what turns this from "another 0.5000"
  into a specific, actionable diagnosis.** It is the only measurement in this session that
  involves zero synthetic data at all, and it is what distinguishes "no real dynamic signal
  exists" from "real signal exists but the fitted profiles cannot see it" — a distinction the
  brief's own three interpretive branches (near-0.5, between, near-0.84) did not anticipate as a
  *fourth* possibility (0.5 exactly, but with real within-dataset separation proven separately).
- **Dead end, recorded so it is not retried:** considered normalizing the mapped count features by
  trace length (a rate rather than a raw count) to control for longer traces naturally producing
  more of every call category. Rejected in favor of matching EMBER's established "count stands in
  for a rate" convention exactly (`ember_mapping.crypto_call_rate`), for consistency with DEV-35's
  precedent rather than introducing a new, unreviewed normalization choice this session could not
  validate against anything.
- **Dead end:** considered building `crypto_ngram_novelty` as novelty against a reference bigram
  vocabulary built from this same dataset's benign rows. Rejected because it would make the
  feature computation depend on the labels of the data being evaluated — a leakage shape, even
  though no model fitting would be involved. Used a self-referential distinct-bigram-ratio
  statistic instead, which turned out to be degenerate (saturates at 1.0) on traces this short —
  a limitation of the specific proxy chosen, flagged in DEV-39, not silently hidden.

## Numbers

All appended to `RESULTS.md` "M7-13" section; sidecar `results/logs/20260926T091633Z-be5973ca.json`.

- Synthetic CSV-path sanity check: bal_acc=0.8408 (reproduces M7-3, confirms the fit is not
  corrupted before touching real data).
- MalbehavD-V1 transfer: n=2570 (1285/1285), bal_acc=0.5000, prec=0.0000, rec=0.0000, mcc=0.0000,
  pr_auc=0.4557 — the ensemble predicts the constant class `benign` for every real row.
- 12 KS tests (synthetic vs. MalbehavD-V1-mapped), D-statistics 0.19-0.99, all p<1e-38.
- 7 per-group permutation-importance pairs (synthetic eval vs. real): synthetic drops range
  0.0082-0.0950 across groups; every real drop is exactly 0.0000.
- 12 within-dataset Mann-Whitney tests (real malware vs. real benign, no synthetic data): 9/12
  significant at p<1e-4, `crypto_ngram_novelty` degenerate (p=1.00, both means 1.0000).

## Deviations opened or changed

- **DEV-39 (new)**: dynamic-behavioral transfer via MalbehavD-V1 — dataset search findings
  (all four brief candidates ruled out for verified reasons), the 12/22-feature mapping table and
  its MISSING-vs-PROXY discipline, the transfer result and its scale-calibration diagnosis, the
  within-dataset separation proof, and the actionable generator-recalibration suggestion.

---

## Handover *(written last)*

**State after:** M7-13 delivered. Three real-malware datasets now transfer-evaluated against the
committed synthetic-trained detector (ClaMP 3/22, EMBER 6/22, MalbehavD-V1 12/22 across 5/7
groups), all `bal_acc=0.5000`, with M7-13 adding the first precise mechanistic diagnosis (constant
saturated prediction, proven-real-but-uncalibrated signal) rather than only a coverage-fraction
data point. `data/external/malbehavd/` is committed (2.3MB CSV + README). `make test` (1693
passed, including this session's 21 new `test_honeypot_malbehavd_mapping.py` tests) and
`make lint` both green. Report recompiles clean at 25 pages, unchanged from before this session.

**Next task:** None forced by this session. If a future session wants to act on this session's
own "actionable for future work" finding, the specific next step is: re-calibrate
`honeypot.collector`'s count-feature distributions (`files_touched`, `renames`, `crypto_calls`,
and the seven Poisson-count features) to a bounded-observation-window regime instead of their
current unbounded-episode scale, then re-run M7-7/M7-10a/M7-13's transfer scripts unchanged to see
whether any of the three real datasets' transfer result moves off 0.5000 — this would be a
generator change, explicitly OUT OF SCOPE for this session, and would need its own DEV entry per
CLAUDE.md's "never silently fix" rule before any code lands.

**New blockers:** None technical. Standing note (not a blocker, but worth carrying forward):
CICMalDroid-2020 and MalwareBazaar/Triage remain unusable by any future session unless the user
personally creates the relevant account/submits the access request — this is a standing
limitation of the sandboxed environment, not something a future session should re-investigate from
scratch.

**Questions opened / closed:** None of `PROJECT_STATE.md`'s prior open questions (Q11) are
touched by this session. No new open questions raised — the generator-recalibration idea above is
recorded as a **Next task** suggestion, not a numbered open question, since it does not block
anything currently shipped.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated (DEV-39)
- [x] Committed (`16a2db4`) and pushed to `origin/main`, message explains *why*
