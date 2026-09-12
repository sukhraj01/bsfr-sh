# Session 2026-09-12-02 — M3b, Phase 2 (honeypot, signatures, features)

**Milestone:** M3b · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`, `docs/ALGORITHMS.md`,
`docs/PAPER_NOTES.md` §II-C and §IV-B only, `docs/ARCHITECTURE.md` §honeypot, `docs/NOTATION.md`,
`sessions/_TEMPLATE.md`; then the code this builds on (`framework/entities.py`,
`framework/_block_pipeline.py`, `framework/phase1_backup.py`, `recovery/locator.py`,
`blockchain/transaction.py`, `util/seeding.py`), `configs/ml.yaml` and `configs/bench.yaml` for the
index-gating pre-task, and DEV-03 in `docs/DEVIATIONS.md`. `docs/EXPERIMENTS.md` was **not** read.
· **Duration:** one working session

---

## Brief *(written before any work)*

**Task:** Build Phase 2 — a honeypot that synthesizes labelled behavioural records, the
preprocessing, signature and feature layers over them, and the Alg. 2 wiring onto `BC_SigRW` — such
that the corpus is hard enough for M4's result to mean something.

**Exit condition:** `make test` and `make lint` exit 0; `BC_SigRW` builds 15 blocks × 100 real
signature records through consensus; a corpus exists under `data/honeypot/` with its seeds recorded
in a manifest; the stated expected difficulty is not ceiling, and a simple baseline on a *separate
draw* lands near it; no single feature separates the classes on its own.

**Out of scope:** no ML models, no training, no detection, no metrics — Phase 3 is M4. The only
evaluation here is the leakage and difficulty check, which exists to validate the generator rather
than to measure a detector. No real malware: samples are statistical records, never programs.

**Prior context needed:** DEV-03 and `docs/ARCHITECTURE.md` §honeypot (the 7-group schema), §II-C's
kill chain, M3a's `_block_pipeline` (Phase 2 is a payload builder over it), `crypto.channel` (how
`SK_{CS_l,HP_RW}` carries data), and `SignatureRecordPayload` as the on-chain carrier.

### Pre-task, done first: the index must not sit in the benchmarked append path

`phase1_backup.run(..., index=...)` currently calls `BackupIndex.sync()` after the pipeline
returns, so anything timing `run()` in M6 times our index maintenance too. The paper's design has
no index (DEV-05), so Fig. 6(a) would compare our indexed append against their unindexed one.

**Decision: split it out, rather than gate it with a flag.** `run()` loses the `index` parameter,
and `phase1_backup.maintain_index(index, cluster)` becomes an explicit step the caller invokes.
A flag would leave the cost one default away from re-entering the span; a separate function makes
it structurally impossible and gives M6 something to time as its own column. `configs/bench.yaml`
records that the index is measured separately and never folded into Target 3.

### Decisions taken before writing the generator

1. **Intended Bayes-optimal accuracy: ≈ 0.85 (design target 0.83–0.88), not ceiling.** The
   generator draws a declared fraction (0.25) of both classes from *confusable profile pairs*
   whose distributions are near-identical — benign disk-encryption against fast ransomware, benign
   backup agents against low-and-slow ransomware. Near-identical pairs at 25% of the mass put
   irreducible error at about 0.125, and partial overlap elsewhere adds a little more. Verified
   afterwards by a baseline trained on one draw and evaluated on another: it must land in
   [0.70, 0.90] and must **not** reach 0.95.
2. **Kill-chain leakage: the group is truncated, not included whole, and not dropped entirely.**
   §II-C's stages run infection → identification → encryption → notification → cleanup → payment →
   decryption. Stages 5–7 have no benign analogue, so `stage_reached` over the full chain *is* the
   label wearing a feature's clothes. `FT_RW` therefore carries only the observable prefix that
   both classes genuinely produce — arrival, enumeration, bulk transform, cleanup — capped at 4,
   plus dwell-time statistics over those stages. The full stage walk stays in the raw and clean
   records for provenance and is never a feature. Recorded as a DEV entry.
3. **Benign samples come from the decoy host, and some of them look malicious.** Profiles include
   a backup agent (many files fast), a disk-encryption tool (key generation, high-entropy writes),
   an installer (child processes, persistence writes) and a cleanup utility (shadow-copy pruning),
   so no feature is zero-for-all-benign.
4. **"Remove the abnormalities" (Alg. 2 line 3) gets a concrete definition**, because read
   literally as anomaly removal it would delete the positive class. It becomes five structural
   rules — invalid structure, impossible values, duplicates, unobserved-marking, rate
   normalisation — with a count kept per rule. DEV entry.
5. **Unobserved features are marked, never imputed.** A real honeypot misses stages. The canonical
   encoder has no NaN, so the record carries a `missing_mask` bitmask alongside the vector and M4
   decides what to do with it.
6. **Two independent draws, never one shuffled.** The corpus writer emits a train draw and an eval
   draw from *different* seeds, both recorded in the manifest, because samples from one call share
   latent parameters and would leak across a shuffled split.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/ALGORITHMS.md,
docs/PAPER_NOTES.md §II-C and §IV-B only, docs/ARCHITECTURE.md §honeypot,
docs/NOTATION.md. Not docs/EXPERIMENTS.md.

Create the session file from the template and fill the brief first.

Before starting: gate BackupIndex construction off during bench runs, or
split it into its own measured column. It currently sits inside the append
path that Fig. 6(a) times, and the paper's design has no index — so as it
stands M6 would compare our indexed append against their unindexed one.
Small change, but do it now while the reason is fresh.

TASK — M3b. Phase 2: honeypot, signatures, features. Algorithm 2.

SAFETY, non-negotiable, CLAUDE.md §2: this module synthesizes feature
vectors and digests describing ransomware behaviour. It does not generate,
download, store or execute executable code of any kind. Samples are
statistical records, never programs. If any part of the design starts to
require real malware behaviour to be meaningful, stop and say so rather
than approximating it.

1. honeypot/collector.py — Alg. 2 lines 1-2.
   Honeypot.deploy(), harvest(). A sample is a record of an emulated
   infection walking the seven kill-chain stages in §II-C. Data structure
   only.

2. honeypot/preprocess.py — Alg. 2 lines 3-4. DT_RW -> DT_RWC.
   The paper says "remove the abnormalities" and nothing else. Decide what
   that means concretely, implement it, and document the decision — it is
   another undefined step, not a detail.

3. honeypot/signatures.py — Alg. 2 line 5.
   Per DEV-03, two distinct things: content_digest (SHA-256 over the
   canonical behavioural trace, the malware-signature sense) and attestation
   (ECDSA by CS_l over digest || timestamp || collector_id, the
   digital-signature sense). The paper conflates these under one symbol.

4. honeypot/features.py — Alg. 2 line 6. This is the hard part.
   The 7-group schema in docs/ARCHITECTURE.md §honeypot: filesystem,
   entropy, crypto API, process, network, persistence, kill-chain.

   THE TRAP, and the main reason this is its own session:

   You are writing both the generator and, in M4, the classifier that
   consumes it. If benign and malicious samples are drawn from visibly
   different distributions, M4 reports ~100% and the number means nothing —
   it measures the generator's separability, not the detector's skill. That
   result would look like success and be worthless.

   So the generator must produce genuine class overlap:
     - Benign profiles that legitimately look ransomware-like. Backup
       software touches many files fast. Disk encryption tools generate
       keys and write high-entropy blocks. Installers spawn children and
       write persistence entries. Include these as benign.
     - Per-feature distributions that overlap, not just differ in mean.
     - Noise and missing observations, since a real honeypot does not see
       every stage of every sample.

   LABEL LEAKAGE: the kill-chain group is dangerous. If stage_reached is
   deterministic of the label — only ransomware ever reaches stage 5 — it
   is the label wearing a feature's clothes, and every model will find it.
   Either let benign samples reach comparable stages, or exclude the
   group and say why.

   State an intended Bayes-optimal difficulty in the brief before writing
   the generator: what accuracy *should* a perfect classifier get on this
   data? If the answer is 100%, redesign. Verify afterwards that a simple
   baseline lands near that figure rather than at ceiling.

   TRAIN/TEST HYGIENE: corpus generation takes an explicit seed, and the
   evaluation split in M4 must come from a different draw, not a shuffle of
   one draw. Two samples from the same generator call can share latent
   parameters and leak across the split.

5. framework/phase2_collection.py — Alg. 2 lines 7-20.
   Reuse _block_pipeline from M3a with the signature-record payload builder.
   Nothing here should duplicate M3a's pipeline; if it does, the M3a
   factoring was wrong and this is where to find out.

6. Define the on-chain record schema that M4's HoneypotBackend will read.
   Write it down in docs/ARCHITECTURE.md. M4 is the consumer and it is a
   separate session, so an undocumented schema is a guaranteed rework.

TESTS
Generator determinism under a fixed seed. Class overlap is real — assert
per-feature distributions overlap rather than separate. No single feature
achieves near-perfect separation on its own (this is the leakage test,
and it should catch the kill-chain problem if it exists). Signatures
verify, tampered traces produce different digests, attestation rejects a
wrong signer. Round trip: harvest -> preprocess -> sign -> encrypt -> chain
-> decrypt -> features recovered intact.

Include the DEV-23 mutants I mentioned separately if you have room; if not,
open it as debt rather than dropping it.

EXIT CONDITION
make test and make lint green. BC_SigRW builds 15 blocks x 100 transactions
of real signature records through consensus. A corpus exists on disk with a
recorded seed, and a stated expected difficulty that is not ceiling.

OUT OF SCOPE
No ML models, no training, no detection, no metrics. Phase 3 is M4. Build
the data and the schema; do not evaluate them beyond the leakage check.

END OF SESSION
Session file with attribution and dead ends. DEV entries for the
preprocessing definition, the feature schema as built (amending DEV-03 if it
diverges), and the kill-chain leakage decision. Record the expected
difficulty figure in PROJECT_STATE.md — M4 will need it to know whether its
result is real. Rewrite PROJECT_STATE.md, under 200 lines. Tick M3b. Commit
explaining why.
```

---

## What was done

**Attribution.** All new code, tests and doc text are **AI-generated (Claude, Opus 5),
human-directed**. From the prompt: the M3b scope, the safety rule, the four module names, the
overlap requirement and its three mechanisms, the kill-chain leakage warning, the instruction to
state a Bayes difficulty *before* writing the generator, train/test hygiene, the pipeline-reuse
constraint, and the index pre-task. Claude's: the confusable-pair mechanism that puts a computable
floor under the Bayes error, truncating the kill chain rather than dropping it, DEV-26's five
rules, the `Honeypot`/`HoneypotNode` split, the corpus format and manifest, and every parameter in
the profile tables. No file was human-edited this session.

**Pre-task (index gating).** `phase1_backup.run()` lost its `index` parameter;
`maintain_index(index, cluster)` is now an explicit step. `configs/bench.yaml` gains
`timing.index_maintenance: separate_column`; DEV-05 carries the amendment; the two call sites in
`test_phase1_backup.py` and `tests/integration/test_backup_recovery.py` were updated.

**New modules**

| Module | What it does |
|---|---|
| `honeypot/collector.py` | `Honeypot` (deploy/harvest), `RawSample`, ten behaviour profiles, three confusable pairs, blind sensor groups, injected sensor defects, `pack_samples`/`unpack_samples` |
| `honeypot/preprocess.py` | `CleanSample`, `clean()` under DEV-26's five rules, `CleaningReport` counting each rule |
| `honeypot/signatures.py` | `content_digest` (identification) + `SampleSignature.verify` (authenticity) — DEV-03's two senses |
| `honeypot/features.py` | `ft_rw.v1`: 22 features in 7 groups, truncated kill chain, `missing_mask` |
| `honeypot/corpus.py` | `build_draw`, CSV read/write, `CorpusManifest`, `EXPECTED_BAYES_ACCURACY` |
| `framework/phase2_collection.py` | Alg. 2 lines 1-20 on M3a's pipeline, unchanged |
| `scripts/make_honeypot_corpus.py` | thin CLI; writes two draws and the manifest |

**Changed:** `framework/entities.py` (`HoneypotNode`, `CloudServer.receive_samples`,
`PURPOSE_COLLECT`), `blockchain/transaction.py` (`SignatureRecordPayload` gains `schema`,
`missing_mask`, `label`, all defaulted), `crypto/hashing.py` (two sample domains),
`configs/bench.yaml`, and the docs (ARCHITECTURE §honeypot rewritten with the record schema,
ALGORITHMS Alg. 2 rows, NOTATION `HP_RW`, DEVIATIONS DEV-26/DEV-27, ROADMAP M3b ticked).

**Corpus.** `data/honeypot/corpus_train.csv` (1467 records, seed 20260912),
`corpus_eval.csv` (731, seed 20260913), `manifest.json`. 48.9% malicious; 52 of 2250 requested
samples were dropped by cleaning.

**Tests: 831 → 983 unit (+152), 10 integration, 993 under `make test-all`.** New:
`test_honeypot_collector.py`, `test_honeypot_preprocess.py`, `test_honeypot_signatures.py`,
`test_honeypot_features.py`, `test_honeypot_corpus.py`, `test_honeypot_is_inert.py`,
`test_phase2_collection.py`, `tests/integration/test_sigrw_scale.py`, harness `m3b_harness.py`,
plus a `honeypot/` rule in `test_module_boundaries.py`.

## Findings

**The preprocessing step, read literally, deletes the positive class.** Alg. 2 line 3 says
"remove the abnormalities" and stops. The natural reading — remove statistical outliers — is
catastrophic in this pipeline: ransomware behaviour *is* the outlier among ordinary software, so an
anomaly-removal step before Phase 3 strips out exactly what Phase 3 exists to find, and it does so
silently. The result would be a clean-looking dataset, a confident-looking model, and nothing
underneath. DEV-26 therefore reads "abnormalities" as sensor defects only, and
`test_cleaning_does_not_remove_the_positive_class` pins the class balance across the step.

**The kill-chain group is a label in disguise unless truncated.** §II-C ends notification →
payment → decryption; no benign program reaches those. Keeping `stage_reached` whole would give
every model a perfect feature and produce a meaningless 100%. Truncating to the observable prefix
(arrival, enumeration, bulk transform, cleanup) keeps real signal — `observed_stages` measures 0.796
separability, well inside the 0.90 bound — while both classes reach the top value.

**The generator is bounded by construction, and the numbers confirm it.** 25% of both classes come
from confusable pairs that share one parameter set, so those samples carry *no* label information:
a floor of 0.125 on the Bayes error before any other overlap. Intended Bayes accuracy ≈ 0.85;
measured baseline 0.830 on a separate draw; most separable single feature 0.816; every feature's
class ranges overlap; missingness differs between classes by at most 0.017.

**M3a's factoring held.** Phase 2 supplied a payload builder and a cluster and changed nothing in
`_block_pipeline` — the thing the M3a session claimed and this session tested
(`test_phase_two_adds_no_pipeline_of_its_own`).

**A note in `PROJECT_STATE.md` was wrong, and following it would have inverted the dependency
graph.** M3a's handover said "`HP_RW` should be a `framework.entities.Participant` subclass". But
`honeypot/` sits *below* `framework/` and may not import it. Correction: `honeypot.collector.Honeypot`
synthesizes and holds no keys; `framework.entities.HoneypotNode` owns the identity and the session
and ships harvests. A new boundary test pins it.

**Mutation check — 3/3 killed**, covering the M3a integrity rules the previous session left
unmutated: removing DEV-23's attestation check, reassembling by arrival order instead of
`chunk_index`, and skipping `BackupIndex`'s anchor check each break at least one test. The mutants
were applied and reverted by a scratchpad script; the tree was verified clean afterwards.

**Dead ends and corrections**

- *The first parameter set leaked through one feature.* `extension_change_rate` alone reached 0.885
  separability — a near-giveaway that would have let a single decision stump score ~0.88 in M4. Four
  profile parameters were widened (benign backup and cleanup tools rewrite extensions too), bringing
  it to 0.816. This is precisely what the leakage test exists to catch, and it caught it before the
  corpus was committed.
- *My probe script took five minutes; the library takes 40 milliseconds.* The slowness was in the
  throwaway analysis script, not in generation (500 samples synthesize in 0.04 s). Worth recording
  because the obvious conclusion — "the generator is too slow for unit tests" — was wrong, and
  acting on it would have meant optimising code that was already fast.
- *Two `int()` casts and three `type: ignore` comments were redundant*, and ruff/mypy flagged them
  one at a time across two runs. Minor, but the lesson is that fixing the first reported instance
  and re-running beats assuming there is only one.
- *Rejected: dropping the kill-chain group entirely.* It was the safe option and it throws away a
  genuinely observable signal; truncation keeps the signal and removes the answer.
- *Rejected: imputing missing counters at collection time.* It would hide the honeypot's blind
  spots inside the data, where M4 could not see them. They are marked instead.
- *Rejected: putting `profile` on-chain.* It is generator provenance; it stays in the CSV for
  analysis and is named in `METADATA_COLUMNS` so it cannot be mistaken for an input.

## Numbers

No benchmark this session, so `RESULTS.md` is untouched — these are properties of the corpus, not
timings, and none has a run id or sidecar:

| Quantity | Value |
|---|---|
| Intended Bayes-optimal accuracy (design) | **0.85** |
| Baseline balanced accuracy, train draw → eval draw | **0.830** (committed corpus), 0.826 (test draws) |
| Most separable single feature | `extension_change_rate`, 0.816 (was 0.885 before tuning) |
| Next two | `rename_rate_per_s` 0.803, `observed_stages` 0.796 |
| Max class difference in missingness rate | 0.017 |
| Features whose class ranges overlap | 22 of 22 |
| Corpus | 1467 train + 731 eval records, 48.9% malicious, 52 dropped by cleaning |
| Suite | 983 unit + 10 integration = 993, 7.5 s |
| Mutants killed | 3 of 3 |

## Deviations opened or changed

- **DEV-26** opened (FILL): what "remove the abnormalities" means — five rules, and why the
  literal reading would delete the positive class.
- **DEV-27** opened (FILL): `FT_RW` as built — 22 features, the truncated kill chain, the corpus's
  stated difficulty, `label`/`missing_mask` as metadata, two carriers and two draws. Extends DEV-03
  rather than contradicting it.
- **DEV-05** amended: index maintenance is not part of Alg. 1's timed path.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** M3 is complete. Phases 1, 2 and 5 run end to end on their own chains. Phase 2
produces real `Sig_RW` and `FT_RW` records, commits them to `BC_SigRW` through consensus at
case-3 scale, and writes a labelled corpus to `data/honeypot/` with its seeds and difficulty in a
manifest. `make test-all` runs 993 tests; `make lint` is clean.

**Next task:** Build M4, Phase 3 detection. `detection/dataset.py` with both backends
(`BitcoinHeistBackend`, and `HoneypotBackend` reading the corpus or the chain),
`detection/models.py` (the four estimators, hyperparameters from `configs/ml.yaml`),
`detection/profiles.py` (`NProf`/`AProf`), `detection/metrics.py` (both metric sets plus the
constant-classifier baselines), and `framework/phase3_detection.py` (Alg. 3). Exit: Table II's
BSFR-SH row reproduced in `paper_mode` with `honest_mode` reported beside it (DEV-06), and the
honeypot backend's accuracy compared against the corpus's stated 0.85 — **a number near 1.0 is a
leak to be found, not a result**. Split the two backends into separate sessions if they do not fit.

**New blockers:** none.

**Questions opened / closed:** **Q9 opened** — is the committed corpus the fixed dataset, or does
each experiment regenerate one? The manifest makes either reproducible; decide at M4 start. Q3
(BitcoinHeist subsampling) becomes live at M4.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended — **not applicable**, no benchmark was run, by instruction
- [x] `docs/ROADMAP.md` boxes ticked — M3b `[x]`, current milestone → M4
- [x] `docs/DEVIATIONS.md` updated — DEV-26 and DEV-27 opened, DEV-05 amended
- [x] Committed, message explains *why*
