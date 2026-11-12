# Session 2026-11-12-02 — Phase 2, part 2: three attacks/questions on the deployed design

**Milestone:** Project Phase 2 (continued) · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/THREAT_MODEL.md` (§2, §4, §5 gap list), `src/bsfr_sh/recovery/restore.py`,
`src/bsfr_sh/mitigation/policy.py`, last session's handover · **Duration:** one sitting

**Protocol note:** as in session 01, the user directed several small independent experiments in one
sitting. Each has its own script, `RESULTS.md` block and DEV entry.

---

## Brief *(written before any work)*

**Task:** measure three significant weaknesses of the deployed design that Phase 1 and P2-A..D did
not touch: whether yearly retraining rescues the detector (P2-E), the single backup-key holder
(P2-F), and slow-burn ransomware that poisons the backups recovery depends on, plus partial
encryption as the bypass of the obvious check (P2-G).

**Exit condition:** each has a script, `measured` lines in `RESULTS.md` with sidecars, a figure and
a DEV entry; `make lint` and `make test` clean; committed on `phase2`.

**Out of scope:** the report PDF; Phase 1 defaults; the shortlist items the user did not pick
(#4 chain-stall downgrade — dropped, see Findings; #6–#10); real file encryption of any kind
(ciphertext is modelled as uniform random bytes in memory, CLAUDE.md §2).

**Prior context needed:** P2-C (DEV-46), DEV-25 (key holder), Alg. 1/5, Gap 3/Gap 4.

---

## Prompts *(verbatim, in order)*

```
3. have you generated any report or doc for this that i can refer to to see what changes were made
   and go through them to understand, in simple words, i want to go through them and keep that file
   out of git, i will share it directly to my partner then

4. thats fine for now, so now that youve filled the gaps start working on more things we can test
   for this project such that they are relvent annd make sense to check and test, maybe some
   additional kind of attack which warrants a new kind of security check or something that can
   bypass the current system, just thking on top of my head but you see what makes sense, list the
   top 10 things you find best and then i'll give my go ahead

5. ok go ahead with your recommendation and also remember that we need not do the ones that look
   identical just for the sake of doing, but also we should do the different ones which really make
   more sense in this type of system and are significant not just some minor inconvenience type
   thing which one can ignore or it doesnt even do much damage type thing. so you can start
   accordingly but give me eta first and then star

6. (mid-run) meanwhile of i close my laptop (put it to sleep) will it continue running? or if not
   will it at least resume from where i left off?
```

---

## What was done *(all AI-generated under the user's direction)*

- `PHASE2_EXPLAINED.md` (repo root, plain-language explainer for the user's partner) — **kept out
  of git on purpose** via `.git/info/exclude`.
- Shortlisted 10 candidate attacks/questions; user approved #1+#2, #3, #5. #4 (stall the chain to
  force wipe-or-pay) was **dropped**: Alg. 5 only *reads* committed blocks, which needs no
  consensus, so a stalled chain stops new backups but does not block recovery — that residual is
  P2-G's "backups stop being clean" story, so it would have duplicated it.
- **P2-E** `scripts/p2e_yearly_retraining.py`.
- **P2-F** `src/bsfr_sh/crypto/secret_sharing.py`, `src/bsfr_sh/crypto/threshold_kem.py`,
  `tests/unit/test_secret_sharing.py`, `scripts/p2f_key_holder.py` (41 new unit tests across P2-F/G).
- **P2-G** `src/bsfr_sh/recovery/screening.py`, `restore.begin_screened`,
  `phase5_recovery.run(accept=...)` (default unchanged), `tests/unit/test_screening.py`,
  `scripts/p2g_slow_burn_backups.py`; `scripts/p2_figures.py` gained P2-E and P2-G figures.

## Findings

- **P2-E.** Yearly retraining: balanced 0.47–0.59 (no `year`) on 2014–17, FPR ~0.8. 2015/2017 are
  ~98% already-seen families and still fail: the same family's address statistics drift.
- **P2-F.** Real pipeline: key holder lost → 0/4 systems recoverable by any other server despite 4
  intact replicas; its key stolen → 4/4 systems read from another replica. 2-of-4 sharing: lose
  needs 3, leak needs 2; at p=0.1 per server, loss 10% → 0.37%, leak 10% → 5.2%. Cost per 4 KiB
  chunk: seal ×4.5, open ×1.7, +399 B.
- **P2-G.** Any slow burn of ≥1 day defeats Alg. 5 (67–81% of restored files still encrypted; D=0
  smash-and-grab: 0%). Restore-time screening: 0% encrypted, D days rolled back. Backup-time
  screening: alarm on the attack's first day, 4–16 of 48 files encrypted. Naive entropy check
  restores nothing (flags all JPEG/office). Blind spot: header-preserving stripes on office docs.

**Dead ends / surprises (recorded so they are not retried):**
- First P2-G run counted a file as "damaged" whenever the restored copy differed from its latest
  clean version, so ordinary lost edits looked like ransomware damage (14% "damaged" at D=0).
  Fixed to "restored copy *is* the ciphertext". Files shorter than the 4 KiB skipped header are
  untouched by striping and are no longer counted as encrypted.
- First DICOM window settings (1024 B, threshold 7.4) caught **no** 512-byte stripes: a half-random
  1024 window is only ~7.1–7.3 bits. Recalibrated to 512 B / 7.0 (clean max 5.89, striped min 7.61).
- At whole-backup granularity the FORMAT/HISTORY difference barely shows in the timeline, because
  striped *text* files give the attack away on day one. The bypass only works if the attacker
  *chooses* targets — hence the office-only variant.

## Numbers

All in `RESULTS.md` under "Phase 2 / P2-E..G". Sidecars: P2-E `20261112T150327Z-9ba241b2`, P2-F
`20261112T151009Z-dc551838`, P2-G `20261112T152026Z-27a8cbee`.

## Deviations opened or changed

- DEV-48 (P2-F), DEV-49 (P2-G), DEV-50 (P2-E). `docs/ARCHITECTURE.md` updated for the new modules.

---

## Handover

**State after:** P2-A..G measured, figured and documented; Phase 1 defaults untouched (threshold
wrapping and screening are opt-in / prototype). `make lint` clean, `make test` 1884 passed,
recovery integration tests pass.

**Next task:** Build the Phase 2 presentation (Phase 1 recap + P2-A..G, one slide each, figures from
`results/figures/p2*.png`) in the style of `BSFR-SH_Presentation.pptx`.

**New blockers:** none.

**Questions opened / closed:** opened — screening false-alarm rate on *real* hospital files (synthetic
corpus gives 0); wiring DEV-48 into Alg. 1/5. Closed — shortlist #4 (dropped, reason above).

## Checklist

- [x] `PROJECT_STATE.md` rewritten, under 200 lines (125)
- [x] `RESULTS.md` appended
- [x] `docs/ROADMAP.md` ticked
- [x] `docs/DEVIATIONS.md` DEV-48..50, `docs/ARCHITECTURE.md`
- [x] `make lint` clean, `make test` 1884 passed
- [x] committed on branch `phase2`
