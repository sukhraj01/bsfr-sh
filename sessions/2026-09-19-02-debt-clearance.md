# Session 2026-09-19-02 — debt clearance (D2/D3/D4 + report cosmetics)

**Milestone:** debt clearance (no M-number; not on `docs/ROADMAP.md`) · **Files read at start:**
`CLAUDE.md`, `PROJECT_STATE.md`, `RESULTS.md` (tail), `docs/DEVIATIONS.md` (D2/D3/D4 = DEV-20
item 5, DEV-30, and the D2 carried-debt row itself), `docs/report/report.tex` (for the cosmetic
fixes) · **Duration:** one long session, no interruption

---

## Brief *(written before any work)*

**Task:** Close three items of carried debt (D2 — `scripts/` outside lint coverage; D3 — the bus
never serialises, magnitude only estimated; D4 — `ClientRequest` unauthenticated) and three report
cosmetic fixes (references [4]-[7], Table precision cell, one overclaiming sentence).

**Exit condition:** `make test` and `make lint` green, with lint now covering `scripts/` or the
logic moved out; D2/D3/D4 closed in `PROJECT_STATE.md`; report recompiles clean with all three
cosmetic fixes; one new `RESULTS.md` line for the D3 bench run.

**Out of scope:** adversarial evasion, new features, slides.

**Prior context needed:** `docs/DEVIATIONS.md` DEV-20 item 5 (D4's origin), DEV-30 (D3's earlier
estimate), and the exact carried-debt wording in `PROJECT_STATE.md`. Not the rest of `docs/`.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: RESULTS.md tail,
   docs/DEVIATIONS.md for D2/D3/D4. docs/report/report.tex for the cosmetic
   fixes.

   Create the session file from the template and fill the brief first.

   TASK — Debt clearance. Six items accumulated across M1–M6b that were deferred
   with reasons at the time and now have no reason to remain open.

   1. D2 — lint coverage of scripts/.
      scripts/bench_ecdsa_backends.py has real logic but make lint runs ruff and
      mypy only over src/ and tests/. Either move the logic into src/bsfr_sh/
      where it belongs and make the script a thin wrapper (CLAUDE.md §3 says
      scripts/ has no logic), or extend lint to cover scripts/. The first is
      cleaner. Do whichever is faster and record which.

   2. D4 — unauthenticated client-to-replica requests.
      Cloud servers submit transactions and blocks to the consensus cluster
      without authenticating. A non-member can waste consensus rounds by
      submitting junk. Add sender authentication at the cluster boundary —
      reject submissions from identities not in the configured membership,
      the same check that already exists for inter-replica messages. Test that
      a non-member submission is rejected. This closes the gap between §V-3's
      Sybil-resistance claim and the actual implementation.

   3. D3 — bus serialization cost.
      The in-process bus passes Python object references. Real consensus
      serializes every message. M6a quantified the omission at 0.2-0.3%.
      Add a configurable serialization mode to the bus: when enabled, every
      message is serialized and deserialized through util/serialization.py
      before delivery. Default OFF for tests (speed), ON for bench runs
      (honesty). Re-run one bench case (case-3, both chains) with it ON and
      update the RESULTS.md lines and the relevant sidecar. If the delta is
      within M6a's stated 0.2-0.3%, that validates the estimate and D3 is
      closed. If it's larger, update the report's stated magnitude.

   4. Report: references [4]–[7].
      Fill in full citations from the original paper's reference list:
      [4] Almashhadani et al., IEEE Access, vol. 7, 2019.
      [5] Hwang et al., Wireless Personal Commun., vol. 112, 2020.
      [6] Sharmeen et al., IEEE Access, vol. 8, 2020.
      [7] Bae et al., Concurrency Comput. Pract. Exp., vol. 32, 2020.

   5. Report: Table IV precision.
      Constant-negative baseline precision is undefined (0/0 — no positive
      predictions), not zero and not a dash. Either print "undef." with a
      footnote explaining why, or leave the cell blank with the footnote.
      Do not print 0.0000.

   6. Report: §VII wording.
      "an ablation over every leakage source we could identify" — change to
      "both candidate leakage sources we identified." You tested two. "Every"
      is technically defensible but reads as exhaustive to an examiner.

   EXIT CONDITION
   make test and make lint green, with lint now covering scripts/ or the logic
   moved out. D2, D3, D4 closed in PROJECT_STATE.md. Report recompiles clean
   with all three cosmetic fixes. One new RESULTS.md line for the D3 bench run.

   OUT OF SCOPE
   No adversarial evasion, no new features, no slides.

   END OF SESSION
   Session file. Rewrite PROJECT_STATE.md. Commit and push.
```

---

## What was done

*All AI-generated, reviewed against `make test`/`make lint`/manual round-trip checks as it went.*

**D2 (lint coverage).** Moved `scripts/bench_ecdsa_backends.py`'s measurement logic
(`Measurement`, `bench_cryptography`, `bench_pure_python`, `_time_operation`, the backend
comparison) into new `src/bsfr_sh/bench/ecdsa_backends.py`. The script is now argparse + seed +
call + sidecar-write only. Chosen over extending `make lint` to `scripts/` because that would have
meant bringing five *other*, never-type-checked scripts (`fetch_bitcoinheist.py`,
`make_honeypot_corpus.py`, `q10_leakage_ablation.py`, `run_bench.py`, `run_phase3_detection.py`)
up to `mypy --strict` too — moving one file's logic was the smaller, contained change. Added
`ecdsa.*` to `pyproject.toml`'s mypy overrides (no `py.typed` marker, same shape as the existing
sklearn/matplotlib overrides) and to `tests/unit/test_module_boundaries.py`'s `HASHLIB_ALLOWED`
(the pure-Python `ecdsa` library's own `hashfunc=` parameter needs a hashlib-shaped constructor,
which `crypto.hashing.h()`'s one-shot `bytes -> bytes` cannot substitute for — a different case
from the D1 precedent that comment warns against reopening). New test file
`tests/unit/test_bench_ecdsa_backends.py` (3 tests, no timing assertions, matching
`test_bench_harness.py`'s stated convention).

**D4 (`ClientRequest` authentication).** `consensus/protocol.py`: `ClientRequest` gained
`chain`/`submitter_id`/`signature` fields, a `signed_body()`/`verify()`/`.create()` following the
existing vote-message pattern, and a new `check_request_identity()` mirroring
`check_vote_identity()` but against a separate `submitters: Mapping[str, PublicKey]` rather than
the replica `Membership` — confirmed via the test fixtures (`tests/unit/m3a_harness.py`'s
`make_server` comment: "Use 10+ so the name never suggests one of the harness's replicas") that a
submitting `CS_l` is architecturally distinct from a pBFT replica in this codebase (DEV-22 leaves
whether they coincide unspecified), so reusing `Membership` itself would have been wrong.
`consensus/pbft.py`: `Cluster`/`Replica` both take `submitters`; `Cluster.submit()` now requires
`submitter_id`/`key` and signs; `Replica._on_request()` calls `check_request_identity` and rejects
before a request ever occupies a pending slot. Threaded `submitter_id`/`key` through
`framework/_block_pipeline.py`'s `run()`/`commit()`, `phase1_backup.py`/`phase2_collection.py`
(using the already-available `collector.identity`/`collector.keypair.private`), `bench/harness.py`
(`_cluster()`, `run_once()`, `verify_modelled_network_formula()`), and
`scripts/run_phase3_detection.py`. Updated every test call site across `tests/unit/` and
`tests/integration/` (about a dozen files) — `pbft_harness.py` gained a default `SUBMITTER_ID`/
`SUBMITTER` fixture so most `make_cluster()` callers needed no change beyond `submit_block()`
itself; call sites with a real `CloudServer` collector (phase1/phase2 tests) register that
collector's identity explicitly. New tests in `tests/unit/test_pbft.py` (non-member rejected,
forged signature rejected, wrong-chain rejected) and `tests/unit/test_protocol.py`
(`check_request_identity` unit tests).

**D3 (bus serialization, measured).** `consensus/network.py`'s `P2PCSNetwork` gained
`serialize: Callable[[object], object] | None` — discovered mid-implementation that
`consensus/network.py` must import *nothing* internal
(`tests/unit/test_module_boundaries.py::test_consensus_depends_only_on_crypto_blockchain_and_util`
asserts this explicitly for that one file), so the first attempt (importing
`consensus.protocol.encode_message` directly into `network.py`) failed that test and had to be
redesigned as an injected opaque hook instead. `consensus/pbft.py` supplies the hook
(`_roundtrip_message`, composing `encode_message`/`decode_message`) when
`PBFTPolicy.serialize_messages` is set; `configs/chain.yaml` declares the default (`false`),
`configs/bench.yaml` declares the bench override (`true`), `bench/harness.py`'s
`BenchPolicy.from_config` applies it. `consensus/protocol.py` gained `encode_message`/
`decode_message` and, for each of the six message shapes, a hand-written `_wire_*`/`_unwire_*`
pair using `util.serialization.encode`/`decode` over plain mappings (not a declared `Struct`
domain — nothing here is hashed or signed) — mypy --strict rejected an earlier, more "clever"
version built on `**kwargs` splats and a heterogeneous dispatch dict, so it was rewritten with
explicit named-argument construction and `typing.cast` at every field extraction instead. Ran the
actual D3 validation (not scripted permanently — an ad hoc script in the scratchpad, deleted after
use, reusing only already-lint-covered `bsfr_sh.bench.harness` functions): case-3, both chains,
n=25, identical seeds, serialize on vs. off. **Result: BC_DTBU +67.6%, BC_SigRW +48.8%** — far
larger than DEV-30's ~0.2-0.3% estimate, because that estimate priced one `encode_block()` per
committed block while the real bus now pays a full encode+decode on every one of 28 per-block
message hops (`n=4`: 4 requests + 3 pre-prepares + 3×3 prepares + 4×3 commits). Sidecar written to
`results/logs/20260919T013422Z-1cf934ad.json`; `RESULTS.md` and `docs/DEVIATIONS.md` DEV-30
amended (see Deviations below). Checked `docs/report/report.tex` for the earlier 0.2-0.3% figure
per the prompt's conditional instruction — it was never stated there, so there was no report
number to correct.

**Report cosmetics.** Refs [4]-[7] (`\bibitem{almashhadani,hwang,sharmeen,bae}`) got the given
journal/volume/year appended, keeping the existing descriptive phrase (not a fabricated title —
the prompt gave venue/volume/year, not titles, and inventing one would misrepresent it as
verified). The precision-cell fix targeted **Table V** (`\label{tab:honest}`, "Honest-mode
evaluation"), not Table IV as the prompt said — confirmed by compiling and reading
`report.aux`'s `\newlabel{tab:q10}{{IV}{6}}` vs `\newlabel{tab:honest}{{V}{7}}`; Table IV (Q10
leakage ablation) has no precision column or constant-negative row at all, while Table V's
description matches the prompt's exactly. Changed `--` to `undef.$^{\dagger}$` with a two-line
footnote. The "every leakage source" wording was fixed in the Conclusion as asked, and also in the
abstract, which had the identical overclaim as "exhaustive leakage ablation" — not explicitly
named in the prompt, so flagged here and in `PROJECT_STATE.md` rather than silently expanding
scope.

## Findings

- **`consensus/network.py`'s "imports nothing internal" rule is real and enforced by a test, not
  just a docstring claim.** The first D3 implementation attempt violated it directly (`from
  bsfr_sh.consensus.protocol import decode_message, encode_message` at module level in
  `network.py`) and `make test` caught it immediately with a clear assertion message. Redesigning
  around an injected `Callable[[object], object]` hook was the fix, and in hindsight is the more
  reusable shape anyway (the bus genuinely doesn't need to know what a message is to charge its
  cost).
- **A submitting `CS_l` is not a pBFT replica in this codebase's model**, confirmed by
  `m3a_harness.make_server`'s own comment ("Use 10+ so the name never suggests one of the
  harness's replicas"). This meant D4's fix needed a second, separate `submitters` mapping on
  `Cluster`/`Replica` rather than reusing the existing `Membership` — reusing `Membership` would
  have silently required every test's collector identity to also be a consensus replica, which
  contradicts the existing test fixtures throughout `tests/unit/` and `tests/integration/`.
- **Table/figure numbers in a prompt should be verified against a real compile, not trusted.** The
  prompt named "Table IV" for the constant-negative-precision fix; the actual table (by content
  match and by compiling and reading `report.aux`) is Table V. Cheap to check (`grep newlabel
  report.aux`), expensive to get wrong (editing the wrong table silently leaves the actual bug in
  place).
- **A LaTeX overfull-hbox warning can be a directory/font-cache artifact, not a content
  regression.** One new-looking `83.3953pt` overfull warning appeared after the report edits;
  bisecting by applying each edit's exact diff hunk to a clean baseline in `/tmp` reproduced
  *none* of them individually or combined, while the *unmodified* `git show HEAD:...` content,
  compiled in the real `docs/report/` directory, reproduced the identical warning. Conclusion: it
  is pre-existing and environment-dependent (likely font substitution/caching keyed to that
  directory), not something these edits caused. Recorded so a future session doesn't re-diagnose
  the same false lead.
- **D3's earlier estimate undercounted by roughly the ratio of hops it excluded** (1 encode/block
  vs. 28 hops/block, each now paying encode+decode) — not a subtle measurement error, a
  structurally different accounting. Worth remembering next time an "estimate, not measured"
  number in this codebase needs validating: check what fraction of the real operation the estimate
  actually covers before trusting its order of magnitude.

## Numbers

```
2026-09-19 | bench/d3-measured | BC_DTBU case_3 15blk x 100tx, n=25 | seconds_off=0.48785 seconds_on=0.81785 delta=+67.64% | measured | 20260919T013422Z-1cf934ad | D3 closed; supersedes DEV-30's encode-only ~0.33% estimate
2026-09-19 | bench/d3-measured | BC_SigRW case_3 15blk x 100tx, n=25 | seconds_off=0.68031 seconds_on=1.01215 delta=+48.78% | measured | 20260919T013422Z-1cf934ad | D3 closed; supersedes DEV-30's encode-only ~0.16% estimate
```

Also appended to `RESULTS.md` (with the fuller D3-closed narrative paragraph above the two lines).

## Deviations opened or changed

- **DEV-30 amended (2026-09-19).** Added the measured case-3 result (+67.6%/+48.8%, closing D3)
  above the original M6a encode-only estimate (~0.33%/~0.16%), explaining the ~28x hop-count gap
  between what the estimate priced and what the real bus now pays. Original estimate entry left
  intact for provenance; the amendment explains why it undercounted rather than replacing it.
- No new deviation opened for D4 — it closes DEV-20 item 5 exactly as that entry already
  described the gap; no amendment needed there since DEV-20 item 5's text already anticipated
  "closing the gap means signing requests with the submitting server's key," which is exactly
  what happened.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** D2, D3, D4 closed (removed from `PROJECT_STATE.md`'s carried-debt table; only D5
remains there). Report has its four cosmetic fixes. `consensus.pbft.Cluster` now requires
`submitters` at construction and `submit()`/`_block_pipeline.run()`/`.commit()` require
`submitter_id`/`key` — this is a breaking signature change for any future code that constructs a
`Cluster` or calls these functions directly; every existing call site in `src/`, `tests/`, and
`scripts/` was updated in this session, so `make test`/`make lint` being green means the change is
complete, not partially done.

**Next task:** Pick one of the two remaining M7 stretch items (adversarial evasion, Q4; or hybrid
blockchain) if continuing, or stop — the core deliverable and both debt-clearance exit conditions
are met. No specific next task is implied by this session's work.

**New blockers:** None.

**Questions opened / closed:** No `PROJECT_STATE.md` Q-numbers touched. Q8 (pBFT state transfer,
tied to the now-dropped "async pBFT" framing of the D3 item) was removed from open questions since
that stretch item no longer has a debt-closure motivation now that D3 is closed independently of
it.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines (142 lines)
- [x] `RESULTS.md` appended, one line per run (plus the D3-closed narrative paragraph)
- [x] `docs/ROADMAP.md` boxes ticked — none applicable; D2/D3/D4 are debt items, not roadmap milestones
- [x] `docs/DEVIATIONS.md` updated if the paper was departed from (DEV-30 amended)
- [x] Committed, message explains *why*
