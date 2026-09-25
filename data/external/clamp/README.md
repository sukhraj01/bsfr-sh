# ClaMP — external real-malware dataset (M7-7)

**Source:** https://github.com/urwithajit9/ClaMP, file `dataset/ClaMP_Integrated-5184.csv`
(fetched as `ClaMP_Integrated-5210.csv` here — the repository's own README states 5184 rows, the
committed file parses to 5210; the discrepancy is in the upstream repository, not introduced here,
and is recorded rather than silently corrected).

**What it is:** "Classification of Malware with PE headers" — real Windows Portable Executable
files' header-derived structural features (DOS/File/Optional header fields, section counts,
entropy of the code/data sections and the whole file, packer detection), labelled malicious or
benign. 5210 rows, 70 columns, 2722 malicious / 2488 benign (`class` column: 1 = malware, 0 =
benign). Openly published on GitHub for exactly this kind of ML research use; no registration
gate, no license file, so provenance and terms are recorded here rather than assumed.

**Fetched:** 2026-09-25, via direct HTTPS GET (no API key, no authentication).
**SHA-256:** `41332e79aa7a1fcafac479fb636028e2a0dd647f2ea92efcf51bcfa959c5d90a`

**Why this dataset and not the ones named in the M7-7 brief:** EMBER's actual feature dataset is a
~2.4GB archive, and this sandbox's measured throughput (~40.6KB/s on a 1.28MB test fetch)
projects a ~17-hour download — infeasible in one session. CIC-MalMem-2022/CICMalDroid-2020 are
gated behind UNB's research-access request form, not a direct scriptable download. ClaMP is real,
labelled, structurally similar in spirit to EMBER's static-PE-feature approach, and small enough
to fetch reliably and commit for full reproducibility (CLAUDE.md §2 — a number in `results/` must
trace to something that can be re-derived, not to a download that may not still be reachable).

**Use, per the M7-7 brief's constraint:** evaluation only. This data is never used to fit or
tune `detection/`'s models or `honeypot/`'s generator — only to score the ensemble already fitted
on the committed synthetic corpus (`data/honeypot/corpus_{train,eval}.csv`).

**Mapping to `FT_RW`:** `src/bsfr_sh/honeypot/external_mapping.py`, documented per-feature in
`docs/DEVIATIONS.md` DEV-34. Because ClaMP is purely static (no dynamic execution is observed),
only the entropy group has any real or proxied correspondence to `FT_RW`; the other six groups
(19 of 22 features) have no analogue in a static PE-header dataset and are marked missing.
