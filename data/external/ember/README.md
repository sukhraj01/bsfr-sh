# EMBER — external real-malware dataset, richer mapping (M7-10a)

**Source:** https://github.com/elastic/ember, dataset file `ember_dataset_2018_2.tar.bz2`
(direct download: `https://ember.elastic.co/ember_dataset_2018_2.tar.bz2`).

**What it is:** the EMBER2018 (feature version 2) dataset — LIEF-extracted static structural
features of ~1.1M real Windows PE files (900K train, 200K fully-labelled test), published by
Elastic for malware-classifier research. Each sample's *raw* features (not yet vectorized) are a
JSON object per line across `train_features_0.jsonl` .. `train_features_5.jsonl` and
`test_features.jsonl`, carrying: a 256-bin whole-file byte histogram, a byte-entropy 2D
histogram, per-section name/size/entropy/permission-flags, general file info (size, imports
count, exports count, has-signature, ...), header fields, the full per-DLL import table, exported
function names, and string statistics. `label` is `1` (malicious), `0` (benign), or `-1`
(unlabelled — train split only; the test split used here is fully labelled 0/1).

**Fetched:** 2026-09-25, on Ada (`ada.iiit.ac.in`), via direct HTTPS GET (no API key). Full
archive size 1,696,539,273 bytes; **SHA-256**
`b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812` (matches the checksum
published in the upstream repository's README).

**Only `test_features.jsonl` is extracted, not the six train shards.** M7-10a evaluates only (it
never fits or tunes anything in `honeypot/` or `detection/` on real data, same posture as M7-7's
ClaMP evaluation), so the ~900K-row train split is never read. This is also a storage decision:
Ada's per-user quota on this cluster does not have room for the full ~10GB decompressed archive
alongside this account's other projects; extracting the single fully-labelled 200,000-row test
shard (`tar xjf ember_dataset_2018_2.tar.bz2 --wildcards --no-anchored 'test_features.jsonl'
--strip-components=1 -C .`, ~1.87GB decompressed) is sufficient for this session's evaluation and
fits comfortably. The compressed archive and the extracted `test_features.jsonl` are **not**
committed to git (both far too large; `.gitignore` excludes `data/external/ember/*.jsonl` and
`*.tar.bz2` — this README, and the mapping code that reads the file, are what make the evaluation
reproducible without committing the data itself).

**Use, per the M7-10 brief's constraint:** evaluation only. Never used to fit or tune anything in
`detection/` or `honeypot/` — only to score the ensemble/MLP already fitted on the committed
synthetic corpus (`data/honeypot/corpus_{train,eval}.csv`).

**Mapping to `FT_RW`:** `src/bsfr_sh/honeypot/ember_mapping.py`, documented per-feature in
`docs/DEVIATIONS.md` DEV-35. EMBER's richer raw data (byte histogram, per-section entropy,
section permission flags, full import table) grounds 6 of 22 `FT_RW` features — entropy (3/3),
crypto_api (2/3), filesystem (1/5) — against ClaMP's 3/22 (M7-7, DEV-34), all entropy-only.
