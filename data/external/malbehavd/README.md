# MalbehavD-V1 — real dynamic-behavioral dataset (M7-13)

**Source:** https://github.com/mpasco/MalbehavD-V1, file `MalBehavD-V1-dataset.csv`.

**What it is:** Maniriho, Mahmood & Chowdhury's MalbehavD-V1 — 2,570 real Windows PE files
(1,285 malware, 1,285 benign, perfectly balanced), each **executed** in an isolated Cuckoo-sandbox
environment (Windows VMs under Oracle VirtualBox, orchestrated from a Linux host) and represented
as the ordered sequence of Win32/Nt API calls Cuckoo observed during that execution — up to 175
calls per file, 291 distinct API names across the whole corpus. Malware samples were collected
from VirusTotal (submitted in Q2 2021); benign samples from CNET's download site, each verified
clean against VirusTotal before inclusion. Published alongside:

> P. Maniriho, A. N. Mahmood, M. J. M. Chowdhury, "API-MalDetect: Automated malware detection
> framework for Windows based on API calls and deep learning techniques," *Journal of Network and
> Computer Applications*, 2023.

**This is genuinely dynamic behavioral data, unlike M7-7's ClaMP and M7-10's EMBER.** Both of
those are LIEF-extracted *static* PE-header/structure features — read off a file that is never
run. MalbehavD-V1's rows are what actually happened when the file executed: process creation,
file I/O, registry writes, network connection attempts, cryptographic API use — the categories
`FT_RW`'s process/network/persistence groups describe and that no static dataset can touch
(DEV-34, DEV-35).

**Fetched:** 2026-09-26, via direct HTTPS GET (`raw.githubusercontent.com/mpasco/MalbehavD-V1/
main/MalBehavD-V1-dataset.csv`), no API key, no account, no research-access form. File size
2,345,393 bytes; **SHA-256** `1e39c43a014e9b4ee56766ad6bb367ffe8ec4316eb0be75eb182c3b2d15f6364`.
Verified against the upstream repo's own file-size listing (GitHub API `contents` endpoint
reports the identical byte count) before use. Row count and label balance verified by direct
inspection (2,570 data rows; `labels` column exactly 1,285 zeros and 1,285 ones) — not taken from
the README's stated numbers alone.

**Committed to git** (2.3MB, MIT-licensed per the upstream repo's `license` file — same posture
as M7-7's committed ClaMP CSV; unlike EMBER's multi-GB archive, this is small enough to commit
directly for full reproducibility without a separate fetch step).

**Schema, as shipped:** `sha256,labels,0,1,2,...,152` (153 sequence-position columns, ragged —
shorter traces leave the tail blank). `labels` is `0` (benign) or `1` (malware). Each numbered
column holds one API call name in call order, or empty past the trace's own length. No
timestamps, no call arguments (paths, registry keys, domain names, buffer contents) are
captured — only the call name and its position in the sequence. This absence is the reason
several `FT_RW` features remain `MISSING` even though the *category* of API is present in the
vocabulary (see `src/bsfr_sh/honeypot/malbehavd_mapping.py` and `docs/DEVIATIONS.md` DEV-39/40 for
which, and why).

**Use, per the M7-13 brief's constraint:** evaluation only. Never used to fit or tune anything in
`detection/` or `honeypot/` — only to score the ensemble/profiles already fitted on the committed
synthetic corpus (`data/honeypot/corpus_{train,eval}.csv`), same posture as M7-7/M7-10a.

**Mapping to `FT_RW`:** `src/bsfr_sh/honeypot/malbehavd_mapping.py`, documented per-feature in
`docs/DEVIATIONS.md` DEV-39. Grounds 12 of 22 features across 5 of 7 groups (filesystem,
crypto_api, process, network, persistence) — against ClaMP's 3/22 (entropy only, DEV-34) and
EMBER's 6/22 (entropy + partial crypto_api/filesystem, DEV-35). The entropy and kill_chain groups
are fully `MISSING` here — the inverse of ClaMP/EMBER, where entropy was the *only* grounded
group — because this dataset never captures byte content (no entropy signal) or wall-clock timing
(no stage-dwell signal), only call identity and order.

**Why BODMAS, CICMalDroid-2020, MalwareBazaar/Triage, and public Cuckoo instances were not used
instead:** see `sessions/2026-09-26-04-m7-13-dynamic-behavioral-dataset.md` and DEV-39 for the
per-candidate findings. In short: BODMAS is static (same LIEF pipeline as EMBER, confirmed against
its own project page, not the session brief's description of it); CICMalDroid-2020 and
MalwareBazaar/Triage both require creating an account or submitting a personal-information access
request under the user's identity, which this session does not do unilaterally; public Cuckoo
instances (`cuckoo.cert.ee`) did not respond.
