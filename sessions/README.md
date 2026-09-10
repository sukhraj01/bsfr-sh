# Sessions

One file per session. One session per task. Never edited after the session ends.

**Naming:** `YYYY-MM-DD-NN-<slug>.md` — `NN` is the session number that day, `<slug>` is the
task, e.g. `2026-09-11-01-m1-crypto-layer.md`.

**These files are never read wholesale.** They are the archive that lets `PROJECT_STATE.md`
stay under 200 lines. Read one only when you need to know *why* a specific past decision was
made, and then read only that one. `grep sessions/ -l "<term>"` first.

Copy `_TEMPLATE.md` to start. Fill the top half before working, the bottom half after.
