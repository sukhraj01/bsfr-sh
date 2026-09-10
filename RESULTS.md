# Results Log

Append-only. **One line per benchmark run. Never edit or delete a line.** A superseded result
stays; the newer line below it is the current one.

This file exists so `PROJECT_STATE.md` never has to carry numbers. It is read *selectively* —
`tail`, or `grep` for a component — never in full.

---

## Format

```
YYYY-MM-DD | <component> | <config> | <metric>=<value> ... | <mode> | run_id | note
```

- `<mode>` is `measured` or `paper_reported`. There is no third value.
- `run_id` matches a file in `results/logs/<run_id>.json` for `measured` rows. `—` for
  `paper_reported`.
- `<note>` is at most one short clause. Reasoning belongs in the session log, not here.

**Rule:** if a number appears anywhere — a report, a figure, a chat message — it must have a line
here first. A number without a line in this file does not exist.

---

## ML detection

```
2023-02-01 | detection/bsfr-sh    | 90/10 split, DecisionTree | acc=0.9898 f1=0.990 | paper_reported | — | Table II, best of 4 algorithms
2023-02-01 | detection/almashhadani| network traces           | acc=0.9708 f1=0.971 | paper_reported | — | Table II row 1, different dataset
2023-02-01 | detection/hwang      | dynamic analysis          | acc=0.9730 f1=0.973 | paper_reported | — | Table II row 2, different dataset
2023-02-01 | detection/sharmeen   | own corpus                | acc=0.9596 f1=0.960 | paper_reported | — | Table II row 3, different dataset
2023-02-01 | detection/bae        | PE features               | acc=0.9865 f1=0.987 | paper_reported | — | Table II row 4, different dataset
```

Baseline to beat before any of the above means anything:

```
2026-09-10 | detection/constant-positive | 90/10 split | acc=0.9000 f1=0.9474 | computed | — | analytic, not a run; always-ransomware classifier on the paper's split
```

## Blockchain timing

```
2023-02-01 | chain/BC_DTBU  | case1 5blk×100tx  | time=3.10s tps=161 | paper_reported | — | Fig 6a/6c
2023-02-01 | chain/BC_DTBU  | case2 10blk×100tx | time=4.17s tps=240 | paper_reported | — | Fig 6a/6c
2023-02-01 | chain/BC_DTBU  | case3 15blk×100tx | time=5.71s tps=263 | paper_reported | — | Fig 6a/6c
2023-02-01 | chain/BC_SigRW | case1 5blk×100tx  | time=4.36s tps=115 | paper_reported | — | Fig 6b/6d
2023-02-01 | chain/BC_SigRW | case2 10blk×100tx | time=5.54s tps=181 | paper_reported | — | Fig 6b/6d
2023-02-01 | chain/BC_SigRW | case3 15blk×100tx | time=6.76s tps=222 | paper_reported | — | Fig 6b/6d
```

Note: every `tps` above equals `tx/time` exactly — derived by the authors, not measured. See
DEV-08.

## Ours

*(nothing measured yet)*
