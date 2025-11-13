# Evaluation Harness (M7)

This folder contains the **reproduce → check → plot** pipeline for M7.

* `tools/scripts/reproduce.sh` — builds the CLI and runs scenarios to produce artifacts
* `tools/scripts/checks.py` — sanity checks over CSV metrics
* `tools/scripts/plot.py` — generates figures from the CSVs

Artifacts land under `docs/eval/out/runs/<git-short-commit>/`. Figures go to `docs/eval/plots/`.

---

## Prerequisites

* Rust (stable) with `cargo`
* Python 3.11+ (3.12 recommended)

  ```bash
  python -m venv .venv
  source .venv/bin/activate
  pip install --upgrade pip
  pip install matplotlib pandas
  export MPLBACKEND=Agg   # headless plotting
  ```
* Optional: GNU `parallel` (the script auto-detects it)

---

## Quick smoke test (good for CI)

```bash
source .venv/bin/activate
export MPLBACKEND=Agg
QUICK=1 CLEAN_LEGACY=1 USE_PARALLEL=no bash tools/scripts/reproduce.sh
python tools/scripts/checks.py docs/eval/out/runs/$(git rev-parse --short HEAD)
ls -1 docs/eval/plots
```

You should see:

* `docs/eval/out/runs/<commit>/...` with `.csv`, `-timeline.jsonl`, `-state.json`
* `docs/eval/plots/fig-replay-cost.png`
* `docs/eval/plots/fig-rollback-rate.png`

> Note: `reproduce.sh` stamps outputs into a commit-specific dir and exports `ECAC_COMMIT` so each CSV header includes the commit used for the run.

---

## Scenarios (M7)

* `hb-chain` — single author, linear happens-before chain (no true concurrency)
* `concurrent` — multiple authors racing on the same key (true concurrency)
* `offline-revocation` — linear chain with a deterministic “revoke” cut; **policy is not enforced in M7**, so checks only warn if zero ops were skipped
* `partition-3` — **not run in M7** (net harness not wired; script will skip it)

---

## Output layout & naming

Artifacts for each scenario/seed are written like:

```
docs/eval/out/runs/<commit>/
  hb-chain-1.ops1000.p1.csv
  hb-chain-1.ops1000.p1-timeline.jsonl
  hb-chain-1.ops1000.p1-state.json
  ...
```

Pattern: `<scenario>-<seed>.ops<total_ops>.p<peers>.<ext>`

CSV header (first line) encodes metadata, e.g.:

```
# ecac-metrics v1, commit=ab14946, scenario=hb-chain, seed=1
```

Then a header row and a single metrics row. Key fields include:
`ops_total, ops_applied, ops_skipped_policy, revocations_seen,
replay_full_ms_p50_ms, replay_incremental_ms_p50_ms, ...`

---

## Controls (environment variables)

All knobs are **env vars**; pass them inline before the script.

* `OPS` — comma list of op counts (default: `1000,10000,50000`)
* `PEERS` — comma list of peer counts (default: `1,3,5`)
* `SEEDS` — space or comma list of integer seeds (default: `1..10`)
* `SCENS` — comma list of scenarios (default: `hb-chain,concurrent`; script may add `partition-3` if supported)
* `QUICK` — `1` to run a tiny subset (`ops=1000,10000; peers=1; seeds=1`)
* `USE_PARALLEL` — `yes` (default) or `no`
* `CLEAN_LEGACY` — `1` to erase old, unstamped top-level artifacts that could confuse checks
* `MPLBACKEND` — set to `Agg` for headless plots

### Examples

Modest grid (denser than quick, still fast):

```bash
OPS="1000,10000" SEEDS="1 2" PEERS="4" CLEAN_LEGACY=1 USE_PARALLEL=no \
  bash tools/scripts/reproduce.sh
```

Single scenario:

```bash
SCENS="hb-chain" QUICK=1 bash tools/scripts/reproduce.sh
```

Full default grid (slow):

```bash
bash tools/scripts/reproduce.sh
```

---

## Running checks & plots by hand

```bash
python tools/scripts/checks.py docs/eval/out/runs/$(git rev-parse --short HEAD)
python tools/scripts/plot.py docs/eval/out/runs/$(git rev-parse --short HEAD) docs/eval/plots
```

Figures produced in M7:

* `fig-replay-cost.png` — Full vs Incremental replay cost (p50 across runs)
* `fig-rollback-rate.png` — Rollback/deny rate for `offline-revocation` (expected to be ~0% in M7; policy not enforced)

`fig-convergence-cdf.png` is only generated when `partition-3` runs exist (post-M7).

---

## What the checks enforce (M7)

* CSVs must exist under the **commit-stamped** output dir
* `hb-chain`: **no concurrency artifacts** in metrics (fixed in M7 by correct checkpointing)
* `offline-revocation`: will **warn** (not fail) if `ops_skipped_policy == 0` (expected in M7)

If checks fail, the script exits non-zero; the harness prints a short reason.

---

## Troubleshooting

* **“no CSVs in …/runs/<commit>”**
  You probably passed the wrong path to `checks.py`, or the script didn’t copy artifacts from its tmp dirs. Re-run with `CLEAN_LEGACY=1`. Make sure you’re pointing to `docs/eval/out/runs/$(git rev-parse --short HEAD)`.

* **Matplotlib can’t open display / backend errors**
  Activate the venv and set `export MPLBACKEND=Agg`. Ensure `matplotlib` and `pandas` are installed.

* **Concurrency violations on `hb-chain`**
  You’re likely using an older `ecac-cli`. Rebuild (`cargo build -p ecac-cli --release`) and re-run. M7 builds the prefix checkpoint correctly—p95 should be ≤ 1.

* **Offline-revocation warnings**
  Expected in M7; policy enforcement lands later. Warnings do not fail the run.

---

## Reproducibility notes

* Each run is **scoped to the current git short commit**: `docs/eval/out/runs/<commit>/…`
* The script exports `ECAC_COMMIT=<git-short-commit>` so each CSV header embeds the commit used for that run
* Artifacts are deterministic for a given commit, seed, and inputs

---

## CI (optional)

A minimal GitHub Actions workflow can run `QUICK=1`, check metrics, and upload plots as artifacts. See the suggested workflow in the PR description or wire up `.github/workflows/m7.yml` accordingly.
