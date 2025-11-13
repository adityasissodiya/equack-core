Great—here are the two deliverables.

---

### `docs/evaluation-plan.md`

```markdown
# Evaluation Plan — M7 (Metrics & Harness)

**Objective.** Produce repeatable, commit-stamped metrics and plots for:
- Replay cost (full vs. incremental)
- Concurrency (MVReg winners) on synthetic workloads
- Offline revocation (deny-wins) accounting
- (If `--net` is added later) convergence after partition heal

This plan locks scenarios, invariants, and reproduction commands so paper results are regenerable.

---

## Scenarios

### 1) `hb-chain`
Single author, linear happens-before chain on the same key (`mv:o:x`). No revocations, no true concurrency.

**Expected:**
- `ops_skipped_policy = 0`
- MVReg p95 ≤ 1 (no multi-winner)
- Replay parity: full == incremental digest

### 2) `concurrent`
N authors (clamped 2..8 based on `--peers`) concurrently write the same key; independent parent chains → true conflicts.

**Expected:**
- `ops_skipped_policy = 0`
- MVReg p95 ≥ 1 (some multi-winner present)
- Replay parity holds

### 3) `offline-revocation`
Linear HB chain; deterministically “cut” the tail (~30%). Tail is *conceptually* invalidated by a revoke. In M7 the policy engine is not enforced, so **we only log the plan** (timeline includes a `"revoke"` breadcrumb) and keep accounting in metrics. Checks tolerate zero actual skips and warn instead of failing.

**Expected:**
- `ops_skipped_policy` **may be 0** (policy not enforced in M7)
- Timeline contains a `{"type":"revoke", ...}` entry
- Replay parity holds

> Note: A 3-way partition scenario (`partition-3`) is intentionally **skipped** unless the bench exposes `--net/--peers/--partition`.

---

## Metrics (frozen keys)

Counters:
- `ops_total`, `ops_applied`, `ops_skipped_policy`, `revocations_seen`,
  `ops_invalidated_by_revoke`, `epochs_total`,
  `gossip_announces_sent`, `gossip_announces_recv`,
  `fetch_batches`, `ops_fetched`, `ops_duplicates_dropped`,
  `orset_tombstones_total`

Histograms (quantiles exported as columns, e.g. `_p50_ms`, `_p95_ms`, `_max_ms`):
- `replay_full_ms`, `replay_incremental_ms`,
  `epoch_build_ms`, `mvreg_concurrent_winners`,
  `batch_write_ms`, `checkpoint_create_ms`, `checkpoint_load_ms`,
  `convergence_ms`

---

## Invariants the harness checks

1) `ops_applied + ops_skipped_policy == ops_total`  
2) If `revocations_seen == 0` then `ops_skipped_policy == 0`  
3) For `hb-chain`: `mvreg_concurrent_winners_p95_ms <= 1`  
4) Replay parity: full digest equals incremental digest (bench ensures this or fails)

**M7 relaxation:** For `offline-revocation`, zero skipped ops emit a **warning** (not a failure).

---

## Outputs

For each scenario+seed:
- `docs/eval/out/runs/<commit>/<scenario>-<seed>.csv`
- `docs/eval/out/runs/<commit>/<scenario>-<seed>-timeline.jsonl`
- `docs/eval/out/runs/<commit>/<scenario>-<seed>-state.json`

Plots (optional):
- `docs/eval/plots/fig-replay-cost.png`
- `docs/eval/plots/fig-rollback-rate.png`
- (`fig-convergence-cdf.png` only appears if net/partition runs are included)

CSV header line is:
```

# ecac-metrics v1, commit=<hash>, scenario=<name>, seed=<seed>

````
followed by a header row and a single data row.

---

## Reproduction

```bash
# one-time (py deps)
python -m venv .venv
source .venv/bin/activate
pip install -r docs/eval/requirements.txt  # matplotlib, pandas
export MPLBACKEND=Agg

# run the harness
QUICK=1 CLEAN_LEGACY=1 USE_PARALLEL=no bash tools/scripts/reproduce.sh

# validate + browse outputs
python tools/scripts/checks.py docs/eval/out/runs/$(git rev-parse --short HEAD)
ls -1 docs/eval/out/runs/$(git rev-parse --short HEAD)
ls -1 docs/eval/plots
````

**Notes**

* `reproduce.sh` exports `ECAC_COMMIT` so the CSV header is commit-stamped.
* QUICK mode runs a tiny, deterministic subset: ops ∈ {1000, 10000}, peers=1, seeds=1.

---

## Acceptance Criteria

* Re-running the harness with the same commit and seed yields **byte-identical** CSV/JSON (except timestamps inside PNG files).
* Replay parity holds for all scenarios.
* Checks script prints `OK` (with optional warnings for offline-revocation in M7).
* Plots render without user interaction when `MPLBACKEND=Agg`.

````