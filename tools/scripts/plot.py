#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, csv, re, math, statistics, io
from pathlib import Path

# Be headless-friendly by default
try:
    import matplotlib
    matplotlib.use("Agg", force=True)
except Exception:
    pass
import matplotlib.pyplot as plt


IN = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/eval/out")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "docs/eval/plots")
OUT.mkdir(parents=True, exist_ok=True)


def parse_csv(path: Path):
    """
    Parse a 2-line snapshot CSV preceded by a single comment header line.
    Returns (meta: dict[str,str], row: dict[str, float|str])
    """
    with path.open("r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f]

    # extract meta from the first comment line beginning with '#'
    meta = {}
    for ln in lines:
        if ln.startswith("#"):
            # e.g. "# ecac-metrics v1, commit=XXXX, scenario=hb-chain, seed=1"
            for k, v in re.findall(r"(\w+)=([^,\s]+)", ln):
                meta[k] = v
            break

    # Find the first two non-comment, non-empty lines as header+row
    data_lines = [ln for ln in lines if ln and not ln.startswith("#")]
    if len(data_lines) < 2:
        return meta, {}

    header = next(csv.reader([data_lines[0]]))
    row = next(csv.reader([data_lines[1]]))
    d = dict(zip(header, row))

    # best-effort numeric casting
    for k, v in list(d.items()):
        try:
            if v.strip() == "":
                continue
            # ints look nicer, but floats are fine for plotting
            fv = float(v)
            # keep integers as ints where applicable
            d[k] = int(fv) if fv.is_integer() else fv
        except Exception:
            # leave as string
            pass
    return meta, d


def pick(d: dict, *candidates, default=None):
    """Return first present candidate key from dict d, else default."""
    for k in candidates:
        if k in d and d[k] is not None and d[k] != "":
            return d[k]
    return default


def pick_metric(d: dict, base: str, *, ms_suffix=True):
    """
    Robust lookup across histogram summaries and raw counters.
    Tries: base_p50_ms, base_p95_ms, base_max_ms, base (in that order).
    """
    suff = "_ms" if ms_suffix else ""
    return pick(
        d,
        f"{base}_p50{suff}",
        f"{base}_p95{suff}",
        f"{base}_max{suff}",
        base,
        default=None,
    )


# Collect all runs
runs = []
for p in sorted(IN.glob("*.csv")):
    meta, d = parse_csv(p)
    if d:
        runs.append((p, meta, d))

wrote = []


def savefig(path: Path):
    plt.tight_layout()
    plt.savefig(path, dpi=180, bbox_inches="tight")
    plt.close()
    wrote.append(str(path))


# -------------------- 1) Convergence CDF --------------------
# Only meaningful for partition scenarios
conv_samples = []
for _, meta, d in runs:
    scen = meta.get("scenario", "")
    if scen in ("partition-3", "three-way-partition"):
        v = pick_metric(d, "convergence_ms", ms_suffix=True)
        if isinstance(v, (int, float)) and v >= 0:
            conv_samples.append(float(v))

if conv_samples:
    xs = sorted(conv_samples)
    n = len(xs)
    ys = [(i + 1) / n for i in range(n)]
    plt.figure()
    plt.plot(xs, ys, marker=".", linestyle="-")
    plt.xlabel("Convergence latency (ms)")
    plt.ylabel("CDF")
    plt.title("Convergence CDF (3-way partition)")
    plt.grid(True, alpha=0.3)
    savefig(OUT / "fig-convergence-cdf.png")


# -------------------- 2) Replay cost vs N ops --------------------
# Group by ops_total, take median (or mean) across seeds
by_ops_full = {}
by_ops_incr = {}

for _, _meta, d in runs:
    ops_total = d.get("ops_total")
    if not isinstance(ops_total, (int, float)) or ops_total <= 0:
        continue
    rf = pick_metric(d, "replay_full_ms", ms_suffix=True)
    ri = pick_metric(d, "replay_incremental_ms", ms_suffix=True)
    if isinstance(rf, (int, float)):
        by_ops_full.setdefault(int(ops_total), []).append(float(rf))
    if isinstance(ri, (int, float)):
        by_ops_incr.setdefault(int(ops_total), []).append(float(ri))

if by_ops_full or by_ops_incr:
    xs_f = sorted(by_ops_full.keys())
    ys_f = [statistics.median(by_ops_full[k]) for k in xs_f] if xs_f else []

    xs_i = sorted(by_ops_incr.keys())
    ys_i = [statistics.median(by_ops_incr[k]) for k in xs_i] if xs_i else []

    if xs_f or xs_i:
        plt.figure()
        if xs_f:
            plt.plot(xs_f, ys_f, marker="o", label="Full")
        if xs_i:
            plt.plot(xs_i, ys_i, marker="o", label="Incremental")
        plt.xlabel("Total ops")
        plt.ylabel("Replay time (ms)")
        plt.title("Replay cost: Full vs Incremental (median)")
        plt.legend()
        plt.grid(True, alpha=0.3)
        savefig(OUT / "fig-replay-cost.png")


# -------------------- 3) Rollback rate (offline revocation) --------------------
# Prefer explicit offline-revocation scenario; otherwise accept runs with revocations>0
roll_points = {}

def is_offline_revocation(meta):
    return meta.get("scenario", "") == "offline-revocation"

any_offline = any(is_offline_revocation(meta) for _, meta, _ in runs)

for _, meta, d in runs:
    if not any_offline:
        # fallback: accept runs that actually observed revocations
        if not (isinstance(d.get("revocations_seen"), (int, float)) and d.get("revocations_seen", 0) > 0):
            continue
    else:
        if not is_offline_revocation(meta):
            continue

    n = d.get("ops_total")
    s = d.get("ops_skipped_policy", 0)
    if not isinstance(n, (int, float)) or n <= 0:
        continue
    rate_pct = 100.0 * (float(s) / float(n))
    roll_points.setdefault(int(n), []).append(rate_pct)

if roll_points:
    xs = sorted(roll_points.keys())
    ys = [statistics.mean(roll_points[k]) for k in xs]
    plt.figure()
    plt.plot(xs, ys, marker="o")
    plt.xlabel("Total ops")
    plt.ylabel("Rollback rate (%)")
    plt.title("Rollback (deny-wins) — offline revocation")
    plt.grid(True, alpha=0.3)
    savefig(OUT / "fig-rollback-rate.png")


# -------------------- 4) E6: Replay Scaling (Linear Fit) --------------------
# Show linear scaling with fitted line
if by_ops_full:
    xs_all = sorted(by_ops_full.keys())
    ys_all = [statistics.median(by_ops_full[k]) for k in xs_all]

    if len(xs_all) >= 2:
        # Simple linear regression
        import numpy as np
        coeffs = np.polyfit(xs_all, ys_all, 1)
        fit_line = np.poly1d(coeffs)

        plt.figure()
        plt.scatter(xs_all, ys_all, marker='o', s=100, label='Measured', zorder=3)
        plt.plot(xs_all, fit_line(xs_all), '--', label=f'Linear fit: t = {coeffs[0]:.4f}n + {coeffs[1]:.1f}', zorder=2)
        plt.xlabel("Operations")
        plt.ylabel("Replay time (ms)")
        plt.title("E6: Replay Time Scaling (Linear)")
        plt.legend()
        plt.grid(True, alpha=0.3)
        savefig(OUT / "fig-e6-scaling.png")


# -------------------- 5) E7: Throughput Comparison --------------------
# Bar chart of throughput per scenario
throughput_by_scenario = {}
for _, meta, d in runs:
    scenario = meta.get("scenario", "unknown")
    ops_total = d.get("ops_total")
    replay_full = pick_metric(d, "replay_full_ms", ms_suffix=True)

    if isinstance(ops_total, (int, float)) and isinstance(replay_full, (int, float)) and replay_full > 0:
        throughput = (ops_total / replay_full) * 1000  # ops/sec
        seed = meta.get("seed", "0")
        key = f"{scenario}-{seed}"
        throughput_by_scenario[key] = (scenario, throughput, ops_total)

if throughput_by_scenario:
    # Group by scenario and take median
    by_scenario = {}
    for key, (scenario, tput, ops) in throughput_by_scenario.items():
        by_scenario.setdefault(scenario, []).append(tput)

    scenarios = sorted(by_scenario.keys())
    medians = [statistics.median(by_scenario[s]) for s in scenarios]

    plt.figure(figsize=(10, 6))
    bars = plt.bar(range(len(scenarios)), medians, color=['#1f77b4', '#ff7f0e', '#2ca02c'][:len(scenarios)])
    plt.xticks(range(len(scenarios)), scenarios, rotation=15, ha='right')
    plt.ylabel("Throughput (ops/s)")
    plt.title("E7: Replay Throughput by Scenario")
    plt.grid(True, alpha=0.3, axis='y')

    # Add value labels on bars
    for i, (bar, val) in enumerate(zip(bars, medians)):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(medians)*0.02,
                f'{int(val):,}', ha='center', va='bottom', fontsize=9)

    savefig(OUT / "fig-e7-throughput.png")


# -------------------- 6) E10: Checkpoint Speedup --------------------
# Bar chart showing speedup factors
speedup_data = []
for _, meta, d in runs:
    ops_total = d.get("ops_total")
    replay_full = pick_metric(d, "replay_full_ms", ms_suffix=True)
    replay_incr = pick_metric(d, "replay_incremental_ms", ms_suffix=True)

    if all(isinstance(x, (int, float)) for x in [ops_total, replay_full, replay_incr]) and replay_incr > 0:
        speedup = replay_full / replay_incr
        speedup_data.append((ops_total, speedup, replay_full, replay_incr))

if speedup_data:
    # Group by ops_total
    by_ops_speedup = {}
    for ops, speedup, rf, ri in speedup_data:
        by_ops_speedup.setdefault(int(ops), []).append((speedup, rf, ri))

    ops_keys = sorted(by_ops_speedup.keys())
    avg_speedups = [statistics.median([x[0] for x in by_ops_speedup[k]]) for k in ops_keys]

    plt.figure(figsize=(8, 6))
    bars = plt.bar(range(len(ops_keys)), avg_speedups, color='#2ca02c')
    plt.xticks(range(len(ops_keys)), [f'{k:,}' for k in ops_keys])
    plt.xlabel("Operations")
    plt.ylabel("Speedup Factor (x)")
    plt.title("E10: Checkpoint Speedup (Full / Incremental)")
    plt.grid(True, alpha=0.3, axis='y')

    # Add value labels
    for bar, val in zip(bars, avg_speedups):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(avg_speedups)*0.02,
                f'{val:.1f}x', ha='center', va='bottom', fontsize=10, fontweight='bold')

    savefig(OUT / "fig-e10-checkpoint-speedup.png")


# -------------------- Done --------------------
if wrote:
    print("[plots] wrote:", " ".join(wrote))
else:
    print("[plots] no plots generated (missing columns or scenarios)")
