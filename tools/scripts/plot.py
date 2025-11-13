#!/usr/bin/env python3
import csv, sys, pathlib, re, math, statistics
import matplotlib.pyplot as plt

IN = pathlib.Path(sys.argv[1] if len(sys.argv)>1 else "docs/eval/out")
OUT = pathlib.Path(sys.argv[2] if len(sys.argv)>2 else "docs/eval/plots")
OUT.mkdir(parents=True, exist_ok=True)

def parse(path):
    with open(path) as f:
        header = f.readline().strip()
        hdr = next(csv.reader([f.readline().strip()]))
        row = next(csv.reader([f.readline().strip()]))
    meta = dict(re.findall(r'(\w+)=([^,]+)', header))
    d = dict(zip(hdr,row))
    for k in list(d.keys()):
        try: d[k] = float(d[k])
        except: pass
    return meta, d

runs = []
for p in sorted(IN.glob("*.csv")):
    meta, d = parse(p)
    runs.append((p, meta, d))

def pick(d, *candidates, default=None):
    for k in candidates:
        if k in d: return d[k]
    return default

# 1) Convergence CDF (use p50 or p95 per run, whichever exists)
conv = []
for _, meta, d in runs:
    if meta.get("scenario") in ("partition-3", "three-way-partition"):
        v = pick(d, "convergence_ms_p95_ms", "convergence_ms_p50_ms", "convergence_ms_max_ms")
        if isinstance(v, (int,float)) and v is not None:
            conv.append(v)
if conv:
    xs = sorted(conv)
    ys = [ (i+1)/len(xs) for i in range(len(xs)) ]
    plt.figure()
    plt.plot(xs, ys, marker='.')
    plt.xlabel("Convergence latency (ms)")
    plt.ylabel("CDF")
    plt.title("Convergence CDF (3-way partition)")
    plt.grid(True, alpha=0.3)
    plt.savefig(OUT/"fig-convergence-cdf.png", bbox_inches="tight", dpi=180)
    plt.close()

# 2) Replay cost vs N ops
replay_full = {}
replay_incr = {}
for _, meta, d in runs:
    n = int(d.get("ops_total", 0))
    rf = pick(d, "replay_full_ms_p50_ms", "replay_full_ms_max_ms")
    ri = pick(d, "replay_incremental_ms_p50_ms", "replay_incremental_ms_max_ms")
    if isinstance(rf,(int,float)): replay_full.setdefault(n, []).append(rf)
    if isinstance(ri,(int,float)): replay_incr.setdefault(n, []).append(ri)

def avgmap(m): return sorted((k, sum(v)/len(v)) for k,v in m.items())
ff = avgmap(replay_full)
ii = avgmap(replay_incr)
if ff or ii:
    plt.figure()
    if ff: plt.plot([k for k,_ in ff], [v for _,v in ff], marker='o', label="Full")
    if ii: plt.plot([k for k,_ in ii], [v for _,v in ii], marker='o', label="Incremental")
    plt.xlabel("Total ops")
    plt.ylabel("Replay time (ms)")
    plt.title("Replay cost: Full vs Incremental")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(OUT/"fig-replay-cost.png", bbox_inches="tight", dpi=180)
    plt.close()

# 3) Rollback tally (offline-revocation), normalized
roll = {}
for _, meta, d in runs:
    if meta.get("scenario") == "offline-revocation":
        n = int(d.get("ops_total", 0))
        s = float(d.get("ops_skipped_policy", 0))
        roll.setdefault(n, []).append(100.0 * (s / n if n else 0.0))
rr = sorted((k, sum(v)/len(v)) for k,v in roll.items())
if rr:
    plt.figure()
    plt.plot([k for k,_ in rr], [v for _,v in rr], marker='o')
    plt.xlabel("Total ops")
    plt.ylabel("Rollback rate (%)")
    plt.title("Rollback (deny-wins) — offline revocation")
    plt.grid(True, alpha=0.3)
    plt.savefig(OUT/"fig-rollback-rate.png", bbox_inches="tight", dpi=180)
    plt.close()

print("[plots] wrote:",
      (OUT/"fig-convergence-cdf.png"),
      (OUT/"fig-replay-cost.png"),
      (OUT/"fig-rollback-rate.png"))
