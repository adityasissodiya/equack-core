#!/usr/bin/env bash
set -euo pipefail

# repo root (two levels up from tools/scripts)
SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPTDIR/../.." && pwd)"
OUT="$ROOT/docs/eval/out"
PLOTS="$ROOT/docs/eval/plots"
PARTITION="$ROOT/docs/eval/partition/three_way_small.json"
CLI="$ROOT/target/release/ecac-cli"

# 0) Freeze/tag + build (from repo root so target paths align)
cd "$ROOT"
git tag -f m7-freeze || true
COMMIT="$(git rev-parse --short HEAD || echo unknown)"
echo "[m7] commit=$COMMIT (tagged m7-freeze)"
cargo build -p ecac-cli --release

[[ -x "$CLI" ]] || { echo "[m7] fatal: missing CLI at $CLI"; exit 1; }

# 1) Ensure dirs + partition schedule
mkdir -p "$(dirname "$PARTITION")" "$OUT" "$PLOTS"
if [[ ! -f "$PARTITION" ]]; then
  cat > "$PARTITION" <<'JSON'
[
  {"t_ms":   0, "type": "isolate", "groups": [["A"],["B"],["C"]]},
  {"t_ms": 500, "type": "merge",   "groups": [["A","B","C"]]}
]
JSON
fi

# 2) Defaults (grid)
ops=(1000 10000 50000)
peers=(1 3 5)
seeds="$(seq 1 10)"
scens=(hb-chain concurrent)
checkpoint_every=1000

# ---------- user overrides ----------
# e.g. OPS="1000,10000" PEERS="1" SEEDS="1 2" SCENS="hb-chain,concurrent" QUICK=1 bash tools/scripts/reproduce.sh
if [[ -n "${OPS:-}"   ]]; then IFS=',' read -ra ops   <<<"$OPS"; fi
if [[ -n "${PEERS:-}" ]]; then IFS=',' read -ra peers <<<"$PEERS"; fi
if [[ -n "${SEEDS:-}" ]]; then seeds="${SEEDS//,/ }"; fi
if [[ -n "${SCENS:-}" ]]; then IFS=',' read -ra scens <<<"$SCENS"; fi

# QUICK mode: tiny subset
if [[ "${QUICK:-0}" == "1" ]]; then
  ops=(1000 10000)
  peers=(1)
  seeds="1"
  scens=(hb-chain concurrent)
fi

# 2b) Run-scoped output root (commit-specific so checks ignore stale files)
RUN_OUT="$OUT/runs/$COMMIT"
mkdir -p "$RUN_OUT"
# Freshen run dir each invocation (reproducible artifacts per commit)
rm -f "$RUN_OUT"/* 2>/dev/null || true

# Optional: purge legacy, unstamped top-level artifacts that confuse checks.py
if [[ "${CLEAN_LEGACY:-0}" == "1" ]]; then
  shopt -s nullglob
  for f in "$OUT"/hb-chain-*.csv "$OUT"/hb-chain-*-timeline.jsonl "$OUT"/hb-chain-*-state.json \
           "$OUT"/concurrent-*.csv "$OUT"/concurrent-*-timeline.jsonl "$OUT"/concurrent-*-state.json; do
    # Keep only new stamped files (contain ".ops" in the name); delete the rest
    if [[ "$f" != *".ops"* ]]; then rm -f -- "$f"; fi
  done
  shopt -u nullglob
fi

# 3) Discover supported flags on the CLI
HELP="$("$CLI" bench --help 2>/dev/null || true)"
has() { grep -q -- "$1" <<<"$HELP"; }

have_checkpoint=0; has --checkpoint-every && have_checkpoint=1
have_peers=0;      has --peers             && have_peers=1
have_net=0;        has --net               && have_net=1
have_partition=0;  has --partition         && have_partition=1

net_scen="partition-3"
if (( have_peers && have_net && have_partition )); then
  scens+=("$net_scen")
else
  echo "[m7] Skipping $net_scen (bench lacks --peers/--net/--partition flags)."
fi

run_one() {
  local scen="$1" seed="$2" nops="$3" mpeers="$4"

  # Unique scratch dir for CLI outputs
  local run_dir="$RUN_OUT/.tmp/${scen}-seed${seed}-ops${nops}-p${mpeers}"
  mkdir -p "$run_dir"

  local args=(bench --scenario "$scen" --seed "$seed" --ops "$nops" --out-dir "$run_dir")
  (( have_checkpoint )) && args+=(--checkpoint-every "$checkpoint_every")

  if [[ "$scen" == "$net_scen" ]]; then
    (( have_peers ))     && args+=(--peers 3)
    (( have_net ))       && args+=(--net)
    (( have_partition )) && args+=(--partition "$PARTITION")
    mpeers=3
  else
    (( have_peers )) && args+=(--peers "$mpeers")
  fi

  echo "[m7] $CLI ${args[*]}"
  "$CLI" "${args[@]}"

  # Stamp outputs (ops + peers) and promote to RUN_OUT
  local stamp="ops${nops}.p${mpeers}"
  local base="${scen}-${seed}"
  for kind in "csv" "timeline.jsonl" "state.json"; do
    local src="$run_dir/${base}-${kind}"
    local dst="$RUN_OUT/${base}.${stamp}-${kind}"
    [[ -f "$src" ]] && mv -f "$src" "$dst"
  done

  rmdir "$run_dir" 2>/dev/null || true
}

# 4) Compose job list
jobs=()
for scen in "${scens[@]}"; do
  for seed in $seeds; do
    for nops in "${ops[@]}"; do
      for m in "${peers[@]}"; do
        if [[ "$scen" == "$net_scen" && "$m" != "3" ]]; then continue; fi
        jobs+=("$scen $seed $nops $m")
      done
    done
  done
done

# 5) Run (parallel if available and requested)
export -f run_one
if [[ "${USE_PARALLEL:-yes}" != "no" && -n "${jobs[*]:-}" && "$(command -v parallel || true)" ]]; then
  printf '%s\n' "${jobs[@]}" \
    | parallel --colsep ' ' --jobs "$(nproc)" run_one {1} {2} {3} {4}
else
  for j in "${jobs[@]}"; do run_one $j; done
fi

# 6) Invariants + plots (only against this run)
if command -v python3 >/dev/null 2>&1; then
  python3 "$ROOT/tools/scripts/checks.py" "$RUN_OUT" || echo "[m7] checks.py failed (non-fatal)"
  python3 "$ROOT/tools/scripts/plot.py" "$RUN_OUT" "$PLOTS" || echo "[m7] plot.py failed (non-fatal; try 'pip install matplotlib pandas')"
else
  echo "[m7] python3 not found; skipping checks/plots"
fi

echo "[m7] DONE. Artifacts in $RUN_OUT ; plots in $PLOTS ; commit=$COMMIT"
