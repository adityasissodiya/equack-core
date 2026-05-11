#!/usr/bin/env bash
# run-network-experiment.sh -- E16 (networked multi-node sync) driver.
#
# Orchestrates docker-compose + tc netem to run a networked multi-node
# experiment with real packet transport. Captures convergence latency
# under three conditions:
#
#   A) baseline               -- no delay, no loss
#   B) moderate WAN-ish       -- 100 ms delay, 1% loss
#   C) partition + heal       -- full drop for 30 seconds, then heal
#
# Results are written to deploy/results/e16-<timestamp>.txt.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY_DIR="${REPO_ROOT}/deploy"
RESULTS_DIR="${DEPLOY_DIR}/results"
mkdir -p "${RESULTS_DIR}"

STAMP="$(date +%Y%m%dT%H%M%S)"
LOG_FILE="${RESULTS_DIR}/e16-${STAMP}.txt"

log() {
  echo "$@" | tee -a "${LOG_FILE}"
}

{
  echo "# E16 networked multi-node sync results"
  echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
} > "${LOG_FILE}"

cd "${DEPLOY_DIR}"

# -----------------------------------------------------------------------------
# Bring up the three-node testbed.
# -----------------------------------------------------------------------------
log "=== [E16] bringing up docker-compose testbed ==="
docker compose up -d --build 2>&1 | tail -5

trap 'log "=== [E16] tearing down testbed ==="; docker compose down --remove-orphans >/dev/null 2>&1 || true' EXIT

# Wait for nodes to be ready (HTTP server up).
log "waiting for nodes to become ready..."
for attempt in $(seq 1 20); do
  if curl -sf http://localhost:9001/api/state/digest >/dev/null 2>&1 && \
     curl -sf http://localhost:9002/api/state/digest >/dev/null 2>&1 && \
     curl -sf http://localhost:9003/api/state/digest >/dev/null 2>&1; then
    log "all nodes ready after ${attempt}s"
    break
  fi
  sleep 1
done

# -----------------------------------------------------------------------------
# Scenario A: baseline (no delay, no loss)
# -----------------------------------------------------------------------------
log ""
log "=== [E16] scenario A -- baseline (no delay, no loss) ==="

# Generate 1000 ops on each node
curl -sf -X POST http://localhost:9001/api/generate -d '{"ops":1000}' >/dev/null
curl -sf -X POST http://localhost:9002/api/generate -d '{"ops":1000}' >/dev/null
curl -sf -X POST http://localhost:9003/api/generate -d '{"ops":1000}' >/dev/null
log "generated 1000 ops on each node (3000 total)"

# Measure convergence
./measure-convergence.sh 60 | tee -a "${LOG_FILE}"
RESULT_A=$?
if [ $RESULT_A -eq 0 ]; then
  log "scenario A: PASS"
else
  log "scenario A: FAIL (did not converge)"
fi

# -----------------------------------------------------------------------------
# Scenario B: moderate WAN emulation (delay + loss)
# -----------------------------------------------------------------------------
log ""
log "=== [E16] scenario B -- 100 ms delay, 1% loss on node3 uplink ==="

docker exec equack-node3 tc qdisc add dev eth0 root netem delay 100ms loss 1% 2>/dev/null || true
log "tc netem applied on node3"

# Generate 1000 ops on each node
curl -sf -X POST http://localhost:9001/api/generate -d '{"ops":1000}' >/dev/null
curl -sf -X POST http://localhost:9002/api/generate -d '{"ops":1000}' >/dev/null
curl -sf -X POST http://localhost:9003/api/generate -d '{"ops":1000}' >/dev/null
log "generated 1000 ops on each node (6000 total cumulative)"

# Measure convergence (allow more time due to delay/loss)
./measure-convergence.sh 90 | tee -a "${LOG_FILE}"
RESULT_B=$?

docker exec equack-node3 tc qdisc del dev eth0 root 2>/dev/null || true
log "tc netem removed"

if [ $RESULT_B -eq 0 ]; then
  log "scenario B: PASS"
else
  log "scenario B: FAIL (did not converge)"
fi

# Brief pause to let sync stabilize after removing netem
sleep 3

# -----------------------------------------------------------------------------
# Scenario C: partition + heal (30 s)
# -----------------------------------------------------------------------------
log ""
log "=== [E16] scenario C -- partition + heal (30 s) ==="

# Generate ops on node1 during partition (node3 will be isolated)
# Launch background generation that runs 5s into the partition
(sleep 5 && curl -sf -X POST http://localhost:9001/api/generate -d '{"ops":1000}' >/dev/null) &
BG_PID=$!

# Inject 30-second partition (blocks until healed)
./inject-partition.sh 30 | tee -a "${LOG_FILE}"
wait $BG_PID 2>/dev/null || true

log "post-heal convergence check:"
./measure-convergence.sh 60 | tee -a "${LOG_FILE}"
RESULT_C=$?

if [ $RESULT_C -eq 0 ]; then
  log "scenario C: PASS"
else
  log "scenario C: FAIL (did not converge after heal)"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
log ""
log "=== [E16] complete. results: ${LOG_FILE} ==="
log "Scenario A (baseline):      $([ $RESULT_A -eq 0 ] && echo PASS || echo FAIL)"
log "Scenario B (WAN emulation): $([ $RESULT_B -eq 0 ] && echo PASS || echo FAIL)"
log "Scenario C (partition+heal):$([ $RESULT_C -eq 0 ] && echo PASS || echo FAIL)"
