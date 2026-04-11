#!/usr/bin/env bash
# measure-convergence.sh -- Poll all three EQUACK nodes until their state
# digests match (convergence) or a timeout is reached.
#
# Usage:
#   ./measure-convergence.sh [MAX_WAIT_SECONDS]
#
# Exit code 0 = converged, 1 = timeout or error.

set -euo pipefail

MAX_WAIT="${1:-60}"
POLL_INTERVAL=1
DIGEST_ENDPOINT="/api/state/digest"

fetch_digest() {
  local port="$1"
  curl -sf "http://localhost:${port}${DIGEST_ENDPOINT}" 2>/dev/null \
    | jq -r '.digest' 2>/dev/null || echo "UNAVAILABLE"
}

echo "=== Measuring convergence across 3 EQUACK nodes (timeout ${MAX_WAIT}s) ==="

START_S=$(date +%s)

while true; do
  D1=$(fetch_digest 9001)
  D2=$(fetch_digest 9002)
  D3=$(fetch_digest 9003)

  NOW_S=$(date +%s)
  ELAPSED=$((NOW_S - START_S))

  if [[ "$D1" != "UNAVAILABLE" && "$D2" != "UNAVAILABLE" && "$D3" != "UNAVAILABLE" ]]; then
    if [[ "$D1" == "$D2" && "$D2" == "$D3" ]]; then
      echo "CONVERGED in ${ELAPSED}s (digest: $D1)"
      echo "  node1: $D1  node2: $D2  node3: $D3"
      exit 0
    fi
  fi

  if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
    echo "TIMEOUT after ${MAX_WAIT}s -- nodes have NOT converged"
    echo "  node1: $D1"
    echo "  node2: $D2"
    echo "  node3: $D3"
    exit 1
  fi

  sleep "$POLL_INTERVAL"
done
