#!/usr/bin/env bash
# measure-convergence.sh -- Check whether all three EQUACK nodes have
# converged by comparing their state digests.
#
# Usage:
#   ./measure-convergence.sh
#
# Exit code 0 = converged, 1 = divergent.

set -euo pipefail

# TODO: HUMAN -- Configure the actual endpoint or CLI command that returns
# the node's current state digest. The placeholder below assumes an HTTP
# endpoint at /api/state/digest on port 9000. Adjust to match the real
# EQUACK server API or replace with a CLI invocation such as:
#   docker exec equack-node1 equack-cli state digest

DIGEST_ENDPOINT="/api/state/digest"

echo "=== Measuring convergence across 3 EQUACK nodes ==="

fetch_digest() {
  local name="$1"
  local port="$2"
  # TODO: HUMAN -- Replace curl call if the node exposes digests via CLI
  # rather than HTTP. The current command assumes a JSON response with a
  # "digest" field. Adjust the jq selector as needed.
  local digest
  digest=$(curl -sf "http://localhost:${port}${DIGEST_ENDPOINT}" | jq -r '.digest' 2>/dev/null) || {
    echo "  ERROR: could not reach ${name} on port ${port}" >&2
    echo "UNAVAILABLE"
    return
  }
  echo "${digest}"
}

DIGEST1=$(fetch_digest "node1" 9001)
DIGEST2=$(fetch_digest "node2" 9002)
DIGEST3=$(fetch_digest "node3" 9003)

echo "  node1 digest: ${DIGEST1}"
echo "  node2 digest: ${DIGEST2}"
echo "  node3 digest: ${DIGEST3}"

if [[ "${DIGEST1}" == "UNAVAILABLE" || "${DIGEST2}" == "UNAVAILABLE" || "${DIGEST3}" == "UNAVAILABLE" ]]; then
  echo ""
  echo "RESULT: one or more nodes were unreachable -- cannot determine convergence."
  exit 1
fi

if [[ "${DIGEST1}" == "${DIGEST2}" && "${DIGEST2}" == "${DIGEST3}" ]]; then
  echo ""
  echo "RESULT: ALL NODES CONVERGED (digest: ${DIGEST1})"
  exit 0
else
  echo ""
  echo "RESULT: NODES HAVE NOT CONVERGED"
  if [[ "${DIGEST1}" != "${DIGEST2}" ]]; then
    echo "  - node1 and node2 differ"
  fi
  if [[ "${DIGEST2}" != "${DIGEST3}" ]]; then
    echo "  - node2 and node3 differ"
  fi
  if [[ "${DIGEST1}" != "${DIGEST3}" ]]; then
    echo "  - node1 and node3 differ"
  fi
  exit 1
fi
