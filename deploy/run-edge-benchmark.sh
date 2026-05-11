#!/usr/bin/env bash
# run-edge-benchmark.sh -- E15 (edge-device replay benchmark) driver.
#
# Cross-compiles the replay/throughput benchmarks for an aarch64 edge
# target, copies the artefacts to the target device, and runs the E6 and
# E7 benchmarks there. Results are written into deploy/results/e15-*.txt
# so they can be folded into the evaluation table by hand.
#
# Usage:
#   ./run-edge-benchmark.sh <ssh-user@host> [extra-scp-opts]
#
# Requirements on the host:
#   rustup target add aarch64-unknown-linux-gnu
#   sudo apt install gcc-aarch64-linux-gnu
#
# Requirements on the target (e.g., Raspberry Pi 4):
#   Linux aarch64 with glibc >= 2.31 (Raspberry Pi OS Bookworm is fine).
#   Roughly 1 GiB free RAM and 2 GiB free disk.
#
# HUMAN: fill in the target hostname and run this once the cross toolchain
# and SSH access are in place. The script is intentionally conservative --
# it builds and transfers but only runs short benchmark variants by
# default; edit the INVOCATIONS list below to match the E6/E7 matrix you
# want reported in the paper.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <ssh-user@host> [extra scp options]" >&2
  exit 2
fi

TARGET_HOST="$1"
shift || true
SCP_OPTS=("$@")

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TRIPLE="aarch64-unknown-linux-gnu"
BUILD_DIR="${REPO_ROOT}/target/${TRIPLE}/release"
RESULTS_DIR="${REPO_ROOT}/deploy/results"
mkdir -p "${RESULTS_DIR}"

# -----------------------------------------------------------------------------
# 1. Cross-compile the binaries needed by E6/E7.
# -----------------------------------------------------------------------------
echo "=== [E15] cross-compiling for ${TRIPLE} ==="
(
  cd "${REPO_ROOT}"
  cargo build --release --target "${TRIPLE}" --bin equack-cli
  # The core crate ships bench harnesses as plain binaries (see
  # crates/core/src/bin). Build those too when available.
  cargo build --release --target "${TRIPLE}" --bin bench_sync || true
)

# -----------------------------------------------------------------------------
# 2. Stage artefacts on the target device.
# -----------------------------------------------------------------------------
REMOTE_DIR="~/equack-edge-bench"
echo "=== [E15] transferring artefacts to ${TARGET_HOST}:${REMOTE_DIR} ==="
ssh "${TARGET_HOST}" "mkdir -p ${REMOTE_DIR}"
scp "${SCP_OPTS[@]}" "${BUILD_DIR}/equack-cli" "${TARGET_HOST}:${REMOTE_DIR}/"
if [[ -f "${BUILD_DIR}/bench_sync" ]]; then
  scp "${SCP_OPTS[@]}" "${BUILD_DIR}/bench_sync" "${TARGET_HOST}:${REMOTE_DIR}/"
fi

# -----------------------------------------------------------------------------
# 3. Run a short E6/E7 matrix on the target.
# -----------------------------------------------------------------------------
# HUMAN: extend this list to match the sizes used in Tables VII--IX so the
# edge numbers are directly comparable to the x86_64 baseline.
INVOCATIONS=(
  "equack-cli bench replay --ops 10000 --workload hb-chain"
  "equack-cli bench replay --ops 50000 --workload hb-chain"
  "equack-cli bench replay --ops 10000 --workload concurrent --writers 8"
  "equack-cli bench replay --ops 10000 --workload offline-revocation"
)

STAMP="$(date +%Y%m%dT%H%M%S)"
LOG_FILE="${RESULTS_DIR}/e15-${STAMP}.txt"

{
  echo "# E15 edge benchmark results"
  echo "# host: ${TARGET_HOST}"
  echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# triple: ${TRIPLE}"
  echo
} > "${LOG_FILE}"

for cmd in "${INVOCATIONS[@]}"; do
  echo "=== [E15] running on target: ${cmd} ==="
  {
    echo "--- ${cmd}"
    ssh "${TARGET_HOST}" "cd ${REMOTE_DIR} && ./${cmd}" || {
      echo "!!! invocation failed: ${cmd}"
    }
    echo
  } | tee -a "${LOG_FILE}"
done

echo "=== [E15] results written to ${LOG_FILE} ==="
echo "HUMAN: fold these numbers into the E15 table in the paper."
