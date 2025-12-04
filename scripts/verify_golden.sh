#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN_DIR="${ROOT_DIR}/docs/eval/golden"

if [[ ! -f "${GOLDEN_DIR}/SHA256SUMS" ]]; then
  echo "ERROR: ${GOLDEN_DIR}/SHA256SUMS not found."
  echo "       First, run scripts/reproduce.sh once and then copy docs/eval/out/* to docs/eval/golden/ and commit."
  exit 1
fi

TMP_DIR="$(mktemp -d -t ecac-repro-verify-XXXXXX)"

cleanup() {
  # Best-effort cleanup; if worktree isn't there, ignore.
  if git -C "${ROOT_DIR}" worktree list --porcelain | grep -q "^worktree ${TMP_DIR}$"; then
    git -C "${ROOT_DIR}" worktree remove --force "${TMP_DIR}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "== verify_golden: creating detached worktree at ${TMP_DIR} =="
git -C "${ROOT_DIR}" worktree add --detach "${TMP_DIR}" >/dev/null

pushd "${TMP_DIR}" >/dev/null

echo "== verify_golden: running reproduce.sh in clean tree =="
scripts/reproduce.sh

OUT_DIR="${TMP_DIR}/docs/eval/out"

if [[ ! -f "${OUT_DIR}/SHA256SUMS" ]]; then
  echo "ERROR: reproduce.sh did not produce ${OUT_DIR}/SHA256SUMS"
  exit 1
fi

echo "== verify_golden: comparing SHA256SUMS =="
diff -u "${GOLDEN_DIR}/SHA256SUMS" "${OUT_DIR}/SHA256SUMS"

echo "== verify_golden: verifying per-file hashes from golden in new out dir =="
(
  cd "${OUT_DIR}"
  sha256sum -c "${GOLDEN_DIR}/SHA256SUMS"
)

echo "OK: reproduce.sh matches golden artifacts."
