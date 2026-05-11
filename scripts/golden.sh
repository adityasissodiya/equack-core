#!/usr/bin/env bash
set -euo pipefail

# Deterministic-ish environment, just to be consistent.
export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/docs/eval/out"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/golden-artifacts.tar.gz" >&2
  exit 1
fi

GOLDEN_TAR="$1"

if [[ ! -f "${GOLDEN_TAR}" ]]; then
  echo "ERROR: golden tarball not found: ${GOLDEN_TAR}" >&2
  exit 1
fi

shopt -s nullglob
LOCAL_TARS=( "${OUT_DIR}"/ecac-artifacts-*.tar.gz )
shopt -u nullglob

if [[ ${#LOCAL_TARS[@]} -eq 0 ]]; then
  echo "ERROR: no local artifacts tarball in ${OUT_DIR}; run scripts/reproduce.sh first." >&2
  exit 1
elif [[ ${#LOCAL_TARS[@]} -gt 1 ]]; then
  echo "ERROR: multiple local artifact tarballs in ${OUT_DIR}; clean up and rerun scripts/reproduce.sh." >&2
  printf '  %s\n' "${LOCAL_TARS[@]}" >&2
  exit 1
fi

LOCAL_TAR="${LOCAL_TARS[0]}"

echo "Local tarball:  ${LOCAL_TAR}"
echo "Golden tarball: ${GOLDEN_TAR}"
echo

local_hash=$(sha256sum "${LOCAL_TAR}"   | cut -d' ' -f1)
golden_hash=$(sha256sum "${GOLDEN_TAR}" | cut -d' ' -f1)

echo "Local SHA256:  ${local_hash}"
echo "Golden SHA256: ${golden_hash}"
echo

if [[ "${local_hash}" == "${golden_hash}" ]]; then
  echo "OK: local artifacts tarball matches golden tarball bit-for-bit."
  exit 0
else
  echo "ERROR: local artifacts tarball does NOT match golden tarball." >&2
  exit 1
fi
