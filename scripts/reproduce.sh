#!/usr/bin/env bash
set -euo pipefail

# Deterministic environment for M11
export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1}"

# If ECAC_TIME_MS is not set, derive it from SOURCE_DATE_EPOCH so all
# trust/audit timestamps are reproducible.
if [[ -z "${ECAC_TIME_MS:-}" ]]; then
  ECAC_TIME_MS="$((SOURCE_DATE_EPOCH * 1000))"
  export ECAC_TIME_MS
fi

# Default RUSTFLAGS for deterministic, stripped binaries unless caller overrides.
export RUSTFLAGS="${RUSTFLAGS:--C debuginfo=0 -C strip=symbols -C link-arg=-s}"

# Resolve repo root (scripts/..)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUT_DIR="${ROOT_DIR}/docs/eval/out"
DB_DIR="${ROOT_DIR}/.ecac.db"
AUDIT_DIR="${ROOT_DIR}/.audit"

# Clean previous state
rm -rf "${OUT_DIR}" "${DB_DIR}" "${AUDIT_DIR}"
mkdir -p "${OUT_DIR}"

export ECAC_DB="${DB_DIR}"
export ECAC_AUDIT_DIR="${AUDIT_DIR}"

echo "== M11 repro: building workspace =="
cargo build --workspace --release --locked --features audit --manifest-path "${ROOT_DIR}/Cargo.toml"

CLI="${ROOT_DIR}/target/release/ecac-cli"

# --------------------------------------------------------------------
# M7 scenarios – you MUST align these with your actual CLI.
# The spec expects:
#   - hb-chain
#   - concurrent
#   - offline-revoke
#
# I’m assuming a shape like:
#   ecac-cli bench run --scenario <name> --seed 42 \
#      --out-csv <file> --out-timeline <file> --out-state-json <file>
#
# If your flags differ, change JUST these invocations and keep the
# filenames exactly as per the M11 spec.
# --------------------------------------------------------------------

run_scenario() {
  local scenario="$1"   # hb-chain | concurrent | offline-revoke
  local seed="$2"       # 42
  local prefix="$3"     # hb-chain | concurrent | offline-revoke

  echo "== M11 repro: running ${scenario} (seed=${seed}) =="

  # Scenario-specific subdir where bench dumps whatever filenames it uses
  local subdir="${OUT_DIR}/${prefix}-${seed}"
  rm -rf "${subdir}"
  mkdir -p "${subdir}"

  "${CLI}" bench \
    --scenario "${scenario}" \
    --seed "${seed}" \
    --out-dir "${subdir}"

  # Now normalize to the canonical M11 filenames.
  # Assumptions:
  #   - exactly one CSV per subdir
  #   - exactly one JSONL (timeline) per subdir
  #   - exactly one JSON (state) per subdir

  local csv_src
  csv_src=$(printf '%s\n' "${subdir}"/*.csv | head -n1)
  local timeline_src
  timeline_src=$(printf '%s\n' "${subdir}"/*.jsonl | head -n1)
  local state_src
  state_src=$(printf '%s\n' "${subdir}"/*.json | head -n1)

  if [ ! -f "${csv_src}" ] || [ ! -f "${timeline_src}" ] || [ ! -f "${state_src}" ]; then
    echo "ERROR: missing artifacts in ${subdir}; got:"
    ls -l "${subdir}" || true
    exit 1
  fi

  cp "${csv_src}"      "${OUT_DIR}/${prefix}-${seed}.csv"
  cp "${timeline_src}" "${OUT_DIR}/${prefix}-${seed}-timeline.jsonl"
  cp "${state_src}"    "${OUT_DIR}/${prefix}-${seed}-state.json"
}

run_scenario hb-chain          42 hb-chain
run_scenario concurrent        42 concurrent
run_scenario offline-revocation 42 offline-revoke

# If you have a multi-peer / net scenario behind a feature, gate it:
# if "${CLI}" node --help >/dev/null 2>&1; then
#   echo "== M11 repro: running net scenario =="
#   "${CLI}" bench run \
#     --scenario net-multipeer \
#     --seed 42 \
#     --out-csv "${OUT_DIR}/net-multipeer-42.csv" \
#     --out-timeline "${OUT_DIR}/net-multipeer-42-timeline.jsonl" \
#     --out-state-json "${OUT_DIR}/net-multipeer-42-state.json"
# fi

# --------------------------------------------------------------------
# Audit + trust artifacts
# Assumes you’ve wired CLI subcommands that call:
#   cmd_audit_export, cmd_audit_verify, cmd_trust_dump
# If the flags are different, adjust here.
# --------------------------------------------------------------------

echo "== M11 repro: seeding store + audit log =="

DB_DIR=".ecac.db"
AUDIT_DIR=".audit"

rm -rf "$DB_DIR" "$AUDIT_DIR"
mkdir -p docs/eval/out

export ECAC_DB="$DB_DIR"
export ECAC_AUDIT_DIR="$AUDIT_DIR"

# Fixed node key for audit signatures (32-byte Ed25519 SK hex)
export ECAC_NODE_SK_HEX="0000000000000000000000000000000000000000000000000000000000000001"

# Fixed author key for deterministic minimal op
MIN_SK_HEX="1111111111111111111111111111111111111111111111111111111111111111"

MIN_OP="docs/eval/out/m11-min.op.cbor"

# 1) Generate deterministic minimal op
target/release/ecac-cli op-make-min "$MIN_SK_HEX" "$MIN_OP"

# 2) Append it into RocksDB with audit hook
target/release/ecac-cli op-append-audited --db "$DB_DIR" "$MIN_OP"

echo "== M11 repro: exporting audit log =="

# 3) Export deterministic JSONL
# The CLI writes 'audit.jsonl' in the current working directory.
target/release/ecac-cli audit-export

# Move it under OUT_DIR so it gets hashed and included in the tarball.
mv audit.jsonl "${OUT_DIR}/audit.jsonl"

# 4) Verify audit chain + DB consistency
# New CLI subcommand name: audit-verify-full (or audit-verify-chain if you only want the chain).
target/release/ecac-cli audit-verify-full > "${OUT_DIR}/audit.verify.txt"

# --------------------------------------------------------------------
# Hash outputs
# --------------------------------------------------------------------

echo "== M11 repro: hashing outputs =="
(
  cd "${OUT_DIR}"
  # Stable ordering before hashing.
  find . -type f ! -name 'SHA256SUMS' -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)

# --------------------------------------------------------------------
# Deterministic tarball bundling
# --------------------------------------------------------------------

GIT_SHA="$(git -C "${ROOT_DIR}" rev-parse --short=12 HEAD)"
TAR_NAME="ecac-artifacts-${GIT_SHA}.tar.gz"
TAR_PATH="${OUT_DIR}/${TAR_NAME}"

GIT_SHA="$(git -C "${ROOT_DIR}" rev-parse --short=12 HEAD)"
TAR_NAME="ecac-artifacts-${GIT_SHA}.tar.gz"
TAR_PATH="${OUT_DIR}/${TAR_NAME}"
TAR_TMP="${ROOT_DIR}/${TAR_NAME}"

echo "== M11 repro: creating tarball ${TAR_NAME} =="
(
  cd "${OUT_DIR}"
  tar \
    --sort=name \
    --mtime='UTC 1970-01-01' \
    --owner=0 --group=0 --numeric-owner \
    -czf "${TAR_TMP}" .
)

mv "${TAR_TMP}" "${TAR_PATH}"


echo
echo "OK: reproducible artifacts written to:"
echo "  ${OUT_DIR}"
echo "Tarball:"
echo "  ${TAR_PATH}"
echo
echo "SHA256SUMS:"
column -t "${OUT_DIR}/SHA256SUMS" | sed 's|^\./||'
