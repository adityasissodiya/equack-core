#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# Config / constants
# -------------------------

# Resolve repo root:
# this script lives at <root>/tools/scripts/m10.sh, so go two levels up.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$ROOT_DIR"

# Use a dedicated M10 DB so we don't ruin your existing .ecac.db
DB_DIR="${ROOT_DIR}/.ecac.m10.db"
export ECAC_DB="$DB_DIR"

# Hard-coded issuer identity for M10 experiments
ISSUER_ID="oem-issuer-1"
ISSUER_KEY_ID="key-1"
ISSUER_ALGO="EdDSA"

# 32-byte ed25519 seed (exactly 64 hex chars)
# DO NOT CHANGE LENGTH. If you want random, replace this with a 64-hex string.
ISSUER_SK_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# Validity window for the issuer key (ms since epoch)
VALID_FROM_MS=1700000000000
VALID_UNTIL_MS=1730000000000

# Status-list identifiers
LIST_ID="list-0"
STATUS_VERSION=1
CHUNK_INDEX=0
LIST_FILE="${ROOT_DIR}/${LIST_ID}.bin"

# Path to ecac-cli binary
BIN="${ROOT_DIR}/target/debug/ecac-cli"

# -------------------------
# Build CLI
# -------------------------

echo "==> Building ecac-cli (dev)..."
cargo build -p ecac-cli

echo "==> Using DB at: ${DB_DIR}"
# Nuke only the dedicated M10 DB if it exists (safe, isolated)
if [ -d "$DB_DIR" ]; then
  echo "    Removing existing ${DB_DIR} (M10 sandbox DB)..."
  rm -rf "$DB_DIR"
fi

# -------------------------
# Step 1: Publish IssuerKey (M10 in-band trust)
# -------------------------

echo
echo "==> Publishing IssuerKey via trust-issuer-publish"
echo "    issuer_id      = ${ISSUER_ID}"
echo "    key_id         = ${ISSUER_KEY_ID}"
echo "    algo           = ${ISSUER_ALGO}"
echo "    issuer_sk_hex  = ${ISSUER_SK_HEX}"
echo "    valid_from_ms  = ${VALID_FROM_MS}"
echo "    valid_until_ms = ${VALID_UNTIL_MS}"

"${BIN}" trust-issuer-publish \
  "${ISSUER_ID}" \
  "${ISSUER_KEY_ID}" \
  "${ISSUER_ALGO}" \
  "${ISSUER_SK_HEX}" \
  --valid-from-ms "${VALID_FROM_MS}" \
  --valid-until-ms "${VALID_UNTIL_MS}"

echo "==> IssuerKey op written into ${DB_DIR}"

# -------------------------
# Step 2: Create status list bitset + publish StatusListChunk
# -------------------------

echo
echo "==> Creating status bitset file ${LIST_FILE}"

# For now: 1 byte = 0x00 -> 8 entries, all 'not revoked'
# If you want entry 0 revoked, change to printf '\x01'.
printf '\x00' > "${LIST_FILE}"

# Compute SHA-256 over the raw bitset
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "FATAL: sha256sum not found in PATH. Install coreutils or add equivalent." >&2
  exit 1
fi

BITSET_SHA256_HEX="$(sha256sum "${LIST_FILE}" | awk '{print $1}')"

echo "    bitset_sha256_hex = ${BITSET_SHA256_HEX}"

echo "==> Publishing StatusListChunk via trust-status-chunk"
echo "    issuer_id      = ${ISSUER_ID}"
echo "    list_id        = ${LIST_ID}"
echo "    version        = ${STATUS_VERSION}"
echo "    chunk_index    = ${CHUNK_INDEX}"
echo "    chunk_path     = ${LIST_FILE}"
echo "    issuer_sk_hex  = ${ISSUER_SK_HEX}"

"${BIN}" trust-status-chunk \
  "${ISSUER_ID}" \
  "${LIST_ID}" \
  "${STATUS_VERSION}" \
  "${CHUNK_INDEX}" \
  "${LIST_FILE}" \
  "${ISSUER_SK_HEX}" \
  --bitset-sha256-hex "${BITSET_SHA256_HEX}"

echo "==> StatusListChunk op written into ${DB_DIR}"

# -------------------------
# Done / summary
# -------------------------

echo
echo "============================================================"
echo "M10 baseline setup complete."
echo
echo "DB:        ${DB_DIR}"
echo "Issuer ID: ${ISSUER_ID}"
echo "Key ID:    ${ISSUER_KEY_ID}"
echo "List ID:   ${LIST_ID}"
echo "Status ver:${STATUS_VERSION}, chunk=${CHUNK_INDEX}"
echo
echo "Next steps you can run manually:"
echo "  # Sanity: run core tests including M10 trustview/VC coupling"
echo "  cargo test -p ecac-core vc_policy_tests"
echo
echo "  # Inspect DB ops (using your existing replay tools, etc.)"
echo "  # or extend this script to drive keyrotate/grant-key/write flows."
echo "============================================================"
