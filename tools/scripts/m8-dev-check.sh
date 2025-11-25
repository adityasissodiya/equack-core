#!/usr/bin/env bash
# m8-dev-check.sh — essential sanity for ECAC audit/M8 work
# Usage: scripts/m8-dev-check.sh [--keep] [--no-build] [--verbose]

set -Eeuo pipefail
IFS=$'\n\t'

KEEP=0
NOBUILD=0
VERBOSE=0
while (( $# )); do
  case "$1" in
    --keep)    KEEP=1 ;;
    --no-build) NOBUILD=1 ;;
    --verbose|-v) VERBOSE=1 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

log() { printf '%s\n' "$*" >&2; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }
run() {
  if (( VERBOSE )); then printf '>> %s\n' "$*" >&2; fi
  eval "$@"
}

need() { command -v "$1" >/dev/null 2>&1 || die "missing required cmd: $1"; }

# --- preflight ---------------------------------------------------------------
need cargo
need grep
need stat
need python3
need truncate || true # BSD/macOS has /usr/bin/truncate; if not, we fallback via dd

[ -f Cargo.toml ] || die "run from repo root (no Cargo.toml found)"

# Defaults (can be overridden via exported env)
: "${ECAC_NODE_SK_HEX:=0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210}"
WORKDIR="$(mktemp -d -t m8dev.XXXXXX)"
DB="$WORKDIR/.m8test.db"
AUD="$DB/audit"

cleanup() {
  (( KEEP )) && { log "keeping workdir: $WORKDIR"; return; }
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

log "workdir: $WORKDIR"
log "ECAC_NODE_SK_HEX: ${ECAC_NODE_SK_HEX:0:8}… (len=${#ECAC_NODE_SK_HEX})"

# --- optional build gate -----------------------------------------------------
if (( ! NOBUILD )); then
  run "cargo check -q -p ecac-store -p ecac-cli --features audit"
fi

# --- helpers -----------------------------------------------------------------
expect_fail_with() {
  local pattern="$1"; shift
  set +e
  out="$("$@" 2>&1)"; rc=$?
  set -e
  (( rc != 0 )) || { printf '%s\n' "$out" >&2; die "expected failure, but rc=0"; }
  printf '%s\n' "$out" | grep -Ei -- "$pattern" >/dev/null || {
    printf 'stderr:\n%s\n' "$out" >&2
    die "failure didn't match /$pattern/"
  }
}

verify_ok() {
  local what="$1"; shift
  run "$@"
  log "OK: $what"
}

# --- 1) Clean good-path round trip ------------------------------------------
log "== good path: record → verify-chain → verify-full =="

export ECAC_AUDIT_DIR="$AUD"
run "ECAC_NODE_SK_HEX=$ECAC_NODE_SK_HEX ECAC_AUDIT_DIR=$AUD cargo run -q -p ecac-cli --features audit -- audit-record --db $DB"
verify_ok "audit-verify-chain" cargo run -q -p ecac-cli --features audit -- audit-verify-chain --dir "$AUD"
verify_ok "audit-verify-full"  cargo run -q -p ecac-cli --features audit -- audit-verify-full  --db "$DB"

# append a second entry to exercise index resume
run "ECAC_NODE_SK_HEX=$ECAC_NODE_SK_HEX ECAC_AUDIT_DIR=$AUD cargo run -q -p ecac-cli --features audit -- audit-record --db $DB"
verify_ok "audit-verify-chain (after second append)" cargo run -q -p ecac-cli --features audit -- audit-verify-chain --dir "$AUD"

# quick structure check
[ -f "$AUD/index.json" ] || die "missing index.json"
SEG="$(printf '%s/segment-00000001.log' "$AUD")"
[ -s "$SEG" ] || die "empty first segment"
log "segment size: $(stat -c '%s' "$SEG" 2>/dev/null || stat -f '%z' "$SEG") bytes"

# --- 2) Negative: truncation should be detected ------------------------------
log "== negative path: truncation should fail =="
TRUNC_DIR="$WORKDIR/trunc"
run "mkdir -p '$TRUNC_DIR' && cp -a '$AUD' '$TRUNC_DIR/'"
TSEG="$TRUNC_DIR/audit/segment-00000001.log"

if command -v truncate >/dev/null 2>&1; then
  run "truncate -s -1 '$TSEG'"
else
  # POSIX-ish fallback: drop last byte
  sz="$(stat -c '%s' "$TSEG" 2>/dev/null || stat -f '%z' "$TSEG")"
  (( sz > 0 )) || die "segment too small to truncate"
  run "dd if=/dev/zero of='$TSEG' bs=1 seek=$((sz-1)) count=0 conv=notrunc 2>/dev/null"
  # portable truncate-by-1 via Python (cannot embed heredoc inside run/eval)
  (( VERBOSE )) && printf ">> python3 - '%s' <<'PY'  # truncate last byte\n" "$TSEG" >&2
  python3 - "$TSEG" <<'PY'
import os, sys
p = sys.argv[1]
sz = os.path.getsize(p)
with open(p, 'rb+') as f:
    f.truncate(sz - 1)
PY
fi

expect_fail_with 'truncated record' \
  cargo run -q -p ecac-cli --features audit -- audit-verify-chain --dir "$TRUNC_DIR/audit"

# --- 3) Negative: bit flip should invalidate signature -----------------------
log "== negative path: corruption → signature invalid (or parse error) =="
FLIP_DIR="$WORKDIR/flip"
run "mkdir -p '$FLIP_DIR' && cp -a '$AUD' '$FLIP_DIR/'"
FSEG="$FLIP_DIR/audit/segment-00000001.log"

# Flip a mid-payload byte to preserve length prefix; aim for CBOR-valid area.
# (Do not wrap in run/eval; here-documents must be at top level.)
(( VERBOSE )) && printf ">> python3 - '%s' <<'PY'  # flip a payload byte\n" "$FSEG" >&2
python3 - "$FSEG" <<'PY'
import sys
p = sys.argv[1]
with open(p, 'rb') as f:
    b = bytearray(f.read())
if len(b) < 64:
    raise SystemExit(1)
start = 4  # skip 4-byte length prefix
idx = min(max(start + 32, len(b)//2), len(b) - 1)
b[idx] ^= 0x01
with open(p, 'wb') as f:
    f.write(b)
PY


# Accept either signature failure or decode failure; both must be non-zero.
expect_fail_with 'signature invalid|truncated record' \
  cargo run -q -p ecac-cli --features audit -- audit-verify-chain --dir "$FLIP_DIR/audit"

# --- 4) (Optional) CLI ops smoke (M8 helpers) --------------------------------
log "== CLI ops smoke =="
TMP="$WORKDIR/tmpops"; run "mkdir -p '$TMP'"
GOOD="$TMP/good.cbor"; ORPH="$TMP/orphan.cbor"
run "cargo run -q -p ecac-cli -- op-make-min '$ECAC_NODE_SK_HEX' '$GOOD'"
run "cargo run -q -p ecac-cli -- op-append --db '$DB' '$GOOD'"
run "cargo run -q -p ecac-cli -- op-make-orphan '$GOOD' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' '$ORPH'"
run "cargo run -q -p ecac-cli -- op-append --db '$DB' '$ORPH'"
verify_ok "audit-verify-full (after ops)" cargo run -q -p ecac-cli --features audit -- audit-verify-full --db "$DB"

log "All checks passed."
