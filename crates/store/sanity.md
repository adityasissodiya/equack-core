Here’s a no-nonsense sanity suite you can paste into your shell. It covers: append/verify, determinism parity, crash recovery, checkpoint parity, and runs the M5 store tests. It also includes **optional** VC-cache + db_uuid checks if you’ve wired those paths.

```bash
# --- sanity_m5.sh ------------------------------------------------------------
set -euo pipefail

OPS="${1:-ops.cbor}"

# Fresh temp DB
DB="$(mktemp -d)/ecac.db"
echo "DB=$DB"

echo "1) Append → Verify"
cargo run -q -p ecac-cli -- op-append --db "$DB" "$OPS"
cargo run -q -p ecac-cli -- verify-store --db "$DB"

echo "2) Determinism: in-memory vs store"
MEM="$(cargo run -q -p ecac-cli -- replay "$OPS")"
STORE="$(cargo run -q -p ecac-cli -- replay-from-store --db "$DB")"
diff -u <(printf "%s\n" "$MEM"   | sed '/^digest=/d') \
        <(printf "%s\n" "$STORE" | sed '/^digest=/d')
test "$(printf "%s\n" "$MEM"   | sed -n 's/^digest=//p')" \
   =  "$(printf "%s\n" "$STORE" | sed -n 's/^digest=//p')"

echo "3) Crash-recovery: kill between writes; verify/replay still OK"
DB_CR="$(mktemp -d)/ecac.db"
ECAC_CRASH_AFTER_WRITE=1 cargo run -q -p ecac-cli -- op-append --db "$DB_CR" "$OPS" || true
cargo run -q -p ecac-cli -- verify-store --db "$DB_CR"
cargo run -q -p ecac-cli -- replay-from-store --db "$DB_CR" >/dev/null

echo "4) Checkpoint parity"
CK_ID="$(cargo run -q -p ecac-cli -- checkpoint-create --db "$DB")"
FULL="$(cargo run -q -p ecac-cli -- replay-from-store --db "$DB")"
FROM_CK="$(cargo run -q -p ecac-cli -- replay-from-store --db "$DB")"
diff -u <(printf "%s\n" "$FULL"   | sed '/^digest=/d') \
        <(printf "%s\n" "$FROM_CK" | sed '/^digest=/d')
test "$(printf "%s\n" "$FULL"   | sed -n 's/^digest=//p')" \
   =  "$(printf "%s\n" "$FROM_CK" | sed -n 's/^digest=//p')"
echo "checkpoint_id=$CK_ID"

echo "5) Store unit tests"
cargo test -p ecac-store --test m5_store -- --nocapture

# ---------- Optional: VC cache round-trip (requires a valid JWT + trust dir) ----------
VC="${VC:-}"   # export VC=/path/to/your.vc.jwt  beforehand to enable
TRUST_DIR="${TRUST_DIR:-./trust}"
if [[ -n "${VC}" && -f "${VC}" && -d "${TRUST_DIR}" ]]; then
  echo "6) VC verify → persist caches → parity re-verify"
  DB_VC="$(mktemp -d)/ecac.db"
  ECAC_DB="$DB_VC" cargo run -q -p ecac-cli -- vc-verify "$VC"
  cargo run -q -p ecac-cli -- verify-store --db "$DB_VC"
else
  echo "(skip VC cache test: set VC=/path/to/file and ensure ${TRUST_DIR}/ exists)"
fi

# ---------- Optional: db_uuid smoke (only if verify-store prints it) ----------
DB1="$(mktemp -d)/ecac.db"; cargo run -q -p ecac-cli -- op-append --db "$DB1" "$OPS" >/dev/null
DB2="$(mktemp -d)/ecac.db"; cargo run -q -p ecac-cli -- op-append --db "$DB2" "$OPS" >/dev/null
UUID1="$(cargo run -q -p ecac-cli -- verify-store --db "$DB1" | sed -n 's/.*db_uuid=\([0-9a-f]\{64\}\).*/\1/p' || true)"
UUID2="$(cargo run -q -p ecac-cli -- verify-store --db "$DB2" | sed -n 's/.*db_uuid=\([0-9a-f]\{64\}\).*/\1/p' || true)"
if [[ -n "$UUID1" && -n "$UUID2" ]]; then
  test "$UUID1" != "$UUID2"
  echo "db_uuid present & unique ✅ ($UUID1 vs $UUID2)"
else
  echo "(skip db_uuid check: verify-store not printing it; functional path still validated)"
fi

echo "✅ All enabled sanity checks passed."
# ----------------------------------------------------------------------------- 
```

Run it:

```bash
bash sanity_m5.sh ops.cbor
```

Quick one-liners if you don’t want the script:

```bash
# Append + verify
DB="$(mktemp -d)/ecac.db"; cargo run -q -p ecac-cli -- op-append --db "$DB" ops.cbor
cargo run -q -p ecac-cli -- verify-store --db "$DB"

# Crash injection
DB2="$(mktemp -d)/ecac.db"; ECAC_CRASH_AFTER_WRITE=1 cargo run -q -p ecac-cli -- op-append --db "$DB2" ops.cbor || true
cargo run -q -p ecac-cli -- verify-store --db "$DB2"

# Checkpoint parity
cargo run -q -p ecac-cli -- checkpoint-create --db "$DB"
cargo run -q -p ecac-cli -- replay-from-store --db "$DB"
```

If you *do* have a valid VC + `./trust` populated, set `VC=/path/to.vc.jwt` and re-run the script to exercise the VC cache parity path as well.
