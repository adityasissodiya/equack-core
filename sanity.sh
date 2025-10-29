set -euo pipefail
OPS="${1:-ops.cbor}"

DB="$(mktemp -d)/ecac.db"
echo "DB=$DB"

# 1) Append → verify
cargo run -q -p ecac-cli -- op-append --db "$DB" "$OPS"
cargo run -q -p ecac-cli -- verify-store --db "$DB"

# 2) Determinism: file replay vs store replay
MEM="$(cargo run -q -p ecac-cli -- replay "$OPS")"
STORE="$(cargo run -q -p ecac-cli -- replay-from-store --db "$DB")"

MEM_JSON="$(printf "%s\n" "$MEM"   | sed '/^digest=/d')"
STORE_JSON="$(printf "%s\n" "$STORE" | sed '/^digest=/d')"
diff -u <(printf "%s\n" "$MEM_JSON") <(printf "%s\n" "$STORE_JSON")

MEM_DIG="$(printf "%s\n" "$MEM"   | sed -n 's/^digest=//p')"
STORE_DIG="$(printf "%s\n" "$STORE" | sed -n 's/^digest=//p')"
test "$MEM_DIG" = "$STORE_DIG"

# 3) Checkpoint parity (equals current store state)
CK_ID="$(cargo run -q -p ecac-cli -- checkpoint-create --db "$DB")"
CK_JSON="$(cargo run -q -p ecac-cli -- checkpoint-load --db "$DB" "$CK_ID" 2>/dev/null)"
diff -u <(printf "%s\n" "$STORE_JSON") <(printf "%s\n" "$CK_JSON")

# 4) Crash-recovery: kill mid-append of a large batch, then finish
TMPDIR="$(mktemp -d)"
# make a large batch (500 copies) to ensure we can kill in-flight
for i in $(seq -w 0001 0500); do cp "$OPS" "$TMPDIR/$i.cbor"; done

DB2="$(mktemp -d)/ecac.db"
( cargo run -q -p ecac-cli -- op-append --db "$DB2" "$TMPDIR" & echo $! > "$TMPDIR/pid" )
sleep 0.2
# it's OK if the process already finished; ignore failure
kill -9 "$(cat "$TMPDIR/pid")" 2>/dev/null || true

# finish append and verify
cargo run -q -p ecac-cli -- op-append --db "$DB2" "$TMPDIR"
cargo run -q -p ecac-cli -- verify-store --db "$DB2"

STORE2="$(cargo run -q -p ecac-cli -- replay-from-store --db "$DB2")"
STORE2_JSON="$(printf "%s\n" "$STORE2" | sed '/^digest=/d')"
STORE2_DIG="$(printf "%s\n" "$STORE2" | sed -n 's/^digest=//p')"

diff -u <(printf "%s\n" "$STORE_JSON") <(printf "%s\n" "$STORE2_JSON")
test "$STORE_DIG" = "$STORE2_DIG"

# 5) Idempotence across runs
for i in 1 2 3; do
  cargo run -q -p ecac-cli -- replay-from-store --db "$DB" | sed -n 's/^digest=//p'
done | awk 'NR==1{s=$1} NR>1 && $1!=s{print "digest changed"; exit 1} END{print "stable digest stream ok"}'

echo "✅ Sanity suite passed."
