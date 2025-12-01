#!/usr/bin/env bash
set -euo pipefail

# Run from repo root (same place you run `cargo run -p ecac-cli -- ...`)
cd "$(dirname "$0")"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for this demo (apt install jq / brew install jq)" >&2
  exit 1
fi

echo "== M9 VC-backed grant demo =="

# 0) Fresh DB + trust
rm -rf .ecac.db trust
mkdir -p trust/status

export ECAC_DB=".ecac.db"

echo
echo "== 1) Mint VC + trust config =="
info=$(cargo run -q -p ecac-cli -- vc-mint-demo)

echo "$info" | jq .

issuer_vk_hex=$(echo "$info" | jq -r '.issuer_vk_hex')
subject_pk_hex=$(echo "$info" | jq -r '.subject_pk_hex')
vc_path=$(echo "$info" | jq -r '.vc_path')

echo
echo "issuer_vk_hex  = ${issuer_vk_hex}"
echo "subject_pk_hex = ${subject_pk_hex}"
echo "vc_path        = ${vc_path}"

echo
echo "== 2) Key admin: rotate 'confidential' once =="

export ECAC_KEYADMIN_SK_HEX
ECAC_KEYADMIN_SK_HEX=$(openssl rand -hex 32)
echo "ECAC_KEYADMIN_SK_HEX=${ECAC_KEYADMIN_SK_HEX}"

cargo run -q -p ecac-cli -- keyrotate confidential

echo
echo "== 3) Writer: emit confidential value o.x = \"hello\" =="

export ECAC_SUBJECT_SK_HEX
ECAC_SUBJECT_SK_HEX=$(openssl rand -hex 32)
echo "ECAC_SUBJECT_SK_HEX=${ECAC_SUBJECT_SK_HEX}"

cargo run -q -p ecac-cli -- write data o x "hello"

echo
echo "== 4) Grant key for VC subject on (confidential, version=1) =="

cargo run -q -p ecac-cli -- grant-key "${subject_pk_hex}" confidential 1 "${vc_path}"

echo
echo "== 5) Show o.x as VC subject (should see: hello) =="
cargo run -q -p ecac-cli -- show o x --subject-pk "${subject_pk_hex}"

echo
echo "== 6) Show o.x as some other subject (should be redacted) =="

other_pk_hex=$(openssl rand -hex 32)   # just 32 random bytes as hex; doesn't need to be a real keypair
echo "unauthorized subject_pk_hex = ${other_pk_hex}"
cargo run -q -p ecac-cli -- show o x --subject-pk "${other_pk_hex}"

echo
echo "== Done =="
