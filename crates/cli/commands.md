cargo run -p ecac-cli -- replay fixtures/hb_chain.cbor
cargo run -p ecac-cli -- replay fixtures/mv_concurrent.cbor
cargo run -p ecac-cli -- replay fixtures/orset_races.cbor

cargo run -p ecac-cli -- project fixtures/mv_concurrent.cbor o x
cargo run -p ecac-cli -- project fixtures/orset_races.cbor o s

cargo test -p ecac-cli --test e2e
cargo run -p ecac-cli --example make_fixtures

### CLI usage

```bash
# Verify a JWT-VC under ./trust
ecac-cli vc-verify <vc.jwt>

# Attach a verified VC (emit Credential + Grant ops in CBOR)
ecac-cli vc-attach <vc.jwt> <issuer_sk_hex> <admin_sk_hex> [out_dir]

# Flip a single revocation bit (little-endian: byte=index/8, bit=index%8)
ecac-cli vc-status-set <list_id> <index> <0|1|true|false|on|off>

# Replay and project (existing)
ecac-cli replay <ops.cbor>
ecac-cli project <ops.cbor> <obj> <field>

# Set bit 1 in trust/status/list-0.bin (revoke)
ecac-cli vc-status-set list-0 1 1

# Clear it again (un-revoke)
ecac-cli vc-status-set list-0 1 0

# Verify VC (will error when revoked)
ecac-cli vc-verify fixtures/example.jwt

Exit codes

Success: 0

Any validation/replay/IO error: 1 (error message printed to stderr)


You don’t have a globally installed `ecac-cli` yet—you’ve only been running it via `cargo run`. Use one of these:

### Quickest (run from repo)

```bash
# Debug build
cargo build -p ecac-cli
./target/debug/ecac-cli --help
./target/debug/ecac-cli vc-status-set list-0 1 1
./target/debug/ecac-cli vc-verify fixtures/example.jwt

# Or release build
cargo build -p ecac-cli --release
./target/release/ecac-cli vc-status-set list-0 1 0
```

### One-liner run (no install)

```bash
cargo run -p ecac-cli -- vc-status-set list-0 1 1
cargo run -p ecac-cli -- vc-verify fixtures/example.jwt
```

### Install to your PATH

```bash
# From the repo root:
cargo install --path crates/cli --force

# Ensure ~/.cargo/bin is on PATH (if needed):
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Now works anywhere:
ecac-cli --help
ecac-cli vc-status-set list-0 1 1
ecac-cli vc-verify fixtures/example.jwt
```

Tip: if you still get “command not found” after `cargo install`, your shell likely doesn’t have `~/.cargo/bin` in `PATH`—add it as shown above.

Here’s a quick, copy-pasteable sanity checklist for M4. Run from your repo root.

---

# 0) Clean build & tests

```bash
# Build everything
cargo build --workspace

# Core unit + integration tests (including new VC tests)
cargo test -p ecac-core --tests
cargo test -p ecac-core --lib

# Whole workspace (optional)
cargo test --workspace
```

---

# 1) CLI wiring & help

```bash
# Top-level help
cargo run -p ecac-cli -- --help

# Subcommand-specific help (including vc-status-set)
cargo run -p ecac-cli -- vc-status-set --help
cargo run -p ecac-cli -- vc-verify --help
cargo run -p ecac-cli -- vc-attach --help
```

---

# 2) VC verify (happy path) with your existing fixture

```bash
# Use whichever you created earlier (example.jwt or example2.jwt)
cargo run -p ecac-cli -- vc-verify fixtures/example2.jwt
# Expect: JSON with issuer, role, scope, nbf/exp, status list/id, cred_hash
```

---

# 3) CLI non-zero exit on failure (quick check)

```bash
# Intentionally bad path → should print error and exit non-zero
cargo run -p ecac-cli -- vc-verify DOES_NOT_EXIST 2>/dev/null || echo "exit=$?"
# Expect: exit=<non-zero>, e.g. exit=101
```

---

# 4) End-to-end replay: allowed → revoke → denied

> If you still have these env vars from earlier, reuse them. Otherwise:

```bash
# If needed, generate fresh keys
export ISSUER_SK_HEX=$(openssl rand -hex 32)
export ADMIN_SK_HEX=$(openssl rand -hex 32)
export SUBJECT_SK_HEX=$(openssl rand -hex 32)

# Make folders
mkdir -p trust/status fixtures demo
```

## 4a) Create/verify VC and pin issuer

```bash
# Make a demo VC (prints issuer_vk_hex; copy into issuers.toml)
cargo run -p ecac-cli --example make_jwt_subject -- "$ISSUER_SK_HEX" "$SUBJECT_SK_HEX" fixtures/demo.jwt

# Pin issuer VK in trust/issuers.toml (paste the printed issuer_vk_hex)
# Example:
cat > trust/issuers.toml <<'EOF'
[issuers]
oem-issuer-1 = "<PASTE_issuer_vk_hex>"
EOF

# Verify VC under trust/
cargo run -p ecac-cli -- vc-verify fixtures/demo.jwt
```

## 4b) Attach VC → (Credential + Grant) ops

```bash
cargo run -p ecac-cli -- vc-attach fixtures/demo.jwt "$ISSUER_SK_HEX" "$ADMIN_SK_HEX" demo/
# Expect: writes demo/cred.op.cbor and demo/grant.op.cbor, prints op_ids and cred_hash
```

## 4c) Make a write op by the subject

```bash
cargo run -p ecac-cli --example make_write -- "$SUBJECT_SK_HEX" 15000 mv:o:x OK demo/write.op.cbor
```

## 4d) Replay (should be ALLOWED with status bit clear)

```bash
cargo run -p ecac-cli --example vc_replay -- demo/cred.op.cbor demo/grant.op.cbor demo/write.op.cbor
# Expect: "... → ALLOWED"
```

## 4e) Flip revocation bit → replay (should be DENIED)

```bash
# Set bit (list-0, index 1 → adjust if your VC printed a different index)
cargo run -p ecac-cli -- vc-status-set list-0 1 1

# (Optional) peek file to see the bit changed
hexdump -C trust/status/list-0.bin

# Replay again
cargo run -p ecac-cli --example vc_replay -- demo/cred.op.cbor demo/grant.op.cbor demo/write.op.cbor
# Expect: "... → DENIED"
```

---

# 5) Scope intersection quick checks

```bash
# Write in MV tag ("hv") → allowed if VC scope contains "hv"
cargo run -p ecac-cli --example make_write -- "$SUBJECT_SK_HEX" 16000 mv:o:y OK demo/write2.op.cbor
cargo run -p ecac-cli --example vc_replay -- demo/cred.op.cbor demo/grant.op.cbor demo/write2.op.cbor

# Write in a SET tag ("mech") → should be DENIED if VC scope lacks "mech"
cargo run -p ecac-cli --example make_write -- "$SUBJECT_SK_HEX" 17000 set+:o:s:e VAL demo/write3.op.cbor
cargo run -p ecac-cli --example vc_replay -- demo/cred.op.cbor demo/grant.op.cbor demo/write3.op.cbor
```

---

# 6) Optional: issuer→schema allowlist (if you enabled it)

```bash
# Add a schema label (no behavior change right now; guardrail for future)
cat >> trust/issuers.toml <<'EOF'
[schemas]
oem-issuer-1 = "standard-v1"
EOF

# Re-run verify
cargo run -p ecac-cli -- vc-verify fixtures/demo.jwt
```

---

# 7) Lints & formatting (optional but nice)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

That’s it—if all of the above behaves as expected (tests green, vc-verify prints claims, replay toggles with `vc-status-set`, bad inputs fail non-zero), M4 is in good shape.
