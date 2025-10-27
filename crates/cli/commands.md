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
