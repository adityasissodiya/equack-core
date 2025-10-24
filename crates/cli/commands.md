cargo run -p ecac-cli -- replay fixtures/hb_chain.cbor
cargo run -p ecac-cli -- replay fixtures/mv_concurrent.cbor
cargo run -p ecac-cli -- replay fixtures/orset_races.cbor

cargo run -p ecac-cli -- project fixtures/mv_concurrent.cbor o x
cargo run -p ecac-cli -- project fixtures/orset_races.cbor o s

cargo test -p ecac-cli --test e2e
cargo run -p ecac-cli --example make_fixtures