# Repository Guidelines

## Project Structure & Module Organization
- Rust workspace anchored by `Cargo.toml`; main crates live under `crates/` (`core` state machine and policy logic, `store` RocksDB persistence, `net` libp2p sync, `cli` for `ecac-cli`, `ui` for demos).
- Integration and property tests sit in `tests/` (e.g., convergence, policy safety). Fixtures and CBOR/JWT samples live in `fixtures/`, `fixtures_m5/`, and root `.cbor`/`.jwt` files. Scripts for reproducible runs: `scripts/`, `tools/scripts/`.
- Docs and diagrams: `docs/`, `milestones/`, `techstack-diagram.*`; examples and experiments in `examples/`, `experiments/`.

## Build, Test, and Development Commands
- `cargo build --workspace --locked` (add `--release` for benchmarks) builds all crates with the pinned toolchain in `rust-toolchain.toml`.
- `cargo fmt` then `cargo clippy --all-targets --all-features -D warnings` before sending changes.
- `cargo test --workspace --all-features` runs unit + integration suites; keep deterministic env (`TZ=UTC SOURCE_DATE_EPOCH=1` when reproducing).
- `make repro` (or `bash scripts/reproduce.sh`) generates deterministic artifacts and hashes under `docs/eval/out/`; `make audit` runs `cargo audit` and `cargo deny`.
- `target/release/ecac-cli ...` commands expect `ECAC_DB`/`ECAC_AUDIT_DIR` paths; defaults are `.ecac.db` and `.audit` when using `scripts/reproduce.sh`.

## Coding Style & Naming Conventions
- Standard Rust style via `rustfmt` (4-space indent). Keep modules/functions in `snake_case`; types/traits in `CamelCase`; constants in `SCREAMING_SNAKE_CASE`.
- Prefer small, deterministic helpers; propagate errors with `anyhow::Result`/`?` as used in existing code. Avoid panics except in tests or impossible states with comments.
- Keep serialization stable (canonical CBOR, deterministic ordering); note when new fields affect hashing/op-id computation.

## Testing Guidelines
- Integration scenarios live in `tests/` (convergence, replay determinism, policy safety). Add new cases near existing patterns and name files `feature_behavior.rs`.
- For reproducibility-sensitive paths, fix time inputs (`SOURCE_DATE_EPOCH`, `ECAC_TIME_MS`) and document seeds. Include fixtures under `fixtures/` and reference them explicitly.
- When touching networking or audit, assert deterministic ordering and hash expectations; prefer property-style tests over golden files when possible.

## Phase-by-Phase Experiment Plan (per evaluation.tex)
- **Phase 0 – Environment & CLI verification**: Install toolchain in `rust-toolchain.toml`; set `TZ=UTC SOURCE_DATE_EPOCH=1 ECAC_TIME_MS=$((SOURCE_DATE_EPOCH*1000))`. Build once via `cargo build --workspace --release --locked --features audit` (no crate edits). Smoke-check `target/release/ecac-cli --help`, `ecac-cli bench --help`, `ecac-cli audit-verify-full --help` to ensure required subcommands exist. Prep clean state dirs: `rm -rf .ecac.db .audit docs/eval/out && mkdir -p docs/eval/out`. Record platform (CPU/RAM/OS/kernel) for reproducibility notes in evaluation.tex.
- **Phase 1 – Property Validation (E1–E5)**:  
  - `core`: generate canonical logs/workloads W1–W5 via CLI.  
  - `store`: run replay order permutations (E1), cross-platform digests (E2), revocation/deny-wins (E3), multi-issuer conflicts (E4), audit tamper checks (E5). Capture state digests and audit verification output.  
  - Commands: `ecac-cli bench --scenario <wX> --seed <s> --out-dir <dir>`; `ecac-cli audit-verify-full`.
- **Phase 2 – Scalability & Performance (E6–E10)**:  
  - `core`/`store`: measure full vs incremental replay across 10K–10M ops; checkpoint intervals (25/50/75/90%).  
  - `net`: throughput with concurrent writers and partitioned keyspaces (E7); sync overhead.  
  - Artifacts under `docs/eval/out/`; use `make repro` as baseline, add additional log sizes with consistent naming.
- **Phase 3 – Revocation Propagation (E11–E12)**:  
  - `net`: partition simulations (6–10 nodes), measure enforcement delay and convergence time/bandwidth after healing. Use `tc/netem` configs noted in evaluation.tex; record p50/p95 times and bytes/op.
- **Phase 4 – Confidentiality Overhead (E13–E14)**:  
  - `core`: enable per-tag encryption and key rotation intervals; `store`: measure storage overhead; `cli`: profile append/replay latency. Report throughput deltas and bytes/op.
- **Phase 5 – Reporting**: Populate evaluation.tex placeholders with tables for E1, E3, E6, E11 first; include seeds, hardware, command lines, and hashes. Keep all raw outputs reproducible in `docs/eval/out/` with `SHA256SUMS`.

## Commit & Pull Request Guidelines
- Recent history favors concise, present-tense titles (`sensor p2p demo`, `updating readme`). Use short, imperative summaries (<70 chars) plus details in the body if needed.
- Reference issues (`#123`) and call out breaking changes, new features, or migrations.
- Before opening a PR: run fmt/clippy/tests, note which commands were executed, and attach relevant artifacts or screenshots for CLI/UI output. Describe any reproducibility or trust/audit implications of the change.

## Security & Configuration Tips
- Do not commit secrets (e.g., `ECAC_NODE_SK_HEX`); use local env vars instead. Clean `.ecac.db` and `.audit` outputs before pushing.
- When adding new CLI flags or file outputs, keep paths under `docs/eval/out/` or `.ecac.*` to avoid polluting the repo root and to preserve deterministic tarball creation.
