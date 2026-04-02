<div align="center">
  <h1>🦆 ECAC-core</h1>
  <p><strong>Eventually Consistent Access Control with Deterministic Deny-Wins Replay for Multi-Stakeholder Offline Systems.</strong></p>
  <p>
    <a href="https://github.com/adityasissodiya/equack-core/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" alt="Build"></a>
    <a href="https://github.com/adityasissodiya/equack-core/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License"></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.85%2B-orange.svg?style=flat-square" alt="Rust Version"></a>
  </p>
</div>

> A Rust implementation of a deterministic access-control substrate built around a signed, hash-linked causal operation log with VC-backed authorization, in-band trust, tamper-evident audit, and reproducible evaluation artifacts.

## 📂 Repository Layout

```
crates/
  core/       Deterministic core: ops, DAG, HLC, replay, policy, trust, CRDTs, crypto
  store/      RocksDB-backed persistence, checkpoints, audit writer/reader
  net/        libp2p networking, gossip, sync protocol
  cli/        CLI tool, benchmarks, server, e2e tests
tests/        Top-level integration tests
examples/     Example scenarios
fixtures/     Test fixtures (CBOR logs, JWTs)
schemas/      Protocol and VC schema artifacts
scripts/      Reproduction, golden-artifact verification, sanity tests
tools/        M7 evaluation grid scripts, checks, plotting
docs/         Architecture, protocol, policy, audit, evaluation documentation
  eval/       Evaluation results, plots, and methodology
deploy/       Docker and partition-simulation tooling
```

## 🚀 Quick Start

### 📋 Prerequisites

- **Rust 1.85** (pinned via `rust-toolchain.toml`; installed automatically by `rustup`)
- A C toolchain for RocksDB (the `rocksdb` crate requires `libclang` and a C compiler)
- **Python 3** and `matplotlib` (only for plotting scripts)

### 🛠️ Build

```bash
cargo build --workspace --locked --release
```

### 🧪 Test

```bash
cargo test --workspace --locked
```

### 📊 Reproduce Paper Artifacts

The canonical reproduction script builds the workspace, runs all benchmark scenarios, generates audit and trust artifacts, computes SHA-256 hashes, and bundles a deterministic tarball:

```bash
scripts/reproduce.sh
```

Outputs land in `docs/eval/out/`. To verify against a golden artifact set:

```bash
scripts/golden.sh /path/to/golden-artifacts.tar.gz
scripts/verify_golden.sh
```

The `Makefile` provides shorthand targets:

| Target           | Description                              |
|------------------|------------------------------------------|
| `make test`      | Run workspace tests                      |
| `make repro`     | Run `scripts/reproduce.sh`               |
| `make verify-golden` | Verify against golden artifacts      |
| `make m7`        | Run M7 evaluation grid (quick mode)      |
| `make plots`     | Generate evaluation plots                |

## 🏗️ Design Overview

ECAC-core is a deterministic state machine driven by a signed, hash-linked operation log:

1. **Signed operations** -- Each op has a canonical CBOR header (parents, HLC, author key, payload). Op-ids are `BLAKE3("ECAC_OP_V1" || canonical_header)`, signed with Ed25519.

2. **Causal DAG** -- Ops reference parents, forming a DAG. A pending-parent buffer holds children until all parents arrive. Deterministic topological order breaks ties by `(HLC, op_id)`.

3. **Deny-wins replay** -- Replay walks the DAG in topo order. If no valid VC-backed credential chain exists (expired, revoked, out of scope), data ops are deterministically skipped.

4. **VC-backed authorization** -- Grants reference JWT-VCs via `cred_hash = BLAKE3(jwt_bytes)`. VC verification checks EdDSA signatures, time windows, scopes, and revocation status.

5. **In-band trust** -- Issuer keys, revocations, and status lists are themselves signed ops. A deterministic `TrustView` is assembled from the log (first-wins keys, latest-complete status lists).

6. **CRDT state** -- Authorized writes drive CRDTs (MVReg, OR-Set). Deterministic replay ensures identical final state for a fixed op-log.

7. **Durable store** -- RocksDB persistence with checkpoints. Checkpoint + incremental replay matches full replay.

8. **Networking** -- Optional libp2p layer with gossipsub announcements and frontier-based sync.

9. **Audit** -- Ed25519-signed, BLAKE3-linked audit log. CLI commands verify chain integrity and cross-check against replay.

10. **Confidentiality** *(experimental)* -- Per-tag XChaCha20-Poly1305 encryption with VC-backed key grants. Functionally incomplete (over-redacts); de-emphasized in favor of in-band trust.

### 📚 Documentation Reference

| Document | Description |
|----------|-------------|
| 📐 [`docs/architecture.md`](docs/architecture.md) | System architecture |
| 🔌 [`docs/protocol.md`](docs/protocol.md) | Wire protocol |
| 🛡️ [`docs/policy-model.md`](docs/policy-model.md) | Policy semantics |
| 🔎 [`docs/audit.md`](docs/audit.md) | Audit subsystem |
| 🤝 [`docs/m10_inband_trust.md`](docs/m10_inband_trust.md) | In-band trust model |
| 📈 [`docs/eval/RESULTS.md`](docs/eval/RESULTS.md) | Evaluation results |

## 🌟 Highlighted Evaluation Results

> **Note:** Full plots and detailed metrics are available in [`docs/eval/plots/`](docs/eval/plots/).

| Experiment | Key Result |
|-----------|-----------|
| E1: Convergence | 100% convergence across 100 randomized orderings (10K ops) |
| E6: Replay scaling | Linear O(n); 20K ops in 500ms, 10x speedup with checkpoints |
| E7: Throughput | 40-50K ops/s (linear), 4-10K ops/s (concurrent 8 writers) |
| E10: Checkpoints | 10x speedup at 20K ops with 90% checkpoint |

## 🔐 Guarantees

- **Deterministic replay**: identical op set and trust inputs produce identical state, regardless of insertion order or crash boundaries.
- **Deny-wins safety**: any VC verification failure causes data ops to be skipped, never partially applied.
- **In-band trust correctness**: TrustView assembly is deterministic and gated by `issuer_admin`.
- **Crash consistency**: RocksDB writes are crash-safe; no op is visible without all parents present.
- **Audit integrity**: append-only, hash-linked, signed log with replay cross-check.
- **Reproducible artifacts**: `scripts/reproduce.sh` yields bit-for-bit identical outputs for the same commit and toolchain.

## ⚠️ Limitations

- **Confidentiality**: per-tag encryption is implemented but functionally incomplete (authorized subjects still see `<redacted>`).
- **Trust model**: no StatusPointer support, no multi-issuer quorums, no advanced key rollover.
- **Networking**: not part of the reproduction pipeline; optional and tested separately.
- **Audit repair**: crash-tail truncation is detected but not automatically repaired.

ECAC-core is a research prototype, not a production access-control system.

## ⚙️ Toolchain

| Component | Version |
|-----------|---------|
| Rust | 1.85.0 (`rust-toolchain.toml`) |
| Nix shell | `flake.nix` (same toolchain) |
| Build | `cargo build --locked --release` |

## 📄 License

[MIT](LICENSE)

## 📖 Citation

See [`CITATION.cff`](CITATION.cff) for machine-readable citation metadata.
