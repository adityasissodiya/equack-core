# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ECAC-Core is a Rust-based deterministic access control system with VC-backed authorization, in-band trust, and reproducible evaluation. It implements a causal DAG with CRDTs and deny-wins policy enforcement.

## Build & Development Commands

```bash
# Build
cargo build --locked --release
cargo build --workspace --release --locked --features audit  # with audit feature

# Test
cargo test                              # all tests
cargo test -p ecac-core                 # core crate only
cargo test -p ecac-store                # store crate only
cargo test --test replay_prop           # specific integration test
cargo test -- --nocapture               # with output

# Lint & Format
cargo fmt                               # format code
cargo fmt --check                       # check formatting
cargo clippy                            # lint

# Security
cargo audit                             # security audit
cargo deny check                        # dependency checks

# Evaluation (M7)
make m7                                 # quick evaluation (QUICK=1)
make m7-full                            # full evaluation
make plots                              # generate CSV/plot artifacts
make repro                              # deterministic reproduction
make verify-golden                      # verify against golden artifacts
```

## Architecture

### Crate Structure

- **crates/core** - Deterministic engine: crypto, DAG, replay, policy, VC verification, TrustView
- **crates/store** - RocksDB persistence with column families for ops, edges, VCs, checkpoints, audit logs
- **crates/cli** - 15+ subcommands for data ops, replay, policy, audit, benchmarks
- **crates/net** - libp2p gossip/fetch networking with deterministic anti-entropy

### Core Data Flow

1. Ops are verified and inserted into DAG (pending staging if parents missing)
2. Topo-sort produces deterministic order using (HLC, op_id) tiebreaker
3. TrustView is built from in-band trust ops (IssuerKey, StatusListChunk, IssuerKeyRevoke)
4. Authorization epochs are constructed from Grant/Revoke ops using TrustView
5. Replay applies CRDTs only for ops passing deny-wins policy checks
6. Audit events emitted during replay (IngestedOp, AppliedOp, SkippedOp)

### Key Modules

- `core/src/dag.rs` - Causal DAG with pending-parent staging, deterministic topo-sort
- `core/src/replay.rs` - Deterministic replay engine with policy gating
- `core/src/policy.rs` - Authorization epoch construction, deny-wins evaluation
- `core/src/trustview.rs` - In-band TrustView assembly from signed ops (most complex, ~922 LOC)
- `core/src/vc.rs` - JWT-VC parsing, signature verification, scope extraction
- `core/src/crdt/` - MVReg and OR-Set implementations with merge logic
- `store/src/lib.rs` - RocksDB Store with column families
- `store/src/audit.rs` - Hash-linked, signed audit log writer/reader

### Op Payload Types

```rust
Payload::Data { key, value }
Payload::Credential { cred_id, cred_bytes, format }
Payload::Grant { subject_pk, cred_hash }
Payload::Revoke { subject_pk, role, scope_tags, at }
Payload::IssuerKey { issuer_id, key_id, algo, pubkey, valid_from_ms, valid_until_ms }
Payload::IssuerKeyRevoke { issuer_id, key_id, reason }
Payload::StatusListChunk { list_id, issuer_id, version, chunk_index, bitset_sha256, chunk_bytes }
Payload::KeyGrant { subject_pk, tag, key_version, cred_hash }
Payload::KeyRotate { tag, new_version, new_key }
```

## Testing

Integration tests in `crates/core/tests/`:
- `replay_prop.rs` - Replay determinism property tests
- `replay_split_prop.rs` - Checkpoint/incremental replay parity
- `topo_prop.rs` - Topological sort determinism
- `vc_policy_tests.rs` - VC verification and policy tests
- `mvreg_tests.rs`, `orset_tests.rs` - CRDT convergence tests

Tests use `proptest` for property-based testing with random DAG generation and permutations.

## Environment Variables

- `ECAC_DB` - RocksDB path (default: `.ecac.db`)
- `ECAC_AUDIT_DIR` - Audit log directory
- `ECAC_NODE_SK_HEX` - Node signing key for audit (64 hex chars)
- `ECAC_TIME_MS` - Override system time for reproducibility
- `SOURCE_DATE_EPOCH` - Unix timestamp for reproducible builds

## Determinism Requirements

The system is designed for deterministic replay. Key invariants:
- Topo-sort is stable: same DAG always produces same order
- Replay digest is reproducible across runs
- Network layer treats PublishError::Duplicate as success
- Builds use `--locked` and reproducible flags

## CLI Subcommands

**Data ops:** `write`, `replay`, `project`, `op-append`, `replay-from-store`
**VC/Policy:** `vc-verify`, `vc-attach`, `vc-status-set`
**Store:** `checkpoint-create`, `checkpoint-load`, `checkpoint-list`, `verify-store`
**Audit:** `audit-record`, `audit-verify-chain`, `audit-verify-full`, `audit-export`, `audit-cat`
**Trust:** `trust-issuer-publish`, `trust-status-chunk`, `trust-issuer-revoke`, `trust-dump`
**Benchmark:** `bench --scenario hb-chain|concurrent|offline-revocation`
