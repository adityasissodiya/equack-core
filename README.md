# ECAC Prototype — Eventually Consistent Access Control

A **Rust-based, verifiable prototype** implementing the *Eventually Consistent Access Control (ECAC)* model.
It demonstrates how **policy-correct state** can be achieved in a distributed, offline-first system using **CRDT replication**, **verifiable credentials**, and a **deterministic deny-wins replay**.

This repo contains the core runtime, audit system, crypto plumbing, and reproducible evaluation setup used in the paper *“Eventually Consistent Access Control for Multi-Stakeholder Remanufacturing”*.

---

## 🧩 Core Philosophy

* All actions—data updates, grants, revocations—are **signed and hash-linked events** in a causal DAG.
* Every node maintains a **local log** and can work offline using its **best local knowledge**.
* When nodes sync, a deterministic **replay** with a **deny-wins** rule ensures:

  * **Convergence:** all replicas end in the same state.
  * **Policy safety:** unauthorized ops are retroactively removed.
* Security and correctness are prioritized over throughput.
  Every component is deterministic, auditable, and reproducible.

---

## ⚙️ Architecture Overview

```
crates/
 ├── core/        # Ops, DAG, CRDTs, replay engine
 ├── policy/      # Authorization epochs & deny-wins filtering
 ├── crypto/      # Signatures, hashes, encryption
 ├── store/       # RocksDB persistence + checkpoints
 ├── net/         # libp2p gossip sync
 ├── vc/          # Verifiable Credential handling (TrustView)
 ├── audit/       # Tamper-evident audit trail
 ├── metrics/     # Bench harness + metrics exporter
 ├── cli/         # Command-line driver & scenarios
 └── ui/          # (optional) local-first viewer
docs/
 ├── protocol.md
 ├── policy-model.md
 ├── evaluation-plan.md
 ├── audit.md
 └── paper/
scripts/
 ├── reproduce.sh
 ├── verify_golden.sh
 └── plot.py
```

---

## 🧠 Model Summary

Each node maintains a **log of signed events**:

```
{
  op_id: blake3(canonical_bytes),
  parents: [OpId],
  hlc: HybridLogicalClock,
  author: PublicKey,
  payload: {type, data...},
  sig: Ed25519Signature
}
```

### Deterministic Replay

1. Topologically sort the DAG (parents-first; tie: `(hlc, op_id)`).
2. For each op:

   * If `author` lacks valid permission for `(action, resource, hlc)` → skip (`deny-wins`).
   * Otherwise, apply the op’s CRDT effect (MVReg, ORSet, etc.).
3. Merge and apply across replicas → identical state.

---

## 🔒 Cryptography & Trust

* **Signatures:** Ed25519 (via `ed25519-dalek`)
* **Hashing:** BLAKE3 (fast, collision-resistant)
* **Encryption:** XChaCha20-Poly1305 for confidential tags (per-tag keys, rotated on revoke)
* **Credentials:** JWT-VCs (W3C Verifiable Credentials)
* **TrustView:** issuer keys + status lists are distributed **in-band** through signed ops
* **Audit chain:** every decision (applied/skipped/synced) logged and signed by node key

---

## 🧮 Policy & Authorization

* Policies expressed via **AWS Cedar** (deny-overrides semantics).
* Grants and revocations form **authorization epochs** (intervals of validity).
* During replay:

  * Ops outside any valid epoch are skipped deterministically.
  * Revocations override concurrent writes (`deny-wins`).
* Supports scoped tags for fine-grained step-level control (RBAC/ABAC hybrid).

---

## 📦 Storage & Persistence

* **RocksDB** backend with separate column families for ops, edges, keys, audit, and checkpoints.
* **Append-only** writes with `sync=true` for crash consistency.
* Deterministic **checkpoints** and **replay parity** tests ensure idempotent recovery.
* **Audit logs** hash-linked and signed, providing offline verifiable integrity.

---

## 🌐 Networking & Replication

* **libp2p Gossipsub** for anti-entropy gossip; **Noise** for secure transport.
* Static peers; no DHT in prototype.
* **Causal completeness:** parent-first fetch and dedup guarantee consistency.
* Nodes exchange only **encrypted or signed ops**, never plaintext state.

---

## 📊 Metrics & Evaluation

Implements a deterministic **bench harness** (`cli bench`) with reproducible scenarios:

| Scenario         | Purpose                                      |
| ---------------- | -------------------------------------------- |
| `hb-chain`       | Baseline causal replay                       |
| `concurrent`     | MVReg/ORSet concurrency                      |
| `offline-revoke` | Offline edit + concurrent revoke (deny-wins) |
| `partition-3`    | Partition/heal convergence (gossip sync)     |

Metrics exported as CSV + JSONL:

```
ops_total, ops_applied, ops_skipped_policy, replay_ms, convergence_ms
```

All results in `/docs/eval/out/` are **bit-for-bit reproducible** via `scripts/reproduce.sh`.

---

## 🧾 Audit & Observability

* **Audit trail** = signed, hash-linked stream of:

  * `IngestedOp`, `AppliedOp`, `SkippedOp{reason}`, `SyncEvent`, `Checkpoint`
* **Verifier** (`cli audit-verify`) replays ops and ensures audit matches deterministic outcome.
* Detects tampering, missing entries, or divergent replay decisions.
* **Tracing:** structured logs tagged with op_id, author, and reason.

---

## 🔑 Read Control & Confidential Data

* Fields tagged as confidential are stored as `EncV1`:

  ```
  {tag, key_version, nonce, aead_tag, ciphertext}
  ```
* Only users with a valid `KeyGrant{tag, version}` (VC-backed) can decrypt.
* Key rotation (`KeyRotate`) provides **forward secrecy**.
* Non-authorized readers see deterministic `<redacted>` placeholders.

---

## 🧱 Trust Distribution (In-Band)

* Issuer keys and revocation lists are shared through ops:

  * `IssuerKey`, `IssuerKeyRevoke`, `StatusListChunk`
* The **TrustView** builder reconstructs current valid keys and revocations deterministically.
* No filesystem or network trust roots required; fully self-contained.

---

## 🧪 Verification & Testing

* **Property-based:** random DAGs → invariant check (convergence + policy safety)
* **Model checking:** TLA+/Apalache spec for replay invariants
* **Fuzzing:** `cargo-fuzz` on DAG merge and replay
* **Crash recovery tests:** partial write → consistent replay
* **Audit parity:** replay output vs audit log cross-verified

---

## 🧰 Build & Reproducibility

* Pinned Rust toolchain (via `rust-toolchain.toml`)
* Deterministic Docker/Nix build environments
* `make repro` → clean build + deterministic benchmark run + artifact tarball
* `scripts/verify_golden.sh` compares new run vs golden outputs (hash match)
* CI (`.github/workflows/repro.yml`) enforces reproducibility, `cargo audit`, SBOM

---

## 🧱 Milestones Summary

| M#        | Result                                                         |
| --------- | -------------------------------------------------------------- |
| **M1–M2** | Core CRDT + signed op DAG + deterministic replay               |
| **M3**    | Authorization epochs + deny-wins policy filter                 |
| **M4–M5** | Verifiable credentials + durable RocksDB store                 |
| **M6**    | Gossip sync + causal completeness                              |
| **M7**    | Bench harness + metrics export                                 |
| **M8**    | Tamper-evident audit log                                       |
| **M9**    | Confidential read-control (encryption & key rotation)          |
| **M10**   | In-band issuer trust & revocation lists                        |
| **M11**   | Reproducible build pipeline (CI, SBOM, golden artifacts)       |
| **M12**   | Paper-ready docs, evaluation summary, reproducibility manifest |

---

## 🧠 Core Invariants

1. **Convergence:** Replicas with the same events produce identical state.
2. **Policy Safety:** Final state contains no effects of unauthorized ops.
3. **Determinism:** Given the same DAG, replay produces byte-identical output.
4. **Audit Integrity:** Hash-linked audit chain verifies end-to-end.
5. **Forward Secrecy:** Revoked users can’t decrypt new encrypted data.

---

## 🚀 Reproduce the Paper Artifacts

```bash
# 1. Build inside Docker/Nix
make image && make repro

# 2. Verify artifacts
scripts/verify_golden.sh

# 3. Check audit integrity
cli audit-verify

# 4. Dump trust and metrics
cli trust-dump
```

Results are written to:

```
docs/eval/out/
  hb-chain-42.csv
  offline-revoke-42.csv
  audit.jsonl
  trustview.json
  SHA256SUMS
```

---

## 🧾 Licensing & Integrity

* License: MIT/Apache 2.0 dual license.
* No unsafe code except vetted crypto crates.
* Each release includes:

  * `sbom.json`
  * `cosign.sig`
  * `ecac-artifacts-<gitsha>.tar.gz`

---

## 🧩 Why Rust and Why ECAC

Rust provides predictable execution, verifiable memory safety, and reproducible builds—exactly what correctness-driven distributed systems need.
ECAC shows that **availability and eventual consistency** can coexist with **formal access-control guarantees**, which most industry systems still lack.

---

**Status:** Architecture frozen, implementation in progress.
**Tag target:** `v1.0-paper` — reproducible, policy-correct, verifiable.

---

## Fixtures & Quick Demo (M4)

We ship tiny helpers to create deterministic test credentials and ops locally (no network):

```bash
# 1) Keys and trust
ISSUER_SK_HEX=$(openssl rand -hex 32)
ADMIN_SK_HEX=$(openssl rand -hex 32)
SUBJECT_SK_HEX=$(openssl rand -hex 32)

mkdir -p trust/status fixtures out
# Pin issuer VK in trust:
cargo run -p ecac-cli --example make_jwt -- "$ISSUER_SK_HEX" fixtures/example.jwt
# Copy printed issuer_vk_hex into trust/issuers.toml:
cat > trust/issuers.toml <<EOF
[issuers]
oem-issuer-1 = "<PASTE_issuer_vk_hex>"
EOF

# 2) Verify VC and inspect claims/hash
cargo run -p ecac-cli -- vc-verify fixtures/example.jwt

# 3) Attach to log as ops (Credential + Grant)
cargo run -p ecac-cli -- vc-attach fixtures/example.jwt "$ISSUER_SK_HEX" "$ADMIN_SK_HEX" out/

# 4) Create a write op signed by the SUBJECT (the make_jwt_subject example also exists)
cargo run -p ecac-cli --example make_write -- "$SUBJECT_SK_HEX" 15000 mv:o:x OK out/write.op.cbor

# 5) Replay (allowed when status bit is clear)
cargo run -p ecac-cli --example vc_replay -- out/cred.op.cbor out/grant.op.cbor out/write.op.cbor

# 6) Flip status bit to revoke, then rerun (denied)
cargo run -p ecac-cli -- vc-status-set list-0 1 1
cargo run -p ecac-cli --example vc_replay -- out/cred.op.cbor out/grant.op.cbor out/write.op.cbor
