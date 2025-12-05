# ECAC-core

A Rust workspace for deterministic, VC-backed access control over a signed, causal op-log, with in-band trust, deny-wins policy replay, tamper-evident audit, and reproducible evaluation artifacts. 

---

## Motivation

ECAC-core targets settings where multiple parties jointly control data and access rights, but still require:

- Offline-friendly operation: no central online authority is assumed.
- Deterministic convergence: any node that sees the same signed event log should derive the same state.
- Policy correctness under revocation: access decisions must respect credential expiry, status lists, and key revocation.
- Forensics and reproducibility: a reviewer should be able to replay policy decisions, verify audit logs, and regenerate evaluation artifacts bit-for-bit. 

ECAC-core provides a minimal but end-to-end stack to explore such systems: from cryptographic ops and deterministic replay, through VC-backed authorization and in-band trust, to storage, networking, audit, confidentiality, and a reproducible benchmark harness.

---

## High-level Design

At its core, ECAC-core is a deterministic state machine driven by a signed, hash-linked operation log:

1. **Signed operations**  
   Each operation (`Op`) has a canonical CBOR-encoded header (parents, HLC, author key, payload). The op-id is `BLAKE3("ECAC_OP_V1" || canonical_header)`, and the header hash is then signed with Ed25519. :contentReference[oaicite:2]{index=2}  

2. **Causal DAG and total order**  
   Ops reference parent op-ids, forming a causal DAG. A pending-parent DAG holds children until all parents arrive, then computes a deterministic topological order, breaking ties by `(HLC, op_id)`.   

3. **Deterministic replay with deny-wins**  
   Replay walks the DAG in topo order. Policy logic slices the log into authorization epochs, then applies a deny-wins rule: if there is no valid credential chain (or it is expired/revoked/out of scope), the data op is deterministically skipped.   

4. **VC-backed authorization and in-band trust**  
   Grants no longer carry raw roles or scopes; instead, they reference a `cred_hash` pointing to a JWT-VC. VC verification checks EdDSA signatures, time windows, scopes, and revocation status lists. All issuer keys and status lists are themselves carried as signed ops (`IssuerKey`, `IssuerKeyRevoke`, `StatusListChunk`) and assembled into a deterministic `TrustView`. VC verification runs solely against this in-band `TrustView`.   

5. **CRDT-backed state**  
   Authorized writes drive CRDTs (e.g., MVReg, OR-Set). Deterministic replay and deny-wins ensure that, for a fixed op-log and trust configuration, every node computes the same final CRDT state.   

6. **Durable store and checkpoints**  
   A RocksDB-backed store persists ops, DAG edges, indexes, authorization artifacts, and checkpoints. Checkpoints snapshot the state (as canonical CBOR), allowing fast restart via checkpoint-then-incremental replay, which is proven to match full replay. :contentReference[oaicite:7]{index=7}  

7. **Networking and sync (deterministic libp2p)**  
   An optional libp2p layer gossips ANNOUNCE messages and fetches missing ops via a deterministic frontier-based sync protocol. Sync metrics and tests enforce deterministic convergence across peers.   

8. **Audit and forensics**  
   Audit events (IngestedOp, AppliedOp, SkippedOp, ViewEvent, Checkpoint, SyncEvent) are appended to an Ed25519-signed, BLAKE3-linked audit log encoded in canonical CBOR. Dedicated CLI commands verify chain integrity and cross-check audit decisions against deterministic replay, and an exporter produces deterministic JSONL audit traces.   

9. **Confidentiality (experimental)**  
   Confidential fields are encrypted-at-rest per tag with XChaCha20-Poly1305. Keys are derived per `(tag, version)` via BLAKE3 and distributed via `KeyRotate` ops and a keyring. Authorized read access is routed through `KeyGrant` ops backed by VCs. This read-control path is functional but currently over-redacts and has been de-emphasized in later milestones.   

10. **Reproducible evaluation**  
    A metrics harness runs deterministic scenarios (HB-chain, concurrent, offline-revocation) and produces CSV/JSONL/plot artifacts. A pinned toolchain and environment, together with `scripts/reproduce.sh`, yield bit-for-bit identical artifacts and a deterministic submission tarball.   

---

## Features

### Core semantics

- Hybrid Logical Clock (HLC) with deterministic `tick_local` and merge functions over `(physical_ms, logical, node_id)`. :contentReference[oaicite:12]{index=12}  
- Canonical CBOR serialization for all ops and checkpoints, ensuring stable bytes and op-ids across platforms.   
- Signed, hash-linked ops with:

  - Op-id: BLAKE3 with domain separation (`"ECAC_OP_V1"`).  
  - Signatures: Ed25519 over op-id. :contentReference[oaicite:14]{index=14}  

- Pending-parent DAG with deterministic topological ordering and strict “parents-before-children” invariant.   

### Policy and authorization

- JWT-VC support (`alg=EdDSA` only), including cred-hash (`BLAKE3(jwt_bytes)`) for stable VC references. :contentReference[oaicite:16]{index=16}  
- VC-backed grants: grant payloads contain `{subject_pk, cred_hash}`, with role/scope taken exclusively from the VC. :contentReference[oaicite:17]{index=17}  
- Time-window enforcement: ops are accepted only if their HLC physical time lies within `[nbf, exp)`. :contentReference[oaicite:18]{index=18}  
- Local revocation lists via status bitstrings, with little-endian bit ordering and deterministic interpretation.   
- Deny-wins semantics: invalid, expired, or revoked credentials—or scope mismatches—cause the corresponding ops to be deterministically skipped.   

### In-band trust (M10)

- New op payloads:

  - `IssuerKey`
  - `IssuerKeyRevoke`
  - `StatusListChunk` :contentReference[oaicite:21]{index=21}  

- Deterministic TrustView:

  - IssuerKey: first-wins per `(issuer_id, key_id)`.  
  - Activation time: `max(valid_from_ms, op.hlc.physical_ms)`.  
  - Revocation effective immediately at op.hlc.  
  - StatusListChunk: only complete lists usable; latest complete version per `(issuer_id, list_id)` wins; SHA-256 digest required. :contentReference[oaicite:22]{index=22}  

- Issuer-admin gating: once `issuer_admin` is active, only issuer-admin-authored trust ops are accepted. :contentReference[oaicite:23]{index=23}  
- VC verification path updated to `verify_vc_with_trustview`, using TrustView for issuer key selection and status-list revocation checks only from the log, not the filesystem.   

### Storage and checkpoints (M5)

- RocksDB store with column families for:

  - `ops` (op-id → canonical CBOR op)
  - `edges` (op-id → parents/metadata)
  - `by_author` (author+hlc+op-id)
  - `meta` (schema_version, db_uuid, last_checkpoint)
  - `vc_raw`, `vc_verified`
  - `checkpoints` :contentReference[oaicite:25]{index=25}  

- Crash-safe writes via `WriteBatch` + `sync=true`. :contentReference[oaicite:26]{index=26}  
- Topological reconstruction from stored edges with missing-parent filtering. :contentReference[oaicite:27]{index=27}  
- Canonical-CBOR checkpoints with APIs to create, load, and list checkpoints; replay from checkpoint + incremental ops matches full replay. :contentReference[oaicite:28]{index=28}  

### Networking and sync (M6–M7)

- libp2p-based networking with:

  - Gossipsub ANNOUNCE topic for head/topology broadcasts.
  - Request-response fetch protocol for missing ops.
  - Ping + Identify behaviors integrated in a composed swarm.   

- Deterministic frontier-based sync:

  - Per-peer SyncState including frontier, inflight, unavailable sets.
  - ANNOUNCE-driven sync planning and batch fetches.
  - Idempotent handling of duplicate ANNOUNCE storms; `PublishError::Duplicate` treated as success.   

- Sync metrics: counts for gossip sent/received, fetched ops, dropped duplicates. :contentReference[oaicite:31]{index=31}  

### Audit and forensics (M8, M11)

- Audit schema: `IngestedOp`, `AppliedOp`, `SkippedOp(reason)`, `ViewEvent`, `Checkpoint`, `SyncEvent`. :contentReference[oaicite:32]{index=32}  
- Canonical CBOR encoding for audit entries: `{seq, ts_monotonic, prev_hash, event, node_id, signature}`. :contentReference[oaicite:33]{index=33}  
- Hash chaining with `BLAKE3("ECAC_AUDIT_V1" || canonical(entry_without_signature))`, signed with Ed25519. :contentReference[oaicite:34]{index=34}  
- Segment-based storage with `segment-XXXXXXXX.log` and `index.json` tracking seq/hash bounds. :contentReference[oaicite:35]{index=35}  
- CLI:

  - `audit-record`
  - `audit-verify-chain`
  - `audit-verify-full` (cross-checks replay decisions)
  - `audit-cat`
  - deterministic JSONL export wired via in-band audit hooks (`OpAppendAudited`) and the M11 reproduction path.   

### Confidentiality (M9; experimental / partially deprecated)

- Per-tag encryption (`"confidential"`) using XChaCha20-Poly1305 with:

  - 32-byte keys, 24-byte nonces, 16-byte tags.  
  - AAD binding derived from author, HLC, parents, and object/field ids. :contentReference[oaicite:37]{index=37}  

- Deterministic key derivation per `(db_uuid, tag, version)` via BLAKE3, populated by `KeyRotate` ops and CLI. :contentReference[oaicite:38]{index=38}  
- `KeyGrant` ops binding `subject_pk`, `(tag, version)`, and `cred_hash`, backed by VC verification. :contentReference[oaicite:39]{index=39}  
- CLI flow (`vc-mint-demo`, `keyrotate`, `grant-key`, `write`, `show`) demonstrates encrypt-on-write and subject-specific projection, but the intended “authorized subject sees plaintext” behavior is not yet achieved; current behavior over-redacts (authorized subject still sees `<redacted>`).   

### Benchmarks and evaluation (M7, M11)

- `ecac-cli bench` scenarios:

  - `hb-chain`: linear causal chain, MVReg winner count should be 1.
  - `concurrent`: many concurrent writers without edges.
  - `offline-revocation`: synthetic cut/skip analysis (policy-neutral).   

- Deterministic metrics:

  - Stable CSV schemas (column order locked).
  - JSONL timelines per run.
  - Final-state JSON snapshots. :contentReference[oaicite:42]{index=42}  

- Python tooling (`checks.py`, `plot.py`) for invariants and deterministic plots. :contentReference[oaicite:43]{index=43}  
- `scripts/reproduce.sh` (M11):

  - Cleans workspace and builds with `cargo build --locked --release` under a pinned Rust toolchain.
  - Runs all M7 benchmark scenarios (`hb-chain`, `concurrent`, `offline-revocation`).
  - Normalizes outputs into `docs/eval/out/`.
  - Seeds an audit store, appends a minimal op, exports and verifies the audit log.
  - Runs trust CLI to produce a deterministic `trust-dump`.
  - Computes `SHA256SUMS` over all outputs.
  - Produces `ecac-artifacts-<gitsha>.tar.gz` with stable ordering and timestamps.   

- Golden-artifact verification via `scripts/golden.sh` / `verify_golden.sh`. :contentReference[oaicite:45]{index=45}  

---

## Architecture Overview

ECAC-core is organized as a Rust workspace with several crates:

### `crates/core`

Implements the logical core:

- `crypto.rs`, `serialize.rs`, `hlc.rs`, `op.rs`, `dag.rs`: op model, canonical CBOR, HLC, signatures, and the pending-parent DAG. :contentReference[oaicite:46]{index=46}  
- Policy and replay:

  - Deterministic replay engine over the DAG (M2/M3).  
  - `policy.rs`: epoch construction and deny-wins gating based on VCs and trust state.   

- VC and trust:

  - `vc.rs`: VC parsing, signature verification, time window checks, scope extraction, and revocation via status lists.
  - `trust.rs`: pinned issuer loading (M4) and, where still applicable, filesystem trust as a fallback.
  - `status.rs`: status-list bitstring handling.
  - `trustview.rs`: deterministic assembly of issuer keys and status lists from in-band trust ops (M10).   

- CRDTs (e.g., MVReg, OR-Set) and replayed state.   

Data flow: ops are verified and added to the DAG; replay builds a TrustView from trust ops, then constructs authorization epochs and applies CRDT transitions only for ops that pass deny-wins checks.

### `crates/store`

Provides a durable RocksDB-backed store:

- Column families for ops, edges, indexes, VC caches, and checkpoints. :contentReference[oaicite:50]{index=50}  
- APIs to:

  - Append ops (`put_op_cbor`), ensuring canonical encoding and parent presence.
  - Reconstruct topo order from `edges`.
  - Create, load, and list checkpoints (`checkpoint_create`, `checkpoint_load`, `checkpoint_latest`). :contentReference[oaicite:51]{index=51}  

- Optional VC cache parity checks and integrity scanning (`verify_integrity`). :contentReference[oaicite:52]{index=52}  

This store underlies both standalone replay and networked replicas.

### `crates/net`

Implements deterministic networking:

- `transport.rs`: `Node` wrapper managing gossipsub, connections, and ANNOUNCE publish/flush behavior.
- `gossip.rs`: helper functions (`build_gossipsub`, announce topic binding, publish/parse helpers).
- `sync.rs`: sync planning from heads/frontiers, inflight tracking, anti-entropy.   

ANNOUNCE messages describe node head sets and Bloom filters; peers determine missing ops and use a fetch protocol to obtain them. Sync is designed to be deterministic and idempotent, with tests guarding against duplicate-storm regressions.   

### `crates/store/src/audit.rs`

Audit subsystem:

- `AuditWriter` and `AuditReader` for canonical CBOR audit entries, BLAKE3 hash-chaining, Ed25519 signing, and segment/index management. :contentReference[oaicite:55]{index=55}  

This crate integrates with replay to emit `AppliedOp`/`SkippedOp`/other events and with CLI commands to verify and export logs.

### `crates/cli`

User-facing commands:

- Policy and VC:

  - `vc-verify`, `vc-attach`, `vc-status-set`, plus demo helpers.   

- Store and replay:

  - `op-append`, `replay-from-store`, `checkpoint-create`, `checkpoint-load`, `checkpoint-list`, `verify-store`. :contentReference[oaicite:57]{index=57}  

- Benchmarks:

  - `bench` with `hb-chain`, `concurrent`, `offline-revocation` scenarios. :contentReference[oaicite:58]{index=58}  

- Audit:

  - `audit-record`, `audit-verify-chain`, `audit-verify-full`, `audit-export`, `audit-cat`.   

- Trust:

  - `trust-issuer-publish`, `trust-status-chunk`, `trust-dump`.   

- Confidentiality (experimental):

  - `vc-mint-demo`, `keyrotate`, `grant-key`, `write`, `show` for the M9 per-tag encryption/key-grant path. :contentReference[oaicite:61]{index=61}  

### Tooling and docs

- `scripts/reproduce.sh`, `scripts/golden.sh`, `verify_golden.sh` for reproducibility and golden-artifact verification. :contentReference[oaicite:62]{index=62}  
- `tools/scripts/checks.py`, `plot.py`, and `docs/eval/README.md` for evaluation workflows. :contentReference[oaicite:63]{index=63}  

---

## Guarantees

Subject to the implemented milestones, ECAC-core provides the following guarantees:

- **Deterministic op identity**: identical canonical CBOR header bytes produce identical BLAKE3 op-ids across platforms and runs.   
- **Deterministic replay**: given the same set of ops and trust inputs (now fully in-band), replay is pure and produces the same CRDT state and policy decisions regardless of insertion order or crash boundaries. Full replay and checkpoint+incremental replay are proved equal.   
- **Deny-wins policy safety**: any failure in VC verification, trust lookup, revocation, or scope/time conditions leads to data ops being skipped, not partially applied.   
- **In-band trust correctness**: issuer keys, revocations, and status lists are themselves signed ops; TrustView assembly is deterministic (first-wins, latest-complete) and gated by an `issuer_admin` role, eliminating external trust directories as a correctness dependency. :contentReference[oaicite:67]{index=67}  
- **Crash consistency and causal correctness**: RocksDB writes are crash-safe; no op is visible without all parents present; DAG reconstruction rejects malformed or parent-missing edges. :contentReference[oaicite:68]{index=68}  
- **Audit integrity**: the audit log is append-only, hash-linked, and signed. Chain verification detects bit flips and mid-segment truncation; replay cross-check ensures the audit trail matches the deterministic policy engine.   
- **Deterministic evaluation and packaging**: given the same git commit, toolchain, and environment variables, `scripts/reproduce.sh` yields identical benchmark outputs, trust dumps, audit JSONL, `SHA256SUMS`, and submission tarball.   

---

## Limitations / Non-goals

ECAC-core is a research prototype with several explicit limitations:

- **Confidentiality/read-control**:

  - The per-tag encryption + KeyGrant read-control path is implemented but not semantically complete; in the observed run, even the intended authorized subject sees `<redacted>`. The implementation is conservatively safe (over-redaction) but does not yet meet its functional goal. :contentReference[oaicite:71]{index=71}  
  - Network-level guarantees that plaintext is never transmitted are assumed rather than fully audited. :contentReference[oaicite:72]{index=72}  
  - M10 deprecates M9’s read-control semantics as a primary concern; future work is needed to reconcile in-band trust with confidentiality.   

- **Trust model features**:

  - No StatusPointer support, no multi-issuer quorum logic, and no advanced key rollover windows. Bootstrapping helpers such as `--bootstrap issuers.toml` are deferred. :contentReference[oaicite:74]{index=74}  

- **Audit subsystem**:

  - Crash-tail truncation repair is specified but not fully implemented; detection exists, but automatic repair is deferred. :contentReference[oaicite:75]{index=75}  
  - Cross-node audit reconciliation and transparency features are future work. :contentReference[oaicite:76]{index=76}  

- **Networking**:

  - Network scenarios are not part of the M11 reproduction pipeline; network tests are optional and gated behind explicit flags.   
  - Some networking behavior (particularly ANNOUNCE duplicate handling) went through design-only phases; while the M6–M7 summary claims a functional stack, more exhaustive nondeterminism testing is still desirable.   

- **Benchmarks and policy coverage**:

  - The “offline-revocation” benchmark is diagnostic only; it does not yet enforce real policy semantics for revocation. :contentReference[oaicite:79]{index=79}  

- **Documentation and CI**:

  - Several documents (full audit spec, protocol diagrams, persistent CF schemas) are specified but not yet implemented in the repo.   
  - CI workflows (including reproducibility checks and `cargo audit`/`cargo deny`/SBOM generation) are planned but not fully detailed here. :contentReference[oaicite:81]{index=81}  

ECAC-core should therefore be treated as a well-instrumented prototype, not a production-ready access control system.

---

## Getting Started

### Prerequisites

- Rust toolchain pinned via `rust-toolchain.toml` (Rust 1.85). :contentReference[oaicite:82]{index=82}  
- Standard Rust build toolchain (`cargo`) and a C toolchain suitable for RocksDB (as required by the `rocksdb` crate).  
- Python 3 and `matplotlib` if you intend to run the plotting scripts. :contentReference[oaicite:83]{index=83}  

### Building

From the repository root:

```bash
cargo build --locked --release


This matches the build invocation used in the deterministic reproduction pipeline. 

### Running Tests

Standard cargo commands are used to run the test suite (unit tests, property tests, and integration tests):

```bash
cargo test
```

Tests cover CRDT behavior, policy/V C semantics, replay parity, networking invariants, audit correctness, and benchmark determinism.

### Reproducing Evaluation Artifacts

To reproduce the evaluation artifacts and packaging used in the paper:

```bash
scripts/reproduce.sh
```

This script will:

* Clean the workspace.
* Build the workspace with the pinned toolchain (`--locked --release`).
* Run the M7 benchmark scenarios (`hb-chain`, `concurrent`, `offline-revocation`).
* Normalize outputs to `docs/eval/out/`.
* Seed the audit store, append a minimal audited op, export and verify the audit chain.
* Dump the in-band TrustView.
* Compute `SHA256SUMS`.
* Build `ecac-artifacts-<gitsha>.tar.gz` with deterministic ordering and timestamps.

You can compare the results against a golden artifact set using:

````bash
scripts/golden.sh
scripts/verify_golden.sh
``` :contentReference[oaicite:87]{index=87}  

### Benchmarks

For ad-hoc benchmarking beyond `reproduce.sh`, use the CLI:

```bash
ecac-cli bench --scenario hb-chain
ecac-cli bench --scenario concurrent
ecac-cli bench --scenario offline-revocation
````

Exact flags and options follow the M7 harness design (scenario names and metrics schemas are fixed).

---

## Project Status & Roadmap

* Milestones M1–M5: core op model, deterministic replay, VC-backed authorization, persistence, and checkpoints are implemented and tested.
* M6–M7: deterministic networking stack and evaluation harness are implemented; network scenarios remain optional.
* M8: audit chain and CLI are implemented; integration with replay is complete by M11.
* M9: encryption-on-write and KeyGrant/KeyRotate are implemented but remain experimental and functionally incomplete; M10 de-emphasizes them in favor of in-band trust.
* M10: in-band trust and TrustView are the authoritative trust/VC semantics going forward. 
* M11: reproducible builds and packaging are in place; no further protocol changes are introduced. 

Future work (beyond the current milestones) includes solidifying confidentiality semantics, expanding trust features (quorums, advanced rollover), improving network coverage, and completing documentation/CI.

---

## License

TBD – fill in once the final license for ECAC-core is chosen.


# Architecture Section (paper draft)

## 4.x ECAC-core Architecture

ECAC-core implements a deterministic access-control substrate built around a signed, hash-linked operation log and a causal DAG. All state is derived by replaying this log under a deny-wins policy and VC-backed authorization, with trust and revocation information expressed entirely as signed log events. Persistence, networking, audit, confidentiality, and reproducible evaluation are layered on top of this core.   

At a high level, each node maintains:

1. A **durable op store** over RocksDB, containing canonical CBOR-encoded ops, DAG edges, indexes, and checkpoints. :contentReference[oaicite:96]{index=96}  
2. An in-memory **DAG and replay engine**, which reconstructs a deterministic topological order from the store and applies a deny-wins policy over CRDT-backed state.   
3. A **TrustView** assembled deterministically from in-band trust ops (issuer keys, revocations, status-list chunks), which is the sole authority for VC verification.   
4. An optional **libp2p networking layer** that gossips head information and fetches missing ops, designed to preserve determinism and convergence across peers.   
5. A **tamper-evident audit log** recording ingestion, application, and skipping decisions, linked by BLAKE3 hashes and Ed25519 signatures and cross-checked against the replay engine.   
6. An **experimental confidentiality layer** that encrypts confidential fields and attempts subject-specific projections based on VC-backed key grants. :contentReference[oaicite:101]{index=101}  

The overall pipeline on each node is:

1. Ingest signed ops (from local CLI or the network) into the store and DAG.
2. Reconstruct TrustView from trust ops.
3. Replay the op-log in topo order, using TrustView and VCs to gate epochs and applying deny-wins semantics over CRDTs.
4. Emit audit events capturing ingestion, application, and skipped decisions.
5. Expose current state and audit data to the CLI and benchmark harnesses.

### 4.x.1 Signed Operations and Causal Log

**Operation model.**  
Each operation consists of a header and a signature:

- `OpHeader` contains:

  - `parents`: a list of parent op-ids, forming the DAG.
  - `hlc`: a hybrid logical clock tuple `(physical_ms, logical, node_id)`.
  - `author_pk`: the author’s Ed25519 public key.
  - `payload`: a tagged union including data writes, authorization-related events (e.g., `Grant`, `Credential`), trust events (`IssuerKey`, `IssuerKeyRevoke`, `StatusListChunk`), and other control types.   

The header is encoded using canonical CBOR with stable field ordering. The op-id is computed as:

> `op_id = BLAKE3("ECAC_OP_V1" || canonical_header_bytes)`,  

and then signed with Ed25519, producing a detached signature over the op-id. Signatures are verified on ingestion; any op failing verification is rejected before it can enter the DAG or store.   

**Causal DAG and total order.**  
Ops are inserted into a pending-parent DAG, which ensures that no op becomes visible until all its parents are present. Parents are mandatory, and DAG reconstruction from the persistent store filters out edges whose parents do not exist.   

Topological order is determined purely from DAG structure and HLC metadata:

1. Parents must appear before children.
2. Among ops whose parents are satisfied, ordering is by `(hlc, op_id)`.

This ordering is deterministic regardless of insertion order or runtime environment. Property tests confirm that random insertion permutations yield identical topo orderings and state digests.   

**Persistence.**  
A RocksDB-backed store uses multiple column families to persist ops, edges, and checkpoints. Ops are stored as their canonical CBOR encoding keyed by op-id; edges maintain parent metadata; indexes support author-based queries. A `db_uuid` identifies logical instances to support deterministic key derivation in later milestones. Checkpoints snapshot the state as canonical CBOR; restoring from a checkpoint and replaying remaining ops is guaranteed to produce the same state as full replay. :contentReference[oaicite:106]{index=106}  

### 4.x.2 Deterministic Replay and Deny-Wins Gate

**Replay engine.**  
Given a set of ops, the replay engine:

1. Loads topo-ordered op-ids from the store/DAG.
2. Constructs authorization epochs by scanning grant and credential ops.
3. Applies a policy function over CRDT-backed state, deciding for each op whether to apply it or to skip it, and emitting corresponding audit events.   

CRDTs (e.g., MVReg, OR-Set) provide convergence under concurrent writes; the replay engine ensures that, for a fixed set of ops and trust inputs, every node computes an identical final state. Benchmarks confirm replay parity between full and incremental modes.   

**Deny-wins semantics.**  
Authorization is enforced via a deny-wins rule:

- Replay only accepts a data op if there exists a valid grant referencing a VC that:

  - Has a valid EdDSA signature under a trusted issuer key.
  - Is not revoked in the relevant status list.
  - Is time-valid at the op’s HLC physical time (`nbf ≤ hlc.physical_ms < exp`).
  - Has a scope intersecting the op’s tags or action.   

If any of these conditions fails, the op is **skipped**; it does not partially apply. This deny-wins policy is enforced deterministically during replay and mirrored in audit events (`SkippedOp(reason)`).   

**Epochs and replay parity.**  
The policy layer groups grants and credentials into epochs, representing intervals during which a particular set of authorizations is active. Epoch construction is deterministic and uses the same topo order as data ops. Replay rebuilds these epochs from the op-log and uses them to evaluate each op’s authorization context. Split replay tests confirm that incremental application from checkpoints yields the same epoch structure and decisions as full replay.   

### 4.x.3 Authorization Epochs and Policy Layer

**VC-backed authorization.**  
ECAC-core replaces raw grant entries with VC-backed grants. Each credential op (`Payload::Credential`) carries a compact JWT-VC (`EdDSA` only) and a `cred_id`. The corresponding grant payloads carry `{subject_pk, cred_hash}`, where `cred_hash = BLAKE3(compact_jwt_bytes)`, and no longer embed role/scope directly. Roles and scopes are extracted from the decoded VC payload. :contentReference[oaicite:112]{index=112}  

VC verification (in `vc.rs`) performs:

- Compact JWS parsing and Base64URL decoding.
- Ed25519 signature verification using issuer keys obtained from TrustView (or pinned filesystem trust in legacy paths).
- Claim extraction (`iss`, `sub_pk`, `role`, `scope`, `nbf`, `exp`, status-list metadata).
- Time-window checks using HLC physical time.
- Status-list revocation checks via status-bit caches.   

Verified VCs are persisted in a slim representation, allowing replay to reuse them without re-verification, while optional parity checks guard against cache corruption.   

**Policy evaluation.**  
The policy layer builds epochs by combining:

- Valid grants (referencing verified VCs),
- Revocation status lists,
- Deny-wins rules on expiry and scope.   

For each data op, replay locates the relevant epoch(s), checks scope intersection (e.g., data tags vs VC scope tags), and applies or skips the op. This logic is deterministic and does not depend on wall-clock time, only on HLC timestamps and log contents. Permutation tests and replay parity tests confirm determinism.   

### 4.x.4 TrustView, Storage, and Sync

**In-band trust and TrustView (M10).**  
From M10 onwards, all trust inputs are expressed in-band as signed ops:

- `IssuerKey` ops introduce issuer public keys with validity windows.
- `IssuerKeyRevoke` ops revoke keys.
- `StatusListChunk` ops carry revocation bitstrings identified by `(issuer_id, list_id, version)` and protected by SHA-256 digests. :contentReference[oaicite:117]{index=117}  

TrustView is constructed deterministically from the log:

- For keys, “first-wins” per `(issuer_id, key_id)`; activation is at `max(valid_from_ms, op.hlc.physical_ms)`.
- Revocations take effect at the op’s HLC timestamp.
- For status lists, only complete versions are usable; the latest complete version per `(issuer_id, list_id)` wins. Missing bits default to “not revoked” (availability bias). :contentReference[oaicite:118]{index=118}  

Additionally, an `issuer_admin` role is defined: once an issuer_admin is active, only issuer_admin-authored trust ops are honored. This provides privilege separation and guards against unauthorized trust injection. Tests verify unauthorized trust ops are ignored when issuer_admin is active. :contentReference[oaicite:119]{index=119}  

VC verification now uses `verify_vc_with_trustview`, which consults TrustView for issuer keys and status lists. Filesystem trust directories are retained as a legacy fallback but are no longer required for correctness.   

**Storage and checkpoints (M5).**  
The RocksDB store underpins both local replay and networked replicas:

- Ops are append-only; there are no in-place rewrites or schema changes.
- Edges and indexes are persisted for deterministic DAG reconstruction.
- Checkpoints are canonical CBOR blobs containing `{topo_idx, digest, state_cbor}`; they allow fast restart and incremental replay. :contentReference[oaicite:121]{index=121}  

Crash consistency tests (including fault injection via environment variables) confirm that partial writes do not lead to inconsistent state: either an op is fully committed (with all parents) or it is absent. Integrity scanning detects signature mismatches, missing parents, and malformed entries. :contentReference[oaicite:122]{index=122}  

**Networking and sync (M6–M7).**  
An optional networking layer uses libp2p to synchronize op-logs across nodes while preserving determinism:

- **Gossip**: Gossipsub is used to broadcast ANNOUNCE messages on a dedicated topic (e.g., `ecac/v1/proj/announce`). ANNOUNCE messages carry `SignedAnnounce` payloads with node identifiers, topology watermarks, and Bloom filters summarizing head sets.   
- **Fetch**: A request-response protocol retrieves missing ops based on sync planner decisions. Per-peer `SyncState` tracks frontier, inflight requests, and unavailable ops. :contentReference[oaicite:124]{index=124}  
- **Deterministic behavior**: ANNOUNCEs are queued when there are no subscribers and flushed on subscription or connection events; `PublishError::Duplicate` is treated as success to avoid storms. Anti-entropy tests (two-node sync, duplicate-storm scenarios) confirm convergence and the absence of hot loops.   

These networking paths are used in the evaluation harness and tests but are not required for the core reproducibility pipeline, which focuses on single-node deterministic behavior.   

### 4.x.5 Confidentiality, Audit, and Limitations

**Confidentiality via per-tag encryption (M9).**  
ECAC-core introduces an experimental confidentiality layer:

- Confidential fields (tagged, e.g., as `"confidential"`) are encrypted at write-time using XChaCha20-Poly1305 (`chacha20poly1305` crate). Keys are derived deterministically from `(db_uuid, tag, version)` with BLAKE3 and persisted in the store.   
- AAD for encryption binds ciphertext to the author, HLC timestamp, parents, and object/field identifier, so transplanted ciphertext fails decryption. :contentReference[oaicite:128]{index=128}  
- Key rotation is implemented via `KeyRotate` ops, which advance the `(tag, version)` and provide forward secrecy from the rotation point (no historical re-encryption). :contentReference[oaicite:129]{index=129}  
- `KeyGrant` ops associate `subject_pk`, `tag`, `key_version`, and `cred_hash`, intending to gate decryption on the existence of a matching VC and keyring entry. The CLI’s `show` command delegates to a projection function that either decrypts or emits `<redacted>`. :contentReference[oaicite:130]{index=130}  

However, the end-to-end behavior is not yet correct: in the observed full demo (`m9_grant_vc_demo.sh`), even the intended authorized subject receives `<redacted>`. The design is confidentiality-safe (no unintended plaintext leakage) but functionally incomplete. M10 explicitly deprioritizes M9’s read-control semantics in favor of in-band trust and VC correctness.   

**Tamper-evident audit (M8, M11).**  
The audit subsystem provides an independent, verifiable view of system behavior:

- Audit entries record ingest decisions, apply/skip results, view events, checkpoints, and sync events in a fixed, frozen schema. Each entry includes a monotonic sequence number, a monotonic local timestamp, the previous hash, node id, and an Ed25519 signature over a BLAKE3 hash of the canonical CBOR-encoded entry (excluding the signature field). :contentReference[oaicite:132]{index=132}  
- Entries are written to length-prefixed log segments; `index.json` tracks sequence and hash bounds. Chain verification replays hash and signature checks and detects mid-segment corruption or truncation. :contentReference[oaicite:133]{index=133}  
- `audit-verify-full` cross-checks the audit log against deterministic replay, recomputing the set of applied and skipped ops and ensuring they match exactly.   
- M11 integrates audit hooks and a deterministic JSONL exporter into the reproducibility pipeline, ensuring that audit artifacts are bit-for-bit stable across runs.   

Crash-tail truncation repair is specified but not implemented; detection is in place, but automated recovery from partial tail writes is future work. Cross-node audit reconciliation (e.g., transparent logs across replicas) is also deferred. :contentReference[oaicite:136]{index=136}  

**Reproducibility and environment control (M7, M11).**  
To ensure that experimental results and audit/trust artifacts are reproducible:

- The Rust toolchain is pinned (Rust 1.85) via `rust-toolchain.toml`; builds use `cargo build --locked --release` with deterministic `RUSTFLAGS` disabling debuginfo and stripping symbols. :contentReference[oaicite:137]{index=137}  
- Environment variables (`LC_ALL=C`, `TZ=UTC`, `SOURCE_DATE_EPOCH`, `ECAC_TIME_MS`) are controlled to avoid locale- and time-dependent behavior. :contentReference[oaicite:138]{index=138}  
- `scripts/reproduce.sh` runs M7 benchmarks, audit hooks, and trust dumps; normalizes outputs to `docs/eval/out/`; computes SHA256 hashes of all artifacts; and constructs an archive with deterministic sort order, timestamps, and ownership metadata.   

This pipeline is validated by re-running `reproduce.sh` and checking that all hashes and the final tarball match exactly. A golden-artifact comparison script (`golden.sh` / `verify_golden.sh`) further guards against regressions. :contentReference[oaicite:140]{index=140}  

**Limitations and open issues.**  
ECAC-core deliberately leaves several areas open:

- The confidentiality layer’s semantics (authorized plaintext reads, per-subject key envelopes, network-level guarantees) are incomplete and require additional work.   
- The trust model does not yet support multi-issuer quorums or advanced revocation windows; StatusPointer and bootstrap tooling are deferred. :contentReference[oaicite:142]{index=142}  
- Network scenarios are not part of the core reproducibility pipeline, and long-running nondeterminism/stress tests for networking are not fully explored.   
- Audit log repair and cross-node transparency features are specified but not implemented. :contentReference[oaicite:144]{index=144}  

Despite these limitations, ECAC-core provides a fully instrumented platform where access-control semantics, trust, audit, and evaluation are all driven by a single signed, causal op-log, enabling rigorous reasoning about determinism, policy correctness, and forensics.
