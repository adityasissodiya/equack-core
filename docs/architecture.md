Got it. Here are the two docs. Drop them in your repo at the exact paths below.

---

# docs/architecture.md

## M5 — Persistence & Recovery (RocksDB; no networking)

This describes how ECAC persists operations, rebuilds the causal DAG/materialized state after restart, and performs deterministic checkpoints. The goal is that crashes/restarts never change answers and disk is the source of truth.

---

## Storage layout (column families)

RocksDB database with **explicit CFs**:

* `ops`
  **Key**: `op_id` (32 bytes)
  **Value**: **canonical CBOR** of the full `Op` (exact bytes that were signed/hashed).

* `edges`
  **Key**: `op_id`
  **Value**: CBOR of:

  ```rust
  struct EdgeVal {
      parents: Vec<[u8;32]>,
      author_pk: [u8;32],
      hlc_ms: u64,
      hlc_logical: u32,
      hlc_node: u32,
  }
  ```

  Used to rebuild topo order without decoding the whole op.

* `by_author`
  **Key**: `(author_pk || hlc_ms || hlc_logical || hlc_node || op_id)`
  (big-endian encoding for numeric fields)
  **Value**: empty `[]`.
  Range scans by `(author_pk, time)`.

* `vc_raw`
  **Key**: `cred_hash` (32 bytes)
  **Value**: raw JWT bytes (compact JWS).

* `vc_verified`
  **Key**: `cred_hash` (32 bytes)
  **Value**: CBOR of a minimal verified VC record (issuer, subject, role, scope, validity).
  This is a **cache**; it can be recomputed from `vc_raw` + trust/status.

* `checkpoints`
  **Key**: `checkpoint_id` (u64, big-endian in the key)
  **Value**: CBOR of:

  ```rust
  struct CheckpointBlob {
      topo_idx: u64,
      state_digest: [u8;32],
      state_cbor: Vec<u8>, // canonical CBOR of State
  }
  ```

* `meta`
  **Keys**:

  * `schema_version` → `"ecac:v1"`
  * `last_checkpoint_id` → u64 (big-endian bytes)
  * (optional) future hints: `db_uuid`, `topo_watermark`, etc.

All CFs opened with `paranoid_checks = true`. We use WAL and synced write batches on the correctness path.

---

## Write path (append-only)

`Store::put_op_cbor(op_cbor: &[u8])`

1. **Decode/compat**
   Accepts modern `Op` CBOR; falls back to legacy flat encoding for reads (never written).

2. **Validate**

   * Recompute `op_id = H(OP_HASH_DOMAIN || canonical_cbor(header))`.
   * Verify signature.

3. **Build edges** (`EdgeVal`), independent of parent presence.

4. **Atomic commit**
   Single `WriteBatch` with `sync=true`:

   * `ops[op_id] = op_cbor`  (store **exact** canonical bytes)
   * `edges[op_id] = cbor(EdgeVal)`
   * `by_author[composite_key] = []`

RocksDB guarantees: the batch is applied atomically. On crash, either all 3 entries appear or none do. No partial rows.

---

## Topological rebuild

`Store::topo_ids() -> Vec<OpId>`

* Iterate `edges` CF (fast path). For each node:

  * Skip nodes that reference **missing parents** (pending) — they won’t enter the ready set.
  * Maintain `indegree` and `children` maps.
  * Use **Kahn’s algorithm** with deterministic ready-set ordering:

    * Order key: `(hlc_ms, hlc_logical, hlc_node, op_id)` (lexicographic).
* Output is **parents-first**, ties broken by HLC then `op_id`.
* This is recomputed every process start. Any cached topo order is advisory, not source of truth.

Pending parents: ops whose parents aren’t present on disk are ignored by the topo iterator until parents arrive; once they do, the child appears in the correct order without duplication.

---

## Deterministic replay & policy gate

* `replay_from_store` loads topo ids, decodes ops, and applies them using the same logic as in-memory runs (M1–M4).
* Policy (deny-wins) is computed over the **same topo order**. If no policy events exist, default-allow for M2 compatibility.
* State encoding for external use is deterministic (sorted maps/sets); digest is stable across runs/hosts.

---

## Checkpoints

* `checkpoint_create(state, topo_idx)` stores:

  * `state_cbor = canonical_cbor(state)`
  * `state_digest = state.digest()`
  * `topo_idx` (the last applied index, 0-based in topo order)
  * increments and persists `last_checkpoint_id`.
* `checkpoint_load(id)` returns `(State, topo_idx)`, verifying `digest(state_cbor) == state_digest`.
* Replay-from-store:

  1. Load latest checkpoint if present.
  2. Compute `topo_ids()`.
  3. Apply incrementally from `topo_idx+1` to end using the same rules as full replay.
  4. Result equals a full rebuild from genesis (**parity required**).

---

## Integrity verification

`Store::verify_integrity()` performs:

1. For every `ops` entry:

   * decode, recompute `op_id` and check key equality,
   * verify signature.
2. For every `edges` entry:

   * ensure the matching `ops` key exists,
   * `edges.parents` must equal `op.header.parents`,
   * count missing parent references (must be 0).
3. Build `topo_ids()` and assert:

   * `|topo| == |ops| == |edges|`.

Any error aborts with a precise message (op id hex).

---

## Crash safety

* Always write with a single `WriteBatch` + `WriteOptions::set_sync(true)`.
* WAL enabled; RocksDB provides atomic commit across CFs.
* On restart, we do **not** trust any cached topo; we rebuild from `edges`.
* A crash between appends may leave the DB with fewer committed ops than the caller attempted, but **never a partially written op**.

---

## Determinism rules (pin them down)

* **On-disk op bytes** are the exact canonical CBOR used for hashing/signing; never re-encode when writing.
* **Topo order** is recomputed from `edges` with ordering `(parents-first; tie: HLC, op_id)`.
* **Checkpoints** store **canonical** CBOR of `State`. Restores do not consult wallclock.
* Endianness for composite keys is **big-endian** for numeric fields to preserve lexicographic order.

---

## CLI tooling

* `op-append --db <dir> <file|dir>`: batch append canonical op CBOR files.
* `replay-from-store --db <dir>`: loads latest checkpoint (if any) and applies incrementally to produce deterministic JSON + digest.
* `checkpoint-create --db <dir>` / `checkpoint-list` / `checkpoint-load --db <dir> <id>`.
* `verify-store --db <dir>`: runs full integrity scan.
* `vc-verify [--db <dir>] <vc.jwt>`: verifies a JWT VC under `./trust`, caches into `vc_raw`/`vc_verified` when `--db` (or `ECAC_DB`) is provided.

---

## Invariants

* Every `op` decodes, hashes to its key, and verifies signature.
* Every `edges` row has a matching `op` row and identical `parents`.
* `topo_iter()` never yields a child before any of its parents.
* Given identical DB contents, replay produces **bit-for-bit identical** JSON and digest across runs/hosts.
* `load(latest_checkpoint) + incremental == full replay from genesis`.

---

## Risks / foot-guns

* **Re-encoding drift**: do not serialize ops on the write path; store the **exact** canonical CBOR the signer saw.
* **Treating cached topo as truth**: don’t. Always rebuild from `edges`.
* **Clock bleed**: never consult wall time during replay.
* **Partial writes**: only ever commit with a single synced `WriteBatch`.

---

# docs/protocol.md

## On-disk Encodings (v1)

This file specifies the exact key/value formats stored in RocksDB (`schema_version = "ecac:v1"`). All numeric multibyte fields in composite **keys** are big-endian to preserve lexicographic order.

---

## Canonical CBOR

* **`Op` canonical bytes**: values in the `ops` CF are **canonical CBOR** of the Rust struct:

  ```rust
  struct Op {
      header: OpHeader,
      sig: Vec<u8>,
      op_id: [u8;32],
  }

  struct OpHeader {
      parents: Vec<[u8;32]>,
      hlc: Hlc,                // { physical_ms: u64, logical: u32, node_id: u32 }
      author_pk: [u8;32],
      payload: Payload,
  }
  ```

* Hash rule:
  `op_id = H(OP_HASH_DOMAIN || canonical_cbor(header))`
  The domain constant is `OP_HASH_DOMAIN` (byte string; see `ecac_core::crypto`).

* **Never** re-encode an op on the write path. The bytes in `ops` are exactly the canonical CBOR that was hashed/signed.

**Compatibility note**: The reader tolerates *legacy flat* op encodings on input (fields at top-level). These are only accepted for **reading**; we never write them.

---

## Column families

### CF: `ops`

* **Key**: `op_id` (32B)
* **Value**: **canonical CBOR** of `Op` (as above)

### CF: `edges`

* **Key**: `op_id` (32B)
* **Value**: CBOR of:

  ```cbor
  {
    "parents": [ bytes(32) * ],
    "author_pk": bytes(32),
    "hlc_ms": uint,
    "hlc_logical": uint,
    "hlc_node": uint
  }
  ```

  (This mirrors `EdgeVal` in code. Field order is a CBOR map; we rely on serde’s stable struct field order, but the value is internal and not hashed.)

Semantics:

* `parents` must bit-match `op.header.parents` of the corresponding `ops` row.

### CF: `by_author`

* **Key**: `author_pk(32) || hlc_ms(8) || hlc_logical(4) || hlc_node(4) || op_id(32)`
  All numeric components are **big-endian**.
* **Value**: empty `[]` (zero-length)

This is an index only. Source of truth remains `ops` + `edges`.

### CF: `vc_raw`

* **Key**: `cred_hash` (32B) — typically `BLAKE3` or equivalent 32-byte content hash of the compact JWT.
* **Value**: raw bytes of the compact JWS (ASCII).

### CF: `vc_verified`

* **Key**: `cred_hash` (32B)
* **Value**: CBOR of a compact verified VC record. The project stores a small struct sufficient for authorization:

  ```rust
  struct VerifiedCache {
      cred_id: String,
      issuer: String,
      subject_pk: [u8;32],
      role: String,
      scope_tags: Vec<String>, // or a set; serialized deterministically
      nbf_ms: u64,
      exp_ms: u64,
      status_list_id: Option<String>,
      status_index: Option<u32>,
  }
  ```

  Implementation may vary; it’s a **cache**, not a source of truth. On mismatch, prefer recomputing from `vc_raw` plus local trust/status.

### CF: `checkpoints`

* **Key**: `checkpoint_id` (u64; **big-endian** bytes)
* **Value**: CBOR of:

  ```rust
  struct CheckpointBlob {
      topo_idx: u64,          // last applied topo index (0-based)
      state_digest: [u8;32],  // digest(state_cbor)
      state_cbor: Vec<u8>,    // canonical CBOR of State
  }
  ```

  * `state_cbor` is **canonical** CBOR (sorted maps/sets).
  * `state_digest` must equal `digest(state_cbor)` on load.

### CF: `meta`

* `schema_version` → ASCII bytes `"ecac:v1"`
* `last_checkpoint_id` → u64 (**big-endian** bytes)
* (optional) `db_uuid` → ASCII hex (fixed 32/36 bytes); stable per DB directory.

---

## Deterministic replay contract

Given identical DB contents:

1. Rebuild topo from `edges`, excluding any node that references a missing parent. Order by `(hlc_ms, hlc_logical, hlc_node, op_id)`.
2. Apply policy epochs over the **same** order (deny-wins). If no policy events exist in the entire log, **default-allow** (M2 compatibility).
3. Apply data ops into CRDTs (MVReg, Sets) with happens-before derived from DAG ancestry.
4. Encode `State` as canonical CBOR and/or deterministic JSON.
   Resulting JSON and digest must be **bit-for-bit** identical across runs/hosts.

---

## Integrity rules

* For each `op`:

  * `H(OP_HASH_DOMAIN || canonical_cbor(header)) == op_id == key`
  * signature verifies under `author_pk`.
* For each `edge`:

  * matching `ops[key]` exists,
  * `edges.parents == op.header.parents`.
* Topo must cover **all** ops (and vice versa):

  * `|edges| == |ops| == |topo|`.

On failure, `verify-store` reports a precise reason and `op_id` hex.

---

## Endianness and byte layouts

* Composite keys encode all numeric fields in **big-endian** (`to_be_bytes()`).
* `op_id`, `author_pk`, and `cred_hash` are raw 32-byte values.
* Checkpoint keys (`u64`) are big-endian so that lexicographic order matches numeric order.

---

## Versioning & migration

* `meta/schema_version` must equal `"ecac:v1"`.
  Unknown values must cause `Store::open()` to fail with a clear error.
* Future migrations can add new CFs or evolve value schemas; existing CFs must remain readable.

---

## Compatibility notes

* Reader accepts **legacy flat** op CBOR for input ingestion (compat decode path) but writes only modern `Op` canonical CBOR.
* `vc_verified` is a cache; its schema can evolve without affecting correctness. If absent or stale, recompute from `vc_raw` and local trust/status.

---

## Security & correctness

* Never use wall time during replay or checkpoint restore; only use fields contained in ops/VCs.
* Always commit via a single synced `WriteBatch`; do not split writes to `ops`, `edges`, and indexes.
* The canonical CBOR encoder for `State` and `OpHeader` must be stable across versions and platforms.

---

That’s it. These two files lock the contract for M5.
