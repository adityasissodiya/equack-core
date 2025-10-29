Here’s what I know (from the files) and what’s still missing, plus a blunt, step-by-step plan to land M6 end-to-end without surprises.

## What I know now (concrete context)

* **Op model is frozen.**

  * `OpId = [u8; 32]`, domain-separated hash over canonical CBOR of `OpHeader` (`OP_HASH_DOMAIN`).
  * `Op::verify()` re-hashes and verifies Ed25519.
  * Parents are explicit; HLC exists but **must not touch wall clock** in networking.

* **Canonical bytes.**

  * We use `serde_cbor` 0.11 `to_vec` for “canonical enough” bytes (structs only, no maps with key reordering).
  * All network payloads must use the same CBOR to keep op bytes stable across nodes.

* **Store (RocksDB) is real and crash-safe.**

  * Column families: `ops`, `edges`, `by_author`, `vc_raw`, `vc_verified`, `checkpoints`, `meta`.
  * `put_op_cbor(&[u8])`:

    * Validates `op_id` and signature.
    * Writes **exact** provided op CBOR into `ops`, plus `edges` + `by_author` in one `WriteBatch` (durable with `sync=true` by default).
    * Does **not** enforce parent-presence, but `topo_ids()` only returns nodes whose parents exist; integrity checks ensure edges match op parents.
  * Read paths we can use:

    * `has_op(&OpId) -> bool` (this is effectively `contains`)
    * `get_op_bytes(&OpId) -> Option<Vec<u8>>`
    * `load_ops_cbor(&[OpId]) -> Vec<Vec<u8>>`
    * `topo_ids() -> Vec<OpId>`
    * Watermarks + checkpoints are there.
  * **Missing for M6:** `heads(K)` and `recent_bloom(N)` aren’t implemented. We’ll add them.

* **CLI is deterministic and already exercises replay.**

  * `replay`/`project`/`replay_from_store` work; integrity checks exist.
  * There’s no networking CLI yet.
  * Tests include a CLI e2e that stress shuffles ops (good signal for determinism).

* **Workspace setup**:

  * Root `Cargo.toml` includes only `crates/core` and `crates/cli`.
  * You **do** have `crates/store`, but it’s not listed in the workspace; CLI imports `ecac_store`. We’ll need to add `crates/store` (and our new `crates/net`) to the workspace members. Otherwise builds will be inconsistent.

## Gaps we must fill for M6

1. **New `crates/net` crate** (libp2p + Noise + Gossipsub + simple request/response):

   * `gossip.rs`: ANNOUNCE pub/sub (`ecac/v1/<project-id>/announce`).
   * `rpc.rs`: `FetchMissing { want: Vec<OpId> } -> Stream<OpBytes>`

     * Server: reads from `ops`, streams op and **its ancestors** until requester boundary.
     * Client: verify → `put_op_cbor` in **parent-first** order.
   * `sync.rs`: `SyncPlanner` (diff heads, burn down by parent-closure, batch fetch).

2. **Store additions** (small, deterministic):

   * `Store::contains(id: &OpId) -> bool` → alias of `has_op`.
   * `Store::heads(k: usize) -> Vec<OpId>` → tips with no children (based on `edges`).
   * `Store::recent_bloom(n: usize) -> [u8; 2]` → tiny 16-bit bloom over most recent N op_ids in topo tail (implementation detail we’ll document).

3. **CLI networking commands**:

   * `node --listen <addr> --peer <addr>... --project <id>`
   * `status` (op count, head count, topo watermark)
   * `inject-demo-ops` (to drive manual convergence tests)

4. **Tests**:

   * Unit: `planner_diff_small`, `parent_first_enforced`, `bloom_short_circuit`.
   * Integration: `two_node_sync`, `three_way_partition`, `duplicate_storm`, `invalid_op_drop`.
   * Property: randomized partitions/DAGs.

5. **Docs**:

   * `docs/protocol.md`: schemas (Announce/FETCH), invariants (idempotence, causal completion).
   * `docs/architecture.md`: “Networking & Sync” sequence diagrams.

## How I propose we proceed (no code yet)

### Phase 0 — Wire up workspace, zero-risk changes

* Add `crates/store` to `[workspace].members`.
* Create `crates/net` with `Cargo.toml` and feature flags (libp2p, serde, cbor).
* No runtime logic yet; just compiles.

### Phase 1 — Store helpers (tiny, safe, testable)

* Add `contains` (alias to `has_op`), `heads(K)`, `recent_bloom(N)`.
* Unit tests inside `store` for `heads` and bloom stability (deterministic across restarts).

### Phase 2 — Protocol types + serializer

* Define `Announce { node_id, topo_watermark, head_ids, bloom16 }` (CBOR; no maps; fixed order).
* Define RPC messages: `FetchMissing { want: Vec<OpId> }` and streamed frames (`OpBytes`).
* Sign `Announce` with node key, but treat signature as **authenticity only**; op integrity relies on per-op signatures (already enforced by `put_op_cbor`).

### Phase 3 — Gossip and RPC plumbing

* `gossip.rs`: libp2p Swarm with Noise+Gossipsub, topic per `<project-id>`. Publish on:

  * startup,
  * after each successful ingest batch,
  * periodic anti-entropy tick.
* `rpc.rs`: request/response over libp2p (or tonic over TCP if you prefer; I’ll default to libp2p’s request/response to avoid external deps).

### Phase 4 — SyncPlanner + ingestion path

* Compute missing frontier from `(local_heads, remote_heads, remote_bloom16)`.
* Expand via **parent-closure**; plan batches of e.g. 512 ops.
* Client fetches → verifies → `put_op_cbor` **parent-first**; duplicates ignored via `contains`.

### Phase 5 — CLI node + tests

* Add `node`, `status`, `inject-demo-ops`.
* Implement integration/property tests per acceptance criteria.

### Phase 6 — Docs + final invariants check

* Protocol and architecture updates.
* Confirm `store.verify_integrity()` passes post-sync.
* Run multi-node scripts to demonstrate convergence.

## Decisions I’ll lock unless you veto

* **No wall clock** in network paths; HLC stays inside ops as provided by authors.
* **Parent-first invariant** enforced in planner and client ingestion (store already tolerates orphans; topo excludes them until parents arrive).
* **Exactly-once not assumed**; dedup via `contains` before `put_op_cbor`.
* **Batching**: single in-flight fetch per peer in M6; commit per batch with `WriteBatch + sync=true`.
* **Small bloom**: 16-bit, 3 hash funcs over recent N ids; it’s a hint, not an oracle.

## What I need from you before I start coding

1. **Green-light this plan** (or tell me what to change).
2. Confirm libp2p is acceptable (crate versions are your call; I’ll pick stable ones).
3. Confirm we can update the workspace to include `crates/store` and the new `crates/net`.
4. Preference on RPC transport:

   * A) libp2p request/response (keeps a single networking stack), or
   * B) tonic gRPC on localhost/LAN (heavier, but familiar).
     Default is **A**.

If you say “go,” I’ll start with Phase 0–2 and keep each PR small and reviewable.
