Alright, straight talk.

Think of ECAC as a Lego set you build in a very specific order. M5 makes sure:

1. every brick you snap in is saved to a sturdy box on disk,
2. if the table flips (crash), you can put the bricks back in **exactly** the same order, and
3. photos (checkpoints) of the build let you resume without redoing everything.

Under the hood, here’s what we actually nailed—no hand-waving.

---

# What we write to disk (the “sturdy box”)

* **RocksDB with fixed drawers (column families):**

  * `ops`: the **exact** bytes of each operation (canonical CBOR the signer saw). No re-encoding on write.
  * `edges`: a tiny index for each op: its `parents[]`, author key, and HLC parts. Lets us rebuild order fast.
  * `by_author`: composite key `(author_pk || hlc || op_id)` for range scans.
  * `vc_raw` / `vc_verified`: raw JWT and a compact, verified summary (a cache).
  * `checkpoints`: snapshots of **canonical** state + digest + the last applied topo index.
  * `meta`: schema version and last checkpoint id.

* **Write path is atomic and crash-safe:** one `WriteBatch` with `sync=true`. Either all the pieces land, or none do. No half-written ops.

---

# How we rebuild after a crash (putting Legos back)

* We **never** trust a cached order. We rebuild the topological order from `edges` with Kahn’s algorithm.
* A node only enters the order if **all its parents exist** in `ops`.
* Tie-breaks are deterministic: `(hlc_ms, hlc_logical, hlc_node, op_id)`.
* Result: the replay order is **bit-stable** across machines and runs.

---

# Why the answers don’t change (determinism rules)

* IDs are `H(OP_HASH_DOMAIN || canonical_cbor(header))`. On load, we recompute and cross-check the key.
* We store ops as the **exact** canonical CBOR that was hashed/signed. No drift = same `op_id`, always.
* State and checkpoints are encoded with **canonical** CBOR (sorted maps/sets), so JSON output + digests are stable.

---

# Permissions still apply (deny-wins)

* We compute policy epochs over the **same** topo order and enforce deny-wins before applying data ops.
* If the log has **no** policy events, we default-allow (M2 compatibility). That’s deliberate, not a bug.

---

# Checkpoints (photos of the build)

* A checkpoint stores:

  * `state_cbor` (canonical),
  * `state_digest` (must match when reloaded),
  * `topo_idx` (how far we applied).
* On restart we do: `load(latest) → apply from topo_idx+1`.
  That produces the **same** state as “replay from genesis”. We proved that.

---

# Integrity sweeps (we check the box isn’t rotten)

* For every op: decode, recompute `op_id`, verify signature, verify key matches `op_id`.
* For every edge: ensure matching op exists and `edges.parents == op.header.parents`.
* Rebuild topo and assert: `|topo| == |ops| == |edges|`.
* If anything’s off, we fail loudly with the exact `op_id`.

---

# VC caches (we don’t waste time re-verifying)

* `vc_raw` keeps the compact JWT; `vc_verified` caches the parsed/checked facts.
* It’s a **cache**: if missing or stale, we can recompute. Storing both makes reboot cheaper.

---

# We tested the ugly bits

* **Crash injection:** env var flips a “crash after write” path. After the kill, DB reopens clean; replays match.
* **Parity:** in-memory replay ≡ replay-from-store. Digests match.
* **Corruption detection:** we deliberately flip a byte; `verify-store` complains, as it should.
* **Pending parents:** children stay out of topo until parents arrive; then they slot in once—no dupes.

---

# What this buys you (no fluff)

* **Crash-recovery correctness:** no lost/half ops; same answers before/after crash.
* **Bit-for-bit determinism:** same DB → same JSON → same digest, anywhere.
* **Operational sanity:** fast restarts (edges + checkpoints); integrity checks when suspicious.

M5 means disk is now authoritative and deterministic. When we layer networking in M6, we’re syncing **truth**—not gambling with “maybe” state.
