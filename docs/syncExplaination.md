Here’s the straight read on what you’ve built and what the tests are asserting.

# What `sync.rs` actually does

### Purpose

Given a set of **remote heads**, decide **which missing ops to fetch** and in **what order**, with two goals:

1. never fetch ancestors we already have (hard boundary),
2. avoid walking indefinitely far back if a small **local bloom** says we *probably* have them (soft boundary), **but still keep parent-first order** for anything we do fetch.

### Core pieces

* **Bloom check**: `bloom16_maybe_contains([u8;2], &OpId) -> bool`

  * 16-bit Bloom (2 bytes), 3 lanes (indices derived from blake3(id)).
  * `true` means “maybe present locally”; it’s a *hint*, not a guarantee.

* **Traversal (backwards from heads)**:

  * DFS stack holds `(node_id, expand_flag)`.
  * `expand_flag=false` means “visit this node but **don’t** push its parents” (Bloom bounded).
  * For each popped node:

    * `has_it = have(&id)` — hard boundary.
    * `bloom_here = bloom16_maybe_contains(...)` — soft boundary.
    * `is_head = remote_heads.contains(id)` — heads are special (see inclusion rule).
    * **Inclusion rule** (to put the node into `missing`):
      `include = !has_it && (!bloom_here || is_head)`
      i.e. don’t include something we already have, and if Bloom claims “maybe have” then skip—**except** for remote heads (we never trust Bloom to prune heads).
    * We always wire edges `parent -> child` into `children_map`, and store `parents_map[id]`, regardless of inclusion.
    * **Expansion rule**: for each parent `p`, we *visit* it but set `next_expand = !bloom(p)`; that stops expansion **past** `p` if Bloom hints we already have `p`. We still visit `p` so that if Bloom was wrong, `p` can be included.

* **Batching (parent-first)**:

  * After traversal, we have `missing` and `parents_map`.
  * Compute `indeg[id]` = # of parents that are also in `missing`.
  * Kahn layering:

    * `ready = { id | indeg[id] == 0 }` — these have no missing parents.
    * Emit `ready` as a **batch** (stable order via `BTreeSet` → deterministic bytes order).
    * Decrement children indegrees; when a child hits zero, move it into the next `ready`.
    * Repeat until nothing’s left.
  * Result: `FetchPlan { batches: Vec<Vec<OpId>> }` where **batch 0** contains roots within the missing subgraph (the parents), and later batches move up toward the heads.

### Determinism & safety

* Deterministic ordering via `BTreeSet` when building batches.
* We never rely on Bloom to prune **heads** (to avoid false-positive drop of the very thing we need).
* Bloom only bounds how **far** we expand (no grandparents if parent is “maybe present”).
* We **always** wire edges, even if a node is not included, so indegree math is correct.

### Minor nit you can clean up

You’ve got a duplicate `include` calculation (once up top for logging, again right before insertion). That’s why you saw the “unused variable: `include`” warning. Drop the earlier one or reuse it for insertion.

---

# What the tests in `sync_planner.rs` are asserting

### 1) `planner_diff_small_and_parent_first`

* DAG:

  ```
  A -> B -> D
  A -> C -> D
  ```

  Local has **A**. Remote heads = **[D]**. Bloom is zero (no hints).
* Expectation:

  * Missing set is **{B, C, D}**.
  * Parent-first layering inside the missing subgraph gives:

    * **Batch 0**: `[B, C]` (no missing parents)
    * **Batch 1**: `[D]` (its missing parents are B and C)
* The test verifies exactly `[[B, C], [D]]`. (Your earlier failure was just an index mix-up in the test.)

### 2) `bloom_short_circuit_skips_knowns`

* Construct IDs so the 3 Bloom bits for **B** do **not** accidentally cover **C** or **D**.
* Local has nothing, but Bloom is built to mark **B** as “maybe present”.
* Parents: `D -> [B, C]`.
* Expectation:

  * Because Bloom says **B** is present, the planner **skips B**.
  * It includes **C**, and then **D** (since D still depends on C which is missing).
  * Result: **`[[C], [D]]`**.
* The test also sanity-checks that Bloom indeed hits for **B** but not for **C**/**D**.

---

# Why this design

* **Hard boundary** (“have”) guarantees we don’t refetch ancestors we already possess, but we still **visit** parents to close any gaps up the chain correctly.
* **Soft boundary** (Bloom) prevents us from walking arbitrarily deep histories when we likely have those ancestors; yet we still **visit** the parent node itself (so Bloom false positives don’t hide a truly missing parent), we just avoid expanding past it.
* **Never prune heads via Bloom** because a false positive there would cause you to “sync nothing.”

Net effect: minimal, deterministic, **parent-first** fetch plans with bounded ancestry walks and resilience to Bloom false positives in the only places that matter.
