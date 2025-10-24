**Usage:**

```
cargo run -p ecac-cli -- simulate
cargo run -p ecac-cli -- simulate offline_edit
cargo run -p ecac-cli -- simulate grant_after_edit
```

---

# `docs/policy-model.md` (new file)

````markdown
# ECAC Policy Model (M3)

This document specifies the **write authorization model** used in M3 and how it integrates with the deterministic replay engine from M1/M2.

## Summary

- **Policy is in-band.** Grants/Revoke events live in the *same* signed, hash-linked DAG as data ops.
- **Auth epochs.** We scan the *same* total order (topo + HLC + op_id tie) and build **epochs** of validity.
- **Scope = intersects.** A grant’s `scope_tags` applies to a data op iff the op’s `resource_tags` **intersect** the grant’s scope.
- **Deny-wins.** During replay, a data op is applied iff there exists a valid epoch covering that op; otherwise it is **skipped**. Grants are **not retroactive**.

## Event types

```text
Grant {
  subject_pk: [u8;32],
  role: String,           // e.g., "editor"
  scope_tags: Vec<String>,
  not_before: Hlc,
  not_after: Option<Hlc>  // None = open-ended
}

Revoke {
  subject_pk: [u8;32],
  role: String,
  scope_tags: Vec<String>,
  at: Hlc
}
````

* **Role→permissions** is a static table in code. In M3:

  * `editor` permits: `SetField`, `SetAdd`, `SetRem` (no required tags).
* **Resource tags** are derived from the data key via a static mapping:

  * `(obj="o", field="x") → {"hv"}`
  * `(obj="o", field="s") → {"mech"}`
  * else: `{}`

## Epoch construction

We scan the deterministic total order and maintain per-key `(subject, role)` a vector of `Epoch`:

```
Epoch {
  scope: TagSet,
  start_pos: usize,         // inclusive (position in total order)
  end_pos: Option<usize>,   // exclusive; None = open interval
  not_before: Option<Hlc>,  // HLC guard, inclusive
  not_after: Option<Hlc>,   // HLC guard, exclusive
}
```

Rules:

* On **Grant**, append a new open epoch starting at the current position, with the grant’s scope and HLC window.
* On **Revoke**, close any **open** epochs for the same `(subject, role)` whose `scope` **intersects** the revoke scope; set `end_pos = current_position`.

Normalization is optional in M3; overlapping open intervals are fine because we only need an existential check at replay time.

## Deny-wins replay

For each **data** op at `(pos, hlc)` with author `pk`, action `A`, and `resource_tags`:

1. Check role permissions: `A` must be included in the static permissions for at least one role held by `pk` (in M3 we only use `"editor"` in scenarios).
2. Search epochs for `(pk, role)`:

   * `pos ∈ [start_pos, end_pos)` (using `usize` position in total order)
   * `not_before ≤ hlc < not_after` (if present)
   * `scope ∩ resource_tags ≠ ∅`
3. **Apply** if any epoch passes; otherwise **skip** (no side effects).

**No retroactive authorization:** If a `Grant` appears *after* a data op in the total order, that op **remains denied**.

## Invariants

* **Policy-Safety.** No data op outside any valid epoch can affect materialized state.
* **Convergence w/ policy.** Any permutation of delivery of the same event set yields the same filtered state at all replicas.
* **Determinism.** Epochs are keyed by the total order derived from the DAG; results are byte-identical.

## Implementation references

* `policy.rs` — epoch builder + `is_permitted_at_pos`
* `replay.rs` — deny-wins gate before CRDT apply
* `crdt/` — MVReg and OR-Set remain unchanged

````

---

# `docs/architecture.md` (replace with an updated file that includes the new M3 section)

```markdown
# ECAC Architecture (M1–M3)

This document describes the end-to-end pipeline and the main invariants.

## M1: Signed, Hash-Linked DAG + Deterministic Total Order

- **Event structure:** `Op { header, sig, op_id }`, where `op_id = BLAKE3("ECAC_OP_V1" || CBOR(header))`.
- **Header:** `parents: Vec<op_id>`, `hlc`, `author_pk`, `payload`.
- **DAG staging:** children wait until all parents are present.
- **Total order:** deterministic topological sort — parents before children; tie-break `(HLC, op_id)` ascending.

**Invariant:** All replicas derive the same total order for the same activated set of ops.

## M2: Deterministic Replay + Baseline CRDTs

- **CRDTs:**
  - **MV-Register:** HB-aware overwrite; keeps set of concurrent winners; deterministic projection = min hash(value).
  - **OR-Set:** adds tagged with `op_id`; remove kills only HB-visible add-tags; projection is deterministic.
- **Replay:** scan total order once; apply verified data ops with CRDT semantics; materialize an object/field map with stable JSON export and a state digest.

**Invariant:** Same op set ⇒ byte-identical materialized state (convergence + determinism).

## M3: Replay with Policy Filter (Authorization Epochs + Deny-Wins)

**Core idea:** Treat **policy** as first-class events in the log, build **auth epochs** from the same total order, and apply a **deny-wins** gate *before* CRDT apply.

### Event types

- `Grant { subject_pk, role, scope_tags, not_before, not_after }`
- `Revoke { subject_pk, role, scope_tags, at }`

Roles→permissions are static in code; in M3, `"editor"` permits `SetField`, `SetAdd`, `SetRem`.

### Scope and tags

- **Scope semantics:** **intersects** — a grant applies when `scope ∩ resource_tags ≠ ∅`.
- **Resource tags:** derived from data keys by a fixed mapping (e.g., `("o","x")→{"hv"}`, `("o","s")→{"mech"}`).

### Epoch construction

- Scan the total order:
  - **Grant** ⇒ open an epoch at `[start_pos=cur, end_pos=None]`, recording `scope` and HLC window.
  - **Revoke** ⇒ close any open epoch for the same `(subject, role)` whose scope intersects the revoke’s scope: `end_pos=cur`.
- Epochs are keyed by **position** in the total order. HLC bounds further restrict validity (`[nbf, naf)`).

### Deny-wins gate

For each data op at `(pos, hlc)` by `author`:
1. Derive `action` and `resource_tags` from the key.
2. Check role permissions.
3. Check if **any** epoch for `(author, role)` covers `pos`, intersects the tags, and admits the HLC.
4. **Apply** if permitted; otherwise **skip**. Skipped ops have **no side effects**.

### Invariants

- **Policy-Safety:** If a `Revoke` precedes a data op in the total order, that op does not change state.
- **Convergence with policy:** Any permutation of delivery yields the same filtered state (epochs are derived from the same order).
- **No retroactive authorization:** Grants only affect operations at or after their position; earlier ops remain denied.

### Reference path

````

Signed Events (data + policy)
↓ verify(sig)
Causal DAG staging
↓ topo + (HLC, op_id) tie
Deterministic total order
↓ build epochs (policy)
Deny-wins gate per op
↓ apply CRDT (MVReg/OR-Set)
Materialized State + Digest

```

### Repro

- **Core**: `cargo run -p ecac-core --example simulate_policy`
- **CLI**: `cargo run -p ecac-cli -- simulate [offline_edit|grant_after_edit|both]`
- **Property tests**: `cargo test -p ecac-core --tests`
```

---

## Run commands

* Build CLI:

  ```
  cargo build -p ecac-cli
  ```
* Simulate M3 scenarios:

  ```
  cargo run -p ecac-cli -- simulate
  cargo run -p ecac-cli -- simulate offline_edit
  cargo run -p ecac-cli -- simulate grant_after_edit
  ```
* Replay a CBOR file:

  ```
  cargo run -p ecac-cli -- replay ops.cbor
  cargo run -p ecac-cli -- project ops.cbor o x
  ```

If anything doesn’t compile on your end, paste the exact error block and I’ll adjust immediately.
