- Hash preimage = CBOR(OpHeader) without sig/op_id
- Domain: "ECAC_OP_V1"
- op_id = blake3(domain || cbor_bytes)
- Signature = Ed25519(op_id)
- HLC ordering tie-break: (physical_ms, logical, node_id), then op_id
- DAG rule: child staged until all parents present

# Build (release)
cargo build -p ecac-core --release

# Run ALL tests (unit + integration)
cargo test -p ecac-core

# Run tests in release mode
cargo test -p ecac-core --release

# Show test output (don't capture stdout)
cargo test -p ecac-core -- --nocapture

# List all tests (names only)
cargo test -p ecac-core -- --list

# Run ONLY unit tests in the library crate
cargo test -p ecac-core --lib

# Run a SINGLE unit test (example)
cargo test -p ecac-core dag::tests::chain_parent_before_child_even_if_child_inserted_first

# Run the property test file (integration test)
cargo test -p ecac-core --test topo_prop

# Run the M1 smoke example
cargo run -p ecac-core --example m1_smoke

# (Optional) extra signal while debugging
RUST_BACKTRACE=1 cargo test -p ecac-core -- --nocapture

## M2: Data Payload Semantics & Replay

### Recap: M1 invariants
- **Op preimage**: canonical CBOR of `OpHeader`, domain-separated BLAKE3 (`"ECAC_OP_V1"`).
- **Signature**: Ed25519 signature over `op_id`.
- **Causality**: parent links form a **DAG**; children only activate when all parents are present.
- **Deterministic order**: topological; ties by `(HLC, op_id)` ascending.

### Data payload shape (unchanged)
We continue to use:
```cbor
Payload::Data { key: String, value: Vec<u8> }

No schema change in M2. Semantics come from key prefixes:

Key scheme (M2)

MV-Register write (set field):

key = "mv:<obj_id>:<field_name>"

value = field bytes

OR-Set add:

key = "set+:<obj_id>:<field_name>:<elem_key>"

value = element bytes

Add is tagged by op_id (the op’s id)

OR-Set remove:

key = "set-:<obj_id>:<field_name>:<elem_key>"

value ignored

A remove tombstones only add-tags it has observed (HB-visible)

Notes:

obj_id, field_name, elem_key are opaque ASCII. No escaping for : is provided in M2; avoid colons inside ids.

Unknown prefixes are ignored (forward-compatible).

Happens-before (HB)

HB is derived solely from the DAG:

a → b iff a is a strict ancestor of b by following parent links.

HLC is not used for causality. It’s only part of the deterministic tie-breaker when two activated nodes have no ancestor relation.

CRDT semantics
MV-Register (MVReg)

Each write is identified by its op_id and carries value.

On applying write X:

Drop any prior winners whose tags are HB-older than X.

Keep all concurrent winners.

Projection (for UI/tests): choose the value with min blake3(value); tie by raw bytes.

State stores the full winner set (not just the projection).

OR-Set (Observed-Remove Set)

Each add for (obj, field, elem) is tagged by the add’s op_id and stores a value.

A remove at R tombstones all add-tags A such that A → R (HB-visible).

Element is present iff it has at least one active tag (add minus tombstones).

Projection per element: choose the value with min blake3(value); tie by raw bytes.

Deterministic replay & export

Replay order: topological (parents before children), tie by (HLC, op_id).

Only verified ops apply (op.verify()); invalid ones are skipped.

Materialized state:

objects: BTreeMap<obj_id, BTreeMap<field_name, FieldValue>>
FieldValue = MVReg | ORSet


Tree maps ensure stable iteration.

Stable JSON export:

Objects sorted by obj_id, fields by name.

MVReg winners are listed sorted by hash (then bytes).

OR-Set elements sorted by elem_key.

Digest: blake3("ECAC_STATE_V1" || deterministic_json_bytes).

Properties (M2 acceptance)

Deterministic: same op set ⇒ same JSON bytes/digest.

Convergence: any delivery permutation ⇒ same result.

MVReg: HB-overwrite wins; concurrency keeps all winners.

OR-Set: remove kills only observed add-tags; concurrent add survives; re-add works.

Idempotence: re-apply same ops ⇒ no change.

Incremental parity: full rebuild equals incremental apply for any split of the log.


---

## Append to `docs/architecture.md`

```markdown
## State & Replay (M2)

### Modules
- `crates/core/src/replay.rs`
  - `replay_full(&Dag) -> (State, Digest)`
  - `apply_incremental(&mut State, &Dag) -> (State, Digest)`
- `crates/core/src/state.rs`
  - `State { objects: BTreeMap<obj, BTreeMap<field, FieldValue>>, processed_count }`
  - `to_deterministic_json_bytes()`, `digest()`
  - **Checkpoints**: `snapshot_to_cbor()`, `restore_from_cbor()`
- `crates/core/src/crdt/{mvreg.rs, orset.rs}`

### Execution model
1. Build the M1 DAG (parents-before-children activation).
2. Get deterministic topo order (parents first; tie: HLC, op_id).
3. For each **verified** op with `Payload::Data`:
   - Parse the key prefix (`mv:`, `set+:`, `set-:`).
   - Apply to MVReg/OR-Set with **HB from the DAG** (not from HLC).
4. Update `processed_count` for incremental replays.

### Determinism guarantees
- Given identical activated ops in the DAG, replay yields **byte-identical JSON** and **identical blake3 digest**.
- Determinism is enforced by:
  - Canonical CBOR for op hashing/signing (M1).
  - Deterministic topo + tie-break (M1).
  - BTree maps for stable iteration in state.
  - Fixed ordering rules in export (MV winners by hash, OR-Set elems by key).

### Incremental & checkpoints
- `processed_count` tracks size of the topo-order prefix already applied.
- `apply_incremental` processes the new suffix only; **idempotent**.
- **Checkpoints** (CBOR) allow saving/restoring full in-memory state (including CRDT tags) to avoid full rebuilds in tests or long-running services.

### CLI (developer tool)
- `ecac-cli replay <ops.cbor>`: prints deterministic JSON + digest.
- `ecac-cli project <ops.cbor> <obj> <field>`: prints MVReg projection (winners + chosen) or OR-Set elements.
- CBOR file may be a single `Op` or `Vec<Op>`. Ops with missing parents remain pending and won’t be applied.