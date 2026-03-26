ok, imagine we’re building a super-picky scrapbook together. everyone can add sticky notes, even when they’re offline, but later we all have to agree on the exact same final scrapbook. here’s how we made that work so far (M1 and M2) — in kid-speak, but with the full real details.

# the pieces everyone adds: “events”

* each thing someone does is an **event** (we call it an “op”): “i set X to value V”, or “i added element E to a set”.

* every event has two parts:

  1. a **header** we can hash and sign:

     * `parents: Vec<OpId>` — which earlier events this one knew about
     * `hlc: Hlc { physical_ms:u64, logical:u32, node_id:u32 }` — a clock we only use to break ties (not to define causality)
     * `author_pk: [u8;32]` — who is claiming this event (their Ed25519 public key, raw bytes)
     * `payload: Payload::Data { key: String, value: Vec<u8> }`
  2. a **signature** and a precomputed **op_id** (the hash)

* how we compute the **op_id** (must be identical everywhere):

  * encode the header with **canonical CBOR** (so the bytes are stable)
  * hash `b"ECAC_OP_V1" || cbor(header)` with **BLAKE3** → 32-byte `op_id`
  * sign that 32-byte `op_id` with **Ed25519**

* verification later does the same hash again and confirms the Ed25519 signature using the author’s key.

# M1: making the pile of events safe and ordered

## 1) we only accept “real” events

* before an event does anything, we **verify** it:

  * recompute `op_id` from the header bytes
  * check the signature over that `op_id` with the author’s public key
  * if either fails → reject

## 2) we store events in a **DAG** (a “no-loops” graph)

* edges go from **parent → child** using those parent hashes.
* if an event arrives but some parents are missing, we **stage it as pending** until all parents show up (we keep a `wait_index: missing_parent → waiting_children`).

## 3) we compute a **deterministic total order**

* when enough events are present, we do a **topological sort**:

  * **parents before children** (that’s the causal rule)
  * if two events are not related by parents (concurrent), we break ties by

    1. **HLC** (lexicographic on `(physical_ms, logical, node_id)`)
    2. then by **op_id**
* result: given the same set of events, **every replica produces the exact same order** — no guessing, no randomness.

✅ tests we already have:

* unit tests for verification and DAG activation
* a property test that says the topo order is stable no matter what insertion order you deliver the same events in

# M2: turning the ordered events into a single, agreed-upon state

now we take that ordered list and “replay” it to build an in-memory state. because people can do things at the same time, we use **CRDTs** so concurrent actions don’t break convergence.

## 0) we still use the same single payload form

* **no schema change**: `Payload::Data { key, value }`
* we interpret `key` by a naming convention:

  * `mv:<obj>:<field>` → **MV-Register** “set field” with `value`
  * `set+:<obj>:<field>:<elem>` → **OR-Set add** element `elem` with payload `value`
  * `set-:<obj>:<field>:<elem>` → **OR-Set remove** element `elem` (value ignored)

*(no colons inside ids in M2; keep ids simple ascii)*

## 1) how we decide “happens-before” (HB)

* we **do not** use timestamps for causality.
* **HB** is: event `A` happens-before event `B` **iff `A` is an ancestor of `B` in the DAG** (there’s a path following parents).
* we check ancestry with a small DFS (fine for M2 scale).

## 2) the two CRDTs

### MV-Register (for fields that get set to a value)

* we keep a map `winners: tag(op_id) → value`.
* when we **apply a write X**:

  * remove any existing winners that **HB-precede** X (they’re older in causality)
  * keep any **concurrent** winners (so multiple values can survive)
  * add X’s `op_id → value`
* **projection** (for UI/tests): pick **the value whose BLAKE3(value) is smallest**; if equal, pick the lexicographically smaller bytes.
  state itself still stores **all** concurrent winners.
* **deterministic iteration**: when exporting, we list winners sorted by that **hash order** (ties by bytes).

### OR-Set (for add/remove collections)

* each **add** of `(obj, field, elem)` is tagged by the add’s **op_id** and stores a value.
* a **remove** at event `R` only tombstones add-tags `A` where **A → R** (HB-visible).
  a **concurrent add survives** that remove.
* an element is **present** iff it has **some add-tag not tombstoned**.
* projection for a present element: choose the value with **min BLAKE3(value)** (tie by bytes).
* deterministic iteration: elements are listed by `elem` key in lexicographic order.

✅ unit tests we already have:

* MVReg: HB overwrite wins (single winner), concurrent writes keep both
* OR-Set: observed remove kills only seen adds; concurrent add survives; re-add with new tag works

## 3) the replay engine

* **input:** a `Dag` (we use its topological order) and the set of verified ops
* **process:**

  1. get `topo := dag.topo_sort()`
  2. for each op in `topo`:

     * **verify** again (cheap safety) — recompute hash + signature check
     * if payload is `Data`:

       * parse the key
       * if `mv:...` → `mvreg.apply_put(op_id, value, hb)` where `hb(a,b)` consults DAG ancestry
       * if `set+:...` → `orset.add(elem, op_id, value)`
       * if `set-:...` → `orset.remove_with_hb(elem, &op_id, hb)`
     * ignore unknown prefixes (forward-compatible)
* **state shape:**
  `State { objects: BTreeMap<obj, BTreeMap<field, FieldValue::{MV(MVReg)|Set(ORSet)}>> }`
  we use **BTreeMap** to make iteration order fixed.
* **deterministic export:**
  build stable JSON:

  * objects sorted by `obj`
  * fields sorted by name
  * MV winners sorted by **hash**, plus a `project` field
  * OR-Set elements sorted by key
* **digest:** `blake3( b"ECAC_STATE_V1" || deterministic_json_bytes )`
* **incremental apply:** we remember `processed_count` (how many topo events already applied) and only apply the new suffix. re-applying the same DAG is **idempotent**.
* **snapshot/restore:** we can CBOR-serialize the whole State (CRDT internals included) and restore it later—useful for fast tests.

✅ property tests we already have:

* **convergence:** any permutation of the same events → identical final state
* **idempotence:** re-applying same events → no change
* **incremental parity:** any split (prefix then suffix) → same result as full replay
* plus the original M1 topo-determinism property test

## 4) command-line helper (for humans)

* `ecac-cli replay <ops.cbor>` — reads a CBOR `Vec<Op>` (or single `Op`), builds the DAG, replays it, prints the deterministic JSON and the digest
* `ecac-cli project <ops.cbor> <obj> <field>` — shows the CRDT projection for that field (MV or Set), including MV winners

## 5) tiny glossary (you asked earlier, keeping it here)

* **CBOR**: Concise Binary Object Representation — like JSON, but binary and deterministic in our “canonical” form.
* **DAG**: Directed Acyclic Graph — arrows forward only; we use it to encode causality (parents before children).
* **HLC**: Hybrid Logical Clock `(physical_ms, logical, node_id)` — we **only** use it to break ties when events are concurrent.

# what we deliberately did **not** do yet (that’s M3)

* we have **no deny-wins policy filter** active in the M2 code (no auth epochs, no trust credentials).
  M2 is **data-only correctness**: deterministic replay + CRDT convergence.
  M3 will add:

  * **TrustView** (issuer keys + status from in-band policy/trust events)
  * **authorization epochs**
  * a **deny-wins filter** that drops unauthorized data events during replay (revocations “erase” effects).
  * same determinism guarantees, just with policy-aware filtering.

# a tiny “show me” example (exactly what our example/CLI did)

* we made 5 events:

  1. two concurrent MV writes to `(o, x)` with values `41` and `42` (those are hex of the bytes)
  2. a set add `(o, s, e)` with value `7632`
  3. a remove that **sees** that add (HB), so it tombstones that tag
  4. a second add after the remove with a new tag and value (present)
* replay produces:

  * MV winners for `o.x`: both `41` and `42`, with **project** = `41` (smaller hash)
  * OR-Set `o.s`: element `e` present with value `7632`
  * a stable digest: `5dcab3...e84` (from our run)
* shuffle the input any way you like → same JSON, same digest.

# where the diagram comes from

* i gave you a python script that draws the pipeline:
  `Signed events → Causal DAG → Total Order → (future) TrustView/Epochs/Deny-Wins → CRDT Apply → Final State`
* files are here:

  * PNG: `ecac_m1_m2_architecture.png`
  * PDF: `ecac_m1_m2_architecture.pdf`

---

**one-line summary:**
we turned “people can edit while offline” into “everyone ends up with the exact same, provably-derived state,” by (M1) making each edit a signed, hash-linked event in a causal DAG with a deterministic order, and (M2) replaying those events through CRDTs with a deterministic export and digest. next, in M3, we’ll add deny-wins authorization on top of the same replay so unauthorized edits are deterministically dropped everywhere.
