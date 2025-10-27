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

Here are drop-in docs you can add under `docs/`. They match what you’ve implemented (JWT-VCs, pinned issuers, local status lists, VC-backed `Grant`), and mention the helper + file layout.

---

### `docs/policy-model.md`

````markdown
# Policy model — VC-backed grants (M4)

> **TL;DR** Grants only count if they are backed by a *valid* Verifiable Credential (VC).
> Valid = signature under a *trusted issuer*, not revoked in local status lists, and the op’s
> HLC physical time is within the VC’s `[nbf, exp)` window. Scope is enforced via tag intersection.

## Overview

- A user’s ability to mutate state is governed by **grants**.
- In M4, a `Grant` doesn’t carry role/scope inline; it references a **credential** by hash.
- During replay, we verify that credential against a **trust store** and **status lists**,
  then derive **auth epochs** from the credential’s time window. Deny-wins gating uses those epochs.

## Terms

- **VC (JWT-VC)**: a compact JWS with fixed claims:
  `iss`, `jti`, `sub_pk`, `role`, `scope[]`, `nbf`, `exp`, and optional `status {id,index}`.
- **Trust store**: `trust/issuers.toml` mapping issuer → Ed25519 verifying key (hex).
- **Status lists**: `trust/status/<list_id>.bin` bitstrings (little-endian bit order).
- **Auth epoch**: an interval `[start_ms, end_ms)` for a `(subject, role, tags)` binding created
  from a *verified* VC, optionally intersected by explicit `Revoke` ops.

## Replay model

1. **Scan DAG** (stable topo order).
2. **Index credentials**: for each `Payload::Credential {cred_bytes, format=Jwt}`, compute
   `cred_hash = blake3(cred_bytes)` and *verify*:
   - Signature under `TrustStore[iss]` (Ed25519 / `alg=EdDSA`).
   - Parse claims; collect `{sub_pk, role, scope_tags, nbf_ms, exp_ms}`.
   - If `status` is present, check `StatusCache.is_revoked(list_id, index) == false`.
   - If all checks pass, store **VerifiedVc** keyed by `cred_hash`.
3. **Build epochs from grants**: for each `Payload::Grant {subject_pk, cred_hash}`:
   - Look up `VerifiedVc` by `cred_hash`.
   - Require `subject_pk == vc.subject_pk`.
   - Create an epoch `[vc.nbf_ms, vc.exp_ms)`, associated with `(subject_pk, vc.role, vc.scope_tags)`.
4. **Intersect rejections**: explicit `Revoke` ops still apply and can truncate/void epochs
   for a `(subject_pk, role, scope)` combination.
5. **Gate data ops (deny-wins)**:
   - Derive `(action, tags)` from the key (e.g., `"mv:o:x"`, `"set+:o:s:e"`).
   - A write at HLC `t_ms` is **permitted** iff there exists an epoch for the author where:
     - `t_ms ∈ [nbf_ms, exp_ms)`, and
     - **scope intersection** holds: `op_tags ∩ vc.scope_tags ≠ ∅`, and
     - no applicable revoke out-orders the grant in the total order.

Determinism:
- No wall clock is consulted. We compare `nbf/exp` to the **physical** part of the op’s HLC.
- Output depends only on the DAG and local `trust/` files.

## Scope intersection

- `scope` in the VC is a set of strings (tags).
- Operation keys imply tags (e.g., `mv:<obj>:<field>` → tags inferred by your key scheme; tests use `"hv"`).
- Permission requires **non-empty intersection** between VC scope and op tags.

## Negative cases (must deny)

- **Expired VC**: `t_ms ≥ exp_ms` → no epoch; ops denied.
- **Not-yet-valid VC**: `t_ms < nbf_ms` → no epoch; ops denied.
- **Unknown issuer**: `iss` not in `issuers.toml` (or signature invalid) → VC ignored.
- **Hash mismatch**: `Grant.cred_hash` has no matching verified credential → grant ignored.

## File layout & helpers

- `trust/issuers.toml`:
  ```toml
  [issuers]
  oem-issuer-1 = "10f84d06187932d244b4cdb29e3d371a8ce849249bb0631691d207279f0550ac"
````

* `trust/status/<list_id>.bin`: little-endian bitstring, bit `index` set → **revoked**.
* `ecac-cli vc-status-set <list_id> <index> <0|1>`: convenience to flip status bits.
* `ecac-cli vc-verify <vc.jwt>`: print parsed/verified VC claims + `cred_hash`.
* `ecac-cli vc-attach <vc.jwt> <issuer_sk_hex> <admin_sk_hex> [out_dir]`:
  emits `Credential` + `Grant` ops (CBOR).

## Security notes

* We hash the **exact compact JWT bytes** (ASCII) for `cred_hash` using BLAKE3 (32 bytes).
* Only `alg="EdDSA" (Ed25519)` JWTs are accepted.
* Status checking is local & deterministic; no network fetches in M4.

````

---

### `docs/protocol.md`

```markdown
# Protocol — Operations added in M4 (VC-backed policy)

This doc describes the on-log encodings for **Credential** and **Grant** in Milestone 4.

> Serialization: when written to files, ops use *canonical CBOR*.
> In memory, they’re Rust structs. Fields below match `ecac_core::op::Payload`.

## Credential

Carries a Verifiable Credential (JWT) onto the log so that grants can reference it by hash.

```rust
Payload::Credential {
  cred_id: String,        // VC jti (credential identifier)
  cred_bytes: Vec<u8>,    // the exact compact JWS bytes (header.payload.signature)
  format: CredentialFormat::Jwt, // currently only Jwt is supported
}
````

* **cred_hash** (not stored here) = `blake3(cred_bytes)`; 32-byte digest used by `Grant`.
* The verifier (`vc::verify_vc`) enforces:

  * header: `alg == "EdDSA"`.
  * payload claims: `iss`, `jti`, `sub_pk` (hex 32 bytes), `role` (string),
    `scope` (array of strings), `nbf` (u64), `exp` (u64).
  * optional `status { id: string, index: u64 }`.

## Grant

References a credential by its hash; no inline role/scope.

```rust
Payload::Grant {
  subject_pk: [u8; 32],   // must match the VC’s sub_pk
  cred_hash: [u8; 32],    // BLAKE3 of the JWT bytes from the corresponding Credential
}
```

Rules:

* During replay, the `cred_hash` must resolve to a **verified** `Credential` in the DAG.
* If no matching verified credential exists (hash mismatch, bad issuer, revoked, expired),
  the grant is ignored (no epoch).

## Revoke (carried over from M3)

```rust
Payload::Revoke {
  subject_pk: [u8; 32],
  role: String,
  scope_tags: Vec<String>,
  at: Hlc,                // effective timepoint
}
```

* Revoke events intersect or truncate epochs created from VC-backed grants.

## JWT claims (frozen for M4)

A VC is a compact JWS where the **payload** is JSON with the following fields:

```json
{
  "iss": "oem-issuer-1",
  "jti": "uuid-or-test-id",
  "sub_pk": "a82f...e27e",           // 64 hex chars (32 bytes)
  "role": "editor",
  "scope": ["hv"],                   // string tags
  "nbf": 10000,                      // ms since epoch; compared to op HLC physical
  "exp": 20000,                      // ms since epoch
  "status": {"id": "list-0", "index": 1}   // optional; if set bit=true => revoked
}
```

* Only `alg="EdDSA"` is accepted; Ed25519 verifying keys are pinned in `trust/issuers.toml`.

## Files on disk for trust & status

* **Issuers** (`trust/issuers.toml`):

  ```toml
  [issuers]
  oem-issuer-1 = "<32-byte ed25519 verifying key as 64 hex chars>"
  ```
* **Status lists** (`trust/status/<list_id>.bin`):

  * Byte array, **little-endian bits**. Bit `index` set → credential **revoked**.

Helpful CLI:

* `ecac-cli vc-verify <vc.jwt>` — verify a VC and print claims + `cred_hash`.
* `ecac-cli vc-attach <vc.jwt> <issuer_sk_hex> <admin_sk_hex> [out_dir]`
  — emit `cred.op.cbor` + `grant.op.cbor`.
* `ecac-cli vc-status-set <list_id> <index> <0|1>` — flip a specific revocation bit.

````

---

### `docs/architecture.md`

```markdown
# Architecture — M4 pipeline

The M4 replay pipeline adds **VC verification** and builds **auth epochs** from verified credentials.
Data ops are filtered via **deny-wins** using those epochs.

````

+-----------------+       +--------------------+       +---------------------+       +-------------------------+
|    Op log /     |  -->  |  Credential index  |  -->  |  Auth epoch builder |  -->  |  Deny-wins gate on ops  |
|  DAG (topo)     |       |  (verify_vc)       |       |  (from Grants + VC) |       |  (is_permitted_at_pos)  |
+-----------------+       +--------------------+       +---------------------+       +-------------------------+
|                         |                                |                               |
|                         v                                v                               v
|                 trust/issuers.toml           trust/status/<list>.bin               State (CRDTs)
|                     (pinned Ed25519)           (little-endian bits)
v
Revoke ops (optional)  -> intersect/truncate epochs

```

## Components

### Credential verification (`vc::verify_vc`)
- Input: compact JWT bytes, `TrustStore`, `StatusCache`.
- Steps:
  1. Parse header/payload, require `alg="EdDSA"`.
  2. Verify signature against `TrustStore[iss]` (Ed25519).
  3. Extract `{sub_pk, role, scope[], nbf, exp, iss, jti}`.
  4. If `status` present, check `StatusCache.is_revoked(id, index) == false`.
  5. Output: `VerifiedVc` and `cred_hash = blake3(compact_bytes)`.

### Epoch index (`policy::build_auth_epochs_with`)
- Consumes `Credential` ops (to verify & index by `cred_hash`) and `Grant` ops (to attach to a verified VC).
- Produces per-subject epochs `[nbf, exp)` with attached scope tags and role.
- Intersects with `Revoke` ops when present.

### Deny-wins
- For each data op (action + tags derived from the key), allow iff **an epoch covers the op’s HLC physical**
  and **scope intersection** is non-empty.
- If *any* policy is present, gating is enforced; otherwise M2 behavior (allow-all) is used.

## Determinism & clocks
- No wall clock in replay. All comparisons use the **physical part of HLC** carried by ops.
- Given the same DAG + `trust/` files, all nodes converge.

## Trust & status on disk

- **Issuers**: `trust/issuers.toml` mapping issuer IDs to Ed25519 verifying keys (hex).
- **Status**: `trust/status/*.bin` little-endian bitstrings (bit set = revoked).
- **Helper**: `ecac-cli vc-status-set <list_id> <index> <0|1>` to toggle revocation bits.

## CLI quick reference

- `ecac-cli vc-verify <vc.jwt>` → verify & print claims and hash.
- `ecac-cli vc-attach <vc.jwt> <issuer_sk_hex> <admin_sk_hex> [out_dir]`
  → write `cred.op.cbor` + `grant.op.cbor`.
- `ecac-cli replay <ops.cbor>` → deterministic state + digest (policy enforced if present).

```

---

If you want, I can also add a tiny “Examples” section with copy/pasteable commands showing `vc-status-set` flipping a bit from `0→1` and how it changes `vc-verify`/replay behavior.

Here’s a drop-in **Examples** section you can append to `docs/architecture.md` (or keep as `docs/examples.md`). It shows end-to-end: make a JWT-VC, verify, attach (emit ops), replay (allowed), flip a status bit to revoke (denied), and flip it back.

````markdown
## Examples — end-to-end with vc-verify / vc-attach / vc-status-set

> Prereqs:
> - `trust/issuers.toml` + `trust/status/` will be created below.
> - All paths are relative to repo root.

### 0) Generate keys and folders

```bash
ISSUER_SK_HEX=$(openssl rand -hex 32)
ADMIN_SK_HEX=$(openssl rand -hex 32)
SUBJECT_SK_HEX=$(openssl rand -hex 32)

mkdir -p trust/status fixtures out
````

### 1) Create a test JWT-VC (subject-bound)

This helper writes a compact JWS to `fixtures/example.jwt` and prints the issuer’s verifying key.

```bash
cargo run -p ecac-cli --example make_jwt_subject -- \
  "$ISSUER_SK_HEX" "$SUBJECT_SK_HEX" fixtures/example.jwt
# prints:
#   issuer_vk_hex  = <PASTE_ME>
#   subject_pk_hex = <subject pubkey hex>
```

### 2) Pin the issuer in `trust/issuers.toml`

Copy the `issuer_vk_hex` printed above:

```bash
cat > trust/issuers.toml <<'EOF'
[issuers]
oem-issuer-1 = "<PASTE_issuer_vk_hex_here>"
EOF
```

### 3) Verify the VC (should pass)

```bash
cargo run -p ecac-cli -- vc-verify fixtures/example.jwt
# {
#   "issuer": "oem-issuer-1",
#   "role": "editor",
#   "scope": ["hv"],
#   "nbf_ms": 10000,
#   "exp_ms": 20000,
#   "status_list_id": "list-0",
#   "status_index": 1,
#   "cred_hash_hex": "<...>",
#   "subject_pk_hex": "<...>"
# }
```

> If `trust/status/list-0.bin` doesn’t exist, verification still succeeds (treated as not revoked).

### 4) Attach the VC to the log (emit `Credential` + `Grant` ops)

```bash
cargo run -p ecac-cli -- vc-attach fixtures/example.jwt \
  "$ISSUER_SK_HEX" "$ADMIN_SK_HEX" out/
# prints:
# credential_op_id=<...>
# grant_op_id      =<...>
# cred_hash        =<...>
# wrote: out/cred.op.cbor and out/grant.op.cbor
```

### 5) Make a write op signed by the subject (within VC time window)

```bash
cargo run -p ecac-cli --example make_write -- \
  "$SUBJECT_SK_HEX" 15000 mv:o:x OK out/write.op.cbor
# Wrote out/write.op.cbor
```

### 6) Replay — write is **ALLOWED** with a valid VC

```bash
cargo run -p ecac-cli --example vc_replay -- \
  out/cred.op.cbor out/grant.op.cbor out/write.op.cbor
# order=[..., ..., ...]
# <write_op_id>: mv:o:x → ALLOWED
```

### 7) Flip status bit to **revoke** the credential

`status_index` from step 3 was `1`, and `status_list_id` was `list-0`. Set that bit to 1:

```bash
cargo run -p ecac-cli -- vc-status-set list-0 1 1
# status list-0[1] = 1
# wrote trust/status/list-0.bin
```

Re-verify (now fails with a clear error):

```bash
cargo run -p ecac-cli -- vc-verify fixtures/example.jwt
# Error: VC verify failed: Revoked
```

Replay again — the write is now **DENIED** (grant doesn’t produce an epoch):

```bash
cargo run -p ecac-cli --example vc_replay -- \
  out/cred.op.cbor out/grant.op.cbor out/write.op.cbor
# order=[..., ..., ...]
# <write_op_id>: mv:o:x → DENIED
```

### 8) Clear the bit to un-revoke

```bash
cargo run -p ecac-cli -- vc-status-set list-0 1 0
# status list-0[1] = 0
# wrote trust/status/list-0.bin
```

Verification and replay return to **ALLOWED**:

```bash
cargo run -p ecac-cli -- vc-verify fixtures/example.jwt
# ... prints claims again (OK)

cargo run -p ecac-cli --example vc_replay -- \
  out/cred.op.cbor out/grant.op.cbor out/write.op.cbor
# <write_op_id>: mv:o:x → ALLOWED
```

> Notes
>
> * `vc-status-set` uses **little-endian bits**: byte = `index / 8`, bit = `index % 8`.
> * Replay is deterministic and consults only the **physical HLC ms** in ops + local `trust/` files.
> * Hash mismatch, unknown issuer, expired/not-yet-valid VCs all behave similarly: no epoch → **DENIED**.

```
```
