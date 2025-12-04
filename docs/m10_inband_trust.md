Here’s a concrete doc you can more or less drop in as `docs/m10_inband_trust.md` (or equivalent). It treats the current code as the ground truth and explains it.

You can tweak names/paths, but the semantics should line up with what you actually have.

---

````markdown
# M10: In-band Trust & VC Verification

This document describes the M10 trust model:

* How trust material (issuer keys, status lists) is carried **in-band** on the op log.
* How we deterministically assemble that material into a `TrustView` snapshot.
* How `issuer_admin` gating controls which trust ops are authoritative.
* How VC verification consumes `TrustView` (and only `TrustView`) when deciding whether to trust an issuer and a credential.

The code lives primarily in:

* `crates/core/src/trustview.rs`
* `crates/core/src/policy.rs`
* `crates/core/src/vc.rs` (or equivalent VC verification module)
* Tests under `crates/core/tests/`:
  * `trustview.rs`
  * `vc_policy_tests.rs`

Older M3/M4/M9 policy tests and M9 read-control tests have been removed; the behaviour documented here is the canonical architecture going forward.

---

## 1. Trust Material on the Log

M10 makes all trust state explicit, versioned and replayable from the same op log as application data.

### 1.1 Op types

Trust material is carried via these payload variants:

* `Payload::IssuerKey`  
  Defines a public key for an issuer:

  ```rust
  Payload::IssuerKey {
      issuer_id: String,      // logical issuer, must match VC "iss"
      key_id: String,         // issuer-local key id, must match VC "kid" when present
      algo: String,           // e.g. "EdDSA"
      pubkey: Vec<u8>,        // raw public key bytes
      valid_from_ms: u64,     // declared validity window (ms since epoch)
      valid_until_ms: u64,
      prev_key_id: Option<String>, // currently informational
  }
````

* `Payload::IssuerKeyRevoke`
  Marks an issuer key as revoked from a given point in the log onwards:

  ```rust
  Payload::IssuerKeyRevoke {
      issuer_id: String,
      key_id: String,
      reason: String,
  }
  ```

* `Payload::StatusListChunk`
  Carries a chunk of a credential status list:

  ```rust
  Payload::StatusListChunk {
      issuer_id: String,      // issuer controlling the list
      list_id: String,        // logical list identifier
      version: u32,           // monotonically increasing per (issuer_id, list_id)
      chunk_index: u32,       // 0-based index
      bitset_sha256: [u8; 32],// advertised digest over concatenated chunks
      chunk_bytes: Vec<u8>,   // raw bitstring chunk
  }
  ```

Access control (who is allowed to write data) is still driven by the VC/Grant/KeyGrant machinery in `policy.rs`. M10 adds **a separate trust plane** for issuer keys and revocations, driven by the same log.

---

## 2. TrustView: Deterministic In-band Trust Snapshot

`TrustView` is the single in-memory representation of in-band trust state derived from the log.

```rust
pub type IssuerId = String;
pub type KeyId = String;
pub type ListId = String;

#[derive(Debug, Clone)]
pub struct IssuerKeyRecord {
    pub issuer_id: IssuerId,
    pub key_id: KeyId,
    pub algo: String,
    pub pubkey: Vec<u8>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub activated_at_ms: u64,
    pub revoked_at_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct StatusList {
    pub issuer_id: IssuerId,
    pub list_id: ListId,
    pub version: u32,
    pub chunks: BTreeMap<u32, Vec<u8>>,
    pub bitset_sha256: [u8; 32],
}

#[derive(Debug, Clone, Default)]
pub struct TrustView {
    pub issuer_keys: HashMap<IssuerId, HashMap<KeyId, IssuerKeyRecord>>,
    pub status_lists: HashMap<ListId, StatusList>, // latest complete version per list_id
}
```

The only way to build a `TrustView` is from the op log:

```rust
impl TrustView {
    pub fn build_from_dag(dag: &Dag, order: &[OpId]) -> Self { ... }
}
```

Inputs:

* `dag: &Dag` – all ops by `OpId`.
* `order: &[OpId]` – deterministic topo order (same order used by replay).

Output:

* A fully assembled `TrustView` with:

  * First-wins issuer keys per `(issuer_id, key_id)` (with activation/revocation times).
  * Latest complete and digest-valid status list version per `list_id`.
  * All trust ops filtered through `issuer_admin` gating (see below).

There is **no** filesystem trust in this path; everything comes from the log.

---

## 3. Issuer Key Semantics

### 3.1 First-wins per `(issuer_id, key_id)`

For each `Payload::IssuerKey` in topo order:

* We look at the pair `(issuer_id, key_id)`.
* If no record exists yet, we create an `IssuerKeyRecord`.
* If a record already exists:

  * If the new op has the **same** `(algo, pubkey, valid_from_ms, valid_until_ms)`, it is treated as an idempotent re-publish and ignored.
  * If any of those fields differ, it is treated as a conflicting key definition and ignored (“first-wins”).

This yields a stable, deterministic mapping:

```rust
issuer_id -> key_id -> IssuerKeyRecord
```

### 3.2 Activation time

Issuer keys do not become usable immediately at `valid_from_ms`. The activation point is:

```rust
activated_at_ms = max(valid_from_ms, op.header.hlc.physical_ms)
```

So:

* Keys are not active before the time they actually appeared on the log, even if `valid_from_ms` is earlier.
* If `valid_from_ms` is in the future relative to the op’s HLC, activation is delayed to `valid_from_ms`.

### 3.3 Revocation

For each `Payload::IssuerKeyRevoke` in topo order:

* If we have a matching `(issuer_id, key_id)` in `issuer_keys`, we set `revoked_at_ms` to the earliest HLC we ever see for a revoke of that key:

  ```rust
  rec.revoked_at_ms = Some(min(existing_revoked_at_ms.unwrap_or(infinity), this_rev_ms));
  ```

* If the key was never defined, the revoke is effectively a no-op for `TrustView`.

### 3.4 Key activity predicate

`IssuerKeyRecord::is_active_at(t_ms)` implements the actual key lifecycle:

```rust
pub fn is_active_at(&self, t_ms: u64) -> bool {
    if t_ms < self.activated_at_ms { return false; }
    if t_ms >= self.valid_until_ms { return false; }
    if let Some(rev) = self.revoked_at_ms {
        if t_ms >= rev { return false; }
    }
    true
}
```

The VC layer uses this predicate to decide if a key is usable at a given logical time (typically derived from the VC’s `nbf`/`exp` or “now”).

### 3.5 Key selection

`TrustView::select_key` chooses an issuer key for verification:

```rust
pub fn select_key(
    &self,
    issuer: &str,
    kid: Option<&str>,
    at_ms: u64,
) -> Option<&IssuerKeyRecord>
```

Rules:

* If `kid` is present:

  * Look up that `(issuer, kid)`.
  * Return it only if `is_active_at(at_ms)` is true.
* If `kid` is missing (kid-less VC):

  * Among all keys for `issuer` that are active at `at_ms`, pick the one with the lexicographically highest `(activated_at_ms, key_id)`.
  * This biases towards the newest usable key, and is deterministic across replicas.

If the issuer is unknown or no usable key exists at `at_ms`, `select_key` returns `None`.

---

## 4. Status List Semantics

A `StatusList` represents one version of a logical status list (`list_id`), sliced into chunks.

### 4.1 Completeness and digest checking

`StatusList::digest_matches()` enforces:

* `chunks` is non-empty.
* The smallest index is `0`.
* Indices are contiguous: `{0, 1, ..., max_index}` (no gaps).
* The digest over the concatenated bytes matches `bitset_sha256`:

  ```text
  sha256( chunks[0] || chunks[1] || ... || chunks[max_index] ) == bitset_sha256
  ```

If any of these fail, that version is not exposed via `TrustView.status_lists`.

### 4.2 Version selection per `list_id`

Internally, we track chunks per `(issuer_id, list_id, version)`. After ingesting all `StatusListChunk`s (subject to gating):

* We discard any versions whose `digest_matches()` is false.
* For each *logical* `list_id`, we pick the `StatusList` with the highest `version` among the remaining ones and store it in:

  ```rust
  status_lists: HashMap<ListId, StatusList>
  ```

Note: `list_id` is the map key; we deliberately ignore `issuer_id` at this level. If you want issuer-scoped lists, encode that into `list_id`.

### 4.3 Revocation bit semantics

`StatusList::is_revoked(index)` interprets the bitstring as:

* Little-endian within each byte (LSB = bit 0).
* Fixed chunk size – all chunks for a given version are assumed to have the same length; chunk 0 is used as the reference.

Indexing:

```text
bits_per_chunk = chunk_len * 8
chunk_idx      = index / bits_per_chunk
bit_in_chunk   = index % bits_per_chunk
byte_idx       = bit_in_chunk / 8
bit_offset     = bit_in_chunk % 8
revoked        = (chunk_bytes[byte_idx] & (1 << bit_offset)) != 0
```

Missing data is treated as “not revoked”:

* If the relevant chunk is missing → not revoked.
* If `byte_idx` is out of range → not revoked.
* If the list is missing or empty → not revoked.

This is availability-biased but deterministic.

`TrustView::is_revoked(list_id, index)` simply:

* Looks up the latest valid `StatusList` for `list_id`.
* Applies the same bit logic.

---

## 5. Issuer-admin Gating for Trust Ops

Trust ops are **not** always accepted from everyone. M10 introduces an `issuer_admin` role that gates which ops can affect `TrustView`.

### 5.1 Building issuer_admin epochs

We reuse the existing policy machinery:

* `policy::build_auth_epochs(dag, order)` scans the log for VC-backed `Grant`/`Revoke`/`KeyGrant` and emits an `EpochIndex` describing which principals have which roles over which scopes and at which positions.
* `issuer_admin` is just another role string from the policy layer’s perspective.

If the log contains any “policy-like” ops (Grant/Revoke/KeyGrant), we build `issuer_admin_epochs` from the topo order. Otherwise, we fall back to an empty `EpochIndex`.

### 5.2 When gating is active

For each op in `order`, we decide whether trust-op gating is active at that point using:

* `policy::issuer_admin_mode_active(&issuer_admin_epochs, pos, op.hlc())`

High-level behaviour:

* **Bootstrap phase** – before any issuer_admin epoch is live:

  * `issuer_admin_mode_active` returns false.
  * All trust ops are accepted into `TrustView`, regardless of author.
* **Gated phase** – once an issuer_admin epoch is live at `(pos, hlc)`:

  * `issuer_admin_mode_active` returns true.
  * We only accept trust ops whose `author_pk` currently has the `issuer_admin` role at that point in the `EpochIndex`.

The transition between these phases is derived purely from the log; there is no out-of-band switch.

### 5.3 Gating rule per op

For each op in topo order:

```rust
let is_trust_op = matches!(
    op.header.payload,
    Payload::IssuerKey { .. }
        | Payload::IssuerKeyRevoke { .. }
        | Payload::StatusListChunk { .. }
);

if is_trust_op {
    let at_hlc = op.hlc();
    let gating_active = policy::issuer_admin_mode_active(&issuer_admin_epochs, pos, at_hlc);

    if gating_active
        && !policy::author_is_issuer_admin_at(
            &issuer_admin_epochs,
            &op.header.author_pk,
            pos,
            at_hlc,
        )
    {
        // Unauthorized trust op → ignored for TrustView assembly.
        continue;
    }
}
```

Effect:

* Before gating: any principal can publish issuer keys and status lists.
* After gating turns on: only principals with `issuer_admin` at that position + HLC can publish trust ops that will be visible in `TrustView`.
* Unauthorized trust ops are **silently ignored** for trust assembly; they do not affect issuer keys or status lists.

Tests in `trustview::tests::unauthorized_trust_ops_ignored_once_issuer_admin_active` and `trustview::tests::vc_verification_uses_only_issuer_admin_trust_ops` exercise these semantics explicitly.

---

## 6. VC Verification with TrustView

VC verification is wired to consume `TrustView` as the source of issuer keys and revocation state.

At a high level, `verify_vc_with_trustview(vc_bytes, &TrustView)` does the following:

1. **Parse VC** as a compact JWS / JWT-style structure:

   * Extract header (alg, kid).
   * Extract payload (iss, nbf, exp, scope, list ids/indices if any).
   * Extract the signature bytes.

2. **Resolve issuer key from TrustView**:

   * Let `issuer = payload["iss"]`.

   * Let `kid = header["kid"]` (or `None`).

   * Choose a verification time `t_ms` (e.g. issued time, or “now”; the tests assume a simple 0..1_000_000 window).

   * Call:

     ```rust
     let key_rec = trustview.select_key(issuer, kid.as_deref(), t_ms);
     ```

   * If `key_rec` is `None`, the issuer is unknown or no active key exists → return `VcError::UnknownIssuer(issuer.to_string())`.

3. **Verify signature**:

   * Check that `header["alg"]` matches the key’s algorithm (e.g. `"EdDSA"`).
   * Use `key_rec.pubkey` to verify the JWS signature over `header_base64 + "." + payload_base64`.
   * On failure, return a signature error.

4. **Check VC time bounds**:

   * Validate `nbf` / `exp` against the chosen `t_ms`.
   * If not yet valid → `VcError::NotYetValid`.
   * If expired → `VcError::Expired`.

5. **Status list revocation (if present)**:

   * If the VC encodes a logical status list id and index:

     * Look up revocation via `trustview.is_revoked(list_id, index)`.
     * If revoked → `VcError::StatusRevoked`.
   * If the relevant status list or bits/chunks are missing, we treat the credential as **not revoked** (availability-biased).

6. **Scope / role enforcement**:

   * The VC payload carries `role` and `scope` (e.g. `"editor"` + `["hv"]`).
   * The policy layer uses those to decide whether the VC grants a user access to particular tags (`hv`, `mech`, etc.).
   * VC verification is responsible for the *trust* of the VC itself; actual read/write permissions are checked elsewhere via `policy::can_read_tag_version` and friends.

`vc_policy_tests.rs` covers:

* Unknown issuer denied.
* Not yet valid / expired denied.
* Valid VC under issuer_admin-published key allowed.
* Status lists revoking a VC cause verification failure.
* Scope intersection/disjointness for data ops.
* Empty scope denies everything.

Once M10 is in place, **VC verification never consults any external keyring or filesystem trust**. All trust comes from `TrustView`, and `TrustView` is derived from the log under issuer_admin gating.

---

## 7. Operational Flow

This section describes how an operator is supposed to use M10 in practice.

### 7.1 Bootstrap (no issuer_admin yet)

Initial state:

* Log has no issuer_admin epochs.
* `issuer_admin_mode_active` is false for all positions.
* Any principal can publish trust ops, and they will be accepted into `TrustView`.

Recommended bootstrap pattern:

1. Pick a bootstrapping principal (`bootstrap_admin_pk`).
2. Use that principal to write:

   * One or more `IssuerKey` ops for the initial issuers.
   * Any initial status lists, if needed.
3. Use the same principal to issue a VC granting `issuer_admin` to the desired long-term admin principal(s).
4. Once this VC + `Grant` is on-log, `issuer_admin_mode_active` becomes true in the relevant range.

At that point, trust ops written by non-issuer_admin principals are ignored for `TrustView`.

### 7.2 Normal operation with issuer_admin gating

Once gating is active:

* Trust ops that matter must be authored by a principal with issuer_admin role at the time of the op:

  * Publishing new issuer keys.
  * Revoking issuer keys.
  * Publishing or updating status lists.

* VC verification:

  * Only issuer keys published through these gated trust ops are used to verify VCs.
  * If someone pushes an `IssuerKey` op without issuer_admin role, VCs referencing that issuer will fail with `UnknownIssuer`.

### 7.3 Key rotation and revocation

Typical lifecycle:

1. **Add new key** for an issuer:

   * Write a new `IssuerKey` with a new `key_id`, a `valid_from_ms` in the future, and a suitable `valid_until_ms`.
   * Once `t_ms >= activated_at_ms`, `select_key` can pick this key (if `kid` is absent or matches).

2. **Revoke old key**:

   * Write `IssuerKeyRevoke` for the old `(issuer_id, key_id)`.
   * From `revoked_at_ms` onwards, `is_active_at` for that key will return false.

3. **Status-based revocation of individual credentials**:

   * Publish updated `StatusListChunk`s for the relevant `(issuer_id, list_id, version)`.
   * Ensure chunks are contiguous and the hash is correct; otherwise the version is rejected.
   * New version wins per `list_id`.

VC verification automatically picks up these changes from `TrustView`.

---

## 8. Relationship to Earlier Milestones

* M3/M4/M9 provided:

  * A policy engine for VC-backed Grants/Revokes/KeyGrants (`policy.rs`).
  * Data-path read control and keyring-based decryption, tested via dedicated M9 tests.
* M10 adds:

  * An in-band trust plane (`TrustView`) for issuer keys and revocations.
  * Issuer_admin gating over trust ops.
  * VC verification logic that depends **only** on `TrustView` for issuer trust and revocation, not on any out-of-band key store.

The old M9 read-control integration tests and M3/M4 policy tests that baked in pre-TrustView semantics have been removed. The authoritative behaviour for both trust and policy is now captured by:

* `trustview` unit tests.
* `vc_policy_tests.rs`.
* Replay/property tests that exercise policy under replay.

---

## 9. Summary

M10 closes the loop between:

* The **op log** as the single source of truth,
* The **trust plane** (`TrustView`) derived from that log under issuer_admin gating, and
* **VC verification**, which now strictly consumes that trust plane.

Key invariants:

* Given the same DAG + topo order, all replicas build the same `TrustView`.
* Once issuer_admin mode is active, only issuer_admin principals can affect issuer keys and status lists.
* VC verification trusts issuers **only** if their keys appear in `TrustView` and are active at the relevant time.
* Status revocation is expressed via on-log status lists, and missing/incomplete data is treated as “not revoked” in a deterministic way.

This matches the proposed architecture: all trust and policy decisions are now derived from the log, with explicit roles and epochs controlling who can change what.

```

If you want, I can also give you a small README section that just says “M10 is done, trust is in-band via TrustView; see `docs/m10_inband_trust.md` for details” so you can wire this into whatever top-level docs you already have.
::contentReference[oaicite:0]{index=0}
```
