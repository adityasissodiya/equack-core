Good, that’s the full core picture.

Short version: for **M9 Phase 3**, `replay.rs` and `state.rs` do **not** need structural changes. They already do what we want: apply policy on **writes**, treat values as opaque bytes for CRDTs, and keep the digest deterministic. The read-control layer for confidential fields sits **above** this, in the CLI / view path, using:

* the DAG + topo order (from CLI),
* `policy`’s epoch index, and
* the `Keyring` in `store::keys` plus `crypto::decrypt_value`.

Let me spell out the reasoning so you do not accidentally overcomplicate core.

---

## Where M9 actually hooks in

From the M9 design:

* **Encrypt on write**:

  * Happens when constructing `Payload::Data` for a confidential `(obj, field)` in core/CLI.
  * We already have `crypto::EncV1` + `encrypt_value`.
  * `replay.rs` never sees plaintext; it just applies bytes.

* **Read control** (per subject, per tag, per version):

  * Needs:

    * subject’s public key,
    * tag of the field (from `policy::tags_for` or a dedicated “confidential” tag),
    * key_version (from the `EncV1` envelope),
    * epochs from VCs + KeyGrants, and
    * key material from `store::Keyring`.
  * That logic should sit in the **CLI** when you do `show <obj field>`, not in replay/state.

* **Determinism / safety**:

  * `State::digest()` must stay **viewer-independent**.
  * That means the CRDT state and the deterministic JSON export must not depend on:

    * who is looking,
    * what keys they hold,
    * or whether decryption succeeds.
  * So `State` should continue to store **whatever bytes are in the ops** (ciphertext for confidential fields).

Given that, messing with `replay.rs` or `state.rs` to do decryption/redaction would be the wrong place: you’d either break determinism or tangle core with store/Keyring.

---

## What to do with `replay.rs` (answer: nothing for M9)

`replay.rs` currently:

* builds the **write** epoch index (`build_auth_epochs_with` or fallback),
* gates `Payload::Data` applications via `is_permitted_at_pos_with_reason`,
* applies CRDT updates with opaque `Vec<u8>` payloads,
* maintains metrics and audit events.

For M9, that’s exactly what we want:

* Confidential fields are already enforced at **write** time (same deny-wins gate).
* Encryption is done **before** the op hits the DAG.
* Replay just re-applies the encrypted blob like any other bytes.

We don’t need:

* any change to `apply_over_order` / `apply_over_order_with_audit`,
* any new knowledge of tags or key versions in replay,
* any dependency on `Keyring`.

Leave `replay.rs` as-is.

---

## What to do with `state.rs` (also: nothing for M9)

`State` currently:

* stores CRDT values as raw bytes,
* exports a deterministic JSON structure based on those bytes,
* computes a digest over that export.

If we tried to:

* decrypt inside `State`, or
* selectively replace values with `<redacted>`,

we would:

* need viewer identity + epoch index + keyring inside `State` (ugly cross-crate coupling), or
* make `digest()` depend on who’s looking (completely breaks your existing invariants / tests).

So the correct approach is:

* Keep `State` exactly as a **policy-filtered CRDT over opaque bytes**.
* Use a **separate, view-specific projection** in the CLI to:

  * interpret MVReg / ORSet values as either plaintext or `EncV1`,
  * compute AAD from `(op_id, obj, field)`,
  * call `decrypt_value(keyring, enc, aad)`,
  * gate that by read epochs (`policy::can_read_tag_version`, which we’ll add),
  * and render either plaintext or `"<redacted>"` deterministically.

Again: no edits to `state.rs` for M9. All tests you just ran should remain valid and unchanged.

---

## Where the remaining M9 work actually lives

Given the files you’ve shown so far, the remaining M9 pieces are:

1. **`policy.rs`** (we partially sketched this earlier):

   * Add a static **role → read_tags** table (e.g. `editor` → `{hv, mech, confidential}`).
   * Add a read-side checker:

     ```rust
     pub fn can_read_tag_version(
         idx: &EpochIndex,
         subject: &PublicKeyBytes,
         tag: &str,
         key_version: u32,
         pos_idx: usize,
         at_hlc: Hlc,
     ) -> bool
     ```

     For now, this can ignore `key_version` and just enforce VC epochs + tag scope; once KeyGrant and KeyRotate payloads are introduced, we extend the epoch builder and this function to honour `key_version` and grants.

2. **`op.rs` / core write path** (later phase):

   * Add EncV1-aware data op constructor:

     * When `(obj, field)` is confidential, look up `(tag, current_version)` in the local keyring via the CLI, encrypt plaintext, and put `EncV1` (CBOR) into `Payload::Data.value`.
   * Introduce `KeyGrant` / `KeyRotate` payloads as per spec.

3. **`crates/store/src/keys.rs` + CF wiring** (already done in your Phase 2):

   * Persist `(tag, version) -> key`.
   * Import keys on `KeyRotate` ops.

4. **CLI view path** (the real M9 read-control integration):

   * Build **read** epoch index exactly like write:

     * `policy::build_auth_epochs_with(dag, order, trust, status)`.
   * Given `subject_pk` (from CLI `--subject-pk`):

     * Use `policy::can_read_tag_version` to decide whether to even try decryption for `(tag, version)`.
     * If allowed, get key from `Keyring`, compute AAD from `(op_id, obj, field)`, call `decrypt_value`.
     * If either policy denies or decryption fails, return `"<redacted>"`.
   * Ensure JSON export for `show` uses either plaintext or exactly `"<redacted>"` in a deterministic way (same subject/keys ⇒ same output).

---

## Bottom line

* **No changes** needed to `crates/core/src/replay.rs` for M9.
* **No changes** needed to `crates/core/src/state.rs` for M9.
* The remaining work is:

  * extend `policy.rs` with a read-side helper (`role_read_tags` + `can_read_tag_version`),
  * wire encryption into op creation (later phase),
  * and implement the per-subject decrypted/redacted view in the CLI using the epoch index and keyring.

If you haven’t yet applied the `policy.rs` read-side additions, I can give you a clean diff for that next, then we move on to the CLI and KeyGrant/KeyRotate wiring.
