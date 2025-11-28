Short version: you’ve basically wired everything already. The core now emits `AppliedOp` / `SkippedOp` through `AuditHook`, the store emits `IngestedOp` at ingest time, and `audit-record` pushes replay decisions into the on-disk audit log. The only real bug I see is in the VC cache encoding; I’ll fix that and then summarize the audit wiring so you’re sure it does what you want.

---

## 1. Fix the VC cache struct mismatch (this will bite `VerifyStore`)

Right now you have:

* In `crates/store/src/lib.rs`:

```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct VerifiedVcPersist {
    cred_id: String,
    issuer: String,
    subject_pk: [u8; 32],
    role: String,
    scope: Vec<String>, // <--- field name is `scope`
    nbf_ms: u64,
    exp_ms: u64,
    status_list_id: Option<String>,
    status_index: Option<u32>,
    cred_hash: [u8; 32],
}
```

* In `crates/cli/src/commands.rs`:

```rust
#[derive(Serialize, Deserialize)]
struct PersistVerifiedVc {
    cred_id: String,
    issuer: String,
    subject_pk: [u8; 32],
    role: String,
    scope_tags: Vec<String>,  // <--- different field name
    nbf_ms: u64,
    exp_ms: u64,
    status_list_id: Option<String>,
    status_index: Option<u32>,
    cred_hash: [u8; 32],
}
```

And `cmd_vc_verify` writes `PersistVerifiedVc` into `CF_VC_VERIFIED`, but `Store::verify_integrity` recomputes a `VerifiedVcPersist` and compares raw CBOR bytes. Different field name ⇒ different encoding ⇒ `vc_verified mismatch` as soon as you run `VerifyStore` with trust configured.

Fix it by aligning the CLI struct with the store struct.

**Patch for `crates/cli/src/commands.rs`:**

```diff
-#[derive(Serialize, Deserialize)]
-struct PersistVerifiedVc {
-    cred_id: String,
-    issuer: String,
-    subject_pk: [u8; 32],
-    role: String,
-    scope_tags: Vec<String>,
-    nbf_ms: u64,
-    exp_ms: u64,
-    status_list_id: Option<String>, // <-- was String
-    status_index: Option<u32>,      // <-- was u32
-    cred_hash: [u8; 32],
-}
+#[derive(Serialize, Deserialize)]
+struct PersistVerifiedVc {
+    cred_id: String,
+    issuer: String,
+    subject_pk: [u8; 32],
+    role: String,
+    // IMPORTANT: the field name must be `scope` so CBOR matches
+    // `VerifiedVcPersist` in ecac-store.
+    scope: Vec<String>,
+    nbf_ms: u64,
+    exp_ms: u64,
+    status_list_id: Option<String>,
+    status_index: Option<u32>,
+    cred_hash: [u8; 32],
+}
```

and in `cmd_vc_verify`:

```diff
-    let pv = PersistVerifiedVc {
-        cred_id: v.cred_id.clone(),
-        issuer: v.issuer.clone(),
-        subject_pk: v.subject_pk,
-        role: v.role.clone(),
-        scope_tags: v.scope_tags.iter().cloned().collect(),
-        nbf_ms: v.nbf_ms,
-        exp_ms: v.exp_ms,
-        status_list_id: v.status_list_id.clone(), // now matches Option<String>
-        status_index: v.status_index,             // now matches Option<u32>
-        cred_hash: v.cred_hash,
-    };
+    let pv = PersistVerifiedVc {
+        cred_id: v.cred_id.clone(),
+        issuer: v.issuer.clone(),
+        subject_pk: v.subject_pk,
+        role: v.role.clone(),
+        // keep iteration order identical to store’s VerifiedVcPersist
+        scope: v.scope_tags.iter().cloned().collect(),
+        nbf_ms: v.nbf_ms,
+        exp_ms: v.exp_ms,
+        status_list_id: v.status_list_id.clone(),
+        status_index: v.status_index,
+        cred_hash: v.cred_hash,
+    };
```

After this, `vc_verified` parity in `Store::verify_integrity()` will actually pass.

---

## 2. Where decision events come from now

You *do* already have the three classes of events wired; let’s be explicit so you can sanity-check against your mental model.

### 2.1 IngestedOp (ingest path, `ecac-store`)

In `crates/store/src/lib.rs`, inside `Store::put_op_cbor` you now:

* Decode the op.
* Compute header hash and check `op_id`.
* Compute `sig_ok`.
* Under `#[cfg(feature = "audit")]`, if `self.audit` is `Some`, you append:

```rust
AuditEvent::IngestedOp {
    op_id: op.op_id,
    author_pk: op.header.author_pk,
    parents: op.header.parents.clone(),
    verified_sig: sig_ok,
}
```

This goes through the `AuditWriter` that `Store::open` wires when `ECAC_NODE_SK_HEX` is present:

```rust
audit: {
    if let Ok(hex) = std::env::var("ECAC_NODE_SK_HEX") {
        // derive SigningKey from hex, compute node_id, open <db>/audit
        Some(Arc::new(Mutex::new(AuditWriter::open(
            &audit_dir, sk, node_id,
        )?)))
    } else {
        None
    }
}
```

So:

* If you set `ECAC_NODE_SK_HEX` **when ingesting ops** (e.g. in a daemon), every ingest will log `IngestedOp` into `<db>/audit` with `verified_sig: true/false`.
* `cmd_op_append_audited` adds an extra layer: it logs a `SkippedOp{InvalidSig}` into a *CLI* sink if `put_op_cbor` fails, but the canonical ingest telemetry is now the `IngestedOp` from the store itself.

### 2.2 AppliedOp / SkippedOp / Checkpoint (replay path, `ecac-core`)

In `crates/core/src/replay.rs` you already have the audit-aware replay:

* For each op in topo:

  * On invalid signature: `AuditEvent::SkippedOp { reason: SkipReason::InvalidSig, .. }`
  * On bad parent ordering: `SkippedOp { reason: SkipReason::BadParent, .. }`
  * On policy deny: `SkippedOp { reason: SkipReason::DenyWins, .. }`
  * On successful data application (SetField/SetAdd/SetRem): `AppliedOp { reason: AppliedReason::Authorized, .. }`

* At the end, a `Checkpoint`:

```rust
audit.on_event(AuditEvent::Checkpoint {
    checkpoint_id: state.processed_count() as u64,
    topo_idx: state.processed_count() as u64,
    state_digest: digest,
});
```

That’s exactly the “decision emission” path from `ecac-core` into any `AuditHook`.

---

## 3. How `audit-record` now writes “meaningful” events

In `crates/cli/src/commands.rs`:

```rust
#[cfg(feature = "audit")]
pub fn cmd_audit_record(db_dir_opt: Option<&str>) -> Result<()> {
    let db_dir = db_dir_opt.unwrap_or(".ecac.db");
    let store = Store::open(Path::new(db_dir), Default::default())?;
    let ids = store.topo_ids()?;
    let blobs = store.load_ops_cbor(&ids)?;

    let mut dag = Dag::default();
    for bytes in blobs {
        let op: Op = serde_cbor::from_slice(&bytes)?;
        dag.insert(op);
    }

    // Open default audit sink (respects ECAC_AUDIT_DIR or ".audit")
    let Some(mut sink) = open_audit_sink_default()? else {
        return Err(anyhow::anyhow!(
            "audit sink unavailable: set ECAC_NODE_SK_HEX (64 hex) and ensure .audit is writable"
        ));
    };

    let (_state, _digest) = ecac_core::replay::replay_full_with_audit(&dag, &mut sink);
    println!("OK: wrote decision events to the audit sink");
    Ok(())
}
```

And `open_audit_sink_default`:

```rust
#[cfg(feature = "audit")]
pub fn open_audit_sink_default() -> anyhow::Result<Option<ecac_store::StoreAuditHook>> {
    match ecac_store::StoreAuditHook::open_default() {
        Ok(h) => Ok(Some(h)),
        Err(e) => {
            eprintln!("audit: disabled (failed to open default sink: {e})");
            Ok(None)
        }
    }
}
```

`StoreAuditHook` is just a thin wrapper around `AuditWriter` that implements `AuditHook`:

```rust
pub struct StoreAuditHook {
    inner: Arc<Mutex<AuditWriter>>,
}

impl AuditHook for StoreAuditHook {
    fn on_event(&mut self, e: AuditEvent) {
        if let Ok(mut w) = self.inner.lock() {
            let _ = w.append(e);
        }
    }
}
```

So the flow for `audit-record` is:

* Rebuild full DAG from RocksDB.
* Call `replay_full_with_audit(&dag, &mut sink)`.
* For every decision `ecac-core` makes, `sink.on_event` appends to disk.

That’s exactly what you asked: decisions coming from core’s replay engine, not re-invented in the CLI.

The reason your script prints `OK: replay decisions match audit (0 entries)` in the harness is straightforward: your test DB only has `Credential`/`Grant`/orphan ops and **no `Payload::Data`**. The replay only emits `AppliedOp`/`SkippedOp` for data ops; the only other event is `Checkpoint`, which `cmd_audit_verify_full` deliberately ignores when comparing decisions. So a count of zero there is correct and expected for that scenario.

When you start feeding real Data ops through the store, you’ll see:

* `IngestedOp` from `Store::put_op_cbor` (if ECAC_NODE_SK_HEX set when ingesting).
* `AppliedOp` / `SkippedOp` + `Checkpoint` from `audit-record`’s replay run.

You can inspect them via `audit-cat` or `audit-export`.

---

## 4. `audit-verify-full` cross-check is already non-vacuous

`cmd_audit_verify_full` does the right thing:

* Picks audit dir (ECAC_AUDIT_DIR or `<db>/audit` or `.audit`).

* Validates the chain via `AuditReader::verify()`.

* Rebuilds the store DAG and runs `replay_full_with_audit` into `MemAudit`.

* Streams all on-disk events into `disk_events`.

* Extracts only the decision events with `(op_id, topo_idx, reason)`:

  ```rust
  enum Dec { Applied{..}, Skipped{..} }

  fn extract(v: &[AuditEvent]) -> Vec<Dec> { ... }
  ```

* Sorts both sets, compares, and if they differ prints the first mismatch and per-reason counts.

So once you have real Data ops, this will blow up loudly if the audit log diverges from what a fresh replay would decide.

---

## 5. What I’d do next (if you want to actually *see* non-zero decisions)

You don’t need more wiring; you need some Data ops:

1. Use `OpMakeGrant` or your own tooling to mint a minimal policy (Credential + Grant).

2. Generate a few `Payload::Data` ops (`mv:o:x`, `set+:o:s:elem`, etc.) that:

   * Some are authorized by the grant.
   * Some are unauthorized (wrong author, wrong tags, wrong time) so they get `SkippedOp { DenyWins }`.

3. `op-append` them into a fresh store with `ECAC_NODE_SK_HEX` set so `IngestedOp` is recorded.

4. Run:

   ```bash
   ECAC_NODE_SK_HEX=... ECAC_AUDIT_DIR=<db>/audit \
     cargo run -p ecac-cli --features audit -- audit-record --db <db>

   cargo run -p ecac-cli --features audit -- audit-cat --dir <db>/audit
   cargo run -p ecac-cli --features audit -- audit-verify-full --db <db>
   ```

At that point, you should see non-zero `AppliedOp` / `SkippedOp` counts and `audit-verify-full` comparing a real decision set, not an empty one.

---

Bottom line: audit decision emission from core into the sink is in place. The one concrete fix you need right now is the VC snapshot struct mismatch in `commands.rs`. Apply that patch, re-run `cargo check -p ecac-cli --features audit` and `tools/scripts/m8-dev-check.sh --verbose`, and then you’re ready to start feeding actual Data ops to get meaningful audit logs.
