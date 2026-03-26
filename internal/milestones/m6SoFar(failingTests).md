Got it. Here’s the blunt, exact status report, tied directly to your M6 spec and the diffs you showed.

# What’s been achieved (code-level reality)

## Transport & wiring (libp2p)

* ✅ **Secure transport**: TCP → upgrade(V1) → **Noise** (or plaintext behind a feature flag) → **Yamux**. Present in both old and new `transport.rs`.
* ✅ **Behaviours**: **Gossipsub**, **Request/Response**, **Ping**, **Identify** are all wired in and polled. Identify+Ping were already there; still there.
* ✅ **Announce topic**: `announce_topic(project_id)` created and subscribed on startup.
* ✅ **Public-facing Node API**:

  * `listen(addr)`, `add_peer(peer_id, addr)`, `send_fetch(peer, FetchMissing)`, `is_connected_to(peer)`, `listeners()`, `respond_fetch(channel, frame)`, `subscribe_announce()`, `publish_announce(...)`.
  * MPSC channels surfaced to tests: `listen_addr_rx`, `announces_rx`, `rpc_req_rx`, `rr_resp_rx`, `rr_out_fail_rx`, plus `_conn_evt_tx/conn_evt_rx` for generic swarm events.
* ✅ **R/R client path**: `send_fetch` emits an outbound request and bubbles **responses** (`RpcFrame`) via `rr_resp_rx`. Same as before.
* ✅ **R/R server path** (new capability usable in tests/apps):

  * **M6 addition**: `set_fetch_bytes_provider(F: Fn(&OpId)->Option<Vec<u8>>)` on `Node`. If set, the node **answers incoming** `FetchMissing` requests **in-place** (no hop to `rpc_req_rx`) by sending a single `OpBytes` for the first `want` hit, else `End`. This is the groundwork for server-side streaming; the simple single-frame reply is in place.

## Gossip → Sync integration hooks (M6 scaffolding)

* ✅ **Planner hooks added** (new): `set_sync_providers(have, parents)` stores two closures in the `Node`:

  * `have(&OpId) -> bool`
  * `parents(&OpId) -> Vec<OpId>`
* ✅ **Gossip trigger** (new): On receiving a **SignedAnnounce**, if both providers are present, the node calls `SyncPlanner::plan_with(...)` and **immediately sends a `FetchMissing`** for the first batch to the announcing peer. This is exactly the “announce → diff → fetch” loop in your M6 protocol.
* ⚠️ **Note**: There’s no persistence/store wiring in `transport.rs` (as intended). The server-side `set_fetch_bytes_provider` is a minimal “source of truth” hook; actual store-backed streaming belongs in `rpc.rs`/store integration. For M6, this is acceptable scaffolding.

## Logging & diagnostics

* ✅ **More logging** in the new file (Identify events, listener states, etc.).
* ✅ `listen()` now prints “Starting” / “Successfully started” (harmless; cloned address fixes the earlier move error).

# What regressed and why the tests now fail

**Root cause (real reason your tests hang):**
In the new `poll_once()` you introduced an **early catch-all match arm**:

```rust
other => {
    eprintln!("[{:?}] swarm event: {:?}", self.peer_id, other);
    Ok(false)
}
```

…and you put it **before** specific arms like:

```rust
SwarmEvent::Dialing { .. } => { ... }
SwarmEvent::Behaviour(ComposedEvent::Ping(_)) => { ... }
SwarmEvent::Behaviour(ComposedEvent::Identify(_)) => { ... }
SwarmEvent::NewListenAddr { address, .. } => { ... send on listen_tx ... }
```

A catch-all pattern **matches everything** that wasn’t matched yet, including **`NewListenAddr`**. That means your `NewListenAddr`-specific arm **never runs**, so **the listen address is never sent** into `listen_tx`, so your tests **wait forever** on `listen_addr_rx`.

This exactly matches the logs you posted:

* You see `swarm event: NewListenAddr { ... }` (because the catch-all logs it),
* But you **do not** see your new `"New listen address received: ..."` line (which is only printed in the specific `NewListenAddr` arm),
* And the channel consumer times out.

**Bottom line:** tests didn’t suddenly become flaky; your event dispatcher is swallowing the listen event. Timeouts won’t fix a logic bug.

# M6 scope vs current code (coverage snapshot)

From your M6 contract:

* **Gossip/Announce pipeline**: ✅ Sub/Publish implemented; parsing Announce and triggering the planner request is present (scaffolded).
* **Fetch RPC**:

  * Client: ✅ (`send_fetch`, response frames surfaced).
  * Server: ✅ minimal in-process provider via `set_fetch_bytes_provider` (single `OpBytes` or `End`). Full store-backed streaming still to be built in `rpc.rs` (that’s fine for M6 as long as we can stream frames; your tests already exercise the minimal case).
* **Sync planner**: ✅ `sync.rs` exists and is called from gossip when providers are configured. No store integration here by design.
* **Determinism hooks**: ⚠️ replay/store integration isn’t in `transport.rs` (as desired). You’ll still need the end-to-end wiring to meet the “convergence” acceptance criteria in real runs, but the network surface is ready.
* **Anti-entropy round**: ⚠️ Not visible in `transport.rs`. If you plan to do periodic announces, that belongs in a higher-level task/driver (fine for M6 if your tests don’t require it yet).
* **Static peers**: ✅ manual `add_peer()` preserved and robust (adds address book + explicit dial with `PeerCondition::NotDialing`).

# What to change to unbreak tests (minimal, surgical)

Fix the match order in `poll_once()` so the catch-all is **last**. Keep only one catch-all at the end (you currently have two). Example:

```rust
pub async fn poll_once(&mut self) -> anyhow::Result<bool> {
    let ev = self.swarm.select_next_some().await;
    match ev {
        // 1) Connection lifecycle first
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => { /* ... */ }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => { /* ... */ }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => { /* ... */ }
        SwarmEvent::IncomingConnectionError { error, .. } => { /* ... */ }

        // 2) Dial/status/ping/identify
        SwarmEvent::Dialing { peer_id, .. } => { /* ... */ }
        SwarmEvent::Behaviour(ComposedEvent::Ping(ev)) => { /* ... */ }
        SwarmEvent::Behaviour(ComposedEvent::Identify(ev)) => { /* ... */ }

        // 3) Listen addresses — make sure THIS arm runs!
        SwarmEvent::NewListenAddr { address, .. } => {
            eprintln!("[{:?}] New listen address received: {}", self.peer_id, address);
            let _ = self.listen_tx.send(address);
            Ok(true)
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => { /* ... */ }
        SwarmEvent::ListenerClosed { addresses, reason, .. } => { /* ... */ }
        SwarmEvent::ListenerError { error, .. } => { /* ... */ }

        // 4) Behaviour events
        SwarmEvent::Behaviour(ComposedEvent::Gossipsub(ev)) => { /* ... */ }
        SwarmEvent::Behaviour(ComposedEvent::Fetch(ev)) => { /* ... */ }

        // 5) Everything else — ONLY here.
        other => {
            let dbg = format!("{:?}", &other);
            let _ = self._conn_evt_tx.send(other);
            eprintln!("[{:?}] swarm event: {}", self.peer_id, dbg);
            Ok(false)
        }
    }
}
```

That’s it. With that one change, your tests that `recv()` on `listen_addr_rx` will start receiving again.

# What changed between old/new (net-new M6 features)

* ➕ **Server-side fetch provider**: `set_fetch_bytes_provider` allows handling `FetchMissing` without surfacing to `rpc_req_rx`. If **not** set, the old behaviour (forward to `rpc_req_rx`) still works.
* ➕ **Sync planner providers**: `set_sync_providers(have, parents)` + **auto-fetch first batch** on `Announce`.
* ➕ **Identify event logging** added explicitly.
* 🔧 **Listen logging** added; **address clone** in `listen()` to avoid move error.
* 🪓 **Regression**: early `other =>` arm in `poll_once()` swallowed `NewListenAddr` (and any other arm below it). That’s the blocker.

# Where you stand vs M6 acceptance criteria

* **Convergence across peers**: Partially supported by scaffolding; you still need store-backed fetch streaming + ingestion path (outside `transport.rs`) to prove it end-to-end.
* **Determinism**: Replay layer unchanged; network doesn’t break determinism as long as ingestion enforces parent-first (planner helps, but store must enforce too).
* **Causal completeness**: Planner API is present; enforcement still depends on store/ingest checks.
* **Integrity**: Op signature verification lives outside `transport.rs`. Not regressed by these changes.
* **Liveness (anti-entropy)**: Periodic announce/compare driver not shown here; add in a supervisor/CLI loop.
* **Isolation**: Defensive checks belong to ingest/store; not in `transport.rs`.

# Suggested next steps (no fluff)

1. **Fix the match order** in `poll_once()` (remove the early catch-all; keep one at the end). Re-run the “last known good” tests you pasted — they should go green again.
2. Keep the M6 additions:

   * `set_fetch_bytes_provider` for tests that want a fake store.
   * Planner hook on `Announce` gated behind `set_sync_providers` being set (good).
3. Add a **tiny regression test** for listen delivery:

   * Start a `Node`, call `listen(127.0.0.1:0)`, poll until `listen_addr_rx` yields one address, assert it’s loopback. This catches the exact bug you hit.
4. When ready to prove M6 fully: wire **server fetch** to the store and stream `OpBytes` followed by `End` strictly **parent-first**. Your planner already layers batches — use that.

If you want, paste the patched `poll_once()` here and I’ll sanity-check it.
