# Implementation Plan: `serve` Subcommand with Embedded Web UI

## Overview

Add a `serve` subcommand to `ecac-cli` that starts an HTTP server with an embedded web dashboard. This enables demoing ECAC on Raspberry Pis and laptops without requiring Node.js or external dependencies.

**Goal:** Single binary that serves a web UI for exploring and demonstrating federated IoT data management with ECAC.

---

## Target Demo: Federated IoT Data Management

### Scenario

Industrial IoT sensors across multiple sites with intermittent connectivity:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Site A       │    │    Site B       │    │  Site C (Air)   │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │ Pi + ECAC │  │    │  │ Pi + ECAC │  │    │  │ Pi + ECAC │  │
│  │ (Gateway) │  │    │  │ (Gateway) │  │    │  │ (Gateway) │  │
│  └─────┬─────┘  │    │  └─────┬─────┘  │    │  └─────┬─────┘  │
│        │        │    │        │        │    │        │        │
│   [Sensors]     │    │   [Sensors]     │    │   [Sensors]     │
└────────┼────────┘    └────────┼────────┘    └────────┼────────┘
         │                      │                      │
         │    ┌─────────────────┼──────────────────────┘
         │    │  When connected │  Periodic sync
         ▼    ▼                 ▼
    ┌─────────────────────────────────┐
    │     Central Aggregation         │
    │     (Laptop running ECAC)       │
    └─────────────────────────────────┘
```

### Demo Workflows to Support

1. **Autonomous Edge Operation**
   - Gateway writes sensor data ops locally while disconnected
   - UI shows local state, op count, last sync time

2. **Sync & Merge**
   - Connect gateway to central node
   - Watch ops flow and merge deterministically
   - UI shows sync progress, new ops arriving

3. **Credential-Based Access**
   - Different sensor types have different credentials
   - Grant/revoke access to specific data streams
   - UI shows which data is accessible per credential

4. **Data Provenance & Audit**
   - Every sensor reading has causal history
   - Audit trail shows who wrote what, when, from where
   - UI visualizes data lineage

5. **Conflict Resolution**
   - Two sites update same config while disconnected
   - Reconnect and show CRDT merge (LWW or MVReg)
   - UI highlights concurrent writes and resolution

### Key UI Requirements

| View | Purpose | Demo Value |
|------|---------|------------|
| **Dashboard** | Node status, sync state, peer connections | "Is my gateway healthy?" |
| **Sensor Data** | Live state grouped by sensor/site | "What's the current reading?" |
| **Sync Status** | Connected peers, pending ops, last sync | "Am I up to date?" |
| **Operations** | Recent ops with author/site attribution | "What changed?" |
| **Credentials** | Active grants, who can write what | "Who has access?" |
| **Audit Log** | Tamper-evident history | "Prove data provenance" |
| **DAG View** | Causal graph (optional, for debugging) | "Show me the merge" |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Browser (any device on network)                            │
│  http://192.168.1.x:8080                                    │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP
┌─────────────────────▼───────────────────────────────────────┐
│  ecac-cli serve --port 8080 --db .ecac.db                   │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Axum HTTP Server                                      │ │
│  │  - Static files (embedded HTML/CSS/JS)                 │ │
│  │  - REST API endpoints                                  │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  AppState (Arc<RwLock<...>>)                           │ │
│  │  - Store (RocksDB)                                     │ │
│  │  - Cached State + TrustView (refreshed on demand)      │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 1: HTTP Server Foundation

### 1.1 Add Dependencies to `crates/cli/Cargo.toml`

```toml
[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
tower-http = { version = "0.5", features = ["cors", "fs"] }
rust-embed = "8"
mime_guess = "2"
```

### 1.2 Add `Serve` Subcommand to CLI

**File:** `crates/cli/src/main.rs`

Add to `Cmd` enum:
```rust
/// Start HTTP server with embedded web UI for IoT gateway demo
Serve {
    /// HTTP listen address (use 0.0.0.0 to expose on network)
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// RocksDB database path
    #[arg(long, short, env = "ECAC_DB")]
    db: Option<PathBuf>,

    /// Human-readable site name (displayed in UI header)
    #[arg(long, env = "ECAC_SITE_NAME")]
    site_name: Option<String>,

    /// Allow write operations via API (disabled by default for safety)
    #[arg(long, default_value = "false")]
    allow_writes: bool,

    /// libp2p listen address for peer sync (e.g., /ip4/0.0.0.0/tcp/9000)
    #[arg(long)]
    libp2p_listen: Option<String>,

    /// Bootstrap peer addresses (can be repeated)
    #[arg(long)]
    bootstrap: Vec<String>,
},
```

Add to match in `main()`:
```rust
Cmd::Serve { listen, db, site_name, allow_writes, libp2p_listen, bootstrap } => {
    commands::cmd_serve(ServeConfig {
        listen,
        db: db.as_deref(),
        site_name,
        allow_writes,
        libp2p_listen,
        bootstrap,
    }).await?;
}
```

Note: `main()` will need `#[tokio::main]` attribute.

### 1.3 Create Server Module

**File:** `crates/cli/src/server/mod.rs`

```rust
mod api;
mod state;
mod static_files;

pub use api::create_router;
pub use state::AppState;
```

### 1.4 Application State

**File:** `crates/cli/src/server/state.rs`

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use ecac_store::Store;
use ecac_core::state::State;
use ecac_core::trustview::TrustView;

pub struct AppState {
    pub store: Store,
    pub cached_state: RwLock<Option<CachedReplay>>,
    pub allow_writes: bool,
}

pub struct CachedReplay {
    pub state: State,
    pub trust_view: TrustView,
    pub digest: [u8; 32],
    pub op_count: usize,
}

impl AppState {
    pub fn new(store: Store, allow_writes: bool) -> Arc<Self> { ... }
    pub async fn get_or_refresh(&self) -> Result<CachedReplay> { ... }
    pub async fn invalidate_cache(&self) { ... }
}
```

---

## Phase 2: REST API Endpoints

**File:** `crates/cli/src/server/api.rs`

### 2.1 Endpoint Overview (IoT Demo Focused)

**Node & Sync Status**
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/node` | Node identity (PeerId, site name, listen addrs) |
| GET | `/api/node/peers` | Connected peers with sync status |
| POST | `/api/node/peers` | Add peer by multiaddr (for manual connect) |
| GET | `/api/node/sync` | Sync state: local head, pending, last sync time |

**Sensor Data & State**
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/state` | Full materialized state |
| GET | `/api/state/:obj` | Single object (e.g., `/api/state/sensor-a1`) |
| GET | `/api/state/:obj/:field` | Single field value |
| POST | `/api/data` | Write sensor data (if `--allow-writes`) |

**Operations & DAG**
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ops` | Recent ops (paginated), shows author/site |
| GET | `/api/ops/:op_id` | Single op with full details |
| GET | `/api/ops/by-author/:pubkey` | Ops from specific author |
| GET | `/api/dag` | DAG structure for visualization |
| GET | `/api/dag/conflicts` | Concurrent ops that were merged |

**Credentials & Access Control**
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/grants` | Active grants (who can write what) |
| GET | `/api/grants/:pubkey` | Grants for specific subject |
| POST | `/api/grant` | Issue grant (if `--allow-writes`) |
| POST | `/api/revoke` | Revoke access (if `--allow-writes`) |

**Trust & Verification**
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/trust` | TrustView: issuers, keys, status lists |
| GET | `/api/trust/issuers` | List issuer IDs |
| GET | `/api/trust/issuers/:id` | Issuer details + keys |
| GET | `/api/trust/verify/:cred_hash` | Verify a credential |

**Audit & Provenance**
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/audit` | Recent audit entries |
| GET | `/api/audit/chain` | Verify audit chain integrity |
| GET | `/api/provenance/:obj/:field` | Causal history for a value |

### 2.2 Response Types

```rust
#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    version: String,
}

#[derive(Serialize)]
struct InfoResponse {
    op_count: usize,
    head_count: usize,
    db_path: String,
    state_digest: String,  // hex
}

#[derive(Serialize)]
struct OpView {
    op_id: String,         // hex
    author: String,        // hex pubkey
    hlc: HlcView,
    parents: Vec<String>,  // hex op_ids
    payload: PayloadView,
}

#[derive(Serialize)]
struct DagResponse {
    nodes: Vec<DagNode>,
    edges: Vec<DagEdge>,   // for visualization
}

#[derive(Serialize)]
struct TrustResponse {
    issuers: Vec<IssuerView>,
    status_lists: Vec<StatusListView>,
}
```

### 2.3 Router Setup

```rust
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // API routes
        .route("/api/health", get(health))
        .route("/api/info", get(info))
        .route("/api/state", get(get_state))
        .route("/api/state/:obj/:field", get(get_field))
        .route("/api/ops", get(list_ops))
        .route("/api/ops/:op_id", get(get_op))
        .route("/api/dag", get(get_dag))
        .route("/api/trust", get(get_trust))
        .route("/api/trust/issuers", get(list_issuers))
        .route("/api/trust/issuers/:id/keys", get(get_issuer_keys))
        .route("/api/audit", get(get_audit))
        .route("/api/ops", post(append_op))
        // Static files (fallback)
        .fallback(static_files::serve_static)
        .with_state(state)
}
```

---

## Phase 3: Embedded Web UI

### 3.1 Static File Embedding

**File:** `crates/cli/src/server/static_files.rs`

```rust
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "src/server/ui/dist/"]
struct Assets;

pub async fn serve_static(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
        }
        None => {
            // SPA fallback: serve index.html for client-side routing
            match Assets::get("index.html") {
                Some(content) => {
                    ([(header::CONTENT_TYPE, "text/html")], content.data).into_response()
                }
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
    }
}
```

### 3.2 UI File Structure

```
crates/cli/src/server/ui/
├── dist/                    # Built files (embedded into binary)
│   ├── index.html
│   ├── style.css
│   └── app.js
└── src/                     # Source (for development)
    ├── index.html
    ├── style.css
    └── app.js
```

### 3.3 UI Pages/Views (Vanilla JS)

**index.html** - Single page app shell with IoT dashboard layout:
```html
<!DOCTYPE html>
<html>
<head>
    <title>ECAC Gateway</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <h1>ECAC Gateway</h1>
        <div id="node-status">
            <span id="site-name">Site: --</span>
            <span id="peer-count">Peers: 0</span>
            <span id="sync-status" class="status-dot"></span>
        </div>
    </header>
    <nav>
        <a href="#dashboard">Dashboard</a>
        <a href="#sensors">Sensors</a>
        <a href="#sync">Sync</a>
        <a href="#access">Access</a>
        <a href="#audit">Audit</a>
    </nav>
    <main id="app"></main>
    <script src="app.js"></script>
</body>
</html>
```

**app.js** - Core functionality:
- Hash-based routing
- Polling with configurable interval (default 2s for sensor data)
- WebSocket upgrade path for future real-time updates
- Render functions for each view

**UI Views:**

1. **Dashboard** (default view)
   - Node identity card (PeerId short form, site name)
   - Connected peers list with last-seen times
   - Quick stats: op count, state digest, last sync
   - Health indicators (green/yellow/red)

2. **Sensors View**
   - Cards for each sensor object in state
   - Shows current readings with timestamps
   - Grouped by site/author if known
   - Highlight recent changes (flash on update)
   - "Write Test Data" button (if `--allow-writes`)

3. **Sync View**
   - Peer topology diagram (simple)
   - Per-peer sync status: frontier, pending ops, last exchange
   - "Add Peer" form (enter multiaddr)
   - Sync history log
   - Highlight conflicts/concurrent edits

4. **Access Control View**
   - Active grants table (subject → scope → granted_by)
   - Credential status (valid/revoked/expired)
   - "Grant Access" / "Revoke" buttons (if `--allow-writes`)
   - Shows which data each credential can access

5. **Audit View**
   - Timeline of operations with provenance
   - Filter by author, time range, op type
   - Chain integrity status (✓ valid / ✗ broken)
   - Export button (download JSONL)
   - Click op to see causal parents

6. **DAG View** (advanced, collapsible)
   - Canvas-based graph of recent ops
   - Highlights merge points (multiple parents)
   - Click node to see op details
   - Useful for debugging concurrent writes

---

## Phase 4: Build Integration

### 4.1 Build Script for UI

**File:** `crates/cli/build.rs` (or manual step)

For development, copy `ui/src/*` to `ui/dist/`. No build step needed for vanilla JS.

```rust
// build.rs (optional, for copying files)
use std::fs;
use std::path::Path;

fn main() {
    let src = Path::new("src/server/ui/src");
    let dist = Path::new("src/server/ui/dist");

    if src.exists() {
        fs::create_dir_all(dist).unwrap();
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let dest = dist.join(entry.file_name());
            fs::copy(entry.path(), dest).unwrap();
        }
    }

    println!("cargo:rerun-if-changed=src/server/ui/src/");
}
```

### 4.2 Cargo Feature (Optional)

Could gate the serve command behind a feature:

```toml
[features]
default = ["serve"]
serve = ["axum", "tower-http", "rust-embed", "mime_guess"]
```

---

## Phase 5: libp2p Networking Integration

This is **critical** for the IoT demo - nodes must sync with each other.

**Complexity: LOW** - The `ecac-net` crate already handles all the hard work. We just need to:
1. Create a `Node` and wire up Store as provider/sink
2. Spawn a background task calling `poll_once()`
3. Expose peer info via API

See `crates/net/tests/two_node_sync_minimal.rs` for the pattern.

### 5.1 Integrate `ecac-net::Node` into Server

**File:** `crates/cli/src/server/state.rs`

```rust
use ecac_net::Node;

pub struct AppState {
    pub store: Store,
    pub node: Option<RwLock<Node>>,  // None if --libp2p-listen not provided
    pub cached_state: RwLock<Option<CachedReplay>>,
    pub config: ServeConfig,
}
```

### 5.2 Background Sync Task

When `--libp2p-listen` is provided, spawn a background task. The pattern from the test is straightforward:

```rust
async fn run_sync_loop(node: Arc<RwLock<Node>>, store: Store) {
    // Wire up store as provider/sink (done once at startup)
    {
        let mut n = node.write().await;
        let store_for_fetch = store.clone();
        n.set_fetch_bytes_provider(move |id| {
            store_for_fetch.get_op_bytes(id).ok().flatten()
        });

        let store_for_have = store.clone();
        n.set_sync_providers(
            move |id| store_for_have.contains(id).unwrap_or(false),
            |id| vec![], // parents lookup - can enhance later
        );

        let store_for_ingest = store.clone();
        n.set_ingest_bytes_sink(move |bytes| {
            store_for_ingest.put_op_cbor(bytes)
        });
    }

    // Main loop - just poll
    loop {
        {
            let mut n = node.write().await;
            while n.poll_once().unwrap_or(false) {}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
```

### 5.3 Peer Management API

```rust
// POST /api/node/peers - Add a new peer
async fn add_peer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddPeerRequest>,
) -> impl IntoResponse {
    if let Some(ref node) = state.node {
        let mut node = node.write().await;
        let addr: Multiaddr = req.multiaddr.parse()?;
        // Extract peer_id from multiaddr or require it separately
        node.add_peer(peer_id, addr)?;
        Json(json!({"ok": true}))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "libp2p not enabled")
    }
}

// GET /api/node/peers - List connected peers
async fn list_peers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(ref node) = state.node {
        let node = node.read().await;
        let peers: Vec<PeerView> = node.connected_peers()
            .map(|p| PeerView {
                peer_id: p.to_string(),
                // sync status from SyncState
            })
            .collect();
        Json(peers)
    } else {
        Json(vec![])
    }
}
```

### 5.4 Sync Status Tracking

Track per-peer sync state for UI display:

```rust
#[derive(Serialize)]
struct SyncStatusResponse {
    local_head_count: usize,
    local_op_count: usize,
    peers: Vec<PeerSyncStatus>,
    last_sync_ms: Option<u64>,
}

#[derive(Serialize)]
struct PeerSyncStatus {
    peer_id: String,
    connected: bool,
    their_head_count: usize,
    pending_fetch: usize,      // ops we need from them
    pending_send: usize,       // ops they need from us
    last_exchange_ms: Option<u64>,
}
```

### 5.5 Op Ingestion from Network

When ops arrive via gossip/fetch:

```rust
fn handle_incoming_op(state: &AppState, op_cbor: &[u8]) -> Result<()> {
    // Add to store
    state.store.put_op_cbor(op_cbor)?;

    // Invalidate replay cache (will refresh on next API call)
    state.invalidate_cache();

    // Gossip ANNOUNCE to other peers
    if let Some(ref node) = state.node {
        // ...
    }

    Ok(())
}
```

---

## File Changes Summary

### New Files

```
crates/cli/src/server/
├── mod.rs              # Module exports
├── api.rs              # REST endpoint handlers (~300 LOC)
├── state.rs            # AppState, caching (~100 LOC)
└── static_files.rs     # Embedded file serving (~50 LOC)

crates/cli/src/server/ui/
├── dist/
│   ├── index.html      # Main HTML shell
│   ├── style.css       # Styling (~200 LOC)
│   └── app.js          # Vanilla JS app (~500 LOC)
└── src/                # Source copies (same files)
```

### Modified Files

```
crates/cli/Cargo.toml   # Add axum, tokio, rust-embed, etc.
crates/cli/src/main.rs  # Add Serve variant, #[tokio::main]
crates/cli/src/lib.rs   # Add `mod server;`
```

---

## Implementation Order

1. **Add dependencies** to Cargo.toml
2. **Create server module** structure (mod.rs, state.rs)
3. **Implement AppState** with Store + caching
4. **Add basic API endpoints** (health, info, state)
5. **Add Serve subcommand** to CLI
6. **Test API** with curl
7. **Create minimal HTML/CSS/JS** UI
8. **Embed static files** with rust-embed
9. **Add remaining endpoints** (ops, dag, trust, audit)
10. **Polish UI** with all views
11. **Test on Raspberry Pi**

---

## Usage Examples

### Basic Usage

```bash
# Start server with default settings (localhost only)
ecac-cli serve

# Expose on network (for Pi access from laptop)
ecac-cli serve --listen 0.0.0.0:8080

# Custom database path
ecac-cli serve --listen 0.0.0.0:8080 --db /data/gateway.db

# Enable write operations (for demo sensor writes)
ecac-cli serve --listen 0.0.0.0:8080 --allow-writes

# Set site name (displayed in UI)
ecac-cli serve --listen 0.0.0.0:8080 --site-name "Site-A"
```

### IoT Demo Setup (3 Nodes)

**Site A - Raspberry Pi (192.168.1.10)**
```bash
ecac-cli serve \
  --listen 0.0.0.0:8080 \
  --db /data/site-a.db \
  --site-name "Factory-Floor-A" \
  --allow-writes \
  --libp2p-listen /ip4/0.0.0.0/tcp/9000
```

**Site B - Raspberry Pi (192.168.1.11)**
```bash
ecac-cli serve \
  --listen 0.0.0.0:8080 \
  --db /data/site-b.db \
  --site-name "Factory-Floor-B" \
  --allow-writes \
  --libp2p-listen /ip4/0.0.0.0/tcp/9000 \
  --bootstrap /ip4/192.168.1.10/tcp/9000/p2p/12D3KooW...
```

**Central Aggregator - Laptop (192.168.1.100)**
```bash
ecac-cli serve \
  --listen 0.0.0.0:8080 \
  --db /data/central.db \
  --site-name "Central-Aggregator" \
  --libp2p-listen /ip4/0.0.0.0/tcp/9000 \
  --bootstrap /ip4/192.168.1.10/tcp/9000/p2p/12D3KooW... \
  --bootstrap /ip4/192.168.1.11/tcp/9000/p2p/12D3KooW...
```

### Demo Workflow

1. Start all three nodes
2. Open browser to each: `http://192.168.1.10:8080`, etc.
3. On Site A UI, write some sensor data
4. Watch it sync to Site B and Central
5. Disconnect Site B (unplug network)
6. Write conflicting data on Site A and Site B
7. Reconnect Site B
8. Watch CRDT merge happen, view in DAG view

---

## Security Considerations

- `--allow-writes` is **off by default** (read-only demo)
- Bind to `127.0.0.1` by default (explicit opt-in for network exposure)
- No authentication (this is a demo tool, not production)
- Consider adding `--readonly` flag that blocks all mutations

---

## Testing Plan

1. **Unit tests** for API response serialization
2. **Integration test** - start server, hit endpoints, verify JSON
3. **Manual test** on Raspberry Pi 4
4. **Cross-platform** - test on Linux, macOS, Windows laptops
