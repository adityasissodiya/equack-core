//! Application state for the serve command.

use anyhow::Result;
use ecac_core::dag::Dag;
use ecac_core::replay::replay_full;
use ecac_core::state::State;
use ecac_core::trustview::TrustView;
use ecac_store::Store;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};

/// Configuration for the serve command.
#[derive(Clone)]
pub struct ServeConfig {
    /// HTTP listen address (e.g., "127.0.0.1:8080")
    pub listen: String,
    /// Path to RocksDB database
    pub db: PathBuf,
    /// Human-readable site name
    pub site_name: Option<String>,
    /// Project ID for gossip topic (nodes with same project sync together)
    pub project: String,
    /// Allow write operations via API
    pub allow_writes: bool,
    /// libp2p listen address (e.g., "/ip4/0.0.0.0/tcp/9000")
    pub libp2p_listen: Option<String>,
    /// Bootstrap peer addresses
    pub bootstrap: Vec<String>,
}

/// Cached replay state to avoid re-replaying on every request.
#[derive(Clone)]
pub struct CachedReplay {
    pub state: State,
    pub trust_view: TrustView,
    pub digest: [u8; 32],
    pub op_count: usize,
}

/// Commands that can be sent to the networking task.
#[cfg(feature = "serve")]
pub enum NetCommand {
    /// Get list of connected peers
    GetPeers(oneshot::Sender<Vec<PeerInfo>>),
    /// Add a peer by multiaddr
    AddPeer(String, oneshot::Sender<Result<String, String>>),
    /// Get this node's peer ID
    GetPeerId(oneshot::Sender<Option<String>>),
    /// Trigger an announcement to peers (call after writing new ops)
    Announce(oneshot::Sender<Result<(), String>>),
}

#[cfg(feature = "serve")]
#[derive(Clone)]
pub struct PeerInfo {
    pub peer_id: String,
    pub connected: bool,
}

/// Shared application state.
pub struct AppState {
    pub store: Store,
    pub cached: RwLock<Option<CachedReplay>>,
    pub config: ServeConfig,
    /// Channel to send commands to the networking task
    #[cfg(feature = "serve")]
    pub net_cmd_tx: Option<mpsc::Sender<NetCommand>>,
    /// This node's peer ID (set after networking starts)
    #[cfg(feature = "serve")]
    pub peer_id: RwLock<Option<String>>,
}

impl AppState {
    /// Create new application state from config.
    pub fn new(config: ServeConfig) -> Result<Self> {
        let store = Store::open(&config.db, Default::default())?;

        Ok(Self {
            store,
            cached: RwLock::new(None),
            config,
            #[cfg(feature = "serve")]
            net_cmd_tx: None,
            #[cfg(feature = "serve")]
            peer_id: RwLock::new(None),
        })
    }

    /// Set the networking command channel.
    #[cfg(feature = "serve")]
    pub fn set_net_channel(&mut self, tx: mpsc::Sender<NetCommand>) {
        self.net_cmd_tx = Some(tx);
    }

    /// Set this node's peer ID.
    #[cfg(feature = "serve")]
    pub async fn set_peer_id(&self, id: String) {
        let mut peer_id = self.peer_id.write().await;
        *peer_id = Some(id);
    }

    /// Get this node's peer ID.
    #[cfg(feature = "serve")]
    pub async fn get_peer_id(&self) -> Option<String> {
        self.peer_id.read().await.clone()
    }

    /// Check if networking is enabled.
    #[cfg(feature = "serve")]
    pub fn networking_enabled(&self) -> bool {
        self.net_cmd_tx.is_some()
    }

    #[cfg(not(feature = "serve"))]
    pub fn networking_enabled(&self) -> bool {
        false
    }

    /// Get or refresh the cached replay state.
    pub async fn get_or_refresh(&self) -> Result<CachedReplay> {
        // Check if cache is still valid (op count matches)
        let current_op_count = self.store.topo_ids()?.len();

        {
            let cached = self.cached.read().await;
            if let Some(ref c) = *cached {
                if c.op_count == current_op_count {
                    return Ok(c.clone());
                }
            }
        }

        // Cache miss or stale - replay
        let ids = self.store.topo_ids()?;
        let op_bytes = self.store.load_ops_cbor(&ids)?;

        let mut dag = Dag::new();
        for bytes in &op_bytes {
            let op: ecac_core::op::Op = serde_cbor::from_slice(bytes)?;
            dag.insert(op);
        }

        let order = dag.topo_sort();
        let trust_view = TrustView::build_from_dag(&dag, &order);
        let (state, digest) = replay_full(&dag);

        let cached_replay = CachedReplay {
            state,
            trust_view,
            digest,
            op_count: current_op_count,
        };

        // Update cache
        {
            let mut cached = self.cached.write().await;
            *cached = Some(cached_replay.clone());
        }

        Ok(cached_replay)
    }

    /// Invalidate the cache (call after new ops are ingested).
    pub async fn invalidate_cache(&self) {
        let mut cached = self.cached.write().await;
        *cached = None;
    }

    /// Get connected peers via the networking task.
    #[cfg(feature = "serve")]
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        if let Some(ref tx) = self.net_cmd_tx {
            let (resp_tx, resp_rx) = oneshot::channel();
            if tx.send(NetCommand::GetPeers(resp_tx)).await.is_ok() {
                if let Ok(peers) = resp_rx.await {
                    return peers;
                }
            }
        }
        vec![]
    }

    /// Add a peer via the networking task.
    #[cfg(feature = "serve")]
    pub async fn add_peer(&self, multiaddr: String) -> Result<String, String> {
        if let Some(ref tx) = self.net_cmd_tx {
            let (resp_tx, resp_rx) = oneshot::channel();
            if tx
                .send(NetCommand::AddPeer(multiaddr, resp_tx))
                .await
                .is_ok()
            {
                if let Ok(result) = resp_rx.await {
                    return result;
                }
            }
        }
        Err("Networking not enabled".to_string())
    }

    /// Trigger an announcement to peers (call after writing new ops).
    #[cfg(feature = "serve")]
    pub async fn announce(&self) -> Result<(), String> {
        if let Some(ref tx) = self.net_cmd_tx {
            let (resp_tx, resp_rx) = oneshot::channel();
            if tx.send(NetCommand::Announce(resp_tx)).await.is_ok() {
                if let Ok(result) = resp_rx.await {
                    return result;
                }
            }
        }
        Ok(()) // No-op if networking not enabled
    }
}

/// Spawn the networking task that owns the libp2p Node.
#[cfg(feature = "serve")]
pub async fn spawn_network_task(
    config: &ServeConfig,
    store: Store,
) -> Result<(mpsc::Sender<NetCommand>, String)> {
    use ecac_net::transport::Node;
    use ecac_net::types::{Announce, NodeId, SignedAnnounce};
    use std::time::Duration;

    let project_id = &config.project;
    let mut node = Node::new(project_id)?;

    // Parse and listen on the libp2p address
    let libp2p_addr = config
        .libp2p_listen
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No libp2p listen address"))?;
    let addr: libp2p::Multiaddr = libp2p_addr.parse()?;
    node.listen(addr)?;

    // Wire up store as provider/sink
    let store_for_fetch = store.clone();
    node.set_fetch_bytes_provider(move |id| store_for_fetch.get_op_bytes(id).ok().flatten());

    let store_for_have = store.clone();
    node.set_sync_providers(
        move |id| store_for_have.contains(id).unwrap_or(false),
        |_id| vec![], // Parents lookup - simplified for now
    );

    let store_for_ingest = store.clone();
    node.set_ingest_bytes_sink(move |bytes| store_for_ingest.put_op_cbor(bytes));

    // Wire up announcement sources so the node can build and publish announcements
    let node_id: NodeId = node.peer_id.to_bytes().try_into().unwrap_or([0u8; 32]);
    let store_for_topo = store.clone();
    let store_for_heads = store.clone();
    let store_for_bloom = store.clone();

    node.set_announce_sources(
        move || node_id,
        move || store_for_topo.topo_ids().map(|ids| ids.len() as u64).unwrap_or(0),
        move |k| store_for_heads.heads(k).unwrap_or_default(),
        move |n| store_for_bloom.recent_bloom(n).unwrap_or([0u8; 2]),
        |announce: Announce| {
            // For demo purposes, create an unsigned announcement
            // In production, this would be properly signed
            SignedAnnounce {
                announce,
                sig: vec![],
                vk: [0u8; 32],
            }
        },
    );

    // Subscribe to announcements
    let _ = node.subscribe_announce();

    let peer_id = node.peer_id.to_string();

    // Create command channel
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetCommand>(32);

    // Track connected peers locally
    let connected_peers: std::sync::Arc<std::sync::Mutex<Vec<PeerInfo>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let connected_peers_clone = connected_peers.clone();

    // Spawn the networking task
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(50));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Poll the node for network events
                    match node.poll_once().await {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("poll_once error: {}", e);
                        }
                    }
                }
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        NetCommand::GetPeers(resp) => {
                            // Return our locally tracked peers
                            let peers = connected_peers_clone.lock().unwrap().clone();
                            let _ = resp.send(peers);
                        }
                        NetCommand::AddPeer(multiaddr_str, resp) => {
                            let result = (|| -> Result<String, String> {
                                let addr: libp2p::Multiaddr = multiaddr_str
                                    .parse()
                                    .map_err(|e| format!("Invalid multiaddr: {}", e))?;

                                // Extract peer ID from multiaddr
                                let peer_id = addr
                                    .iter()
                                    .find_map(|p| {
                                        if let libp2p::multiaddr::Protocol::P2p(pid) = p {
                                            Some(pid)
                                        } else {
                                            None
                                        }
                                    })
                                    .ok_or_else(|| {
                                        "Multiaddr must contain /p2p/<peer_id>".to_string()
                                    })?;

                                node.add_peer(peer_id, addr)
                                    .map_err(|e| e.to_string())?;
                                node.add_gossip_explicit_peer(peer_id);

                                // Track this peer locally
                                {
                                    let mut peers = connected_peers_clone.lock().unwrap();
                                    if !peers.iter().any(|p| p.peer_id == peer_id.to_string()) {
                                        peers.push(PeerInfo {
                                            peer_id: peer_id.to_string(),
                                            connected: true,
                                        });
                                    }
                                }

                                Ok(peer_id.to_string())
                            })();
                            let _ = resp.send(result);
                        }
                        NetCommand::GetPeerId(resp) => {
                            let _ = resp.send(Some(node.peer_id.to_string()));
                        }
                        NetCommand::Announce(resp) => {
                            // Trigger an immediate announcement to peers
                            let result = node.trigger_announce().map_err(|e| e.to_string());
                            let _ = resp.send(result);
                        }
                    }
                }
            }
        }
    });

    Ok((cmd_tx, peer_id))
}
