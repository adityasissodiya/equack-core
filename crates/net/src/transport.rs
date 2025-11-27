// crates/net/src/transport.rs
use ::futures::StreamExt;
use anyhow::Result;
use ecac_core::op::{Op, OpId};
//use core::iter;
#[cfg(feature = "net")]
use ecac_core::metrics::METRICS;
use libp2p::identify::{
    Behaviour as IdentifyBehaviour, Config as IdentifyConfig, Event as IdentifyEvent,
};
#[cfg(not(feature = "insecure-plain"))]
use libp2p::noise;
use libp2p::ping::{Behaviour as PingBehaviour, Config as PingConfig, Event as PingEvent};
#[cfg(feature = "insecure-plain")]
use libp2p::plaintext;
use libp2p::{
    core::upgrade::Version,
    gossipsub::{self, Event as GossipsubEvent, IdentTopic as Topic},
    identity,
    request_response::{
        self, Behaviour as RrBehaviour, Event as RequestResponseEvent,
        Message as RequestResponseMessage, OutboundFailure as RrOutboundFailure, OutboundRequestId,
        ResponseChannel,
    },
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
};
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration; // <-- add this
use tokio::sync::mpsc;
use tokio::time::{Interval, MissedTickBehavior};

use crate::gossip::{announce_topic, build_gossipsub, parse_announce, topic_matches_announce};
use crate::types::{FetchMissing, RpcFrame, SignedAnnounce};
use tracing::{info, warn};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ComposedEvent")]
pub struct ComposedBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub fetch: RrBehaviour<crate::rpc::FetchCodec>,
    pub ping: PingBehaviour,
    pub identify: IdentifyBehaviour,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ComposedEvent {
    Gossipsub(gossipsub::Event),
    Fetch(request_response::Event<FetchMissing, RpcFrame>),
    Ping(PingEvent),
    Identify(IdentifyEvent),
}

impl From<gossipsub::Event> for ComposedEvent {
    fn from(e: gossipsub::Event) -> Self {
        ComposedEvent::Gossipsub(e)
    }
}
impl From<request_response::Event<FetchMissing, RpcFrame>> for ComposedEvent {
    fn from(e: request_response::Event<FetchMissing, RpcFrame>) -> Self {
        ComposedEvent::Fetch(e)
    }
}
impl From<PingEvent> for ComposedEvent {
    fn from(e: PingEvent) -> Self {
        ComposedEvent::Ping(e)
    }
}
impl From<IdentifyEvent> for ComposedEvent {
    fn from(e: IdentifyEvent) -> Self {
        ComposedEvent::Identify(e)
    }
}

/// High-level node wrapper used by CLI/daemon.
pub struct Node {
    swarm: Swarm<ComposedBehaviour>,
    pub peer_id: PeerId,
    pub announce_topic: Topic,

    /// Optional: server-side provider to fetch raw op bytes by id.
    fetch_bytes_fn: Option<Arc<dyn Fn(&OpId) -> Option<Vec<u8>> + Send + Sync>>,

    // Outgoing events for upper layers
    pub announces_rx: mpsc::UnboundedReceiver<(PeerId, SignedAnnounce)>,
    pub rpc_req_rx: mpsc::UnboundedReceiver<(PeerId, ResponseChannel<RpcFrame>, FetchMissing)>,
    /// Client-side: frames from responses we receive (peer, req_id, frame)
    pub rr_resp_rx: mpsc::UnboundedReceiver<(PeerId, OutboundRequestId, RpcFrame)>,
    /// Client-side: outbound RR failures (peer, req_id, reason)
    pub rr_out_fail_rx:
        mpsc::UnboundedReceiver<(Option<PeerId>, OutboundRequestId, RrOutboundFailure)>,
    // listen address surfaced for tests / callers
    pub listen_addr_rx: mpsc::UnboundedReceiver<Multiaddr>,

    // internal senders owned by the Node; poll_once() uses these
    ann_tx: mpsc::UnboundedSender<(PeerId, SignedAnnounce)>,
    rpc_tx: mpsc::UnboundedSender<(PeerId, ResponseChannel<RpcFrame>, FetchMissing)>,
    rr_resp_tx: mpsc::UnboundedSender<(PeerId, OutboundRequestId, RpcFrame)>,
    rr_out_fail_tx: mpsc::UnboundedSender<(Option<PeerId>, OutboundRequestId, RrOutboundFailure)>,
    listen_tx: mpsc::UnboundedSender<Multiaddr>,

    // track currently connected peers so tests can gate on it
    connected: HashSet<PeerId>,

    // NEW: fallback providers learned from ANNOUNCEs / fetches
    // (Which peers have ever claimed/served a given OpId)
    announce_sources: HashMap<OpId, SmallVec<[PeerId; 2]>>,

    // NEW: peers we (locally) believe are subscribed to the announce topic
    subscribed: HashSet<PeerId>,

    // --- ingestion + planner state ---
    ingest_fn: Option<Arc<dyn Fn(&[u8]) -> anyhow::Result<OpId> + Send + Sync>>,
    held: HashMap<OpId, Vec<u8>>, // op_id -> exact CBOR bytes (waiting on parents)
    waiting: HashMap<OpId, SmallVec<[OpId; 4]>>, // missing_parent -> children waiting on it
    per_peer: HashMap<PeerId, SyncState>, // planner-driver per peer

    // (future) surface if you want; currently unused
    _conn_evt_tx: mpsc::UnboundedSender<SwarmEvent<ComposedEvent>>,
    pub conn_evt_rx: mpsc::UnboundedReceiver<SwarmEvent<ComposedEvent>>,

    // ---- Sync planner providers (set by upper layer/tests) ----
    have_fn: Option<Arc<dyn Fn(&OpId) -> bool + Send + Sync>>,
    parents_fn: Option<Arc<dyn Fn(&OpId) -> Vec<OpId> + Send + Sync>>,

    // ANNOUNCE sources + signer
    ann_node_id_fn: Option<Arc<dyn Fn() -> crate::types::NodeId + Send + Sync>>,
    ann_topo_fn: Option<Arc<dyn Fn() -> u64 + Send + Sync>>,
    ann_heads_fn: Option<Arc<dyn Fn(usize) -> Vec<OpId> + Send + Sync>>,
    ann_bloom16_fn: Option<Arc<dyn Fn(usize) -> crate::types::Bloom16 + Send + Sync>>,
    ann_sign_fn:
        Option<Arc<dyn Fn(crate::types::Announce) -> crate::types::SignedAnnounce + Send + Sync>>,

    // anti-entropy knobs
    anti_ivl: Option<Interval>,
    ann_heads_k: usize,
    ann_recent_n: usize,
    // republish on-change (ingest, new peer, etc.)
    announce_dirty: bool,

    pending_announces: Vec<crate::types::SignedAnnounce>,
}

struct SyncState {
    frontier: VecDeque<OpId>, // ids we still plan to fetch from this peer
    batch_size: usize,        // simple cap; keep small for tests
    inflight: Option<(OutboundRequestId, OpId)>, // which id did we ask for?
    unavailable: HashSet<OpId>, // don't ask this peer for these again
}

impl Node {
    fn remember_source<I: IntoIterator<Item = OpId>>(&mut self, peer: PeerId, ids: I) {
        for id in ids {
            let e = self.announce_sources.entry(id).or_default();
            if !e.contains(&peer) {
                e.push(peer);
            }
        }
    }

    /// Return peers we believe can provide `id` (learned via ANNOUNCE / fetch).
    /// (Kept generic in case we later merge additional provider sources.)
    fn providers_for(&self, id: &OpId) -> SmallVec<[PeerId; 4]> {
        let mut out: SmallVec<[PeerId; 4]> = SmallVec::new();
        if let Some(srcs) = self.announce_sources.get(id) {
            for p in srcs {
                if !out.contains(p) {
                    out.push(*p);
                }
            }
        }
        out
    }

    fn hex_head(bytes: &[u8], n: usize) -> String {
        use core::fmt::Write;
        let mut s = String::with_capacity(n * 2);
        for b in bytes.iter().take(n) {
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }
    pub fn new(project_id: &str) -> anyhow::Result<Self> {
        // Identity
        let local_key = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(local_key.public());

        // Banner so we know both sides agree on mode
        eprintln!(
            "[{:?}] SECURITY MODE = {}",
            peer_id,
            if cfg!(feature = "insecure-plain") {
                "PLAINTEXT"
            } else {
                "NOISE"
            }
        );

        // Transport: TCP -> upgrade(V1Lazy) -> (Plaintext|Noise) -> Yamux -> boxed
        let transport = libp2p::tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(Version::V1)
            .authenticate({
                #[cfg(feature = "insecure-plain")]
                {
                    plaintext::Config::new(&local_key)
                }
                #[cfg(not(feature = "insecure-plain"))]
                {
                    noise::Config::new(&local_key)?
                }
            })
            .multiplex(yamux::Config::default())
            .boxed();

        // Behaviours
        let gossipsub = build_gossipsub(&local_key);
        let fetch = crate::rpc::build_fetch_behaviour();
        let ping = PingBehaviour::new(PingConfig::new());
        //let behaviour = ComposedBehaviour { gossipsub, fetch, ping };
        let identify = IdentifyBehaviour::new(
            IdentifyConfig::new("/ecac/1.0.0".into(), local_key.public())
                .with_agent_version("ecac-net/0.1.0".into()),
        );
        let behaviour = ComposedBehaviour {
            gossipsub,
            fetch,
            ping,
            identify,
        };

        // Swarm config for tokio, keep connections alive longer than libp2p's ~10s default
        let cfg = libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(60));
        let mut swarm = Swarm::new(transport, behaviour, peer_id, cfg);

        // Subscribe to project topic
        let topic = announce_topic(project_id);
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .expect("subscribe");

        // Channels
        let (ann_tx, ann_rx) = mpsc::unbounded_channel();
        let (rpc_tx, rpc_rx) = mpsc::unbounded_channel();
        // Mirror libp2p::request_response::OutboundFailure { peer: Option<PeerId>, ... }
        let (rr_out_fail_tx, rr_out_fail_rx) =
            mpsc::unbounded_channel::<(Option<PeerId>, OutboundRequestId, RrOutboundFailure)>();
        let (rr_resp_tx, rr_resp_rx) =
            mpsc::unbounded_channel::<(PeerId, OutboundRequestId, RpcFrame)>();
        let (listen_tx, listen_rx) = mpsc::unbounded_channel();
        let (conn_evt_tx, conn_evt_rx) = mpsc::unbounded_channel();
        //let (rr_resp_tx, rr_resp_rx) = mpsc::unbounded_channel();

        Ok(Self {
            swarm,
            peer_id,
            announce_topic: topic,
            fetch_bytes_fn: None,
            announces_rx: ann_rx,
            rpc_req_rx: rpc_rx,
            rr_out_fail_rx,
            rr_resp_rx,
            listen_addr_rx: listen_rx,
            ann_tx,
            rpc_tx,
            rr_out_fail_tx,
            rr_resp_tx,
            listen_tx,
            connected: HashSet::new(),
            subscribed: HashSet::new(), // NEW
            ingest_fn: None,
            held: HashMap::new(),
            waiting: HashMap::new(),
            per_peer: HashMap::new(),
            _conn_evt_tx: conn_evt_tx,
            conn_evt_rx,
            have_fn: None,
            parents_fn: None,
            ann_node_id_fn: None,
            ann_topo_fn: None,
            ann_heads_fn: None,
            ann_bloom16_fn: None,
            ann_sign_fn: None,
            anti_ivl: None,
            ann_heads_k: 16,
            ann_recent_n: 256,
            announce_dirty: true,
            pending_announces: Vec::new(),
            announce_sources: HashMap::new(),
        })
    }

    /// Provide a sink that ingests EXACT canonical op CBOR bytes into the store.
    /// We verify via the store’s `put_op_cbor` (id+sig) and return the op_id on success.
    pub fn set_ingest_bytes_sink<F>(&mut self, f: F)
    where
        F: Fn(&[u8]) -> anyhow::Result<OpId> + Send + Sync + 'static,
    {
        self.ingest_fn = Some(Arc::new(f));
    }

    fn ensure_sync_state(&mut self, peer: PeerId) -> &mut SyncState {
        self.per_peer.entry(peer).or_insert_with(|| SyncState {
            frontier: VecDeque::new(),
            batch_size: 1,
            inflight: None,
            unavailable: HashSet::new(),
        })
    }

    /// Provide a server-side callback to materialize op bytes by id.
    /// If set, incoming `FetchMissing` requests will be answered in-place here.
    pub fn set_fetch_bytes_provider<F>(&mut self, f: F)
    where
        F: Fn(&OpId) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.fetch_bytes_fn = Some(Arc::new(f));
    }

    pub fn listen(&mut self, addr: Multiaddr) -> Result<()> {
        eprintln!(
            "[{:?}] Starting to listen on address: {}",
            self.peer_id, addr
        );
        Swarm::listen_on(&mut self.swarm, addr.clone())?;
        eprintln!(
            "[{:?}] Successfully started listening on: {}",
            self.peer_id, addr
        );
        Ok(())
    }

    pub fn add_peer(&mut self, peer: PeerId, addr: Multiaddr) -> Result<()> {
        // Remember the address (lets the swarm use it for this and future dials).
        Swarm::add_peer_address(&mut self.swarm, peer, addr.clone());

        // Canonical dial: target the PeerId and provide the address explicitly.
        use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
        let opts = DialOpts::peer_id(peer)
            // In prod you probably don't want two connections; NotDialing prevents dup dials
            .condition(PeerCondition::NotDialing)
            .addresses(vec![addr.clone()]) // supply the concrete addr we just learned
            .build();

        // If this returns Err (e.g., NoAddresses, Banned, Backoff), bubble it up now.
        Swarm::dial(&mut self.swarm, opts)
            .map_err(|e| anyhow::anyhow!("peer-id dial failed for {peer}: {e:?}"))?;

        eprintln!(
            "[{:?}] dialing peer {} (addr book includes {})",
            self.peer_id, peer, addr
        );
        Ok(())
    }

    /// Treat `peer` as an explicit gossip forwarding target.
    pub fn add_gossip_explicit_peer(&mut self, peer: PeerId) {
        self.swarm
            .behaviour_mut()
            .gossipsub
            .add_explicit_peer(&peer);
    }

    /// Subscribe this node to the project announce topic (idempotent).
    pub fn subscribe_announce(&mut self) -> Result<(), libp2p::gossipsub::SubscriptionError> {
        let gs = &mut self.swarm.behaviour_mut().gossipsub;
        crate::gossip::subscribe_announce(gs, &self.announce_topic)
    }
    /// Test helper: how many peers do we currently believe are subscribed to our announce topic?
    pub fn announce_subscribed_count(&self) -> usize {
        self.subscribed.len()
    }
    /// Publish a SignedAnnounce to the announce topic.
    /// If there are no known subscribers yet, **queue it** so we don't burn the message-id locally
    /// and lose the ability to deliver later (libp2p will treat identical payloads as duplicates).
    pub fn publish_announce(
        &mut self,
        sa: &crate::types::SignedAnnounce,
    ) -> Result<(), libp2p::gossipsub::PublishError> {
        // No one is subscribed yet? Queue instead of publishing now to avoid local-duplicate suppression later.
        if self.subscribed.is_empty() {
            self.pending_announces.push(sa.clone());
            return Ok(());
        }
        // No one is subscribed yet? Queue instead of publishing now to avoid local-duplicate suppression later.
        if self.subscribed.is_empty() {
            self.pending_announces.push(sa.clone());
            return Ok(());
        }
        let gs = &mut self.swarm.behaviour_mut().gossipsub;
        // IMPORTANT: the match must be the final expression (no trailing `;`), so the function returns Result<()>
        eprintln!("[{:?}] ANN publish_announce() starting", self.peer_id);
        match crate::gossip::publish_announce(gs, &self.announce_topic, sa) {
            Ok(_) | Err(libp2p::gossipsub::PublishError::Duplicate) => Ok(()),
            Err(libp2p::gossipsub::PublishError::InsufficientPeers) => {
                self.pending_announces.push(sa.clone());
                eprintln!(
                    "[announce] queue: publish() -> InsufficientPeers; pending={}",
                    self.pending_announces.len()
                );
                // keep dirty so future events re-attempt
                self.announce_dirty = true;
                eprintln!(
                    "[announce] publish -> InsufficientPeers; queued (pending={})",
                    self.pending_announces.len()
                );
                // Propagate the error so callers can retry until a real publish succeeds.
                Err(libp2p::gossipsub::PublishError::InsufficientPeers)
            }
            Err(e) => Err(e),
        }
    }
    /// Try to flush any queued ANNOUNCEs (added when we previously had no peers).
    /// Removes entries that were successfully sent or were considered duplicates.
    fn try_flush_pending_announces(&mut self) {
        if self.pending_announces.is_empty() {
            return;
        }
        let topic = self.announce_topic.clone();
        let gs = &mut self.swarm.behaviour_mut().gossipsub;
        let _before = self.pending_announces.len();
        // Retain only those that still can't be sent
        eprintln!(
            "[{:?}] ANN flush start count={}",
            self.peer_id,
            self.pending_announces.len()
        );
        self.pending_announces.retain(|sa| {
            // Either actually sent or locally treated as duplicate (already sent) -> drop from queue.
            match crate::gossip::publish_announce(gs, &topic, sa) {
                Ok(_) => {
                    eprintln!("[{:?}] ANN flush -> Ok", self.peer_id);
                    false
                }
                Err(libp2p::gossipsub::PublishError::Duplicate) => {
                    eprintln!("[{:?}] ANN flush -> Duplicate", self.peer_id);
                    false
                }
                Err(libp2p::gossipsub::PublishError::InsufficientPeers) => {
                    eprintln!("[{:?}] ANN flush -> InsufficientPeers (keep)", self.peer_id);
                    true
                }
                Err(e) => {
                    eprintln!("[{:?}] ANN flush -> ERROR {:?} (keep)", self.peer_id, e);
                    true
                }
            }
        });
        eprintln!(
            "[{:?}] ANN flush done remaining={}",
            self.peer_id,
            self.pending_announces.len()
        );
    }

    /// Provide local knowledge so the planner can decide what to fetch.
    pub fn set_sync_providers<FH, FP>(&mut self, have: FH, parents: FP)
    where
        FH: Fn(&OpId) -> bool + Send + Sync + 'static,
        FP: Fn(&OpId) -> Vec<OpId> + Send + Sync + 'static,
    {
        self.have_fn = Some(Arc::new(have));
        self.parents_fn = Some(Arc::new(parents));
    }

    /// Send a FetchMissing request to `peer`.
    pub fn send_fetch(&mut self, peer: PeerId, req: FetchMissing) -> OutboundRequestId {
        let _want_dbg: SmallVec<[String; 4]> =
            req.want.iter().map(|id| format!("{:?}", id)).collect();
        #[cfg(feature = "net")]
        {
            // Count each outbound batch (our client currently batches 1 id per request).
            METRICS.inc("fetch_batches", 1);
        }
        let rid = self.swarm.behaviour_mut().fetch.send_request(&peer, req);
        //info!(target: "rr/client", ?peer, ?rid, want = ?want_dbg, "send_request");
        rid
    }

    /// Quick check for tests: is there at least one open connection to `peer`?
    pub fn is_connected_to(&self, peer: &PeerId) -> bool {
        self.connected.contains(peer)
    }

    /// Current listen addresses (populated after the listen socket is established).
    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }

    // fn pump_sync_if_idle(&mut self, peer: PeerId) {
    //     // Take a snapshot of have_fn so we don't borrow `self` immutably while `st` is mut-borrowed.
    //     let have_fn = self.have_fn.clone();

    //     // Build the next `want` batch inside a limited scope to drop the &mut borrow of `st`.
    //     let (should_send, want) = {
    //         let st = self.ensure_sync_state(peer);
    //         if st.inflight.is_none() {
    //             let mut want = Vec::with_capacity(st.batch_size);
    //             while want.len() < st.batch_size {
    //                 if let Some(id) = st.frontier.pop_front() {
    //                     if let Some(have) = &have_fn {
    //                         if (have)(&id) {
    //                             continue;
    //                         }
    //                     }
    //                     want.push(id);
    //                 } else {
    //                     break;
    //                 }
    //             }
    //             (!want.is_empty(), want)
    //         } else {
    //             (false, Vec::new())
    //         }
    //     };

    //     if should_send {
    //         let rid = self.send_fetch(peer, FetchMissing { want });
    //         let st = self.ensure_sync_state(peer);
    //         st.inflight =  Some((rid, id));
    //     }
    // }

    fn pump_sync_if_idle(&mut self, peer: PeerId) {
        let have_fn = self.have_fn.clone();

        // pick next id
        let next_id = {
            let st = self.ensure_sync_state(peer);
            if st.inflight.is_some() {
                return;
            }
            let mut chosen: Option<OpId> = None;
            while let Some(id) = st.frontier.pop_front() {
                if st.unavailable.contains(&id) {
                    continue;
                }
                if let Some(have) = &have_fn {
                    if (have)(&id) {
                        continue;
                    }
                }
                chosen = Some(id);
                break;
            }
            chosen
        };

        if let Some(id) = next_id {
            let rid = self.send_fetch(peer, FetchMissing { want: vec![id] });
            let st = self.ensure_sync_state(peer);
            st.inflight = Some((rid, id));
        }
    }

    fn ingest_from_peer(&mut self, from: PeerId, bytes: Vec<u8>) -> anyhow::Result<()> {
        // decode enough to get id + parents
        let op: Op =
            serde_cbor::from_slice(&bytes).map_err(|e| anyhow::anyhow!("decode op: {e}"))?;
        let id = op.op_id;

        #[cfg(feature = "net")]
        {
            // We received an op’s bytes over the network.
            METRICS.inc("ops_fetched", 1);
        }

        if let Some(have) = &self.have_fn {
            if (have)(&id) {
                #[cfg(feature = "net")]
                {
                    // We fetched it but already had it locally.
                    METRICS.inc("ops_duplicates_dropped", 1);
                }
                return Ok(());
            }
        }

        let mut missing: SmallVec<[OpId; 4]> = SmallVec::new();
        if let Some(have) = &self.have_fn {
            for p in &op.header.parents {
                if !(have)(p) {
                    missing.push(*p);
                }
            }
        }

        // We just got `id` from `from`; assume the same peer can also provide its parents.
        // This makes recursive fetch robust even if the ANNOUNCE only listed heads.
        if !op.header.parents.is_empty() {
            self.remember_source(from, op.header.parents.iter().copied());
        }

        if !missing.is_empty() {
            self.held.entry(id).or_insert(bytes);
            for m in missing.iter().copied() {
                self.waiting.entry(m).or_default().push(id);
            }
            {
                let st = self.ensure_sync_state(from);
                for m in &missing {
                    if !st.unavailable.contains(m) && !st.frontier.contains(m) {
                        st.frontier.push_back(*m);
                    }
                }
            }

            self.pump_sync_if_idle(from);
            return Ok(());
        }

        if let Some(ing) = &self.ingest_fn {
            let _ = (ing)(&bytes)?;
        }

        if let Some(children) = self.waiting.remove(&id) {
            for ch in children {
                if let Some(bytes) = self.held.remove(&ch) {
                    let _ = self.ingest_from_peer(from, bytes)?;
                }
            }
        }
        Ok(())
    }

    /// Drive the swarm by polling it once (call from a tokio loop).
    /// Returns true if any events were processed.
    pub async fn poll_once(&mut self) -> anyhow::Result<bool> {
        // If anti-entropy is enabled, multiplex timer tick with swarm events.
        if let Some(ivl) = &mut self.anti_ivl {
            tokio::select! {
                _ = ivl.tick() => {
                    // Periodic ANNOUNCE
                    let _ = self.publish_announce_now();
                    self.announce_dirty = false;
                    return Ok(true);
                }
                ev = self.swarm.select_next_some() => {
                    match ev {
                        // ---- connection lifecycle ---------------------------------------------------------
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            self.connected.insert(peer_id);
                            eprintln!("[{:?}] connection established via {:?}", self.peer_id, endpoint);
                            // Make gossip robust in tests: treat all connected peers as explicit.
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            // On-change ANNOUNCE (new peer learned)
                            self.announce_dirty = true;
                    eprintln!("[{:?}] ANN trigger: ConnectionEstablished -> publish_announce_now()", self.peer_id);
                    let _ = self.publish_announce_now();
                    eprintln!("[{:?}] ANN trigger: ConnectionEstablished -> flush_pending()", self.peer_id);
                                            // Also flush any user-staged announces now that we have a peer.
                                            self.try_flush_pending_announces();
                            self.announce_dirty = false;
                            Ok(true)
                        }
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            self.connected.remove(&peer_id);
                            eprintln!("[{:?}] connection CLOSED with {:?}, cause: {:?}", self.peer_id, peer_id, cause);
                            if cause.is_some() {
                                eprintln!("[{:?}] Connection closed due to: {:?}", self.peer_id, cause);
                            }
                            Ok(true)
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            eprintln!("[{:?}] outgoing conn error to {:?}: {}", self.peer_id, peer_id, error);
                            Ok(true)
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            eprintln!("[{:?}] incoming conn error: {}", self.peer_id, error);
                            Ok(true)
                        }

                        // ---- dialing / identify / ping -----------------------------------------------------
                        SwarmEvent::Dialing { peer_id, .. } => {
                            eprintln!("[{:?}] dialing {:?}", self.peer_id, peer_id);
                            Ok(true)
                        }
                        SwarmEvent::Behaviour(ComposedEvent::Ping(ev)) => {
                            eprintln!("[{:?}] ping: {:?}", self.peer_id, ev);
                            Ok(true)
                        }
                        SwarmEvent::Behaviour(ComposedEvent::Identify(ev)) => {
                            eprintln!("[{:?}] identify: {:?}", self.peer_id, ev);
                            Ok(true)
                        }

                        // ---- listen addresses --------------------------------------------------------------
                        SwarmEvent::NewListenAddr { address, .. } => {
                            eprintln!("[{:?}] New listen address received: {}", self.peer_id, address);
                            let _ = self.listen_tx.send(address.clone());
                            Ok(true)
                        }
                        SwarmEvent::ExpiredListenAddr { address, .. } => {
                            eprintln!("[{:?}] listen addr expired: {}", self.peer_id, address);
                            Ok(true)
                        }
                        SwarmEvent::ListenerClosed { addresses, reason, .. } => {
                            eprintln!("[{:?}] listener CLOSED on {:?}, reason: {:?}", self.peer_id, addresses, reason);
                            Ok(true)
                        }
                        SwarmEvent::ListenerError { error, .. } => {
                            eprintln!("[{:?}] listener error: {:?}", self.peer_id, error);
                            Ok(true)
                        }

                        // ---- behaviour: gossipsub ----------------------------------------------------------
                        SwarmEvent::Behaviour(ComposedEvent::Gossipsub(ev)) => {
                            match ev {
                                GossipsubEvent::Message { propagation_source, message_id: _, message, .. } => {
                                    if let Some(sa) = parse_announce(&message.data) {
                                        // Surface to upper layers/tests
                                        let _ = self.ann_tx.send((propagation_source, sa.clone()));
                                                                            // Remember that this peer announced these heads
                                                                            self.remember_source(propagation_source, sa.announce.head_ids.iter().copied());

                                                                            // Borrow-safe enqueue of missing heads:
                                                                            let have_opt = self.have_fn.clone();
                                                                            let mut to_enqueue: SmallVec<[OpId; 4]> = SmallVec::new();
                                                                            if let Some(have) = &have_opt {
                                                                                for id in sa.announce.head_ids.iter().copied() {
                                                                                    if !(have)(&id) {
                                                                                        to_enqueue.push(id);
                                                                                    }
                                                                                }
                                                                            }
                                                                            if !to_enqueue.is_empty() {
                                                                                let st = self.ensure_sync_state(propagation_source);
                                                                                for id in to_enqueue {
                                                                                    if !st.unavailable.contains(&id) && !st.frontier.contains(&id) {
                                                                                        st.frontier.push_back(id);
                                                                                    }
                                                                                }
                                                                                self.pump_sync_if_idle(propagation_source);
                                                                            }


                                                                            // ---- enqueue missing heads (borrow-safe) -----------------------
                                                                            let have_opt = self.have_fn.clone();
                                                                            let mut missing: SmallVec<[OpId; 4]> = SmallVec::new();
                                                                            if let Some(have) = &have_opt {
                                                                                for id in sa.announce.head_ids.iter().copied() {
                                                                                    if !(have)(&id) {
                                                                                        missing.push(id);
                                                                                    }
                                                                                }
                                                                            }
                                                                            if !missing.is_empty() {
                                                                                let st = self.ensure_sync_state(propagation_source);
                                                                                for id in missing {
                                                                                    if !st.unavailable.contains(&id) && !st.frontier.contains(&id) {
                                                                                        st.frontier.push_back(id);
                                                                                    }
                                                                                }
                                                                                self.pump_sync_if_idle(propagation_source);
                                                                            }
                                                                            // ---- enqueue missing heads (borrow-safe) -----------------------
                                                                            // Clone the Arc to avoid holding an immutable borrow of self while we mut-borrow.
                                                                            let have_opt = self.have_fn.clone();
                                                                            // Compute missing first (no &mut self yet).
                                                                            let mut missing: SmallVec<[OpId; 4]> = SmallVec::new();
                                                                            if let Some(have) = &have_opt {
                                                                                for id in sa.announce.head_ids.iter().copied() {
                                                                                    if !(have)(&id) {
                                                                                        missing.push(id);
                                                                                    }
                                                                                }
                                                                            }

                                        // Learn providers from this ANNOUNCE (heads are available from `propagation_source`)
                                        self.remember_source(propagation_source, sa.announce.head_ids.iter().copied());
                                        // If planner providers are set, seed frontier and start RR.
                                        if let (Some(have_arc), Some(parents_arc)) = (&self.have_fn, &self.parents_fn) {
                                            let have_arc = have_arc.clone();
                                            let parents_arc = parents_arc.clone();
                                            let mut have = move |x: &OpId| (have_arc.as_ref())(x);
                                            let mut parents = move |x: &OpId| (parents_arc.as_ref())(x);

                                            let plan = crate::sync::SyncPlanner::plan_with(
                                                &sa.announce.head_ids,
                                                sa.announce.bloom16,
                                                &mut have,
                                                &mut parents,
                                            );

                                            let pid = self.peer_id;
                                            let heads_len = sa.announce.head_ids.len();
                                            let batches_len = plan.batches.len();

                                            let frontier_before = {
                                                let st = self.ensure_sync_state(propagation_source);
                                                st.frontier.len()
                                            };

                                            eprintln!(
                                                "[{:?}] planner: heads={} -> batches={} (frontier_before={})",
                                                pid, heads_len, batches_len, frontier_before
                                            );

                                            if batches_len > 0 {
                                                let st = self.ensure_sync_state(propagation_source);
                                                for b in plan.batches {
                                                    for id in b {
                                                        if !st.unavailable.contains(&id) && !st.frontier.contains(&id) {
                                                            st.frontier.push_back(id);
                                                        }
                                                    }
                                                }
                                            } else {
                                                let st = self.ensure_sync_state(propagation_source);
                                                for id in &sa.announce.head_ids {
                                                    if !st.unavailable.contains(id) && !st.frontier.contains(id) {
                                                        st.frontier.push_back(*id);
                                                    }
                                                }
                                                eprintln!(
                                                    "[{:?}] planner empty -> seeding {} head(s) into frontier",
                                                    pid, heads_len
                                                );
                                            }

                                            // Kick off first fetch; subsequent ones chain via RR responses.
                                            self.pump_sync_if_idle(propagation_source);
                                        }
                                    } else {
                                        eprintln!("[{:?}] gossipsub message (non-announce) ignored", self.peer_id);
                                    }
                                }
                                GossipsubEvent::Subscribed { peer_id, topic } => {
                                    eprintln!("[{:?}] gossipsub SUBSCRIBED {:?} -> {}", self.peer_id, peer_id, topic);
                                                                    // Use helper to match our announce topic robustly.
                                                                    if topic_matches_announce(&self.announce_topic, &topic) {
                                        let first = self.subscribed.insert(peer_id);
                                        eprintln!("[{:?}] ANN subscribed_count={}", self.peer_id, self.subscribed.len());
                                        if first && self.announce_dirty {
                                            // We just learned about a subscriber; try to flush pending announce.
                                            eprintln!("[{:?}] ANN trigger: Subscribed(first) -> publish_announce_now()", self.peer_id);
                                            let _ = self.publish_announce_now();
                                            self.announce_dirty = false;
                                        }
                                        eprintln!("[{:?}] ANN trigger: Subscribed -> flush_pending()", self.peer_id);
                                        self.try_flush_pending_announces();
                                    }
                                }
                                GossipsubEvent::Unsubscribed { peer_id, topic } => {
                                    eprintln!("[{:?}] gossipsub UNSUBSCRIBED {:?} -> {}", self.peer_id, peer_id, topic);
                                    if crate::gossip::topic_matches_announce(&self.announce_topic, &topic) {
                                        self.subscribed.remove(&peer_id);
                                    }
                                }
                                other => {
                                    eprintln!("[{:?}] gossipsub event: {:?}", self.peer_id, other);
                                }
                            }
                            Ok(true)
                        }

                        // ---- behaviour: request-response ----------------------------------------------------
                        SwarmEvent::Behaviour(ComposedEvent::Fetch(ev)) => {
                            match ev {
                                RequestResponseEvent::Message { peer, message } => match message {
                                    RequestResponseMessage::Request { request, channel, .. } => {
                                        if let Some(ref provider) = self.fetch_bytes_fn {
                                            let mut chosen: Option<(OpId, Vec<u8>)> = None;
                                            for id in &request.want {
                                                if let Some(bytes) = (provider)(id) {
                                                    chosen = Some((*id, bytes));
                                                    break;
                                                }
                                            }

                                            let (frame, key_dbg, _len, _head) = if let Some((_id, bytes)) = chosen {
                                                let _len = bytes.len();
                                                let _head = Self::hex_head(&bytes, 8);
                                                (RpcFrame::OpBytes(bytes), String::from("op"), _len, _head)
                                            } else {
                                                (RpcFrame::End, "-".into(), 0, "-".into())
                                            };

                                            if let Err(e) = self.swarm.behaviour_mut().fetch.send_response(channel, frame) {
                                                warn!(target: "rr/provider", ?peer, key = %key_dbg, ?e, "send_response failed");
                                            }
                                        } else {
                                            if let Err(e) = self.rpc_tx.send((peer, channel, request)) {
                                                warn!(target: "rr/provider", ?peer, ?e, "failed to forward RR request to upper layer");
                                            }
                                        }
                                    }

                                    RequestResponseMessage::Response { request_id, response } => {
                                        // surface frame to tests
                                        let _ = self.rr_resp_tx.send((peer, request_id, response.clone()));

                                        match response {
                                            RpcFrame::OpBytes(ref bytes) => {
                                                let cloned = bytes.clone();
                                                match self.ingest_from_peer(peer, cloned) {
                                                    Ok(()) => {
                                                        // On-change ANNOUNCE (new data learned)
                                                        self.announce_dirty = true;
                                                        let _ = self.publish_announce_now();
                                                        self.announce_dirty = false;
                                                    }
                                                    Err(e) => {
                                                        warn!(target: "rr_client", ?peer, ?request_id, len = bytes.len(),
                                                              head = %Self::hex_head(bytes, 8), ?e, "decode/ingest failed; will retry");
                                                    }
                                                }
                                                if let Some(st) = self.per_peer.get_mut(&peer) {
                                                    st.inflight = None;
                                                }
                                            }
                                            RpcFrame::End => {
                                                if let Some(st) = self.per_peer.get_mut(&peer) {
                                                    if let Some((_rid, last_id)) = st.inflight.take() {
                                                        st.unavailable.insert(last_id); // don't ask this peer again
                                                    }
                                                }
                                            }
                                        }

                                        // ask for next one if any
                                        self.pump_sync_if_idle(peer);
                                    }
                                },
                                RequestResponseEvent::OutboundFailure { peer, request_id, error } => {
                                    eprintln!("[{:?}] RR OutboundFailure to {:?} (req {:?}): {:?}", self.peer_id, peer, request_id, error);
                                    let _ = self.rr_out_fail_tx.send((Some(peer), request_id, error));
                                }
                                RequestResponseEvent::InboundFailure { peer, request_id, error } => {
                                    eprintln!("[{:?}] RR InboundFailure from {:?} (req {:?}): {:?}", self.peer_id, peer, request_id, error);
                                    warn!(target: "rr/provider", ?peer, ?request_id, ?error, "inbound failure");
                                }
                                RequestResponseEvent::ResponseSent { peer, request_id } => {
                                    info!(target: "rr/provider", ?peer, ?request_id, "response sent (stream closed)");
                                }
                            }
                            Ok(true)
                        }

                        // ---- everything else (forward + log) ------------------------------------------------
                        other => {
                            let dbg = format!("{:?}", &other);
                            let _ = self._conn_evt_tx.send(other);
                            eprintln!("[{:?}] swarm event: {}", self.peer_id, dbg);
                            if self.announce_dirty {
                                let _ = self.publish_announce_now();
                                self.announce_dirty = false;
                            }
                            Ok(false)
                        }
                    }
                }
            }
        } else {
            // Original single-source event path (no anti-entropy timer configured)
            // Make this non-blocking for test "tick" loops: if no event arrives quickly, report idle.
            let ev = match tokio::time::timeout(
                Duration::from_millis(50),
                self.swarm.select_next_some(),
            )
            .await
            {
                Ok(ev) => ev,
                Err(_elapsed) => {
                    // No event within the short budget; signal "no progress" so callers can continue.
                    return Ok(false);
                }
            };

            match ev {
                // ---- connection lifecycle ---------------------------------------------------------
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    self.connected.insert(peer_id);
                    eprintln!(
                        "[{:?}] connection established via {:?}",
                        self.peer_id, endpoint
                    );
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                    self.announce_dirty = true;
                    let _ = self.publish_announce_now();
                    self.try_flush_pending_announces();
                    self.announce_dirty = false;
                    Ok(true)
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    self.connected.remove(&peer_id);
                    eprintln!(
                        "[{:?}] connection CLOSED with {:?}, cause: {:?}",
                        self.peer_id, peer_id, cause
                    );
                    if cause.is_some() {
                        eprintln!("[{:?}] Connection closed due to: {:?}", self.peer_id, cause);
                    }
                    Ok(true)
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    eprintln!(
                        "[{:?}] outgoing conn error to {:?}: {}",
                        self.peer_id, peer_id, error
                    );
                    Ok(true)
                }
                SwarmEvent::IncomingConnectionError { error, .. } => {
                    eprintln!("[{:?}] incoming conn error: {}", self.peer_id, error);
                    Ok(true)
                }

                // ---- dialing / identify / ping -----------------------------------------------------
                SwarmEvent::Dialing { peer_id, .. } => {
                    eprintln!("[{:?}] dialing {:?}", self.peer_id, peer_id);
                    Ok(true)
                }
                SwarmEvent::Behaviour(ComposedEvent::Ping(ev)) => {
                    eprintln!("[{:?}] ping: {:?}", self.peer_id, ev);
                    Ok(true)
                }
                SwarmEvent::Behaviour(ComposedEvent::Identify(ev)) => {
                    eprintln!("[{:?}] identify: {:?}", self.peer_id, ev);
                    Ok(true)
                }

                // ---- listen addresses --------------------------------------------------------------
                SwarmEvent::NewListenAddr { address, .. } => {
                    eprintln!(
                        "[{:?}] New listen address received: {}",
                        self.peer_id, address
                    );
                    let _ = self.listen_tx.send(address.clone());
                    Ok(true)
                }
                SwarmEvent::ExpiredListenAddr { address, .. } => {
                    eprintln!("[{:?}] listen addr expired: {}", self.peer_id, address);
                    Ok(true)
                }
                SwarmEvent::ListenerClosed {
                    addresses, reason, ..
                } => {
                    eprintln!(
                        "[{:?}] listener CLOSED on {:?}, reason: {:?}",
                        self.peer_id, addresses, reason
                    );
                    Ok(true)
                }
                SwarmEvent::ListenerError { error, .. } => {
                    eprintln!("[{:?}] listener error: {:?}", self.peer_id, error);
                    Ok(true)
                }

                // ---- behaviour: gossipsub ----------------------------------------------------------
                SwarmEvent::Behaviour(ComposedEvent::Gossipsub(ev)) => {
                    match ev {
                        GossipsubEvent::Message {
                            propagation_source,
                            message_id: _,
                            message,
                            ..
                        } => {
                            // Debug id: blake3(payload) first 8 hex chars
                            let h = blake3::hash(&message.data);
                            let mut h8 = String::new();
                            {
                                use core::fmt::Write;
                                for b in h.as_bytes().iter().take(8) {
                                    let _ = write!(&mut h8, "{:02x}", b);
                                }
                            }
                            eprintln!(
                                "[{:?}] ANN recv from {:?} bytes={} blake3[..8]={}",
                                self.peer_id,
                                propagation_source,
                                message.data.len(),
                                h8
                            );
                            if let Some(sa) = parse_announce(&message.data) {
                                let _ = self.ann_tx.send((propagation_source, sa.clone()));
                                // Learn providers from this ANNOUNCE
                                self.remember_source(
                                    propagation_source,
                                    sa.announce.head_ids.iter().copied(),
                                );
                                if let (Some(have_arc), Some(parents_arc)) =
                                    (&self.have_fn, &self.parents_fn)
                                {
                                    let have_arc = have_arc.clone();
                                    let parents_arc = parents_arc.clone();
                                    let mut have = move |x: &OpId| (have_arc.as_ref())(x);
                                    let mut parents = move |x: &OpId| (parents_arc.as_ref())(x);

                                    let plan = crate::sync::SyncPlanner::plan_with(
                                        &sa.announce.head_ids,
                                        sa.announce.bloom16,
                                        &mut have,
                                        &mut parents,
                                    );

                                    let pid = self.peer_id;
                                    let heads_len = sa.announce.head_ids.len();
                                    let batches_len = plan.batches.len();

                                    let frontier_before = {
                                        let st = self.ensure_sync_state(propagation_source);
                                        st.frontier.len()
                                    };

                                    eprintln!(
                                    "[{:?}] planner: heads={} -> batches={} (frontier_before={})",
                                    pid, heads_len, batches_len, frontier_before
                                );

                                    if batches_len > 0 {
                                        let st = self.ensure_sync_state(propagation_source);
                                        for b in plan.batches {
                                            for id in b {
                                                if !st.unavailable.contains(&id)
                                                    && !st.frontier.contains(&id)
                                                {
                                                    st.frontier.push_back(id);
                                                }
                                            }
                                        }
                                    } else {
                                        let st = self.ensure_sync_state(propagation_source);
                                        for id in &sa.announce.head_ids {
                                            if !st.unavailable.contains(id)
                                                && !st.frontier.contains(id)
                                            {
                                                st.frontier.push_back(*id);
                                            }
                                        }
                                        eprintln!(
                                        "[{:?}] planner empty -> seeding {} head(s) into frontier",
                                        pid, heads_len
                                    );
                                    }

                                    self.pump_sync_if_idle(propagation_source);
                                }
                            } else {
                                eprintln!(
                                    "[{:?}] gossipsub message (non-announce) ignored",
                                    self.peer_id
                                );
                            }
                        }
                        GossipsubEvent::Subscribed { peer_id, topic } => {
                            eprintln!(
                                "[{:?}] gossipsub SUBSCRIBED {:?} -> {}",
                                self.peer_id, peer_id, topic
                            );
                            if topic_matches_announce(&self.announce_topic, &topic) {
                                let first = self.subscribed.insert(peer_id);
                                if first && self.announce_dirty {
                                    let _ = self.publish_announce_now();
                                    self.announce_dirty = false;
                                }
                                self.try_flush_pending_announces();
                            }
                        }
                        GossipsubEvent::Unsubscribed { peer_id, topic } => {
                            eprintln!(
                                "[{:?}] gossipsub UNSUBSCRIBED {:?} -> {}",
                                self.peer_id, peer_id, topic
                            );
                            if crate::gossip::topic_matches_announce(&self.announce_topic, &topic) {
                                self.subscribed.remove(&peer_id);
                            }
                        }
                        other => {
                            eprintln!("[{:?}] gossipsub event: {:?}", self.peer_id, other);
                        }
                    }
                    Ok(true)
                }

                // ---- behaviour: request-response ----------------------------------------------------
                SwarmEvent::Behaviour(ComposedEvent::Fetch(ev)) => {
                    match ev {
                        RequestResponseEvent::Message { peer, message } => match message {
                            RequestResponseMessage::Request {
                                request, channel, ..
                            } => {
                                if let Some(ref provider) = self.fetch_bytes_fn {
                                    let mut chosen: Option<(OpId, Vec<u8>)> = None;
                                    for id in &request.want {
                                        if let Some(bytes) = (provider)(id) {
                                            chosen = Some((*id, bytes));
                                            break;
                                        }
                                    }

                                    let (frame, key_dbg, _len, _head) = if let Some((_id, bytes)) =
                                        chosen
                                    {
                                        let _len = bytes.len();
                                        let _head = Self::hex_head(&bytes, 8);
                                        (RpcFrame::OpBytes(bytes), String::from("op"), _len, _head)
                                    } else {
                                        (RpcFrame::End, "-".into(), 0, "-".into())
                                    };

                                    if let Err(e) = self
                                        .swarm
                                        .behaviour_mut()
                                        .fetch
                                        .send_response(channel, frame)
                                    {
                                        warn!(target: "rr/provider", ?peer, key = %key_dbg, ?e, "send_response failed");
                                    }
                                } else {
                                    if let Err(e) = self.rpc_tx.send((peer, channel, request)) {
                                        warn!(target: "rr/provider", ?peer, ?e, "failed to forward RR request to upper layer");
                                    }
                                }
                            }

                            RequestResponseMessage::Response {
                                request_id,
                                response,
                            } => {
                                let _ = self.rr_resp_tx.send((peer, request_id, response.clone()));

                                match response {
                                    RpcFrame::OpBytes(ref bytes) => {
                                        let cloned = bytes.clone();
                                        match self.ingest_from_peer(peer, cloned) {
                                            Ok(()) => {
                                                self.announce_dirty = true;
                                                let _ = self.publish_announce_now();
                                                self.announce_dirty = false;
                                            }
                                            Err(e) => {
                                                warn!(target: "rr_client", ?peer, ?request_id, len = bytes.len(),
                                                  head = %Self::hex_head(bytes, 8), ?e, "decode/ingest failed; will retry");
                                            }
                                        }
                                        if let Some(st) = self.per_peer.get_mut(&peer) {
                                            st.inflight = None;
                                        }
                                    }
                                    RpcFrame::End => {
                                        if let Some(st) = self.per_peer.get_mut(&peer) {
                                            if let Some((_rid, last_id)) = st.inflight.take() {
                                                st.unavailable.insert(last_id);
                                            }
                                        }
                                    }
                                }

                                self.pump_sync_if_idle(peer);
                            }
                        },
                        RequestResponseEvent::OutboundFailure {
                            peer,
                            request_id,
                            error,
                        } => {
                            eprintln!(
                                "[{:?}] RR OutboundFailure to {:?} (req {:?}): {:?}",
                                self.peer_id, peer, request_id, error
                            );
                            let _ = self.rr_out_fail_tx.send((Some(peer), request_id, error));
                        }
                        RequestResponseEvent::InboundFailure {
                            peer,
                            request_id,
                            error,
                        } => {
                            eprintln!(
                                "[{:?}] RR InboundFailure from {:?} (req {:?}): {:?}",
                                self.peer_id, peer, request_id, error
                            );
                            warn!(target: "rr/provider", ?peer, ?request_id, ?error, "inbound failure");
                        }
                        RequestResponseEvent::ResponseSent { peer, request_id } => {
                            info!(target: "rr/provider", ?peer, ?request_id, "response sent (stream closed)");
                        }
                    }
                    Ok(true)
                }

                // ---- everything else (forward + log) ------------------------------------------------
                other => {
                    let dbg = format!("{:?}", &other);
                    let _ = self._conn_evt_tx.send(other);
                    eprintln!("[{:?}] swarm event: {}", self.peer_id, dbg);
                    if self.announce_dirty {
                        let _ = self.publish_announce_now();
                        self.announce_dirty = false;
                    }
                    Ok(false)
                }
            }
        }
    }

    /// Respond to a Fetch request with a single frame (caller can stream multiple calls).
    pub fn respond_fetch(&mut self, ch: ResponseChannel<RpcFrame>, frame: RpcFrame) {
        let _ = self.swarm.behaviour_mut().fetch.send_response(ch, frame);
    }

    /// TEST-ONLY: allow tests to publish a SignedAnnounce via the node's gossipsub.
    #[cfg(test)]
    pub fn publish_announce_for_tests(
        &mut self,
        topic: &libp2p::gossipsub::IdentTopic,
        sa: &crate::types::SignedAnnounce,
    ) -> Result<libp2p::gossipsub::MessageId, libp2p::gossipsub::PublishError> {
        use crate::gossip::publish_announce;
        let gs = &mut self.swarm.behaviour_mut().gossipsub;
        eprintln!("[{:?}] TEST publish_announce_for_tests()", self.peer_id);
        match publish_announce(gs, topic, sa) {
            Ok(id) => Ok(id),
            Err(libp2p::gossipsub::PublishError::InsufficientPeers) => {
                // In tests we often publish before the mesh forms. Queue it so we can
                // flush on GossipsubEvent::Subscribed / ConnectionEstablished.
                self.pending_announces.push(sa.clone());
                // Keep the original error for callers that care; the side-effect is what matters.
                Err(libp2p::gossipsub::PublishError::InsufficientPeers)
            }
            Err(e) => Err(e),
        }
    }

    pub fn set_announce_sources<FN, FT, FH, FB, FS>(
        &mut self,
        node_id_fn: FN,
        topo_fn: FT,
        heads_fn: FH,
        bloom16_fn: FB,
        sign_fn: FS,
    ) where
        FN: Fn() -> crate::types::NodeId + Send + Sync + 'static,
        FT: Fn() -> u64 + Send + Sync + 'static,
        FH: Fn(usize) -> Vec<OpId> + Send + Sync + 'static,
        FB: Fn(usize) -> crate::types::Bloom16 + Send + Sync + 'static,
        FS: Fn(crate::types::Announce) -> crate::types::SignedAnnounce + Send + Sync + 'static,
    {
        self.ann_node_id_fn = Some(Arc::new(node_id_fn));
        self.ann_topo_fn = Some(Arc::new(topo_fn));
        self.ann_heads_fn = Some(Arc::new(heads_fn));
        self.ann_bloom16_fn = Some(Arc::new(bloom16_fn));
        self.ann_sign_fn = Some(Arc::new(sign_fn));
        self.announce_dirty = true;
    }

    /// Start periodic anti-entropy announcements.
    pub fn start_anti_entropy(&mut self, period: Duration, heads_k: usize, recent_n: usize) {
        let mut ivl = tokio::time::interval(period);
        ivl.set_missed_tick_behavior(MissedTickBehavior::Delay);
        self.anti_ivl = Some(ivl);
        self.ann_heads_k = heads_k;
        self.ann_recent_n = recent_n;
        self.announce_dirty = true; // force an early publish
    }

    // --- helper: build+publish now ---
    fn publish_announce_now(&mut self) -> anyhow::Result<()> {
        // If nobody is subscribed yet, queue the freshly built announce; don’t publish now.
        if self.subscribed.is_empty() {
            // Build if sources are wired; if not wired, just return (tests may publish directly).
            let (nidf, tf, hf, bf, sf) = match (
                &self.ann_node_id_fn,
                &self.ann_topo_fn,
                &self.ann_heads_fn,
                &self.ann_bloom16_fn,
                &self.ann_sign_fn,
            ) {
                (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
                _ => return Ok(()),
            };
            let a = crate::types::Announce {
                node_id: (nidf)(),
                topo_watermark: (tf)(),
                head_ids: (hf)(self.ann_heads_k),
                bloom16: (bf)(self.ann_recent_n),
            };
            let sa = (sf)(a);
            self.pending_announces.push(sa);
            return Ok(());
        }
        let (nidf, tf, hf, bf, sf) = match (
            &self.ann_node_id_fn,
            &self.ann_topo_fn,
            &self.ann_heads_fn,
            &self.ann_bloom16_fn,
            &self.ann_sign_fn,
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
            _ => return Ok(()), // not wired yet
        };
        let a = crate::types::Announce {
            node_id: (nidf)(),
            topo_watermark: (tf)(),
            head_ids: (hf)(self.ann_heads_k),
            bloom16: (bf)(self.ann_recent_n),
        };
        let sa = (sf)(a);
        // publish via existing helper
        let gs = &mut self.swarm.behaviour_mut().gossipsub;
        let _ = crate::gossip::publish_announce(gs, &self.announce_topic, &sa)?;
        Ok(())
    }
}
