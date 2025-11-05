// crates/net/src/transport.rs
use ::futures::StreamExt;
use anyhow::Result;
use ecac_core::op::OpId;
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
use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::gossip::{announce_topic, build_gossipsub, parse_announce, publish_announce};
use crate::types::{FetchMissing, RpcFrame, SignedAnnounce};

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

    // (future) surface if you want; currently unused
    _conn_evt_tx: mpsc::UnboundedSender<SwarmEvent<ComposedEvent>>,
    pub conn_evt_rx: mpsc::UnboundedReceiver<SwarmEvent<ComposedEvent>>,

    // ---- Sync planner providers (set by upper layer/tests) ----
    have_fn: Option<Arc<dyn Fn(&OpId) -> bool + Send + Sync>>,
    parents_fn: Option<Arc<dyn Fn(&OpId) -> Vec<OpId> + Send + Sync>>,
}

impl Node {
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
        let ping = PingBehaviour::new(PingConfig::new()); // defaults are fine
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

        // Swarm config for tokio
        let cfg = libp2p::swarm::Config::with_tokio_executor();
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
            _conn_evt_tx: conn_evt_tx,
            conn_evt_rx,
            have_fn: None,
            parents_fn: None,
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
        eprintln!("[{:?}] Starting to listen on address: {}", self.peer_id, addr);
        Swarm::listen_on(&mut self.swarm, addr.clone())?;
        eprintln!("[{:?}] Successfully started listening on: {}", self.peer_id, addr);
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

    /// Publish a SignedAnnounce to the announce topic.
    pub fn publish_announce(
        &mut self,
        sa: &crate::types::SignedAnnounce,
    ) -> Result<(), libp2p::gossipsub::PublishError> {
        let gs = &mut self.swarm.behaviour_mut().gossipsub;
        match crate::gossip::publish_announce(gs, &self.announce_topic, sa) {
            Ok(_id) => Ok(()),
            // Idempotent: if we've already seen/published same message_id, treat as success.
            Err(libp2p::gossipsub::PublishError::Duplicate) => {
                log::trace!("gossipsub publish de-duped (Duplicate) — treating as success");
                Ok(())
            }
            Err(e) => Err(e),
        }
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
        self.swarm.behaviour_mut().fetch.send_request(&peer, req)
    }

    /// Quick check for tests: is there at least one open connection to `peer`?
    pub fn is_connected_to(&self, peer: &PeerId) -> bool {
        self.connected.contains(peer)
    }

    /// Current listen addresses (populated after the listen socket is established).
    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }

    /// Drive the swarm by polling it once (call from a tokio loop).
    /// Returns true if any events were processed.
    pub async fn poll_once(&mut self) -> anyhow::Result<bool> {
        let ev = self.swarm.select_next_some().await;
        match ev {
            // ---- connection lifecycle ---------------------------------------------------------
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                self.connected.insert(peer_id);
                eprintln!("[{:?}] connection established via {:?}", self.peer_id, endpoint);
                // Make gossip robust in tests: treat all connected peers as explicit.
                self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
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
                eprintln!("[{:?}] outgoing conn error to {:?}: {}", self.peer_id, peer_id, error);
                Ok(true)
            }
            // Add more logging around timeouts or issues related to the connection:
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
                // Useful breadcrumbs: learned/confirmed observed addrs, protocols, agent, etc.
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
                        if let Some(sa) = parse_announce(&message.data) {
                            // Surface to upper layers/tests
                            let _ = self.ann_tx.send((propagation_source, sa.clone()));
    
                            // If planner providers are set, immediately plan and send first batch.
                            if let (Some(have_arc), Some(parents_arc)) = (&self.have_fn, &self.parents_fn)
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
    
                                if let Some(first) = plan.batches.first() {
                                    if !first.is_empty() {
                                        let _rid = self.send_fetch(
                                            propagation_source,
                                            FetchMissing { want: first.clone() },
                                        );
                                        log::trace!(
                                            "sync: sent FetchMissing to {} want={}",
                                            propagation_source,
                                            first.len()
                                        );
                                    }
                                }
                            }
                        } else {
                            eprintln!("[{:?}] gossipsub message (non-announce) ignored", self.peer_id);
                        }
                    }
                    GossipsubEvent::Subscribed { peer_id, topic } => {
                        eprintln!("[{:?}] gossipsub SUBSCRIBED {:?} -> {}", self.peer_id, peer_id, topic);
                    }
                    GossipsubEvent::Unsubscribed { peer_id, topic } => {
                        eprintln!("[{:?}] gossipsub UNSUBSCRIBED {:?} -> {}", self.peer_id, peer_id, topic);
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
                        RequestResponseMessage::Request { request, mut channel, .. } => {
                            eprintln!("[{:?}] <- RR Request from {:?}", self.peer_id, peer);
    
                            if let Some(ref provider) = self.fetch_bytes_fn {
                                // Minimal in-place handling: send the first available object if any,
                                // otherwise send End. (Streaming multiple frames can be added later.)
                                if let Some(bytes) = request.want.iter().find_map(|id| (provider)(id)) {
                                    let _ = self.swarm
                                        .behaviour_mut()
                                        .fetch
                                        .send_response(channel, RpcFrame::OpBytes(bytes));
                                } else {
                                    let _ = self.swarm
                                        .behaviour_mut()
                                        .fetch
                                        .send_response(channel, RpcFrame::End);
                                }
                            } else {
                                // No provider: surface to upper layers/tests unchanged.
                                let _ = self.rpc_tx.send((peer, channel, request));
                            }
                        }
                        RequestResponseMessage::Response { request_id, response } => {
                            eprintln!("[{:?}] <- RR Response from {:?}", self.peer_id, peer);
                            let _ = self.rr_resp_tx.send((peer, request_id, response));
                        }
                    },
                    RequestResponseEvent::OutboundFailure { peer, request_id, error } => {
                        eprintln!(
                            "[{:?}] RR OutboundFailure to {:?} (req {:?}): {:?}",
                            self.peer_id, peer, request_id, error
                        );
                        // Surface to upper layers/tests.
                        let _ = self.rr_out_fail_tx.send((Some(peer), request_id, error));
                    }
                    RequestResponseEvent::InboundFailure { peer, request_id, error } => {
                        eprintln!(
                            "[{:?}] RR InboundFailure from {:?} (req {:?}): {:?}",
                            self.peer_id, peer, request_id, error
                        );
                    }
                    RequestResponseEvent::ResponseSent { peer, request_id } => {
                        eprintln!(
                            "[{:?}] RR ResponseSent to {:?} (req {:?})",
                            self.peer_id, peer, request_id
                        );
                    }
                }
                Ok(true)
            }
    
            // ---- everything else (forward + log) ------------------------------------------------
            other => {
                // We own `other`; avoid Clone by formatting before sending.
                let dbg = format!("{:?}", &other);
                let _ = self._conn_evt_tx.send(other);
                eprintln!("[{:?}] swarm event: {}", self.peer_id, dbg);
                Ok(false)
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
        publish_announce(gs, topic, sa)
    }
}
