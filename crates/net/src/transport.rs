// crates/net/src/transport.rs
use anyhow::Result;
use ::futures::StreamExt;
use std::collections::HashSet;
use libp2p::ping::{Behaviour as PingBehaviour, Config as PingConfig, Event as PingEvent};
use libp2p::{
    gossipsub::{self, IdentTopic as Topic, Event as GossipsubEvent},
    request_response::{
        self, Event as RequestResponseEvent, Message as RequestResponseMessage, OutboundRequestId,
        ResponseChannel, Behaviour as RrBehaviour,
    },
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, identity, Swarm, PeerId, Multiaddr,
    core::upgrade::Version,
    Transport,
};

#[cfg(not(feature = "insecure-plain"))]
use libp2p::noise;
#[cfg(feature = "insecure-plain")]
use libp2p::plaintext;

use tokio::sync::mpsc;

use crate::gossip::{announce_topic, build_gossipsub, parse_announce, publish_announce};
use crate::types::{FetchMissing, RpcFrame, SignedAnnounce};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ComposedEvent")]
pub struct ComposedBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub fetch: RrBehaviour<crate::rpc::FetchCodec>,
    pub ping: PingBehaviour,    
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ComposedEvent {
    Gossipsub(gossipsub::Event),
    Fetch(request_response::Event<FetchMissing, RpcFrame>),
    Ping(PingEvent),
}

impl From<gossipsub::Event> for ComposedEvent {
    fn from(e: gossipsub::Event) -> Self { ComposedEvent::Gossipsub(e) }
}
impl From<request_response::Event<FetchMissing, RpcFrame>> for ComposedEvent {
    fn from(e: request_response::Event<FetchMissing, RpcFrame>) -> Self { ComposedEvent::Fetch(e) }
}
impl From<PingEvent> for ComposedEvent {
    fn from(e: PingEvent) -> Self { ComposedEvent::Ping(e) }
}

/// High-level node wrapper used by CLI/daemon.
pub struct Node {
    swarm: Swarm<ComposedBehaviour>,
    pub peer_id: PeerId,
    pub announce_topic: Topic,
    // Outgoing events for upper layers
    pub announces_rx: mpsc::UnboundedReceiver<(PeerId, SignedAnnounce)>,
    pub rpc_req_rx: mpsc::UnboundedReceiver<(PeerId, ResponseChannel<RpcFrame>, FetchMissing)>,
    // listen address surfaced for tests / callers
    pub listen_addr_rx: mpsc::UnboundedReceiver<Multiaddr>,
    // internal senders owned by the Node; poll_once() uses these
    ann_tx: mpsc::UnboundedSender<(PeerId, SignedAnnounce)>,
    rpc_tx: mpsc::UnboundedSender<(PeerId, ResponseChannel<RpcFrame>, FetchMissing)>,
    listen_tx: mpsc::UnboundedSender<Multiaddr>,
    // track currently connected peers so tests can gate on it
    connected: HashSet<PeerId>,
    // (future) surface if you want; currently unused
    conn_evt_tx: mpsc::UnboundedSender<SwarmEvent<ComposedEvent>>,
    pub conn_evt_rx: mpsc::UnboundedReceiver<SwarmEvent<ComposedEvent>>,
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
            if cfg!(feature = "insecure-plain") { "PLAINTEXT" } else { "NOISE" }
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
        let ping = PingBehaviour::new(PingConfig::new());  // defaults are fine
        let behaviour = ComposedBehaviour { gossipsub, fetch, ping };

        // Swarm config for tokio
        let cfg = libp2p::swarm::Config::with_tokio_executor();
        let mut swarm = Swarm::new(transport, behaviour, peer_id, cfg);

        // Subscribe to project topic
        let topic = announce_topic(project_id);
        swarm.behaviour_mut().gossipsub.subscribe(&topic).expect("subscribe");

        // Channels
        let (ann_tx, ann_rx) = mpsc::unbounded_channel();
        let (rpc_tx, rpc_rx) = mpsc::unbounded_channel();
        let (listen_tx, listen_rx) = mpsc::unbounded_channel();
        let (conn_evt_tx, conn_evt_rx) = mpsc::unbounded_channel();

        Ok(Self {
            swarm,
            peer_id,
            announce_topic: topic,
            announces_rx: ann_rx,
            rpc_req_rx: rpc_rx,
            listen_addr_rx: listen_rx,
            ann_tx,
            rpc_tx,
            listen_tx,
            connected: HashSet::new(),
            conn_evt_tx,
            conn_evt_rx,
        })
    }

    pub fn listen(&mut self, addr: Multiaddr) -> Result<()> {
        Swarm::listen_on(&mut self.swarm, addr)?;
        Ok(())
    }

    pub fn add_peer(&mut self, peer: PeerId, addr: Multiaddr) -> Result<()> {
        // Remember the address (lets the swarm use it for this and future dials).
        Swarm::add_peer_address(&mut self.swarm, peer, addr.clone());
    
        // Canonical dial: target the PeerId and provide the address explicitly.
        use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
        let opts = DialOpts::peer_id(peer)
            .condition(PeerCondition::Always)      // force a dial even if swarm thinks it's connected/backing off
            .addresses(vec![addr.clone()])         // supply the concrete addr we just learned
            .build();
    
        // If this returns Err (e.g., NoAddresses, Banned, Backoff), bubble it up now.
        Swarm::dial(&mut self.swarm, opts)
            .map_err(|e| anyhow::anyhow!("peer-id dial failed for {peer}: {e:?}"))?;
    
        // Fallback: also try dialing the full /p2p multiaddr (best-effort; ignore error).
        let mut addr_with_p2p = addr.clone();
        addr_with_p2p.push(libp2p::multiaddr::Protocol::P2p(peer.into()));
        let _ = Swarm::dial(&mut self.swarm, addr_with_p2p.clone());
    
        eprintln!(
            "[{:?}] dialing peer {} (addr book includes {}, also tried {})",
            self.peer_id, peer, addr, addr_with_p2p
        );
        Ok(())
    }
      

    /// Treat `peer` as an explicit gossip forwarding target.
    pub fn add_gossip_explicit_peer(&mut self, peer: PeerId) {
        self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
    }

    /// Publish a SignedAnnounce to the announce topic.
    pub fn publish_announce(&mut self, sa: &SignedAnnounce) -> Result<(), libp2p::gossipsub::PublishError> {
        publish_announce(&mut self.swarm.behaviour_mut().gossipsub, &self.announce_topic, sa)?;
        Ok(())
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
                Ok(true)
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                self.connected.remove(&peer_id);
                eprintln!("[{:?}] connection CLOSED with {:?}, cause: {:?}", self.peer_id, peer_id, cause);
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
            SwarmEvent::Dialing { peer_id, .. } => {
                eprintln!("[{:?}] dialing {:?}", self.peer_id, peer_id);
                Ok(true)
            }
            SwarmEvent::Behaviour(ComposedEvent::Ping(_ev)) => {
                eprintln!("[{:?}] ping: {:?}", self.peer_id, _ev);
                Ok(true)
            }         

            // ---- listen addresses -------------------------------------------------------------
            SwarmEvent::NewListenAddr { address, .. } => {
                let _ = self.listen_tx.send(address);
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

            // ---- behaviour: gossipsub ---------------------------------------------------------
            SwarmEvent::Behaviour(ComposedEvent::Gossipsub(ev)) => {
                match ev {
                    GossipsubEvent::Message { propagation_source, message_id: _, message, .. } => {
                        if let Some(sa) = parse_announce(&message.data) {
                            let _ = self.ann_tx.send((propagation_source, sa));
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

            // ---- behaviour: request-response --------------------------------------------------
            SwarmEvent::Behaviour(ComposedEvent::Fetch(ev)) => {
                match ev {
                    RequestResponseEvent::Message { peer, message } => {
                        match message {
                            RequestResponseMessage::Request { request, channel, .. } => {
                                eprintln!("[{:?}] <- RR Request from {:?}", self.peer_id, peer);
                                let _ = self.rpc_tx.send((peer, channel, request));
                            }
                            RequestResponseMessage::Response { .. } => {
                                eprintln!("[{:?}] <- RR Response from {:?}", self.peer_id, peer);
                            }
                        }
                    }
                    RequestResponseEvent::OutboundFailure { peer, request_id, error } => {
                        eprintln!(
                            "[{:?}] RR OutboundFailure to {:?} (req {:?}): {:?}",
                            self.peer_id, peer, request_id, error
                        );
                    }
                    RequestResponseEvent::InboundFailure  { peer, request_id, error } => {
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

                    // ---- everything else (make these visible) -----------------------------------------
                    other => {
                        // Show noisy lifecycle to see *why* we’re not establishing:
                        // Dialing, IncomingConnection, PendingConnection*, etc.
                        eprintln!("[{:?}] swarm event: {:?}", self.peer_id, other);
                        Ok(false)
                    }
        }
    }

    /// Respond to a Fetch request with a single frame (caller can stream multiple calls).
    pub fn respond_fetch(&mut self, ch: ResponseChannel<RpcFrame>, frame: RpcFrame) {
        let _ = self.swarm.behaviour_mut().fetch.send_response(ch, frame);
    }
}
