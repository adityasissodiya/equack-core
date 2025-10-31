use anyhow::Result;
use ::futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic as Topic},
    request_response::{self, Behaviour as RrBehaviour, OutboundRequestId, ResponseChannel},
    tcp, noise, yamux, identity, PeerId, Multiaddr, Transport, Swarm, SwarmBuilder,
};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use tokio::sync::mpsc;

use crate::gossip::{announce_topic, build_gossipsub, parse_announce, publish_announce};
use crate::rpc::build_fetch_behaviour;
use crate::types::{FetchMissing, RpcFrame, SignedAnnounce};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ComposedEvent")]
pub struct ComposedBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub fetch: RrBehaviour<crate::rpc::FetchCodec>,
}

#[allow(clippy::large_enum_variant)]
pub enum ComposedEvent {
    Gossipsub(gossipsub::Event),
    Fetch(request_response::Event<FetchMissing, RpcFrame>),
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

/// High-level node wrapper used by CLI/daemon.
/// Exposes channels for incoming announces and fetch requests, and methods to publish/ask.
pub struct Node {
    swarm: Swarm<ComposedBehaviour>,
    pub peer_id: PeerId,
    pub announce_topic: Topic,
    // Outgoing events for upper layers
    pub announces_rx: mpsc::UnboundedReceiver<(PeerId, SignedAnnounce)>,
    pub rpc_req_rx: mpsc::UnboundedReceiver<(PeerId, ResponseChannel<RpcFrame>, FetchMissing)>,
}

impl Node {
    pub fn new(project_id: &str) -> Result<Self> {
        // Identity
        let local_key = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(local_key.public());

        // Transport (TCP + Noise + Yamux)
        let transport = libp2p::tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(&local_key)?)
            .multiplex(yamux::Config::default())
            .boxed();

        // Behaviours
        let gossipsub = build_gossipsub(&local_key);
        let fetch = build_fetch_behaviour();
        let behaviour = ComposedBehaviour { gossipsub, fetch };

        // Swarm
        let mut swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_other_transport(|_| transport)?
            .with_behaviour(|_| behaviour)?
            .build();

        let topic = announce_topic(project_id);
        swarm.behaviour_mut().gossipsub.subscribe(&topic).expect("subscribe");

        // Channels
        let (_ann_tx, ann_rx) = mpsc::unbounded_channel();
        let (_rpc_tx, rpc_rx) = mpsc::unbounded_channel();

        Ok(Self {
            swarm,
            peer_id,
            announce_topic: topic,
            announces_rx: ann_rx,
            rpc_req_rx: rpc_rx,
        })
    }

    pub fn listen(&mut self, addr: Multiaddr) -> Result<()> {
        Swarm::listen_on(&mut self.swarm, addr)?;
        Ok(())
    }

    pub fn add_peer(&mut self, peer: PeerId, addr: Multiaddr) -> Result<()> {
        // NOTE: add_address is deprecated; fine for now.
        // Use modern API; Behaviour::add_address is deprecated.
        self.swarm.add_peer_address(peer, addr.clone());
        self.swarm.dial(addr)?;
        Ok(())
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

    /// Drive the swarm by polling it once (call from a tokio loop).
    /// Returns true if any events were processed.
    pub async fn poll_once(
        &mut self,
        ann_tx: &mpsc::UnboundedSender<(PeerId, SignedAnnounce)>,
        rpc_tx: &mpsc::UnboundedSender<(PeerId, ResponseChannel<RpcFrame>, FetchMissing)>,
    ) -> Result<bool> {
        match self.swarm.select_next_some().await {
            SwarmEvent::Behaviour(ComposedEvent::Gossipsub(ev)) => {
                if let gossipsub::Event::Message {
                    propagation_source,
                    message_id: _,
                    message,
                    ..
                } = ev
                {
                    if let Some(sa) = parse_announce(&message.data) {
                        // Upper layer can verify_sig and plan sync
                        let _ = ann_tx.send((propagation_source, sa));
                    }
                }
                Ok(true)
            }
            SwarmEvent::Behaviour(ComposedEvent::Fetch(ev)) => {
                match ev {
                    request_response::Event::Message { peer, message } => match message {
                        request_response::Message::Request { request, channel, .. } => {
                            // Server path: bubble request up to app to stream frames back.
                            let _ = rpc_tx.send((peer, channel, request));
                        }
                        request_response::Message::Response { .. } => {
                            // Client path: handled by upper layer in later phases.
                        }
                    },
                    _ => {}
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Respond to a Fetch request with a single frame (caller can stream multiple calls).
    pub fn respond_fetch(&mut self, ch: ResponseChannel<RpcFrame>, frame: RpcFrame) {
        let _ = self.swarm.behaviour_mut().fetch.send_response(ch, frame);
    }
}
