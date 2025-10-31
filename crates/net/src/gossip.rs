use blake3;
use libp2p::gossipsub::{
    self, IdentTopic as Topic, MessageAuthenticity, MessageId, ValidationMode,
};
use libp2p::identity;

use crate::serializer::{from_cbor_signed_announce, to_cbor_signed_announce};
use crate::types::SignedAnnounce;

/// Build the announce topic string for a project.
pub fn announce_topic(project_id: &str) -> Topic {
    Topic::new(format!("ecac/v1/{}/announce", project_id))
}

/// Build a configured Gossipsub behaviour (MessageAuthenticity::Signed).
pub fn build_gossipsub(local_key: &identity::Keypair) -> gossipsub::Behaviour {
    let message_id_fn = |m: &gossipsub::Message| {
        // De-dup by blake3(payload) to suppress echo storms
        let h = blake3::hash(&m.data);
        MessageId::new(h.as_bytes())
    };

    let cfg = gossipsub::ConfigBuilder::default()
        .validate_messages() // needed to get subscribed handler events
        .validation_mode(ValidationMode::Permissive) // we self-verify SignedAnnounce anyway
        .message_id_fn(message_id_fn)
        .max_transmit_size(64 * 1024)
        .build()
        .expect("gossipsub config");

    gossipsub::Behaviour::new(MessageAuthenticity::Signed(local_key.clone()), cfg)
        .expect("gossipsub")
}

/// Serialize and publish a SignedAnnounce onto the announce topic.
pub fn publish_announce(
    gs: &mut gossipsub::Behaviour,
    topic: &Topic,
    sa: &SignedAnnounce,
) -> Result<gossipsub::MessageId, gossipsub::PublishError> {
    let bytes = to_cbor_signed_announce(sa);
    gs.publish(topic.clone(), bytes)
}

/// Attempt to parse a received message payload into a SignedAnnounce.
pub fn parse_announce(data: &[u8]) -> Option<SignedAnnounce> {
    from_cbor_signed_announce(data).ok()
}
