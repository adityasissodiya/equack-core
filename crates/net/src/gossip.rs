use blake3;
#[cfg(feature = "net")]
use ecac_core::metrics::METRICS;
use libp2p::gossipsub::{
    self, IdentTopic as Topic, MessageAuthenticity, MessageId, TopicHash, ValidationMode,
};
use libp2p::identity;
use std::time::Duration;

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
        .validate_messages()
        .validation_mode(ValidationMode::Permissive)
        .message_id_fn(message_id_fn)
        .flood_publish(true) // allow publish even if not in mesh
        .heartbeat_interval(Duration::from_millis(200)) // speed convergence for tests
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
    let byte_len = bytes.len();
    // Debug id: blake3(payload) first 8 hex chars
    let h = blake3::hash(&bytes);
    let mut h8 = String::new();
    {
        use core::fmt::Write;
        for b in h.as_bytes().iter().take(8) {
            let _ = write!(&mut h8, "{:02x}", b);
        }
    }
    eprintln!(
        "[gossip] PUBLISH try topic={} bytes={} blake3[..8]={}",
        topic.hash().to_string(),
        byte_len,
        h8
    );
    let msg_id = gs.publish(topic.clone(), bytes)?;
    #[cfg(feature = "net")]
    {
        // Count successfully published announces.
        METRICS.inc("gossip_announces_sent", 1);
    }
    eprintln!(
        "[gossip] PUBLISH ok   topic={} (heads={}, topo={}, bytes={})",
        topic.hash().to_string(),
        sa.announce.head_ids.len(),
        sa.announce.topo_watermark,
        byte_len
    );
    #[cfg(feature = "net")]
    {
        METRICS.inc("gossip_announces_sent", 1);
    }
    Ok(msg_id)
}

/// Attempt to parse a received message payload into a SignedAnnounce.
pub fn parse_announce(data: &[u8]) -> Option<SignedAnnounce> {
    match from_cbor_signed_announce(data).ok() {
        Some(sa) => {
            #[cfg(feature = "net")]
            {
                // Count announces we accept/parse.
                METRICS.inc("gossip_announces_recv", 1);
            }
            log::trace!(
                "gossipsub PARSE announce heads={} topo={} bytes={}",
                sa.announce.head_ids.len(),
                sa.announce.topo_watermark,
                data.len()
            );
            #[cfg(feature = "net")]
            {
                METRICS.inc("gossip_announces_recv", 1);
            }
            Some(sa)
        }
        None => None,
    }
}

/// Subscribe to the announce topic (idempotent).
pub fn subscribe_announce(
    gs: &mut gossipsub::Behaviour,
    topic: &Topic,
) -> Result<(), gossipsub::SubscriptionError> {
    match gs.subscribe(topic) {
        Ok(true) => {
            log::trace!("gossipsub SUBSCRIBED -> {}", topic.hash().to_string());
            Ok(())
        }
        Ok(false) => Ok(()), // already subscribed
        Err(e) => Err(e),
    }
}

/// Does a received message belong to *this* announce topic?
#[inline]
pub fn topic_matches_announce(topic: &Topic, incoming: &TopicHash) -> bool {
    topic.hash() == *incoming
}

/// Convenience: if a gossipsub message is for our announce topic, decode it.
pub fn parse_announce_if_for_topic(
    topic: &Topic,
    incoming_topic: &TopicHash,
    data: &[u8],
) -> Option<SignedAnnounce> {
    if topic_matches_announce(topic, incoming_topic) {
        parse_announce(data)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_string_is_stable() {
        let t = announce_topic("proj");
        assert_eq!(
            t.hash().to_string(),
            Topic::new("ecac/v1/proj/announce").hash().to_string()
        );
    }
}
