use serde::{Deserialize, Serialize};
use ecac_core::op::OpId;

/// NodeId = blake3(public_key_bytes). 32 bytes.
pub type NodeId = [u8; 32];

/// Tiny 16-bit bloom over recent N op_ids (little-endian bit order).
pub type Bloom16 = [u8; 2];

/// Unsigned announce payload (CBOR-serialized in this fixed field order).
/// IMPORTANT: Do NOT change field order or names; no maps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Announce {
    pub node_id: NodeId,
    pub topo_watermark: u64,
    pub head_ids: Vec<OpId>, // up to K tips; order is sender-defined
    pub bloom16: Bloom16,    // hint; receiver may ignore
}

/// Signed wrapper for Announce.
/// Signature = Ed25519 over canonical CBOR bytes of `Announce`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedAnnounce {
    pub announce: Announce,
    pub sig: Vec<u8>,    // 64 bytes; kept Vec for serde friendliness
    pub vk: [u8; 32],    // sender’s ed25519 verifying key bytes
}

/// Fetch RPC request. Want is a set of candidate missing IDs (frontier tips).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FetchMissing {
    pub want: Vec<OpId>,
}

/// RPC stream frames sent by the server for a FetchMissing session.
/// `OpBytes` are EXACT canonical CBOR bytes from store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RpcFrame {
    OpBytes(Vec<u8>),
    End,
}
