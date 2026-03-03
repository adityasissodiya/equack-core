#![forbid(unsafe_code)]

pub mod gossip;
pub mod rpc;
pub mod serializer;
pub mod sync;
pub mod transport;
pub mod types; // NEW: Phase 2

// Re-export core types we’ll commonly use later (keeps imports clean)
pub use ecac_core::op::OpId;
pub use types::{Announce, Bloom16, FetchMissing, NodeId, RpcFrame, SignedAnnounce};

// Placeholder newtypes for later phases (avoid re-plumbing)
// #[allow(dead_code)]
// pub type NodeId = [u8; 32];

// #[allow(dead_code)]
// pub type Bloom16 = [u8; 2];
