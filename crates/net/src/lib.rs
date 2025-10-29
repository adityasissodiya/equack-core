#![forbid(unsafe_code)]

pub mod gossip;
pub mod rpc;
pub mod sync;
pub mod serializer;
pub mod transport;

// Re-export core types we’ll commonly use later (keeps imports clean)
pub use ecac_core::op::OpId;

// Placeholder newtypes for later phases (avoid re-plumbing)
#[allow(dead_code)]
pub type NodeId = [u8; 32];

#[allow(dead_code)]
pub type Bloom16 = [u8; 2];
