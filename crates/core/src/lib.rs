pub mod crypto;
pub mod serialize;
pub mod hlc;
pub mod op;
pub mod dag;
pub mod crdt;
pub mod state;
pub mod replay;

// M4 additions
pub mod trust;
pub mod status;
pub mod vc;
pub mod policy; // keep after vc/trust/status so it can use them

pub mod metrics; // M7 metrics registry

// M8 (feature-gated)
#[cfg(feature = "audit")]
pub mod audit;
